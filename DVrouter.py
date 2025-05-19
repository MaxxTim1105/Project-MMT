####################################################
# DVrouter.py
# Name:
# HUID:
#####################################################
import base64
import math
import pickle
# import sys # Không cần thiết nếu dùng số nguyên lớn cố định
from typing import Any, Optional, Dict, Tuple
from packet import Packet
from router import Router

type _Addr = Any
type _Port = Any
type _Cost = float
_INFINITY = math.inf # Định nghĩa giá trị vô cùng cho chi phí
_INFINITY_HOPS = 1000000 # Số hop lớn, coi như vô cùng

# Chỉ số để truy cập tuple trong __forwarding_table
COST_IDX = 0
NEXT_HOP_IDX = 1
PORT_IDX = 2
HOP_COUNT_IDX = 3

# Chỉ số cho tuple chi tiết láng giềng
NEIGHBOR_PORT_IDX = 1

# Chỉ số cho tuple trong received_dv: Dict[_Addr, Tuple[_Cost, int_hops]]
DV_COST_IDX = 0
DV_HOPS_IDX = 1

def _serialize(obj: Any) -> str:
    bytes_ = pickle.dumps(obj)
    return base64.b64encode(bytes_).decode()

def _deserialize(str_: str) -> Any:
    bytes_ = base64.b64decode(str_.encode())
    return pickle.loads(bytes_)

class DVrouter(Router):
    """Triển khai DVrouter với tie-breaking theo số hop."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0.0

        self.__forwarding_table: Dict[_Addr, Tuple[_Cost, Optional[_Addr], Optional[_Port], int]] = {}
        self.__forwarding_table[self.addr] = (0.0, self.addr, None, 0) # 0 hops to self

        self.__neighbor_addrs_by_ports: Dict[_Port, _Addr] = {}
        self.__neighbors_by_addrs: Dict[_Addr, Tuple[_Cost, _Port]] = {}
        self.__last_dv_sent_to_neighbor: Dict[_Addr, Dict[_Addr, Tuple[_Cost, int]]] = {}

    def handle_packet(self, port_received_on: _Port, packet: Packet):
        # Kiểm tra xem địa chỉ đích có trong bảng định tuyến không nếu có thì chuyển đi
        if packet.is_traceroute:
            if packet.dst_addr in self.__forwarding_table:
                entry = self.__forwarding_table[packet.dst_addr]
                if entry[COST_IDX] < _INFINITY and entry[PORT_IDX] is not None:
                    self.send(entry[PORT_IDX], packet)
        else: # Gói tin định tuyến (Distance Vector)
            try:
                received_dv: Dict[_Addr, Tuple[_Cost, int]] = _deserialize(packet.content)
            except Exception:
                return
            
            # Kiểm tra xem địa chỉ nguồn của gói định tuyến có thuộc hàng xóm không 
            sender_neighbor_addr = packet.src_addr
            if sender_neighbor_addr not in self.__neighbors_by_addrs:
                return
            
            # Xác định cost và port của mình để đến neighbor đó
            neighbor_details = self.__neighbors_by_addrs[sender_neighbor_addr]
            cost_to_sender = neighbor_details[COST_IDX]
            port_to_sender = neighbor_details[NEIGHBOR_PORT_IDX]
            something_changed_in_ft = False

            for dest, (adv_cost, adv_hops) in received_dv.items():
                candidate_cost = cost_to_sender + adv_cost
                candidate_hops = adv_hops + 1

                if candidate_cost >= _INFINITY:
                    candidate_cost = _INFINITY
                    candidate_hops = _INFINITY_HOPS
                
                new_potential_entry = (candidate_cost, sender_neighbor_addr, port_to_sender, candidate_hops)
                if candidate_cost == _INFINITY: # Chuẩn hóa entry không thể tới
                    new_potential_entry = (_INFINITY, None, None, _INFINITY_HOPS)

                current_entry = self.__forwarding_table.get(dest)
                
                should_update = False
                if current_entry is None: # Chưa có route, thêm nếu route mới hợp lệ
                    if new_potential_entry[COST_IDX] < _INFINITY:
                        should_update = True
                else: # Đã có route, so sánh
                    # 1. Chi phí tốt hơn
                    if new_potential_entry[COST_IDX] < current_entry[COST_IDX]:
                        should_update = True
                    # 2. Chi phí bằng, số hop ít hơn (chỉ cho route hợp lệ)
                    elif new_potential_entry[COST_IDX] == current_entry[COST_IDX] and \
                         new_potential_entry[COST_IDX] < _INFINITY and \
                         new_potential_entry[HOP_COUNT_IDX] < current_entry[HOP_COUNT_IDX]:
                        should_update = True
                    # 3. Route hiện tại qua chính sender này, và thông tin (cost/hops) đã thay đổi
                    elif current_entry[NEXT_HOP_IDX] == sender_neighbor_addr:
                        if current_entry[COST_IDX] != new_potential_entry[COST_IDX] or \
                           current_entry[HOP_COUNT_IDX] != new_potential_entry[HOP_COUNT_IDX]:
                           should_update = True
                
                if should_update:
                    if self.__forwarding_table.get(dest) != new_potential_entry:
                        self.__forwarding_table[dest] = new_potential_entry
                        something_changed_in_ft = True
            
            if something_changed_in_ft:
                self.__broadcast_to_neighbors()

    def handle_new_link(self, port: _Port, endpoint: _Addr, cost: _Cost):
        self.__neighbor_addrs_by_ports[port] = endpoint
        self.__neighbors_by_addrs[endpoint] = (cost, port)

        new_direct_entry = (cost, endpoint, port, 1) # cost, next_hop, port, hops=1
        current_ft_entry = self.__forwarding_table.get(endpoint)
        
        should_update = False
        if current_ft_entry is None:
            should_update = True
        else:
            # Ưu tiên nếu chi phí thấp hơn
            if new_direct_entry[COST_IDX] < current_ft_entry[COST_IDX]:
                should_update = True
            # Hoặc chi phí bằng nhau VÀ (đường hiện tại nhiều hop hơn HOẶC đường hiện tại không phải là trực tiếp tới endpoint này)
            elif new_direct_entry[COST_IDX] == current_ft_entry[COST_IDX] and \
                 (new_direct_entry[HOP_COUNT_IDX] < current_ft_entry[HOP_COUNT_IDX] or \
                  current_ft_entry[NEXT_HOP_IDX] != endpoint):
                should_update = True
        
        if should_update:
            if self.__forwarding_table.get(endpoint) != new_direct_entry:
                self.__forwarding_table[endpoint] = new_direct_entry
                # self.__broadcast_to_neighbors() được gọi ở cuối hàm này rồi

        self.__broadcast_to_neighbors() # Luôn quảng bá khi có link mới

    def handle_remove_link(self, port: _Port):
        if port not in self.__neighbor_addrs_by_ports:
            return

        removed_neighbor_addr = self.__neighbor_addrs_by_ports.pop(port)
        if removed_neighbor_addr in self.__neighbors_by_addrs:
            del self.__neighbors_by_addrs[removed_neighbor_addr]
        if removed_neighbor_addr in self.__last_dv_sent_to_neighbor:
            del self.__last_dv_sent_to_neighbor[removed_neighbor_addr]

        for dest, ft_entry in list(self.__forwarding_table.items()):
            if dest == self.addr:
                continue
            if ft_entry[NEXT_HOP_IDX] == removed_neighbor_addr: # Điều kiện đơn giản hóa
                if ft_entry[COST_IDX] != _INFINITY or ft_entry[HOP_COUNT_IDX] != _INFINITY_HOPS:
                    self.__forwarding_table[dest] = (_INFINITY, None, None, _INFINITY_HOPS)
        
        self.__broadcast_to_neighbors() # Luôn quảng bá sau khi xóa link

    def handle_time(self, time_ms: float):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.__broadcast_to_neighbors()

    def __repr__(self):
        """Biểu diễn routing table ngắn gọn để debug."""
        ft_summary = {}
        for dest, (cost, nexthop, _port, hops) in self.__forwarding_table.items():
            if dest != self.addr: # Không hiển thị route đến chính nó trong summary này
                if cost < _INFINITY and hops < _INFINITY_HOPS:
                     ft_summary[dest] = (f"c:{cost:.1f}", f"nh:{nexthop}", f"hp:{hops}")
                # else: # Tùy chọn: hiển thị cả các route không tới được nếu muốn
                #     ft_summary[dest] = (f"c:inf", f"nh:-", f"hp:inf")
        return f"DVrouter(addr={self.addr}, FT={ft_summary if ft_summary else 'EMPTY'})"


    def __broadcast_to_neighbors(self):
        if not self.__neighbors_by_addrs:
            return

        for target_neighbor_addr, details_tuple in self.__neighbors_by_addrs.items():
            port_to_target = details_tuple[NEIGHBOR_PORT_IDX]
            dv_to_send: Dict[_Addr, Tuple[_Cost, int]] = {} # (cost, hops)

            for dest, ft_entry in self.__forwarding_table.items():
                cost_adv = ft_entry[COST_IDX]
                hops_adv = ft_entry[HOP_COUNT_IDX]
                next_hop_for_dest = ft_entry[NEXT_HOP_IDX]

                # Poison Reverse
                if next_hop_for_dest == target_neighbor_addr and dest != target_neighbor_addr:
                    cost_adv = _INFINITY
                    hops_adv = _INFINITY_HOPS
                
                dv_to_send[dest] = (cost_adv, hops_adv)
            
            if not dv_to_send: # Không nên xảy ra
                continue

            if self.__last_dv_sent_to_neighbor.get(target_neighbor_addr) != dv_to_send:
                content = _serialize(dv_to_send)
                packet = Packet(Packet.ROUTING, self.addr, target_neighbor_addr, content)
                self.send(port_to_target, packet)
                self.__last_dv_sent_to_neighbor[target_neighbor_addr] = dv_to_send