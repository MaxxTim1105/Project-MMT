####################################################
# DVrouter.py
# Name:
# HUID:
#####################################################
import base64
import math
import pickle
from typing import Any, Optional, Dict, Tuple
from packet import Packet 
from router import Router 

_Addr = Any
_Port = Any
_Cost = float
_INFINITY = math.inf # Định nghĩa giá trị vô cùng cho chi phí

# Chỉ số để truy cập tuple
COST_IDX = 0         # Chỉ số cho chi phí
NEXT_HOP_IDX = 1     # Chỉ số cho địa chỉ chặng kế tiếp
PORT_IDX = 2         # Chỉ số cho cổng cục bộ ra chặng kế tiếp

NEIGHBOR_PORT_IDX = 1 # Chỉ số cho port trong chi tiết láng giềng

# Mã hóa gói tin
def _serialize(obj: Any) -> str:
    """Tuần tự hóa một đối tượng thành một chuỗi base64."""
    bytes_ = pickle.dumps(obj)
    str_ = base64.b64encode(bytes_).decode()
    return str_

# Giải mã gói tin
def _deserialize(str_: str) -> Any:
    """Giải tuần tự hóa một chuỗi base64 trở lại thành một đối tượng."""
    bytes_ = base64.b64decode(str_.encode())
    obj = pickle.loads(bytes_)
    return obj

class DVrouter(Router):
    """Triển khai giao thức định tuyến vector khoảng cách."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time # Thời gian giữa các lần gửi heartbeat định kỳ
        self.last_time = 0.0                 # Thời điểm cuối cùng gửi heartbeat

        # Bảng chuyển tiếp: dest_addr -> Tuple[_Cost, Optional[_Addr], Optional[_Port]]
        # (chi_phí_đến_đích, địa_chỉ_chặng_kế_tiếp_đến_đích, cổng_cục_bộ_ra_chặng_kế_tiếp)
        self.__forwarding_table: Dict[_Addr, Tuple[_Cost, Optional[_Addr], Optional[_Port]]] = {}

        # Khởi tạo tuyến đường đến chính nó
        self.__forwarding_table[self.addr] = (0.0, self.addr, None)

        # Thông tin láng giềng
        # Ánh xạ: cổng_cục_bộ -> địa_chỉ_láng_giềng => Xác định địa chỉ láng giềng dựa trên cổng mạng
        self.__neighbor_addrs_by_ports: Dict[_Port, _Addr] = {}

        # Ánh xạ: địa_chỉ_láng_giềng -> Tuple[_Cost, _Port]
        # (chi_phí_liên_kết_trực_tiếp_đến_láng_giềng, cổng_cục_bộ_ra_láng_giềng) => Xác định chi phí và cổng để liên lạc với một láng giềng cụ thể.
        self.__neighbors_by_addrs: Dict[_Addr, Tuple[_Cost, _Port]] = {}

        # Lưu trữ DV cuối cùng được gửi cho mỗi láng giềng để tránh gửi lại thông tin không đổi
        self.__last_dv_sent_to_neighbor: Dict[_Addr, Dict[_Addr, Tuple[_Cost, _Addr]]] = {}


    def handle_packet(self, port_received_on: _Port, packet: Packet):
        """Xử lý một gói tin đến (traceroute hoặc gói tin định tuyến)."""

        # Xử lí gói tin traceroute
        if packet.is_traceroute:
            if packet.dst_addr in self.__forwarding_table:
                ft_entry = self.__forwarding_table[packet.dst_addr]
                cost = ft_entry[COST_IDX]
                port_to_send = ft_entry[PORT_IDX]

                if cost < _INFINITY and port_to_send is not None:
                    self.send(port_to_send, packet)
                # else: Chi phí vô cùng hoặc không có cổng gửi, gói tin bị loại bỏ
            # else: Đích không có trong bảng chuyển tiếp, gói tin bị loại bỏ

        # Xử lí gói tin định tuyến (Distance Vector)
        elif packet.is_routing: 

            # Giải mã nội dung gói tin
            try:
                received_dv: Dict[_Addr, Tuple[_Cost, _Addr]] = _deserialize(packet.content)
            except Exception:
                return

            # Kiểm tra xem DV nhận được từ láng giềng không xác định/không phải láng giềng, nếu đúng thì return
            sender_neighbor_addr = packet.src_addr
            if sender_neighbor_addr not in self.__neighbors_by_addrs:
                return

            neighbor_details = self.__neighbors_by_addrs[sender_neighbor_addr]
            cost_to_sender_neighbor = neighbor_details[COST_IDX]
            port_to_sender_neighbor = neighbor_details[NEIGHBOR_PORT_IDX]

            something_changed_in_ft = False

            # Duyệt từng "láng giềng" của láng giềng
            for dest_addr_in_dv, dv_entry_tuple in received_dv.items():
                rcvd_adv_cost_from_sender_to_dest = dv_entry_tuple[COST_IDX]
                candidate_total_cost = cost_to_sender_neighbor + rcvd_adv_cost_from_sender_to_dest
                if candidate_total_cost >= _INFINITY:
                    candidate_total_cost = _INFINITY

                # Lấy ra chi phí hiện tại tới "láng giềng"
                current_ft_entry = self.__forwarding_table.get(dest_addr_in_dv)
                current_cost_to_dest = current_ft_entry[COST_IDX] if current_ft_entry else _INFINITY

                # Chi phí tối ưu hơn chi phí ban đầu
                if candidate_total_cost < current_cost_to_dest:
                    if candidate_total_cost == _INFINITY:
                        self.__forwarding_table[dest_addr_in_dv] = (_INFINITY, None, None)
                    else:
                        self.__forwarding_table[dest_addr_in_dv] = (candidate_total_cost, sender_neighbor_addr, port_to_sender_neighbor)
                    something_changed_in_ft = True

                # Chi phí có sự thay đổi trên đường đã đi qua
                elif current_ft_entry and current_ft_entry[NEXT_HOP_IDX] == sender_neighbor_addr:
                    if candidate_total_cost != current_cost_to_dest:
                        if candidate_total_cost == _INFINITY:
                            self.__forwarding_table[dest_addr_in_dv] = (_INFINITY, None, None)
                        else:
                            self.__forwarding_table[dest_addr_in_dv] = (candidate_total_cost, sender_neighbor_addr, port_to_sender_neighbor)
                        something_changed_in_ft = True

            if something_changed_in_ft:
                self.__broadcast_to_neighbors()

    def handle_new_link(self, port: _Port, endpoint: _Addr, cost: _Cost):
        """Xử lý một liên kết mới được thêm vào router."""

        # Lưu lại thông tin gói mới nhận được
        self.__neighbor_addrs_by_ports[port] = endpoint
        self.__neighbors_by_addrs[endpoint] = (cost, port)

        # Lấy ra chi phí hiện tại tới endpoint
        current_ft_entry_to_endpoint = self.__forwarding_table.get(endpoint)
        current_cost_to_endpoint = current_ft_entry_to_endpoint[COST_IDX] if current_ft_entry_to_endpoint else _INFINITY

        # Chi phí mới tối ưu hơn chi phí ban đầu
        if cost < current_cost_to_endpoint:
            self.__forwarding_table[endpoint] = (cost, endpoint, port)

        # Chi phí mới bằng chi phí ban đầu nhưng khác next_hop
        elif cost == current_cost_to_endpoint and \
             (current_ft_entry_to_endpoint is None or current_ft_entry_to_endpoint[NEXT_HOP_IDX] != endpoint):
            self.__forwarding_table[endpoint] = (cost, endpoint, port)

        self.__broadcast_to_neighbors()

    def handle_remove_link(self, port: _Port):
        """Xử lý một liên kết bị xóa khỏi router."""
        
        # Nếu cổng bị xóa không nằm trong danh sách cổng kết nối với láng giềng thì return
        if port not in self.__neighbor_addrs_by_ports:
            return

        # Xóa thông tin láng giềng
        removed_neighbor_addr = self.__neighbor_addrs_by_ports.pop(port)
        if removed_neighbor_addr in self.__neighbors_by_addrs:
            del self.__neighbors_by_addrs[removed_neighbor_addr]

        if removed_neighbor_addr in self.__last_dv_sent_to_neighbor:
            del self.__last_dv_sent_to_neighbor[removed_neighbor_addr]

        # Duyệt qua từng đích trong bảng chuyển tiếp để cập nhật (bỏ qua chính mình)
        for dest_addr, ft_entry in list(self.__forwarding_table.items()):
            if dest_addr == self.addr:
                continue
            if ft_entry[NEXT_HOP_IDX] == removed_neighbor_addr or ft_entry[PORT_IDX] == port :
                if ft_entry[COST_IDX] != _INFINITY:
                    self.__forwarding_table[dest_addr] = (_INFINITY, None, None)
        self.__broadcast_to_neighbors()


    def handle_time(self, time_ms: float):
        """Xử lý thời gian trôi qua, cho các quảng bá định kỳ (heartbeats)."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.__broadcast_to_neighbors()

    def __repr__(self):
        """Biểu diễn routing table để debug."""
        ft_summary = {dest: (cost, hop) for dest, (cost, hop, _port) in self.__forwarding_table.items() if cost < _INFINITY and dest != self.addr}
        return f"DVrouter(addr={self.addr}, FT={ft_summary})"

    def __broadcast_to_neighbors(self):
        """Quảng bá vector khoảng cách hiện tại cho tất cả láng giềng, với split horizon và poison reverse.
        Chỉ gửi gói tin nếu nội dung DV cho láng giềng đó đã thay đổi so với lần gửi trước."""

        # Nếu router không có láng giềng/bị ngắt hết các kết nối thì return
        if not self.__neighbors_by_addrs:
            return

        # Duyệt qua từng láng giềng
        for target_neighbor_addr, neighbor_details_tuple in self.__neighbors_by_addrs.items():
            port_to_target_neighbor = neighbor_details_tuple[NEIGHBOR_PORT_IDX]
            distance_vector_to_send: Dict[_Addr, Tuple[_Cost, _Addr]] = {}

            for dest_in_ft, ft_entry_tuple in self.__forwarding_table.items():
                current_total_cost_to_dest = ft_entry_tuple[COST_IDX]
                current_next_hop_for_dest = ft_entry_tuple[NEXT_HOP_IDX] 

                cost_to_advertise = current_total_cost_to_dest

                if current_next_hop_for_dest == target_neighbor_addr and dest_in_ft != target_neighbor_addr:
                    cost_to_advertise = _INFINITY #poison reverse
                
                next_hop_to_advertise_in_dv = current_next_hop_for_dest if current_next_hop_for_dest is not None else self.addr
                
                distance_vector_to_send[dest_in_ft] = (cost_to_advertise, next_hop_to_advertise_in_dv)

            # Không cần gửi nếu vector khoảng cách trống
            if not distance_vector_to_send:
                continue
            
            # Tiến hành gửi nếu vector khoảng cách mới khác vector khoảng cách gần nhất đã gửi 
            if self.__last_dv_sent_to_neighbor.get(target_neighbor_addr) != distance_vector_to_send:
                content = _serialize(distance_vector_to_send)
                packet_to_send = Packet(kind=Packet.ROUTING, src_addr=self.addr, dst_addr=target_neighbor_addr, content=content)
                self.send(port_to_target_neighbor, packet_to_send)
                self.__last_dv_sent_to_neighbor[target_neighbor_addr] = distance_vector_to_send