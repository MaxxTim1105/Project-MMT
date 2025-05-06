####################################################
# DVrouter.py
# Name:
# HUID:
#####################################################

from router import Router
from packet import Packet
import ast

class DVrouter(Router):
    """Distance vector routing protocol with full recomputation on changes."""

    def __init__(self, addr, heartbeat_time):
        super(DVrouter, self).__init__(addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        # neighbor info: endpoint -> (port, cost)
        self.neighbors = {}
        # store last received vectors: endpoint -> {dest: (cost, path)}
        self.remote_vectors = {}
        # current distance vector: dest -> (cost, path)
        self.distance = {addr: (0, [addr])}
        # forwarding table: dest -> port
        self.forwarding = {}

    def broadcast_distance_vector(self):
        """Send current distance vector to all neighbors."""
        data = repr(self.distance)
        for endpoint, (port, _) in self.neighbors.items():
            pkt = Packet(Packet.ROUTING, self.addr, endpoint, data)
            self.send(port, pkt)

    def recompute_routes(self):
        """Recompute best paths using current neighbors and remote vectors."""
        new_dist = {self.addr: (0, [self.addr])}
        new_fwd = {}
        # initialize direct neighbors
        for endpoint, (port, cost) in self.neighbors.items():
            new_dist[endpoint] = (cost, [self.addr, endpoint])
            new_fwd[endpoint] = port
        # relaxation loop
        updated = True
        while updated:
            updated = False
            for nbr, vect in self.remote_vectors.items():
                if nbr not in self.neighbors:
                    continue
                port, cost_to_nbr = self.neighbors[nbr]
                for dest, (rcost, rpath) in vect.items():
                    if dest == self.addr:
                        continue
                    cand_cost = cost_to_nbr + rcost
                    cand_path = [self.addr] + list(rpath)
                    if dest not in new_dist or cand_cost < new_dist[dest][0] or (
                        cand_cost == new_dist[dest][0] and cand_path < new_dist[dest][1]
                    ):
                        new_dist[dest] = (cand_cost, cand_path)
                        new_fwd[dest] = port
                        updated = True
        # check if changed
        if new_dist != self.distance or new_fwd != self.forwarding:
            self.distance = new_dist
            self.forwarding = new_fwd
            return True
        return False

    def handle_packet(self, port, packet):
        """Process incoming traceroute or routing packet."""
        if packet.is_traceroute:
            dst = packet.dst_addr
            if dst in self.forwarding:
                self.send(self.forwarding[dst], packet)
        elif packet.is_routing:
            try:
                vect = ast.literal_eval(packet.content)
            except Exception:
                return
            neighbor = packet.src_addr
            # record if neighbor known
            if neighbor not in self.neighbors:
                return
            # store remote vector
            self.remote_vectors[neighbor] = vect
            # recompute global routes
            if self.recompute_routes():
                self.broadcast_distance_vector()

    def handle_new_link(self, port, endpoint, cost):
        """Handle a new link: add neighbor and recompute."""
        self.neighbors[endpoint] = (port, cost)
        self.remote_vectors.setdefault(endpoint, {})
        if self.recompute_routes():
            self.broadcast_distance_vector()

    def handle_remove_link(self, port):
        """Handle link removal: remove neighbor and recompute."""
        # find endpoint by port
        eps = [ep for ep, (p, _) in self.neighbors.items() if p == port]
        if not eps:
            return
        ep = eps[0]
        self.neighbors.pop(ep)
        self.remote_vectors.pop(ep, None)
        if self.recompute_routes():
            self.broadcast_distance_vector()

    def handle_time(self, time_ms):
        """Periodic broadcast at heartbeat intervals."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.broadcast_distance_vector()

    def __repr__(self):
        entries = []
        for dest, (cost, path) in sorted(self.distance.items()):
            entries.append(f"{dest}:{cost}:{path}")
        return f"DVrouter({self.addr}) DV={{" + ", ".join(entries) + "}}"
