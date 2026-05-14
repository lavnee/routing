import json

from packet import Packet
from router import Router


class LSrouter(Router):
    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)          # Gọi hàm khởi tạo của class cha Router — bắt buộc, đừng xóa
        self.heartbeat_time = heartbeat_time # Khoảng thời gian giữa 2 lần gửi link state định kỳ (giây)
        self.last_time = 0                   # Lần cuối gửi link state là lúc nào (giây), bắt đầu = 0

        self.neighbors = {}                  # Bảng láng giềng trực tiếp: port → (neighbor_addr, cost)
                                             # Ví dụ: { 1: ("B", 5), 2: ("C", 3) }
                                             # = cổng 1 nối đến B mất 5, cổng 2 nối đến C mất 3

        self.link_state = {self.addr: {}}    # Bản đồ toàn mạng: router → {dest: cost}
                                             # Ví dụ: { "A": {"B": 5, "C": 3}, "B": {"A": 5, "D": 4} }
                                             # = A biết đến B mất 5, đến C mất 3; B biết đến A mất 5, đến D mất 4
                                             # Khởi tạo với entry của chính mình rỗng {self.addr: {}}
                                             # vì lúc đầu mình chưa có link nào

        self.seq_num = 0                     # Sequence number của link state CỦA CHÍNH MÌNH
                                             # Tăng lên 1 mỗi lần mình gửi link state mới
                                             # Dùng để láng giềng biết tin nào là mới hơn

        self.received_seq = {}               # Lưu sequence number mới nhất đã nhận từ mỗi router
                                             # Ví dụ: { "B": 3, "C": 5 }
                                             # = tin mới nhất từ B là seq=3, từ C là seq=5
                                             # Dùng để tránh xử lý lại tin cũ đã xử lý rồi

        self.nexthop = {}                    # Bảng forwarding (kết quả của Dijkstra): dest → port
                                             # Ví dụ: { "C": 1, "D": 2 }
                                             # = muốn đến C thì gửi ra cổng 1, muốn đến D thì gửi ra cổng 2

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            # Đây là gói tin data thật (traceroute) — cần chuyển tiếp đến đích
            dest = packet.dst_addr           # Lấy địa chỉ đích của gói tin

            # Nếu đích không phải mình VÀ mình biết đường đến đích đó
            if dest != self.addr and dest in self.nexthop:
                self.send(self.nexthop[dest], packet)
                #              ↑
                # nexthop[dest] = số cổng cần gửi ra để đến được dest
                # Nếu không biết đường → drop gói tin (không làm gì)
        else:
            # Đây là gói tin routing — láng giềng đang chia sẻ link state của họ
            data = json.loads(packet.content)    # Giải mã JSON thành Python dict
                                                 # packet.content là chuỗi JSON dạng text
                                                 # json.loads() chuyển text → dict để dùng được
            src = data["src"]                    # Router nào đã tạo ra tin link state này
            seq = data["seq"]                    # Đây là tin thứ mấy của router đó
            links = data["links"]                # Router đó có những link nào: { "B": 5, "C": 3 }

            # Kiểm tra: tin này có mới không?
            # Nếu đã nhận tin từ src với seq >= seq này rồi → tin cũ, bỏ qua
            if src in self.received_seq and self.received_seq[src] >= seq:
                return                           # return = dừng hàm ngay đây, không xử lý tiếp

            # Tin mới → lưu lại seq mới nhất của router này
            self.received_seq[src] = seq

            # Cập nhật bản đồ mạng với thông tin link state mới từ src
            self.link_state[src] = links

            # Flood tiếp: chuyển tiếp tin này cho tất cả láng giềng KHÁC
            # (không gửi lại cho cổng vừa nhận vào — tránh vòng lặp)
            for out_port, (neighbor, _) in self.neighbors.items():
                #                      ↑
                # _ = bỏ qua giá trị cost vì không cần dùng ở đây
                if out_port != port:             # Chỉ gửi qua cổng khác cổng nhận vào
                    fwd = Packet(Packet.ROUTING, self.addr, neighbor, packet.content)
                    # Tạo gói tin mới: loại ROUTING, từ mình, đến neighbor, nội dung giữ nguyên
                    self.send(out_port, fwd)

            # Cập nhật forwarding table vì bản đồ mạng vừa thay đổi
            self.run_dijkstra()

    def handle_new_link(self, port, endpoint, cost):     # link mới đến neighbor mới hoặc link mới đến neighbor cũ với chi phí mới
        """Handle new link."""
        # Cập nhật local data structures và forwarding table
        # Broadcast link state mới của router này đến tất cả neighbors

        # Ghi nhớ láng giềng mới: cổng port nối đến router endpoint với chi phí cost
        self.neighbors[port] = (endpoint, cost)

        # Cập nhật bản đồ của chính mình: mình có thêm link đến endpoint với cost này
        self.link_state[self.addr][endpoint] = cost

        # Quảng bá link state mới của mình ra toàn mạng
        self.flood_link_state()

        # Tính lại đường ngắn nhất vì có link mới
        self.run_dijkstra()

    def handle_remove_link(self, port):
        """Handle removed link."""
        # Cập nhật local data structures và forwarding table
        # Broadcast link state mới của router này đến tất cả neighbors

        if port not in self.neighbors:      # Nếu cổng này không tồn tại thì bỏ qua
            return

        neighbor_addr = self.neighbors[port][0]   # Lấy tên router ở đầu kia của link bị xóa
        #                                   ↑
        # self.neighbors[port] = ("B", 5) là một tuple
        # [0] = lấy phần tử đầu tiên = tên router "B"
        # [1] = lấy phần tử thứ hai = cost 5

        del self.neighbors[port]            # Xóa láng giềng này khỏi bảng neighbors
        #   ↑
        # del = xóa một phần tử khỏi dictionary

        # Xóa link đến neighbor này khỏi bản đồ của chính mình
        if neighbor_addr in self.link_state[self.addr]:
            del self.link_state[self.addr][neighbor_addr]

        # Quảng bá link state mới (đã bỏ link vừa xóa) ra toàn mạng
        self.flood_link_state()

        # Tính lại đường ngắn nhất vì link bị remove
        self.run_dijkstra()

    def handle_time(self, time_ms):
        """Handle current time."""
        # time_ms = thời gian hiện tại (milliseconds)
        # Kiểm tra xem đã đến lúc gửi link state định kỳ chưa
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms         # Cập nhật: lần gửi gần nhất = bây giờ
            # Broadcast link state của router này đến tất cả neighbors

            # Gửi lại link state định kỳ dù không có thay đổi
            # (phòng trường hợp gói tin bị mất trên đường)
            self.flood_link_state()

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        # NOTE: hàm này chỉ dùng để debug, không được chấm điểm
        return f"LSrouter(addr={self.addr}, nexthop={self.nexthop})"

    def flood_link_state(self):
        """Quảng bá link state của chính mình ra toàn mạng."""
        self.seq_num += 1                    # Tăng seq_num lên — "đây là tin mới nhất của tao"

        # Đóng gói thông tin thành JSON để gửi đi
        # Dùng key "links" nhất quán với handle_packet
        content = json.dumps({
            "src": self.addr,                    # Tao là ai
            "seq": self.seq_num,                 # Đây là tin thứ mấy của tao
            "links": self.link_state[self.addr]  # Tao có những link nào (chỉ link của CHÍNH MÌNH)
        })
        # json.dumps() = chuyển Python dict → chuỗi JSON text để nhét vào packet

        # Gửi ra TẤT CẢ các cổng
        for port, (neighbor, _) in self.neighbors.items():
            packet = Packet(Packet.ROUTING, self.addr, neighbor, content)
            # Tạo gói tin: loại ROUTING, từ mình (self.addr), đến neighbor, nội dung là content
            self.send(port, packet)

    def run_dijkstra(self):
        """Cập nhật bảng forwarding mới khi có thông tin mới từ neighbor hoặc link."""

        # Khởi tạo
        dist = {self.addr: 0}                # Khoảng cách từ chính mình đến các router khác
                                             # Bắt đầu chỉ biết chắc 1 thứ: đến mình = 0

        prev = {}                            # prev[X] = Y nghĩa là: đường ngắn nhất đến X
                                             # thì bước ngay trước X là Y
                                             # Ví dụ: prev["D"] = "B" → đường đến D đi qua B

        unvisited = set(self.link_state.keys())  # Tập các router chưa được xử lý
                                                 # .keys() lấy tất cả key của link_state
                                                 # tức là tất cả router mà mình biết đến
                                                 # set(...) = tạo tập hợp, mỗi phần tử chỉ 1 lần

        # Lặp Dijkstra
        while unvisited:                     # Lặp cho đến khi xét hết tất cả router

            # Tìm router gần nhất trong unvisited (chưa xử lý)
            current = None                   # None = chưa xác định được
            for router in unvisited:
                if router in dist:           # Chỉ xét router đã biết khoảng cách
                    if current is None or dist[router] < dist[current]:
                        current = router     # Chọn router có khoảng cách nhỏ nhất

            if current is None:              # Không còn router nào có thể đến được → dừng
                break

            unvisited.remove(current)        # Đánh dấu current đã được xử lý

            if current not in self.link_state:   # Nếu không có thông tin link state thì bỏ qua
                continue

            # Xét các láng giềng của current để tìm đường ngắn hơn
            for neighbor, cost in self.link_state[current].items():
                new_cost = dist[current] + cost      # Chi phí đi từ mình → current → neighbor

                # Nếu tìm được đường đến neighbor ngắn hơn đường cũ → cập nhật
                if neighbor not in dist or new_cost < dist[neighbor]:
                    dist[neighbor] = new_cost
                    prev[neighbor] = current         # Ghi lại: đường đến neighbor đi qua current

        # Xây dựng bảng nexthop từ bảng prev
        self.nexthop = {}                    # Reset bảng forwarding

        for dest in dist:                    # Duyệt qua tất cả đích đã tính được khoảng cách
            if dest == self.addr:
                continue                     # Không cần nexthop đến chính mình

            # Truy ngược đường đi từ dest về chính mình
            # Ví dụ: dest=D, prev={D:B, B:A}, mình là A
            # → đi ngược: D → B → A (dừng khi prev[node] == mình)
            # → bước đầu tiên từ A là đến B → nexthop[D] = cổng đến B
            path_node = dest
            while prev.get(path_node) != self.addr:
                # .get() = lấy giá trị, trả về None nếu key không tồn tại
                # (an toàn hơn [] vì không crash khi key không có)
                path_node = prev.get(path_node)
                if path_node is None:        # Không tìm được đường về → bỏ qua dest này
                    break

            if path_node is None:            # Không tìm được đường → bỏ qua dest này
                continue
            # (Lưu ý: PHẢI là "is None" để bỏ qua khi KHÔNG tìm được đường
            #  Nếu viết "is not None" → logic ngược, sẽ bỏ qua khi TÌM ĐƯỢC đường!)

            # path_node bây giờ là router ngay kế tiếp sau mình trên đường đến dest
            # Tìm xem cổng nào của mình nối đến router đó
            for port, (neighbor, _) in self.neighbors.items():
                if neighbor == path_node:
                    self.nexthop[dest] = port    # Ghi vào bảng forwarding
                    break                        # Tìm được rồi, dừng vòng for