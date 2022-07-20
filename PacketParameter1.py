from scapy.layers.inet import TCP, UDP, IP


class PacketParameter1:
    def __init__(self, ether_pkt, pkt_time, logger):
        self.src = ether_pkt.src
        self.dst = ether_pkt.dst
        self.lenght = len(ether_pkt)
        self.packet_time = pkt_time
        self.type = ether_pkt.type

        if self.is_ip():
            ip_pkt = ether_pkt[IP]
            self.src_ip = ip_pkt.src
            self.dst_ip = ip_pkt.dst
            self.proto = ip_pkt.proto
            self.lenght = ip_pkt.len
            self.ttl = ip_pkt.ttl
            self.fragment = ip_pkt.flags == 'MF' or ip_pkt.frag != 0

            if self.is_tcp():  # tcp
                tcp_pkt = ip_pkt[TCP]
                self.payload = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)
                self.flags = tcp_pkt.flags
                self.window = tcp_pkt.window

                self.ack = tcp_pkt.ack
                self.seq = tcp_pkt.seq

            elif self.is_udp():  # udp
                udp_pkt = ip_pkt[UDP]
                self.payload = ip_pkt.len - (ip_pkt.ihl * 4) - (8 * 4)  # UDP header size is always 8

            else:
                logger.Error("Packet parameter is computing for non TCP and UDP packet.")
                self.payload = 0
        else:
            self.payload = self.lenght - 4

    def is_ip(self):
        return self.type == 0x0800

    def is_tcp(self):
        return self.is_ip() and self.proto == 6

    def is_udp(self):
        return self.is_ip() and self.proto == 17

