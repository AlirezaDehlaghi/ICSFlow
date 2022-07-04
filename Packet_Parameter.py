from scapy.layers.inet import TCP, UDP


class PacketParameter:
    def __init__(self, ip_pkt, pkt_time, logger):
        self.src = ip_pkt.src
        self.dst = ip_pkt.dst
        self.proto = ip_pkt.proto
        self.lenght = ip_pkt.len
        self.ttl = ip_pkt.ttl
        self.packet_time = pkt_time
        self.fragment = ip_pkt.flags == 'MF' or ip_pkt.frag != 0

        if self.proto == 6:  # tcp
            tcp_pkt = ip_pkt[TCP]
            self.payload = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)
            self.flags = tcp_pkt.flags
            self.window = tcp_pkt.window

            self.ack = tcp_pkt.ack
            self.seq = tcp_pkt.seq

        elif self.proto == 17:  # udp
            udp_pkt = ip_pkt[UDP]
            self.payload = ip_pkt.len - (ip_pkt.ihl * 4) - (8 * 4)  # UDP header size is always 8

        else:
            logger.Error("Packet parameter is computing for non TCP and UDP packet.")
            self.payload = 0