from scapy.layers.inet import TCP, UDP, IP


class PacketParameter:
    def __init__(self, ether_pkt, pkt_time, logger):
        self.src_mac = ether_pkt.src
        self.dst_mac = ether_pkt.dst
        self.length = len(ether_pkt)
        self.packet_time = pkt_time
        self.type = ether_pkt.type
        self.protocol_name = ether_pkt.type

        if self.is_ip():
            ip_pkt = ether_pkt[IP]
            self.src_ip = ip_pkt.src
            self.dst_ip = ip_pkt.dst
            self.proto = ip_pkt.proto
            self.length = ip_pkt.len
            self.ttl = ip_pkt.ttl
            self.fragment = ip_pkt.flags == 'MF' or ip_pkt.frag != 0

            if self.is_tcp():  # tcp
                tcp_pkt = ip_pkt[TCP]
                self.payload = ip_pkt.len - (ip_pkt.ihl * 4) - (tcp_pkt.dataofs * 4)
                self.flags = tcp_pkt.flags
                self.window = tcp_pkt.window
                self.ack = tcp_pkt.ack
                self.seq = tcp_pkt.seq
                self.protocol_name = "IPV4:TCP"

            elif self.is_udp():  # udp
                udp_pkt = ip_pkt[UDP]
                self.payload = ip_pkt.len - (ip_pkt.ihl * 4) - (8 * 4)  # UDP header size is always 8
                self.protocol_name = "IPV4:UDP"

            else:
                self.payload = 0
                self.protocol_name = "IPV4:" + str(self.proto)
                logger.error("Packet parameter is computing for non TCP and UDP packet type (time = {}).".format(pkt_time))

        elif self.is_arp():
            self.payload = self.length - 4
            self.protocol_name = "ARP"

        else:
            self.payload = self.length - 4
            self.protocol_name = str(self.type)
            logger.error("Packet parameter is computing for unknown packet type (time = {}).".format(pkt_time))

    def is_ip(self):
        return self.type == 0x0800

    def is_arp(self):
        return self.type == 2054

    def is_tcp(self):
        return self.is_ip() and self.proto == 6

    def is_udp(self):
        return self.is_ip() and self.proto == 17

    def get_src(self):
        if self.is_ip():
            return self.src_ip
        else:
            return self.src_mac

    def get_dst(self):
        if self.is_ip():
            return self.dst_ip
        else:
            return self.dst_mac

