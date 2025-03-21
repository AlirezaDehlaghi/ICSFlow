from Helper import Log

from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop
from scapy.all import *
from PacketInfo import PacketInfo


class PacketParameter:
    use_port = False

    def __init__(self, ether_pkt, pkt_time, packet_id):

        self.packet_id = packet_id

        # get ether packet info
        self.src_mac = ether_pkt.src
        self.dst_mac = ether_pkt.dst
        self.time_stamp = pkt_time

        self.type = PacketInfo.get_packet_type(ether_pkt.type)
        self.length = len(ether_pkt)

        self.type_protocol_name = self.type
        self.protocol_length = self.length - 14

        if self.type == PacketInfo.TYPE_ARP:  # process ARP messages
            self.protocol_length -= 18  # 18 is padding size for ARP messages
            self.payload = 0

        elif self.type == PacketInfo.TYPE_VLAN:  # process VLAN messages
            self.payload = self.protocol_length - 4  # 4 bytes VLAN Tag (TPID + TCI)
            # todo: we might dig deeper here by detecting AVTP procotol

        elif self.type == PacketInfo.TYPE_MRP:  # process Multiple Multicast Registration Protocol
            self.payload = 0      # Todo: refine it later, not sure

        elif self.type == PacketInfo.TYPE_MSRP:  # process Multiple Multicast Registration Protocol
            self.payload = self.protocol_length - 5  # 5 is: Version (1), Domain (1), length(1), list_length (2)

        elif self.type == PacketInfo.TYPE_AVTP:  # Audio Video Transport Protocol (AVTP)
            self.payload = self.protocol_length - 2  # ID_Valid (1) Version (1)

        elif self.type == PacketInfo.TYPE_PTPv2:  # process PTP messages
            self.payload = self.protocol_length - 34  # PTPv2 header is 34 bytes

        elif self.type == PacketInfo.TYPE_Realtek:  # process Realtek Messages
            self.payload = 0  # actually the payload is unknown

        elif self.is_ip_based():
            ip_pkt = ether_pkt[IP] if self.type == PacketInfo.TYPE_IP else ether_pkt[IPv6]
            self.protocol_length -= (ip_pkt.ihl * 4 if self.type == PacketInfo.TYPE_IP else 40)

            if self.type == PacketInfo.TYPE_IP:
                proto = ip_pkt.proto
            else:
                if not ip_pkt.nh ==0:
                    proto = ip_pkt.nh
                else:
                    if IPv6ExtHdrHopByHop in ip_pkt:
                        hop_by_hop_header = ip_pkt[IPv6ExtHdrHopByHop]
                        proto = hop_by_hop_header.nh
                    else:
                        proto = 0

            self.protocol = PacketInfo.get_packet_protocol(proto)
            self.type_protocol_name += ':' + self.protocol

            self.ttl = ip_pkt.ttl if self.type == PacketInfo.TYPE_IP else ip_pkt.hlim
            self.fragment = ip_pkt.flags == 'MF' or ip_pkt.frag != 0 if self.type == PacketInfo.TYPE_IP else (IPv6ExtHdrFragment in ether_pkt)
            self.src_ip = ip_pkt.src
            self.dst_ip = ip_pkt.dst

            if self.protocol == PacketInfo.PROTOCOL_TCP:
                tcp_pkt = ip_pkt[TCP]

                self.flags = tcp_pkt.flags
                self.window = tcp_pkt.window
                self.ack = tcp_pkt.ack
                self.seq = tcp_pkt.seq

                self.src_port = str(tcp_pkt.sport)  # Source port
                self.dst_port = str(tcp_pkt.dport)  # Destination port

                self.protocol_length = len(tcp_pkt)
                self.payload = len(tcp_pkt) - (tcp_pkt.dataofs * 4)

            elif self.protocol == PacketInfo.PROTOCOL_UDP:
                udp_pkt = ip_pkt[UDP]

                self.src_port = str(udp_pkt.sport)  # Source port
                self.dst_port = str(udp_pkt.dport)  # Destination port

                self.protocol_length = len(udp_pkt)
                self.payload =  len(udp_pkt[Raw].load) if Raw in udp_pkt else 0

            elif self.protocol == PacketInfo.PROTOCOL_ICMP or \
                    self.protocol == PacketInfo.PROTOCOL_ICMPv6 or \
                    self.protocol == PacketInfo.PROTOCOL_IGMP:  # icmp
                self.payload = 0

            else:
                self.payload = self.protocol_length - 8  # default is 8 bytes
                if self.type_protocol_name!="IP:0":
                    Log.log(f'Packet parameter is computing for non TCP and UDP packet type ({self.type_protocol_name} time = {pkt_time}, id = {packet_id}, packet = {ip_pkt}).',
                        logging.WARNING)
                if IPv6ExtHdrHopByHop in ip_pkt:
                    hop_by_hop_header = ip_pkt[IPv6ExtHdrHopByHop]
                    print("Hop-by-Hop Header:")
                    print(hop_by_hop_header.show())  # Display the Hop-by-Hop header details

                    # Access specific fields
                    # For example, if you want to access the options in the Hop-by-Hop header
                    if hop_by_hop_header.options:
                        for option in hop_by_hop_header.options:
                            print("Option Type:", option.type)
                            print("Option Data:", option.data)

        else:
            self.payload = self.protocol_length
            self.protocol = str(self.type)

            Log.log(f'Packet parameter is computing for unknown packet type {(self.type)}, time = {pkt_time}, packet_id = {self.packet_id}).',
                    logging.WARNING)

    def get_src(self):
        if self.is_ip_based():
            if PacketParameter.use_port and self.is_port_based():
                return f'{self.src_ip}:{self.src_port}'
            else:
                return self.src_ip
        else:
            return self.src_mac

    def get_dst(self):
        if self.is_ip_based():
            if PacketParameter.use_port and self.is_port_based():
                return f'{self.dst_ip}:{self.dst_port}'
            else:
                return self.dst_ip
        else:
            return self.dst_mac

    def is_ip_based(self):
        return self.type == PacketInfo.TYPE_IP or self.type == PacketInfo.TYPE_IPv6

    def is_tcp(self):
        return self.is_ip_based() and self.protocol == PacketInfo.PROTOCOL_TCP

    def is_udp(self):
        return self.protocol == PacketInfo.PROTOCOL_UDP

    def is_port_based(self):
        return self.is_tcp() or self.is_udp()

    def get_flow_key(self):
        flow_src = min(self.get_src(), self.get_dst())
        flow_dst = max(self.get_src(), self.get_dst())
        flow_proto = self.type_protocol_name
        return flow_src, flow_dst, flow_proto

    def get_id(self):
        return self.packet_id

