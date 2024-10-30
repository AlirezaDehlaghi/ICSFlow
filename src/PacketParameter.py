import logging
from Helper import Log

from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrHopByHop
from scapy.all import *
from PacketInfo import PacketInfo


class PacketParameter:

    def __init__(self, ether_pkt, pkt_time):

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

                self.protocol_length = len(tcp_pkt)
                self.payload = len(tcp_pkt) - (tcp_pkt.dataofs * 4)

            elif self.protocol == PacketInfo.PROTOCOL_UDP:
                udp_pkt = ip_pkt[UDP]

                self.protocol_length = len(udp_pkt)
                self.payload = len(udp_pkt) - (8 * 4)  # UDP header size is always 8

            elif self.protocol == PacketInfo.PROTOCOL_ICMP or \
                    self.protocol == PacketInfo.PROTOCOL_ICMPv6 or \
                    self.protocol == PacketInfo.PROTOCOL_IGMP:  # icmp
                self.payload = 0

            # elif self.type == PacketInfo.TYPE_IPv6 and ip_pkt.nh == 0 and ip_pkt.haslayer(HBHOptions):
            #     pass



            else:
                self.payload = self.protocol_length - (8 * 4)  # default is 8 bytes
                Log.log(f'Packet parameter is computing for non TCP and UDP packet type ({self.type_protocol_name} time = {pkt_time} packet = {ip_pkt}).',
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
            Log.log(f'Packet parameter is computing for unknown packet type {hex(self.type)}, time = {pkt_time}).',
                    logging.WARNING)

    def get_src(self):
        if self.is_ip_based():
            return self.src_ip
        else:
            return self.src_mac

    def get_dst(self):
        if self.is_ip_based():
            return self.dst_ip
        else:
            return self.dst_mac

    def is_ip_based(self):
        return self.type == PacketInfo.TYPE_IP or self.type == PacketInfo.TYPE_IPv6

    def is_tcp(self):
        return self.is_ip_based() and self.protocol == PacketInfo.PROTOCOL_TCP

