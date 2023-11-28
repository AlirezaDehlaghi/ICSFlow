import argparse
from scapy.layers.l2 import Ether
from scapy.all import *
from Helper import Log, get_packet_time, format_time, format_decimal, average, maximum, minimum
from PacketParameter import PacketParameter


class Flow:
    REFERENCE_TIME = 0

    def __init__(self, src, dst, protocol):
        self.parameters = dict()

        self.src = min(src, dst)
        self.des = max(src, dst)
        self.protocol = protocol

        self.sen_list = []
        self.rec_list = []
        self.acc_sen_dic = dict()
        self.acc_rec_dic = dict()
        self.sen_delay = []
        self.rec_delay = []

        self.src_ip_list = set()
        self.dst_ip_list = set()
        self.src_mac_list = set()
        self.dst_mac_list = set()

    def add_parameter(self, key, value):
        self.parameters[key] = value

    def start_time(self):
        s_start = sys.float_info.max
        r_start = sys.float_info.max
        if len(self.sen_list) != 0:
            s_start = self.sen_list[0].packet_time
        if len(self.rec_list) != 0:
            r_start = self.rec_list[0].packet_time

        return min(s_start, r_start)

    def end_time(self):
        s_end = 0
        r_end = 0
        if len(self.sen_list) != 0:
            s_end = self.sen_list[-1].packet_time
        if len(self.rec_list) != 0:
            r_end = self.rec_list[-1].packet_time

        return max(s_end, r_end)

    def get_window(self):
        return self.end_time() - self.start_time() + 0.000001

    def is_empty(self):
        return len(self.rec_list) == 0 and len(self.sen_list) == 0

    def add_packet(self, packet_parameter):
        if packet_parameter.get_src() == self.src:
            self.sen_list.append(packet_parameter)
        else:
            self.rec_list.append(packet_parameter)

        self.compute_delay(packet_parameter)

        if packet_parameter.get_src() == self.src:
            self.src_mac_list.add(packet_parameter.src_mac)
            self.dst_mac_list.add(packet_parameter.dst_mac)
            if packet_parameter.is_ip():
                self.src_ip_list.add(packet_parameter.src_ip)
                self.dst_ip_list.add(packet_parameter.dst_ip)
        else:
            self.src_mac_list.add(packet_parameter.dst_mac)
            self.dst_mac_list.add(packet_parameter.src_mac)
            if packet_parameter.is_ip():
                self.src_ip_list.add(packet_parameter.dst_ip)
                self.dst_ip_list.add(packet_parameter.src_ip)


    def compute_delay(self, packet_parameter):
        if not packet_parameter.is_tcp():
            return

        if packet_parameter.get_src() == self.src:
            self.acc_sen_dic[packet_parameter.ack] = packet_parameter.packet_time
            if self.acc_rec_dic.keys().__contains__(packet_parameter.seq):
                self.sen_delay.append(packet_parameter.packet_time - self.acc_rec_dic[packet_parameter.seq])
        else:
            self.acc_rec_dic[packet_parameter.ack] = packet_parameter.packet_time
            if self.acc_sen_dic.keys().__contains__(packet_parameter.seq):
                self.rec_delay.append(packet_parameter.packet_time - self.acc_sen_dic[packet_parameter.seq])


    def compute_parameters(self):
          # flow features
        self.parameters.clear()

        self.parameters["sAddress"] = self.src
        self.parameters["rAddress"] = self.des

        self.parameters["sMACs"] = '/'.join(self.src_mac_list)
        self.parameters["rMACs"] = '/'.join(self.dst_mac_list)

        self.parameters["sIPs"] = '/'.join(self.src_ip_list)
        self.parameters["rIPs"] = '/'.join(self.dst_ip_list)

        self.parameters["protocol"] = str(self.protocol)

        # General features part 1
        self.parameters["startDate"] = str(format_time(self.start_time()))
        self.parameters["endDate"] = str(format_time(self.end_time()))
        self.parameters["start"] = str(format_decimal(self.start_time(), 6))
        self.parameters["end"] = str(format_decimal(self.end_time(), 6))
        self.parameters["startOffset"] = str(format_decimal(self.start_time() - Flow.REFERENCE_TIME, 6))
        self.parameters["endOffset"] = str(format_decimal(self.end_time() - Flow.REFERENCE_TIME, 6))

        self.parameters["duration"] = str(format_decimal(self.get_window(), 6))

        self.parameters["sPackets"] = str(Flow.packets_cnt(self.sen_list))
        self.parameters["rPackets"] = str(Flow.packets_cnt(self.rec_list))

        # We have to remove this feature
        self.parameters["sBytesSum"] = str(Flow.packets_bytes_sum(self.sen_list))
        self.parameters["rBytesSum"] = str(Flow.packets_bytes_sum(self.rec_list))

        self.parameters["sBytesMax"] = str(Flow.packets_bytes_max(self.sen_list))
        self.parameters["rBytesMax"] = str(Flow.packets_bytes_max(self.rec_list))

        self.parameters["sBytesMin"] = str(Flow.packets_bytes_min(self.sen_list))
        self.parameters["rBytesMin"] = str(Flow.packets_bytes_min(self.rec_list))

        self.parameters["sBytesAvg"] = str(Flow.packets_bytes_avg(self.sen_list))
        self.parameters["rBytesAvg"] = str(Flow.packets_bytes_avg(self.rec_list))

        self.parameters["sLoad"] = str(self.load(self.sen_list))
        self.parameters["rLoad"] = str(self.load(self.rec_list))

        # We have to remove this feature
        self.parameters["sPayloadSum"] = str(Flow.payload_sum(self.sen_list))
        self.parameters["rPayloadSum"] = str(Flow.payload_sum(self.rec_list))

        self.parameters["sPayloadMax"] = str(Flow.payload_max(self.sen_list))
        self.parameters["rPayloadMax"] = str(Flow.payload_max(self.rec_list))

        self.parameters["sPayloadMin"] = str(Flow.payload_min(self.sen_list))
        self.parameters["rPayloadMin"] = str(Flow.payload_min(self.rec_list))

        self.parameters["sPayloadAvg"] = str(Flow.payload_avg(self.sen_list))
        self.parameters["rPayloadAvg"] = str(Flow.payload_avg(self.rec_list))

        self.parameters["sInterPacketAvg"] = str(Flow.inter_packets_avg(self.sen_list))
        self.parameters["rInterPacketAvg"] = str(Flow.inter_packets_avg(self.rec_list))

        # TCP features Part 1
        self.parameters["sttl"] = str(Flow.ttl_avg(self.sen_list))
        self.parameters["rttl"] = str(Flow.ttl_avg(self.rec_list))

        self.parameters["sAckRate"] = str(Flow.flag_rate(self.sen_list, 'A'))
        self.parameters["rAckRate"] = str(Flow.flag_rate(self.rec_list, 'A'))

        self.parameters["sUrgRate"] = str(Flow.flag_rate(self.sen_list, 'U'))
        self.parameters["rUrgRate"] = str(Flow.flag_rate(self.rec_list, 'U'))

        self.parameters["sFinRate"] = str(Flow.flag_rate(self.sen_list, 'F'))
        self.parameters["rFinRate"] = str(Flow.flag_rate(self.rec_list, 'F'))

        self.parameters["sPshRate"] = str(Flow.flag_rate(self.sen_list, 'P'))
        self.parameters["rPshRate"] = str(Flow.flag_rate(self.rec_list, 'P'))

        self.parameters["sSynRate"] = str(Flow.flag_rate(self.sen_list, 'S'))
        self.parameters["rSynRate"] = str(Flow.flag_rate(self.rec_list, 'S'))

        self.parameters["sSynRate"] = str(Flow.flag_rate(self.sen_list, 'S'))
        self.parameters["rSynRate"] = str(Flow.flag_rate(self.rec_list, 'S'))

        self.parameters["sRstRate"] = str(Flow.flag_rate(self.sen_list, 'R'))
        self.parameters["rRstRate"] = str(Flow.flag_rate(self.rec_list, 'R'))

        self.parameters["sWinTCP"] = str(Flow.tcp_window_avg(self.sen_list))
        self.parameters["rWinTCP"] = str(Flow.tcp_window_avg(self.rec_list))

        self.parameters["sFragmentRate"] = str(Flow.fragmentation_rate(self.sen_list))
        self.parameters["rFragmentRate"] = str(Flow.fragmentation_rate(self.rec_list))

        # TCP features part 2

        self.parameters["sAckDelayMax"] = str(maximum(self.sen_delay))
        self.parameters["rAckDelayMax"] = str(maximum(self.rec_delay))

        self.parameters["sAckDelayMin"] = str(minimum(self.sen_delay))
        self.parameters["rAckDelayMin"] = str(minimum(self.rec_delay))

        self.parameters["sAckDelayAvg"] = str(average(self.sen_delay))
        self.parameters["rAckDelayAvg"] = str(average(self.rec_delay))

    @staticmethod
    def packets_cnt(packets):
        return len(packets)

    @staticmethod
    def packets_bytes_sum(packets):
        return sum([pkt.length for pkt in packets])

    @staticmethod
    def packets_bytes_avg(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''
        else:
            value = Flow.packets_bytes_sum(packets) / Flow.packets_cnt(packets)
            return format_decimal(format_decimal(value))

    @staticmethod
    def packets_bytes_max(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''
        else:
            return maximum([pkt.length for pkt in packets])

    @staticmethod
    def packets_bytes_min(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''
        else:
            return min([pkt.length for pkt in packets])

    @staticmethod
    def payload_sum(packets):
        return sum([pkt.payload for pkt in packets])

    @staticmethod
    def payload_max(packets):
        return maximum([pkt.payload for pkt in packets])

    @staticmethod
    def payload_min(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''
        else:
            return min([pkt.payload for pkt in packets])

    @staticmethod
    def payload_avg(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''
        else:
            return format_decimal(sum([pkt.payload for pkt in packets]) / Flow.packets_cnt(packets))

    @staticmethod
    def inter_packets_avg(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''

        if Flow.packets_cnt(packets) == 1:
            return ''

        return (packets[-1].packet_time - packets[0].packet_time) / (Flow.packets_cnt(packets) - 1)

    @staticmethod
    def ttl_avg(packets):

        if Flow.packets_cnt(packets) == 0:
            return ''
        if not packets[0].is_tcp():
            return ''

        if not packets[0].is_ip():
            return ''
        else:
            value = sum([pkt.ttl for pkt in packets]) / Flow.packets_cnt(packets)
            return format_decimal(value)

    @staticmethod
    def flag_rate(packets, flag):
        if Flow.packets_cnt(packets) == 0:
            return ''
        if not packets[0].is_tcp():
            return ''

        value = 0

        match flag:
            case 'A':
                value = sum([int(pkt.flags.A) for pkt in packets]) / Flow.packets_cnt(packets)
            case 'U':
                value = sum([int(pkt.flags.U) for pkt in packets]) / Flow.packets_cnt(packets)
            case 'S':
                value = sum([int(pkt.flags.S) for pkt in packets]) / Flow.packets_cnt(packets)
            case 'F':
                value = sum([int(pkt.flags.F) for pkt in packets]) / Flow.packets_cnt(packets)
            case 'R':
                value = sum([int(pkt.flags.R) for pkt in packets]) / Flow.packets_cnt(packets)
            case 'P':
                value = sum([int(pkt.flags.P) for pkt in packets]) / Flow.packets_cnt(packets)
            case _:
                raise Exception('Should not end here.')

        return format_decimal(value)

    @staticmethod
    def tcp_window_avg(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''
        if not packets[0].is_tcp():
            return ''

        return format_decimal(sum([pkt.window for pkt in packets]) / Flow.packets_cnt(packets))

    @staticmethod
    def fragmentation_rate(packets):

        if Flow.packets_cnt(packets) == 0:
            return ''
        if not packets[0].is_ip():
            return ''

        return sum([int(pkt.fragment) for pkt in packets]) / Flow.packets_cnt(packets)

    def load(self, packets):
        value = Flow.packets_bytes_sum(packets) * 8 / self.get_window()
        return format_decimal(value)



