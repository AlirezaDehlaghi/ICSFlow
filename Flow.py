import argparse
import os
import sys
from datetime import datetime

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.all import *

from Packet_Parameter import PacketParameter

class Flow:
    HEADER_PRINTED = False
    REFERENCE_TIME = 0
    ATTACKER_IP = ''
    ATTACKS = []

    @classmethod
    def compile(cls):
        parser = argparse.ArgumentParser(description='PCAP reader')
        parser.add_argument('--input', metavar='<pcap file name>',
                            help='pcap file to parse', required=True)
        parser.add_argument('--output', metavar='<csv file name>',
                            help='csv file to ouput', required=True)
        parser.add_argument('--interval', metavar='interval in seconds', type=float, default=0.5,
                            help='interval to compute flows', required=False)

        parser.add_argument('--attacks', metavar='attack log csv file',
                            help='attack file to classify flows', required=False)

        parser.add_argument('--attackerip', metavar='attack IP ',
                            help='attack IP to classify flows', required=False)

        parser.parse_args()
        args = parser.parse_args()

        Flow.ATTACKER_IP = args.attackerip
        if args.attacks:
            if not os.path.isfile(args.attacks):
                print('"{}" does not exist'.format(args.attacks), file=sys.stderr)
                sys.exit(-1)

            with open(args.attacks) as f:
                lines = f.readlines()
            for line in lines:
                if line.isspace():
                    continue
                paras = line.split(',')
                Flow.ATTACKS.append([paras[0],
                                     datetime.fromisoformat(paras[1].strip()).timestamp(),
                                     datetime.fromisoformat(paras[2].strip()).timestamp()])
        else:
            args.attacks = False

        if not os.path.isfile(args.input):
            print('"{}" does not exist'.format(args.input), file=sys.stderr)
            sys.exit(-1)

        Flow.generate_flows(args.input, args.output, args.interval, args.attacks, args.attackerip)

    @classmethod
    def generate_flows(cls, pcap_file, output_file, interval, attacks, attackerip):
        logger_data = Flow.setup_logger(
            output_file,
            logging.Formatter('%(message)s'),
            file_dir="./",
            file_ext='.csv'
        )
        logger_detail = Flow.setup_logger(
            output_file + "_details",
            logging.Formatter('%(message)s'),
            file_dir="./",
            file_ext='.txt'
        )

        count = 0
        Flow.HEADER_PRINTED = False
        flow_dict = dict()

        for (pkt_data, pkt_metadata,) in RawPcapReader(pcap_file):
            count += 1
            pkt_time = Flow.get_time(pkt_metadata)

            if count == 1:
                Flow.REFERENCE_TIME = pkt_time

            ether_pkt = Ether(pkt_data)

            if 'type' not in ether_pkt.fields:
                # LLC frames will have 'len' instead of 'type'.
                # We disregard those
                logger_detail.info("Note: LLC frames Packet:{}".format(count))
                continue

            if ether_pkt.type != 0x0800:
                # disregard non-IPv4 packets
                logger_detail.info("Note: non-IPv4 packets Packet:{}".format(count))
                continue

            ip_pkt = ether_pkt[IP]

            s_ip = min(ip_pkt.src, ip_pkt.dst)
            d_ip = max(ip_pkt.src, ip_pkt.dst)
            proto = ip_pkt.proto

            if not flow_dict.keys().__contains__((s_ip, d_ip, proto)):
                packet_time = Flow.get_time(pkt_metadata)
                flow_dict[(s_ip, d_ip, proto)] = Flow(s_ip, d_ip, proto, interval, packet_time, logger_data)

            flow_dict[(s_ip, d_ip, proto)].add_packet(PacketParameter(ip_pkt, pkt_time, logger_detail))

            if count % 1000 == 0:
                print(count)

        for flow in flow_dict.values():
            flow.flush_flow()

    @classmethod
    def setup_logger(cls, name, format_str, level=logging.INFO, file_dir="./logs", file_ext=".log", write_mode="w"):
        """To setup as many loggers as you want"""

        """
        logging.basicConfig(filename="./logs/log-" + self.__name +".log",
                            format='[%(levelname)s] [%(asctime)s] %(message)s ',
                            filemode='w')
                            """
        """To setup as many loggers as you want"""
        file_path = os.path.join(file_dir, name) + file_ext
        handler = logging.FileHandler(file_path, mode=write_mode)
        handler.setFormatter(format_str)

        # Let us Create an object
        logger = logging.getLogger(name)

        # Now we are going to Set the threshold of logger to DEBUG
        logger.setLevel(level)
        logger.addHandler(handler)
        return logger

    @classmethod
    def get_time(cls, pkt_metadata):
        return pkt_metadata.sec + pkt_metadata.usec/pow(10, 6)

    @staticmethod
    def format_decimal(value , rnd = 3):
        return round(value, rnd)

    @staticmethod
    def avg(target):
        if len(target) == 0:
            return ''
        else:
            return Flow.format_decimal(sum(target) / len(target),6)

    def __init__(self, src, des, protocol, interval, first_stamp, logger):
        self.src = src
        self.des = des
        self.protocol = protocol
        self.interval = interval
        self.logger = logger
        self.sen_list = []
        self.rec_list = []
        self.acc_sen_dic = dict()
        self.acc_rec_dic = dict()
        self.sen_delay = []
        self.rec_delay = []

    def reset(self):
        self.sen_list = []
        self.rec_list = []
        self.acc_sen_dic = dict()
        self.acc_rec_dic = dict()
        self.sen_delay = []
        self.rec_delay = []

    def add_packet(self, packet_parameter):
        if not self.can_append(packet_parameter.packet_time):
            self.flush_flow()

        if packet_parameter.src == self.src:
            self.sen_list.append(packet_parameter)
        else:
            self.rec_list.append(packet_parameter)

        self.compute_delay(packet_parameter)

    def compute_delay(self, packet_parameter):
        if packet_parameter.proto != 6:
            return

        if packet_parameter.src == self.src:
            self.acc_sen_dic[packet_parameter.ack] = packet_parameter.packet_time
            if self.acc_rec_dic.keys().__contains__(packet_parameter.seq):
                self.sen_delay.append(packet_parameter.packet_time - self.acc_rec_dic[packet_parameter.seq])
        else:
            self.acc_rec_dic[packet_parameter.ack] = packet_parameter.packet_time
            if self.acc_sen_dic.keys().__contains__(packet_parameter.seq):
                self.rec_delay.append(packet_parameter.packet_time - self.acc_sen_dic[packet_parameter.seq])

    def start_time(self):
        if len(self.rec_list) != 0 and len(self.sen_list) != 0:
            return min(self.rec_list[0].packet_time , self.sen_list[0].packet_time)
        elif len(self.sen_list) != 0:
            return self.sen_list[0].packet_time
        elif len(self.rec_list) != 0:
            return self.rec_list[0].packet_time
        else:
            raise Exception('Should not end here.')

    def end_time(self):
        if len(self.rec_list) != 0 and len(self.sen_list) != 0:
            return max(self.rec_list[-1].packet_time , self.sen_list[-1].packet_time)
        elif len(self.sen_list) != 0:
            return self.sen_list[-1].packet_time
        elif len(self.rec_list) != 0:
            return self.rec_list[-1].packet_time
        else:
            raise Exception('Should not end here.')

    def is_empty(self):
        return len(self.rec_list) == 0 and len(self.sen_list) == 0

    def can_append(self, time):
        if self.is_empty():
            return True

        return self.start_time() + self.interval > time






    def get_window(self):
        return self.end_time() - self.start_time() + 0.000001

    @staticmethod
    def format_time( value):
        sec = int(value)
        msec = int (value * 1000000) - sec * 1000000
        return datetime.fromtimestamp(value).strftime('%m/%d/%Y %H:%M:%S %Z')+":" +str(msec).zfill(6)

    @staticmethod
    def packets_cnt(packets):
        return len(packets)

    @staticmethod
    def packets_bytes_sum(packets):
        return sum([pkt.lenght for pkt in packets])

    @staticmethod
    def packets_bytes_avg(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''
        else:
            value = Flow.packets_bytes_sum(packets) / Flow.packets_cnt(packets)
            return Flow.format_decimal(Flow.format_decimal(value))

    @staticmethod
    def payload_sum(packets):
        return sum([pkt.payload for pkt in packets])

    @staticmethod
    def payload_avg(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''
        else:
            return Flow.format_decimal(sum([pkt.payload for pkt in packets]) / Flow.packets_cnt(packets))

    @staticmethod
    def ttl_avg(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''
        else:
            value = sum([pkt.ttl for pkt in packets]) / Flow.packets_cnt(packets)
            return Flow.format_decimal(Flow.format_decimal(value))

    @staticmethod
    def flag_rate(packets, flag):
        if Flow.packets_cnt(packets) == 0:
            return ''
        if packets[0].proto != 6:
            return ''

        value = 0

        match flag:
            case 'A':
                value =  sum([int(pkt.flags.A) for pkt in packets]) / Flow.packets_cnt(packets)
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

        return Flow.format_decimal(value)


    @staticmethod
    def tcp_window_avg(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''
        if packets[0].proto != 6:
            return ''

        return Flow.format_decimal(sum([pkt.window for pkt in packets]) / Flow.packets_cnt(packets))

    @staticmethod
    def fragmentation_rate(packets):
        if Flow.packets_cnt(packets) == 0:
            return ''

        return sum([int(pkt.fragment) for pkt in packets]) / Flow.packets_cnt(packets)

    def load(self, packets):
        value = Flow.packets_bytes_sum(packets) * 8 / self.get_window()
        return Flow.format_decimal(value)

    def flush_flow(self):
        result = self.compute_parameters()

        if not Flow.HEADER_PRINTED:
            Flow.HEADER_PRINTED = True
            self.logger.info(','.join(result.keys()))
        self.logger.info(','.join(result.values()))
        self.reset()

    def compute_parameters(self):
        res = dict()
        res["Source"] = self.src
        res["Destination"] = self.des
        res["Protocol"] = str(self.protocol)
        res["FirstDate"] = str(Flow.format_time(self.start_time()))
        res["LastDate"] = str(Flow.format_time(self.end_time()))
        res["FirstStamp"] = str(Flow.format_decimal(self.start_time() - Flow.REFERENCE_TIME,6))
        res["LastStamp"] = str(Flow.format_decimal(self.end_time() - Flow.REFERENCE_TIME ,6))
        res["FirstOridinalStamp"] = str(Flow.format_decimal(self.start_time(),6))
        res["LastOridinalStamp"] = str(Flow.format_decimal(self.end_time(), 6 ))
        self.compute_dual_parameters('Sen', self.sen_list, res)
        self.compute_dual_parameters('Rec', self.rec_list, res)
        res["Sen_AckDelay"] = str(Flow.avg(self.sen_delay))
        res["Rec_AckDelay"] = str(Flow.avg(self.rec_delay))

        if Flow.ATTACKS:
            class_label = 'Normal'
            if not Flow.ATTACKER_IP or (self.src == Flow.ATTACKER_IP or self.des == Flow.ATTACKER_IP):
                for i in range(len(Flow.ATTACKS)):
                    if not (Flow.ATTACKS[i][1]>= self.end_time() or Flow.ATTACKS[i][2]<= self.start_time()):
                        class_label = Flow.ATTACKS[i][0]
            res["class"] = class_label
        return res

    def compute_dual_parameters(self, prefix, target, res):
        res[prefix + "PacketsCount"] = str(Flow.packets_cnt(target))
        res[prefix + "BytesSum"] = str(Flow.packets_bytes_sum(target))
        res[prefix + "BytesAvg"] = str(Flow.packets_bytes_avg(target))
        res[prefix + "PayloadSum"] = str(Flow.payload_sum(target))
        res[prefix + "PayloadAvg"] = str(Flow.payload_avg(target))
        res[prefix + "Load"] = str(self.load(target))
        res[prefix + "TtlAvg"] = str(Flow.ttl_avg(target))
        res[prefix + "AckRate"] = str(Flow.flag_rate(target,'A'))
        res[prefix + "FinRate"] = str(Flow.flag_rate(target, 'F'))
        res[prefix + "PshRate"] = str(Flow.flag_rate(target, 'P'))
        res[prefix + "SynRate"] = str(Flow.flag_rate(target, 'S'))
        res[prefix + "UrgRate"] = str(Flow.flag_rate(target, 'U'))
        res[prefix + "RstRate"] = str(Flow.flag_rate(target, 'R'))
        res[prefix + "TcpWindowAvg"] = str(Flow.tcp_window_avg(target))
        res[prefix + "FragmentRate"] = str(Flow.fragmentation_rate(target))


if __name__ == '__main__':
    Flow.compile()
