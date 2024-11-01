import logging
import queue
from datetime import datetime

from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff
from scapy.utils import RawPcapReader

from Flow import Flow
from FlowGeneratorActions import FlowGeneratorActions
from Helper import get_packet_time, format_time, Log
from PacketParameter import PacketParameter
from Config import Config


class AgentExtractor:
    def __init__(self, action, source, flow_interval, flow_queue):
        self.action = action
        self.source = source
        self.processing_dict = dict()
        self.processing_queue = queue.Queue()
        self.output_queue = flow_queue
        self.flow_interval = flow_interval
        self.packet_count = 0

    def process_packets(self, ether_pkt, pkt_time):

        if self.packet_count == 0:
            Flow.REFERENCE_TIME = pkt_time

        while (not self.processing_queue.empty()) and self.processing_queue.queue[0][0] + self.flow_interval < pkt_time:
            self.flush_first_flow()

        self.packet_count = self.packet_count + 1

        if 'type' not in ether_pkt.fields:
            Log.log(f'Note: LLC frames Packet:{self.packet_count} on {format_time(pkt_time)}({pkt_time})', logging.INFO)
            return
        packet_para = PacketParameter(ether_pkt, pkt_time)
        flow_src = min(packet_para.get_src(), packet_para.get_dst())
        flow_dst = max(packet_para.get_src(), packet_para.get_dst())
        flow_proto = packet_para.type_protocol_name
        key = (flow_src, flow_dst, flow_proto)

        if not self.processing_dict.keys().__contains__(key):
            new_flow = Flow(flow_src, flow_dst, flow_proto)
            self.processing_dict[key] = new_flow
            self.processing_queue.put((pkt_time, new_flow))

        self.processing_dict[key].add_packet(packet_para)

        if Config.RUN.VERBOSE and self.packet_count % Config.RUN.VERBOSE_SNIFFED_PACKET_STEP == 0:
            self.report_progress()

    def report_progress(self):
        print("{}: {}ed {} item from {}.".format(datetime.now(), self.action, self.packet_count, self.source))

    def flush_first_flow(self):
        time, flow = self.processing_queue.get()
        self.processing_dict.pop((flow.src, flow.des, flow.protocol))
        self.output_queue.put(flow)

    def packet_handler(self, pkt):
        self.process_packets(pkt, pkt.time)

    def __read_pcap_file(self):

        # read packets from the file
        for (pkt_data, pkt_metadata,) in RawPcapReader(self.source):
            ether_pkt = Ether(pkt_data)
            self.process_packets(ether_pkt, get_packet_time(pkt_metadata))
            if Config.RUN.DEBUG and self.packet_count > 3000:
                break

        # flush remained flows in the processing queue
        while not self.processing_queue.empty():
            self.flush_first_flow()

    def extract(self):
        if self.action == FlowGeneratorActions.SNIFF:
            sniff(iface=self.source, prn=self.packet_handler, store=0)
        elif self.action == FlowGeneratorActions.CONVERT:
            self.__read_pcap_file()
