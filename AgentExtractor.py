import queue

from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff
from scapy.utils import RawPcapReader

from Flow import Flow
from FlowGeneratorActions import FlowGeneratorActions
from Helper import get_packet_time, format_time
from PacketParameter import PacketParameter


class AgentExtractor:
    def __init__(self, action, source, flow_interval, flow_queue, logger):
        self.action = action
        self.source = source
        self.processing_dict = dict()
        self.processing_queue = queue.Queue()
        self.output_queue = flow_queue
        self.flow_interval = flow_interval
        self.packet_count = 0
        self.event_logger = logger

    def process_packets(self, pkt_data, pkt_time):
        if self.packet_count == 0:
            Flow.REFERENCE_TIME = pkt_time

        while (not self.processing_queue.empty()) and self.processing_queue.queue[0][0] + self.flow_interval < pkt_time:
            self.flush_first_flow()

        self.packet_count = self.packet_count + 1

        ether_pkt = Ether(pkt_data)

        if 'type' not in ether_pkt.fields:
            self.event_logger.info(
                "Note: LLC frames Packet:{} on {}({})".format(self.packet_count, format_time(pkt_time), pkt_time))
            return

        packet_para = PacketParameter(ether_pkt, pkt_time, self.event_logger)
        flow_src = min(packet_para.get_src(), packet_para.get_dst())
        flow_dst = max(packet_para.get_src(), packet_para.get_dst())
        flow_proto = packet_para.protocol_name
        key = (flow_src, flow_dst, flow_proto)

        if not self.processing_dict.keys().__contains__(key):
            new_flow = Flow(flow_src, flow_dst, flow_proto)
            self.processing_dict[key] = new_flow
            self.processing_queue.put((pkt_time, new_flow))

        self.processing_dict[key].add_packet(packet_para)

        if self.packet_count % 1000 == 0:
            self.report_progress()

    def report_progress(self):
        print("{}ed {} item from {}.".format(self.action, self.packet_count, self.source))

    def flush_first_flow(self):
        time, flow = self.processing_queue.get()
        self.processing_dict.pop((flow.src, flow.des, flow.protocol))
        flow.compute_parameters()
        self.output_queue.put(flow)

    def __packet_handler(self, pkt):
        self.process_packets(pkt, pkt.time)

    def __read_pcap_file(self):

        # read packets from the file
        for (pkt_data, pkt_metadata,) in RawPcapReader(self.source):
            self.process_packets(pkt_data, get_packet_time(pkt_metadata))
            if self.packet_count > 3000:
                break

        # flush remained flows in the processing queue
        while not self.processing_queue.empty():
            self.flush_first_flow()

    def extract(self):
        if self.action == FlowGeneratorActions.SNIFF:
            sniff(self.source, self.__packet_handler)
        elif self.action == FlowGeneratorActions.CONVERT:
            self.__read_pcap_file()