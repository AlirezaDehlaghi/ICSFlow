import logging
import queue
from datetime import datetime

from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff
from scapy.utils import RawPcapReader

from Flow import Flow
from Enums import FlowGeneratorActions
from Helper import get_packet_time, format_time, Log, check_pcap_timestamp_resolution
from PacketParameter import PacketParameter
from Config import Config


class AgentExtractor:
    def __init__(self, action, source, flow_interval, output_queue):
        self.action = action
        self.source = source
        self.flow_interval = flow_interval
        self.output_queue = output_queue

        self.processing_queue = queue.Queue()
        self.processing_dict = dict()

        self.packet_count = 0

    def process_packets(self, ether_pkt, pkt_time):
        """
        Processes an individual packet, updates the flow queue, and manages timeouts.

        :param ether_pkt: The Ethernet packet (Scapy format).
        :param pkt_time: Timestamp of the packet.
        """

        if self.packet_count == 0:
            Flow.REFERENCE_TIME = pkt_time

        # Flush outdated flows from queue
        while (not self.processing_queue.empty()) and self.processing_queue.queue[0][0] + self.flow_interval < pkt_time:
            self.flush_first_flow()

        self.packet_count = self.packet_count + 1

        if 'type' not in ether_pkt.fields:
            Log.log(f'Note: LLC frames Packet:{self.packet_count} on {format_time(pkt_time)}({pkt_time})', logging.INFO)
            return

        packet_para = PacketParameter(ether_pkt, pkt_time, self.packet_count)
        key = packet_para.get_flow_key()

        if not self.processing_dict.keys().__contains__(key):
            new_flow = Flow(key)
            self.processing_dict[key] = new_flow
            self.processing_queue.put((pkt_time, new_flow))

        self.processing_dict[key].add_packet(packet_para)
        self.report_progress()

    def report_progress(self):
        """
        Logs progress at regular intervals if verbosity is enabled.
        """
        if Config.RUN.VERBOSE and self.packet_count % Config.RUN.VERBOSE_SNIFFED_PACKET_STEP == 0:
            print("{}: {}ed {} item from {}.".format(datetime.now(), self.action, self.packet_count, self.source))

    def flush_first_flow(self):
        """
        Removes and outputs the oldest flow from the processing queue.
        """
        time, flow = self.processing_queue.get()
        self.processing_dict.pop(flow.key)
        self.output_queue.put(flow)

    def packet_handler(self, pkt):
        """
        Callback function for sniffing live packets.

        :param pkt: Captured packet.
        """
        self.process_packets(pkt, pkt.time)

    def __read_pcap_file(self):
        """
        Reads and processes packets from a PCAP file.
        """

        check_pcap_timestamp_resolution(self.source)

        for pkt_data, pkt_metadata in RawPcapReader(self.source):
            ether_pkt = Ether(pkt_data)
            self.process_packets(ether_pkt, get_packet_time(pkt_metadata))

            # Debug mode: Stop processing after 3000 packets
            if Config.RUN.DEBUG and self.packet_count > 2000:
                break

        # flush remaining flows
        while not self.processing_queue.empty():
            self.flush_first_flow()

    def extract(self):
        """
        Initiates the packet processing based on the selected mode (sniffing or conversion).
        """
        if self.action == FlowGeneratorActions.SNIFF:
            sniff(iface=self.source, prn=self.packet_handler, store=0)
        elif self.action == FlowGeneratorActions.CONVERT:
            self.__read_pcap_file()
