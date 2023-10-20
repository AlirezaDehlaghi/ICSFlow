import argparse
import errno
import logging
import os
import threading
import time
from FlowExtractor import FlowExtractor
from FlowAnotator import FlowAnnotator
from FlowGeneratorActions import FlowGeneratorActions
from FlowSender import FlowSender


from Helper import  setup_logger

import queue


class ICSFlowGenerator:

    @staticmethod
    def get_args():
        parser = argparse.ArgumentParser(description='PCAP reader')

        parser.add_argument('action',
                            metavar='<action:{}|{}>'.format(FlowGeneratorActions.SNIFF, FlowGeneratorActions.CONVERT),
                            help='Choose online sniffing of a LAN  or offline converting PCAP file')

        parser.add_argument('--source', metavar='<source file or LAN name>>',
                            help='In online sniffing provide <LAN name> and in offline converting provide <PCAP file>',
                            required=True)

        parser.add_argument('--interval', metavar='interval in seconds', type=float, default=0.5,
                            help='interval to compute flows', required=False)

        parser.add_argument('--attacks', metavar='attack log csv file address',
                            help='attack file address for finding true flows\' label', required=False)

        parser.add_argument('--classify', metavar='model',
                            help='address of pre trained ml model  to classify incoming flows', required=False)

        parser.add_argument('--target_stream', metavar='<Stream address>',
                            help='Target server address to stream out network flows')

        parser.add_argument('--target_file', metavar='<csv file name>',
                            help='csv file to output')

        args = parser.parse_args()

        # check action and Source
        if args.action == FlowGeneratorActions.CONVERT:
            if not os.path.isfile(args.source):
                raise FileNotFoundError(
                    errno.ENOENT, os.strerror(errno.ENOENT), args.source)

        elif args.action == FlowGeneratorActions.SNIFF:
            # todo: check LAN name is correct
            pass

        # check attacks
        if args.attacks:
            if not os.path.isfile(str(args.attacks)):
                raise FileNotFoundError(
                    errno.ENOENT, os.strerror(errno.ENOENT), args.attacks)

        # check classify
        if args.classify:
            if not os.path.isfile(args.classify):
                raise FileNotFoundError(
                    errno.ENOENT, os.strerror(errno.ENOENT), args.classify)

        else:
            args.classify = False

        return args

    def __init__(self):
        args = ICSFlowGenerator.get_args()

        self.event_logger = setup_logger(
            "Events_log", logging.Formatter('%(message)s'), file_dir="./", file_ext='.txt')

        self.flow_queue = queue.Queue()

        self.flow_extractor = FlowExtractor(args.action, args.source, args.interval, self.flow_queue, self.event_logger)
        self.flow_annotator = FlowAnnotator(args.classify, args.attacks, self.event_logger)
        self.flow_sender = FlowSender(args.target_file, args.target_stream, self.event_logger)

        self.sniffer_thread = threading.Thread(target=self.generate_flows)
        self.sniffer_thread.daemon = True

        self.sender_thread = threading.Thread(target=self.record_flows)
        self.sender_thread.daemon = True

        self.read_finished_flag = False

    def generate_flows(self):
        self.flow_extractor.extract()
        self.read_finished_flag = True

    def record_flows(self):
        while not self.flow_queue.empty() or (not self.read_finished_flag):
            if self.flow_queue.empty():
                time.sleep(2)
            else:
                flow = self.flow_queue.get()
                self.flow_annotator.annotate(flow)
                self.flow_sender.send(flow)

    def run(self):
        self.sniffer_thread.start()
        self.sender_thread.start()
        self.sniffer_thread.join()
        self.read_finished_flag = True
        self.sender_thread.join()
        # self.generate_flows()
        # self.record_flows()


if __name__ == '__main__':
    flowGenerator = ICSFlowGenerator()
    flowGenerator.run()

