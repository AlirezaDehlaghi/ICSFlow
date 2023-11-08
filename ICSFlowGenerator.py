import argparse
import errno
import logging
import os
import threading
import time
from AgentExtractor import AgentExtractor
from AgentAnotator import AgentAnnotator
from Config import Config
from FlowGeneratorActions import FlowGeneratorActions
from AgentSender import AgentSender
from version import __version__

from Helper import setup_logger

import queue


class ICSFlowGenerator:


    @staticmethod
    def get_args():
        """
To parse input arguments:

  <action:sniff|convert>    Choose online sniffing of a LAN or offline converting
                            PCAP file
  --source <source file or LAN name>>
                            In online sniffing provide <LAN name> and in offline
                        converting provide <PCAP file>
  --interval interval in seconds
                        interval to compute flows
  --attacks attack log csv file address
                        attack file address for finding true flows' label
  --classify model      address of pre trained ml model to classify incoming
                        flows
  --target_stream <Stream address>
                        Target server address to stream out network flows
  --target_file <csv file name>
                        csv file to output"""
        parser = argparse.ArgumentParser(description='PCAP reader')

        parser.add_argument('action',
                            metavar='<action:{}|{}>'.format(FlowGeneratorActions.SNIFF, FlowGeneratorActions.CONVERT),
                            help='Choose online sniffing of a LAN  or offline converting PCAP file',  type=str.lower)

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

        if not os.path.isdir("output"):
            os.mkdir("output")

        self.event_logger = setup_logger(
            "output/Events_log", logging.Formatter('%(message)s'), file_dir="./", file_ext='.txt')

        self.flow_queue = queue.Queue()

        self.agent_extractor = AgentExtractor(args.action, args.source, args.interval, self.flow_queue, self.event_logger)
        self.agent_annotator = AgentAnnotator(args.classify, args.attacks, self.event_logger)
        self.agent_sender = AgentSender(args.target_file, args.target_stream, self.event_logger)

        self.reader_thread = threading.Thread(target=self.read_flows)
        self.reader_thread.daemon = True

        self.sender_thread = threading.Thread(target=self.send_flows)
        self.sender_thread.daemon = True

        self.reader_thread_terminated = False

    def read_flows(self):
        self.agent_extractor.extract()
        self.reader_thread_terminated = True

    def send_flows(self):
        counter = 0
        while not self.flow_queue.empty() or (not self.reader_thread_terminated):
            if self.flow_queue.empty():
                time.sleep(2)

            else:
                counter += 1

                flow = self.flow_queue.get()
                flow.compute_parameters()
                self.agent_annotator.annotate(flow)
                self.agent_sender.send(flow)

                if Config.DEBUG and counter % Config.DEBUG_PROCESSED_FLOW_STEP == 0:
                    print("{} flows sent. ({} flows in the queue) ".format(counter, self.flow_queue.qsize()))

    def run(self):
        if Config.RUN_THREADING:
            self.reader_thread.start()
            self.sender_thread.start()
            self.reader_thread.join()
            self.reader_thread_terminated = True
            self.sender_thread.join()
        else:
            self.read_flows()
            self.send_flows()


if __name__ == '__main__':
    flowGenerator = ICSFlowGenerator()
    flowGenerator.run()

