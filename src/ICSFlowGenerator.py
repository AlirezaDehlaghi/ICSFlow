import argparse
import errno
import logging
import os
import threading
import time
from AgentExtractor import AgentExtractor
from AgentProcessor import AgentProcessor
from FlowGeneratorActions import FlowGeneratorActions

from Helper import Log

import queue

from Config import Config


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
  --predictor model      address of pre trained ml model to predict incoming
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

        parser.add_argument('--predictor', metavar='model',
                            help='address of pre trained ml model  to classify incoming flows', required=False)

        parser.add_argument('--target_connection', metavar='<Target connection>',
                            help='Target server connection file to stream out network flows')

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

        # # check predictor
        # if args.predictor:
        #     if not os.path.isfile(args.predictor):
        #         raise FileNotFoundError(
        #             errno.ENOENT, os.strerror(errno.ENOENT), args.predictor)

        if not args.target_connection and not args.target_file:
            raise RuntimeError("No target defined in arguments." +
                               " Giving one of target_stream or target_file is mandatory")

        if args.target_connection:
            if not os.path.isfile(args.target_connection):
                raise FileNotFoundError(
                    errno.ENOENT, os.strerror(errno.ENOENT), args.target_connection)

        return args

    def __init__(self):
        args = ICSFlowGenerator.get_args()

        if not os.path.isdir("../output"):
            os.mkdir("../output")

        Log.configure_log_files('./output/', True)

        # Works as a pipeline between agents
        self.flow_pipeline = queue.Queue()

        # Create extractor, annotator and sender agents
        self.agent_extractor = AgentExtractor(args.action, args.source, args.interval, self.flow_pipeline)
        self.agent_processor = AgentProcessor(args.predictor, args.attacks, args.target_file, args.target_connection)

        # Create reader thread
        self.reader_thread = threading.Thread(target=self.read_flows)
        self.reader_thread.daemon = True
        self.reader_thread_terminated = False

        # Create sender thread
        self.sender_thread = threading.Thread(target=self.send_flows)
        self.sender_thread.daemon = True

    def read_flows(self):
        self.agent_extractor.extract()
        self.reader_thread_terminated = True

    def send_flows(self):
        counter = 0
        while not self.flow_pipeline.empty() or (not self.reader_thread_terminated):
            if self.flow_pipeline.empty():
                time.sleep(2)

            else:
                counter += 1

                flow = self.flow_pipeline.get()
                flow.compute_parameters()
                self.agent_processor.process(flow)

                if Config.RUN.VERBOSE and counter % Config.RUN.VERBOSE_PROCESSED_FLOW_STEP == 0:
                    print("{} flows sent. ({} flows in the queue) ".format(counter, self.flow_pipeline.qsize()))

    def run(self):
        Log.log('Program started.', logging.INFO)

        if Config.RUN.RUN_THREADING:
            self.reader_thread.start()
            self.sender_thread.start()
            self.reader_thread.join()
            self.reader_thread_terminated = True
            self.sender_thread.join()
        else:
            Log.log('Threading is not enabled!', logging.WARNING)
            self.read_flows()
            self.send_flows()

        logging.info('Program Finished.')


if __name__ == '__main__':
    flowGenerator = ICSFlowGenerator()
    flowGenerator.run()

