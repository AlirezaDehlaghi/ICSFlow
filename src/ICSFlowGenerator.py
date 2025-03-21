import argparse
import logging
import os
import threading
from AgentExtractor import AgentExtractor
from AgentProcessor import AgentProcessor
from Enums import FlowGeneratorActions
from Helper import Log, check_file
import queue
from Config import Config
from PacketParameter import PacketParameter
from FlowAnnotatorAttackPacket import FlowAnnotatorAttackPacket
from FlowAnnotatorAttackTime import FlowAnnotatorAttackTime
from FlowSenderFile import FlowSenderFile
from FlowSenderMQTT import FlowSenderMQTT


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
          --interval <Float> interval in seconds.
                                interval to compute flows.
          --use_port <True or False> indicating the usage of port address.
                                <Determines whether the port number should be included when identifying network.addresses.>
          --attacks_time <string> file address for attack log csv file.
                                attack file address for finding anomalous flows' label.
          --attacks_packet <string> file address for attack packet information csv file.
                                a file address for a CSV file that indicate which packets are anomalous.
          --ids <string> file address for AI model that act as intrusion detection system.
                                address of pre trained ml model to classify incoming flows.
          --target_connection <string> file address for the file indicating details of target connection.
                                Target server connection file to stream out network flows.
          --target_file <string> file address for the output csv file.
                                csv file to output.

        """
        parser = argparse.ArgumentParser(description='PCAP or Network reader')

        parser.add_argument('action',
                            metavar=f'<action:{FlowGeneratorActions.SNIFF}|{FlowGeneratorActions.CONVERT}>',
                            help='Choose online sniffing of a LAN  or offline converting PCAP file',
                            type=str.lower)

        parser.add_argument('--source',
                            metavar='<string> source file or LAN name.',
                            help='In online sniffing provide <LAN name> and in offline converting provide <PCAP file>.',
                            required=True)

        parser.add_argument('--interval',
                            metavar='<Float> interval in seconds.',
                            type=float,
                            default=0.5,
                            help='interval to compute flows.',
                            required=False)

        parser.add_argument('--use_port',
                            metavar='<True or False> indicating the usage of port address.',
                            help='<Determines whether the port number should be included when identifying network.'
                                 'addresses.>',
                            type=bool,
                            default=False,
                            required=False)

        parser.add_argument('--attacks_time',
                            metavar='<string> file address for attack log csv file.',
                            help='attack file address for finding anomalous flows\' label.',
                            required=False)

        parser.add_argument('--attacks_packet',
                            metavar='<string> file address for attack packet information csv file.',
                            help='a file address for a CSV file that indicate which packets are anomalous.',
                            required=False)

        parser.add_argument('--ids',
                            metavar='<string> file address for AI model that act as intrusion detection system.',
                            help='address of pre trained ml model  to classify incoming flows.',
                            required=False)

        parser.add_argument('--target_connection',
                            metavar='<string> file address for the file indicating details of target connection.',
                            help='Target server connection file to stream out network flows.')

        parser.add_argument('--target_file',
                            metavar='<string> file address for the output csv file.',
                            help='csv file to output.')

        args = parser.parse_args()

        # check action and Source
        if args.action == FlowGeneratorActions.CONVERT:
            check_file(args.source)

        elif args.action == FlowGeneratorActions.SNIFF:
            # todo: check LAN name is correct
            pass

        # check required files
        check_file(args.attacks_time)
        check_file(args.attacks_packet)
        check_file(args.ids)
        check_file(args.target_connection)

        if not args.target_connection and not args.target_file:
            raise RuntimeError("No target defined in arguments." +
                               " Giving one of target_stream or target_file is mandatory")

        return args

    def __init__(self):
        args = ICSFlowGenerator.get_args()

        if not os.path.isdir("./output"):
            os.mkdir("./output")

        Log.configure_log_files('./output/', True)

        # Works as a pipeline between agents
        self.flow_pipeline = queue.Queue()

        PacketParameter.use_port = args.use_port

        # Create extractor, annotator and sender agents
        self.agent_extractor = AgentExtractor(action=args.action,
                                              source=args.source,
                                              flow_interval=args.interval,
                                              output_queue=self.flow_pipeline)

        self.agent_processor = AgentProcessor(output_queue=self.flow_pipeline)

        self.agent_processor.add_process(FlowAnnotatorAttackPacket(args.attacks_packet))
        self.agent_processor.add_process(FlowAnnotatorAttackTime(args.attacks_time))
        self.agent_processor.add_process(FlowAnnotatorAttackTime(args.ids))
        # self.agent_processor.add_process(FlowAnnotatorIDS(args.target_file))
        self.agent_processor.add_process(FlowSenderFile(args.target_file))
        self.agent_processor.add_process(FlowSenderMQTT(args.target_connection))
        # self.agent_processor.add_process(FlowSenderStatusMQTT(args.target_connection,
        #                                                       voting_interval=Config.StatusSender.voting_interval))

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
        while not self.flow_pipeline.empty() or (not self.reader_thread_terminated):
            self.agent_processor.process()

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
