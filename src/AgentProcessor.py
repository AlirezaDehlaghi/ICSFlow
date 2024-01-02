from ProcessAnnotator import ProcessAnnotator
from ProcessFlowFileWriter import ProcessFlowFileWriter
from ProcessStatusSenderMQTT import ProcessStatusSenderMQTT
from Config import Config
from ProcessFlowSenderMQTT import ProcessFlowSenderMQTT


class AgentProcessor:

    def __init__(self, predictor_address, attacks_address, file_address, server_connection):
        self.__processes = []
        annotator = ProcessAnnotator(predictor_address, attacks_address)
        flow_file_writer = ProcessFlowFileWriter(file_address)
        status_sender = ProcessStatusSenderMQTT(server_connection, voting_interval=Config.StatusSender.voting_interval)
        flow_sender = ProcessFlowSenderMQTT(server_connection)

        self.__processes.append(annotator)
        self.__processes.append(flow_file_writer)
        if annotator.is_prediction_enabled():
            self.__processes.append(status_sender)
        #self.__processes.append(flow_sender)

    def process(self, flow):
        for prc in self.__processes:
            prc.process(flow)
