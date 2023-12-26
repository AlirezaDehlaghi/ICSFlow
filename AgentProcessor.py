from ProcessAnotator import ProcessAnotator
from ProcessFlowFileWriter import ProcessFlowFileWriter
from ProcessFlowSenderMQTT import ProcessFlowSenderMQTT
from ProcessStatusSenderMQTT import ProcessStatusSenderMQTT


class AgentProcessor:

    def __init__(self, predictor_address, attacks_address, file_address, server_connection):
        self.__processes = []
        self.__processes.append(ProcessAnotator(predictor_address, attacks_address))
        self.__processes.append(ProcessFlowFileWriter(file_address))
        self.__processes.append(ProcessStatusSenderMQTT(server_connection, voting_interval=5))
        #self.__processes.append(ProcessFlowSenderMQTT(server_connection))

    def process(self, flow):
        for prc in self.__processes:
            prc.process(flow)
