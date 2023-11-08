import logging
from Helper import setup_logger


class AgentSender:
    def __init__(self, file_address, server_address, logger):

        self.server = server_address  # todo: we have to create a client here

        self.file = setup_logger(file_address, logging.Formatter('%(message)s'), file_dir="./", file_ext='.csv') \
            if file_address else False

        self.FILE_HEADER_PRINTED = False

        self.event_logger = logger

    def send(self, flow):
        if self.file:
            self.__write_flow_to_file(flow)

        if self.server:
            self.__send_flows_to_server(flow)

    def __write_flow_to_file(self, flow):
        result = flow.parameters
        if not self.FILE_HEADER_PRINTED:
            self.file.info(','.join(result.keys()))
            self.FILE_HEADER_PRINTED = True

        self.file.info(','.join(result.values()))

    def __send_flows_to_server(self, flow):
        pass
        # todo: complete it
