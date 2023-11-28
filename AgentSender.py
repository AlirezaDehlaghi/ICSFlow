import json
import logging
from Helper import Log
import paho.mqtt.client as paho


class AgentSender:
    def __init__(self, file_address, server_address):
        self.topic = 'testtopic/icssim'

        self.client = self.__get_client(server_address)
        self.file = self.__get_file(file_address)

        self.FILE_HEADER_PRINTED = False

    def __get_client(self, server_address):
        if not server_address or not server_address.strip():
            return False;

        tokens = server_address.split(':')
        if len(tokens) != 2:
            Log.log('Server_address is not in correct format!', logging.ERROR)

        broker_address = tokens[0]
        port = tokens[1]
        client = paho.Client()
        client.connect(broker_address, int(port))
        client.loop_start()
        return client

    @staticmethod
    def __get_file(file_address):
        return Log.setup_new_logger(file_address, logging.Formatter('%(message)s'), file_dir="./", file_ext='.csv') \
            if file_address else False

    def send(self, flow):
        if self.file:
            self.__write_flow_to_file(flow)

        if self.client:
            self.__send_flows_to_server(flow)

    def __write_flow_to_file(self, flow):
        result = flow.parameters
        if not self.FILE_HEADER_PRINTED:
            self.file.info(','.join(result.keys()))
            self.FILE_HEADER_PRINTED = True

        self.file.info(','.join(result.values()))

    def __send_flows_to_server(self, flow):
        message = json.dumps(flow.parameters)
        self.client.publish(self.topic, message)
