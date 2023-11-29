import json
import logging

from Connection import Connection
from Helper import Log
import paho.mqtt.client as paho


class AgentSender:
    def __init__(self, file_address, server_connection):
        self.client = self.__get_client(server_connection)
        self.file = self.__get_file(file_address)

        self.FILE_HEADER_PRINTED = False

    @staticmethod
    def __get_client(server_connection):

        if not server_connection or not server_connection.strip():
            return False;

        client = Connection.build(server_connection)
        client.start()
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
        self.client.send(message)
