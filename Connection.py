from abc import ABC, abstractmethod
import paho.mqtt.client as paho
from Helper import Log
import logging


class Connection(ABC):
    def __init__(self, params):
        self.type = params['type']
        self.address = params['address']
        self.port = int(params['port'])

        if params.keys().__contains__('username') and params.keys().__contains__('password'):
            self.credential = True
            self.username = params['username']
            self.password = params['password']

    @staticmethod
    def build(connection_file):
        connection_params = {}

        try:
            with open(connection_file, 'r') as file:
                for line in file:
                    if not line.strip():
                        continue
                    # Split each line into key and value using ':' as the delimiter
                    key, value = map(str.strip, line.split(':', 1))
                    connection_params[key] = value
        except FileNotFoundError:
            err_msg = 'Error: File not found.'
            Log.log(err_msg, logging.ERROR)
            raise Exception(err_msg)
        except Exception as e:
            err_msg = 'Error: cannot read from File.' + e.__str__()
            Log.log(err_msg, logging.ERROR)
            raise Exception(err_msg)

        connection_keys = connection_params.keys()
        if not connection_keys.__contains__('type') \
                or not connection_keys.__contains__('address') \
                or not connection_keys.__contains__('port'):
            err_msg = 'server_connection is not in correct format!'
            Log.log(err_msg, logging.ERROR)
            raise Exception(err_msg)

        if connection_params['type'] == 'MQTT':
            return MQTTConnection(connection_params)

        err_msg = 'server_connection have unknown type!'
        Log.log(err_msg, logging.ERROR)
        raise Exception(err_msg)

    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def send(self, values):
        pass


class MQTTConnection(Connection):

    def __init__(self, params):
        Connection.__init__(self, params)

        self.credential = False
        self.topic = params['topic']
        self.client = paho.Client()

        if self.credential:
            self.client.username_pw_set(self.username, self.password)

    def start(self):
        self.client.connect(self.address, self.port)
        self.client.loop_start()

    def send(self, msg):
        self.client.publish(self.topic, msg)


