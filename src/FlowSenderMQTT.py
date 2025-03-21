import json
from abc import ABC

from Connection import Connection
from src.FlowProcessBase import FlowProcessBase


class FlowSenderMQTT(FlowProcessBase, ABC):
    def _pre_setup(self):
        server_connection_file = self.data_address
        self.client = Connection.build(server_connection_file)

        if self.client:
            self.client.start()

    def _process(self, flow):
        if self.client:
            message = json.dumps(flow.parameters)
            self.client.send(message)
