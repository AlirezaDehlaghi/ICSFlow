import json
from Connection import Connection


class ProcessFlowSenderMQTT:
    def __init__(self, server_connection_file):
        self.client = Connection.build(server_connection_file) if server_connection_file.strip() else False
        self.client.start()

    def process(self, flow):
        if not self.client:
            return

        message = json.dumps(flow.parameters)
        self.client.send(message)


