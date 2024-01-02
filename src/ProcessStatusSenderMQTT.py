import json
import logging
from collections import Counter

from Connection import Connection
from Helper import Log
from Config import Config


class ProcessStatusSenderMQTT:
    def __init__(self, server_connection_file, voting_interval=0):
        self.client = Connection.build(server_connection_file) if server_connection_file.strip() else False
        self.voting_interval = voting_interval

        self.link_flows = dict()
        self.timer_idx = 0

        if self.client:
            self.client.start()

    def process(self, flow):
        if not self.client:
            return

        start_time = flow.start_time()

        if start_time >= self.timer_idx + self.voting_interval:
            self.__flush_status(start_time)

        if start_time < self.timer_idx:
            Log.log("Skipped flow! out of order flow!", level=logging.WARNING)

        link = (flow.src, flow.des, flow.protocol)
        if not self.link_flows.keys().__contains__(link):
            self.link_flows[link] = []

        self.link_flows[link].append(flow)

    def __send_flows_to_server(self, status):
        message = json.dumps(status)
        self.client.send(message)

    def __flush_status(self, end_time):
        if not len(self.link_flows) == 0:
            status = self.extract_network_status(end_time)
            self.__send_flows_to_server(status)

        self.timer_idx = end_time
        self.link_flows = dict()

    def extract_network_status(self, end_time):
        status = dict()
        detected_attacks = []
        counter_flows = 0
        counter_anomalies = 0

        for link, flows in self.link_flows.items():
            counter_flows += len(flows)

            votes = []
            for flow in flows:
                prediction = flow.parameters[Config.Texts.Prediction]
                if not prediction == Config.Labels.Normal:
                    counter_anomalies += 1
                votes.append(prediction)
            counter = Counter(votes)
            most_common_item = counter.most_common(1)[0][0]

            if most_common_item == Config.Labels.Normal or len(flows) < 2:
                #  link[0] == '192.168.0.43' or link[1] == '192.168.0.43':
                continue

            attack = dict()
            confidences = []
            counter_anomalies_link = 0

            for flow in flows:
                prediction = int(flow.parameters[Config.Texts.Prediction])
                if prediction == most_common_item:
                    confidences.append(float(flow.parameters[Config.Texts.prediction_confidence]))
                    counter_anomalies_link += 1

            attack[Config.Texts.src] = link[0]
            attack[Config.Texts.des] = link[1]
            attack[Config.Texts.protocol] = link[2]
            attack[Config.Texts.attack_type] = most_common_item
            attack[Config.Texts.prediction_confidence] = sum(confidences) / len(confidences)
            attack[Config.Texts.num_flows_link] = len(flows)
            attack[Config.Texts.num_anomalous_flows_link] = counter_anomalies_link
            detected_attacks.append(attack)

        status[Config.Texts.num_flows_all] = counter_flows
        status[Config.Texts.num_anomalous_flows_all] = counter_anomalies
        status[Config.Texts.discovered_attacks] = detected_attacks
        status[Config.Texts.start] = self.timer_idx
        status[Config.Texts.end] = end_time
        status[Config.Texts.num_discovered_attacks] = len(detected_attacks)

        return status