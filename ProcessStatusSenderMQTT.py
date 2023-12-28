import json
import logging
from collections import Counter

from Connection import Connection
from Constants import Texts, Labels
from Helper import Log


class ProcessStatusSenderMQTT:
    def __init__(self, server_connection_file, voting_interval=0):
        self.client = Connection.build(server_connection_file) if server_connection_file.strip() else False
        self.voting_interval = voting_interval

        self.link_flows = dict()
        self.timer_idx = 0

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
        normal_index = Labels.dict_class_to_index[Labels.Normal]

        for link, flows in self.link_flows.items():
            counter_flows += len(flows)

            votes = []
            for flow in flows:
                prediction = int(flow.parameters[Texts.Prediction])
                if not prediction == normal_index:
                    counter_anomalies += 1
                votes.append(prediction)
            counter = Counter(votes)
            most_common_item = counter.most_common(1)[0][0]

            if most_common_item == normal_index or len(flows) < 2 or link[0] == '192.168.0.43' or \
                    link[1] == '192.168.0.43':
                continue

            attack = dict()
            confidences = []
            counter_anomalies_link = 0

            for flow in flows:
                prediction = int(flow.parameters[Texts.Prediction])
                if prediction == most_common_item:
                    confidences.append(float(flow.parameters[Texts.prediction_confidence]))
                    counter_anomalies_link += 1

            attack[Texts.src] = link[0]
            attack[Texts.des] = link[1]
            attack[Texts.protocol] = link[2]
            attack[Texts.attack_type] = Labels.dict_index_to_class[most_common_item]
            attack[Texts.prediction_confidence] = sum(confidences) / len(confidences)
            attack[Texts.num_flows_link] = len(flows)
            attack[Texts.num_anomalous_flows_link] = counter_anomalies_link
            detected_attacks.append(attack)

        status[Texts.num_flows_all] = counter_flows
        status[Texts.num_anomalous_flows_all] = counter_anomalies
        status[Texts.discovered_attacks] = detected_attacks
        status[Texts.start] = self.timer_idx
        status[Texts.end] = end_time
        status[Texts.num_discovered_attacks] = len(detected_attacks)

        return status
