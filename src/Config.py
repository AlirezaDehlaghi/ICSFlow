class Config:
    class Debug:
        DEBUG = True
        DEBUG_SNIFFED_PACKET_STEP = 1000
        DEBUG_PROCESSED_FLOW_STEP = 100

        RUN_THREADING = False

    class Train:
        DEFAULT_TRAIN_DATASET = 'input/Dataset.csv'
        BEST_SEARCH_OPTION = True

        @staticmethod
        def labels_index_path(model_name):
            return model_name + ".json"

    class StatusSender:
        voting_interval = 5

    class Texts:
        src = "source"
        des = "destination"
        protocol = "protocol"
        start = "start_date_time"
        end = "end_date_time"

        num_flows_link = "num_flows_in_link"
        num_anomalous_flows_link = "num_anomalous_flows_in_link"
        num_flows_all = "number_of_analyzed_flows"
        num_anomalous_flows_all = "number_of_anomalous_flows"

        prediction_confidence = "prediction_confidence"
        attack_type = "attack_type"
        Prediction = "prediction"
        num_discovered_attacks = "number_of_discovered_attacks"
        discovered_attacks = "discovered_attacks"

    class Labels:
        Normal = "Normal"
        DDoS = "ddos"
        IP_Scan = "ip-scan"
        Port_Scan = "port-scan"
        Replay = "replay"
        MITM = "mitm"

