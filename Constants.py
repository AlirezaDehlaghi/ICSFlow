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

    dict_class_to_index = {
        Normal: 0,
        DDoS: 1,
        IP_Scan: 2,
        Port_Scan: 3,
        Replay: 4,
        MITM: 5
    }

    dict_index_to_class = {
        0: Normal,
        1: DDoS,
        2: IP_Scan,
        3: Port_Scan,
        4: Replay,
        5: MITM
    }