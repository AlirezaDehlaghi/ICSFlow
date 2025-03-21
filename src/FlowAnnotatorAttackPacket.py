from collections import Counter
from FlowProcessBase import FlowProcessBase
from Helper import string_array_to_string, format_decimal


class FlowAnnotatorAttackPacket(FlowProcessBase):

    def _pre_setup(self):
        attacks = dict()

        with open(str(self.data_address)) as f:
            lines = f.readlines()

        for line in lines:
            if line.isspace():
                continue
            paras = line.strip().split(',')

            pkt_id = int(paras[0])
            # label_bin = 0 if paras[1].lower() == "normal" else 1
            label_mul = paras[2]

            attacks[pkt_id] = label_mul

        self.attacks = attacks

    def _process(self, flow):

        types = []
        # ids = []
        for packet_parameter in flow.sen_list:
            new_type = self.attacks[packet_parameter.get_id()]
            types.append(new_type)
            # ids.append(str(packet_parameter.get_id()))

        for packet_parameter in flow.rec_list:
            new_type = self.attacks[packet_parameter.get_id()]
            types.append(new_type)
            # ids.append(str(packet_parameter.get_id()))

        type_counts = Counter(types)
        # Find the most common type and its count
        most_common_attacks = type_counts.most_common(2)
        majority, count = most_common_attacks[0]

        if majority.lower() == "normal" and len(most_common_attacks) > 1:
            if most_common_attacks[1][1] / len(types) > 0.1:
                majority, count = most_common_attacks[1]

        label_confidence = format_decimal(count/len(types) * 100)

        flow.add_parameter("Packet_Label_B", "0" if majority.lower() == "normal" else "1")
        flow.add_parameter("Packet_Label_M", majority)
        flow.add_parameter("Packet_Label_Confidence", f'{label_confidence}%')
        flow.add_parameter("Packet_Label_all", string_array_to_string(type_counts.keys()))
        # flow.add_parameter("IDs", string_array_to_string(ids))
