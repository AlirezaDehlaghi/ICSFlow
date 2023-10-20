
class FlowAnnotator():
    def __init__(self, model_address, attacks_address, logger):
        self.ml_model = self.__get_ml_model(model_address)
        self.attacks = self.__get_attacks(attacks_address)
        self. event_logger = logger

    def __get_ml_model(self, model_address):
        if model_address:
            pass
            # todo: complete it

        return False

    def __get_attacks(self, attacks_address):
        if attacks_address:
            attacks = []

            with open(str(attacks_address)) as f:
                lines = f.readlines()

            lines.pop(0)
            for line in lines:
                if line.isspace():
                    continue
                paras = line.strip().split(',')
                attacks.append([paras[0],
                                float(paras[1].strip()),
                                float(paras[2].strip()),
                                # datetime.fromisoformat(paras[3].strip()).timestamp(),
                                # datetime.fromisoformat(paras[4].strip()).timestamp(),
                                paras[5],
                                paras[6]]
                               )
            return attacks
        return False

    def annotate(self, flow):
        if self.ml_model:
            self.__predict_label(flow)

        if self.attacks:
            self.__set_label(flow)


    def __predict_label(self, flow):
        pass
        # todo complete it

    def __set_label(self, flow):
        if self.attacks:

            it_b_label = '0'
            it_m_label = 'Normal'
            nst_b_label = '0'
            nst_m_label = 'Normal'

            for i in range(len(self.attacks)):
                if not (self.attacks[i][1] >= flow.end_time() or self.attacks[i][2] <= flow.start_time()):
                    it_b_label = '1'
                    it_m_label = self.attacks[i][0]

                    attacker_mac = self.attacks[i][3]
                    attacker_ip = self.attacks[i][4]
                    if attacker_mac in flow.src_mac_list or \
                            attacker_mac in flow.dst_mac_list or \
                            attacker_ip in flow.src_ip_list or \
                            attacker_ip in flow.dst_ip_list:
                        nst_b_label = '1'
                        nst_m_label = self.attacks[i][0]

            flow.add_parameter("IT_B_Label", it_b_label)
            flow.add_parameter("IT_M_Label", it_m_label)
            flow.add_parameter("NST_B_Label", nst_b_label)
            flow.add_parameter("NST_M_Label", nst_m_label)

