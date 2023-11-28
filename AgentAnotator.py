import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
from ModelCreator import create_model
from sklearn.model_selection import StratifiedKFold, GridSearchCV, train_test_split
from scikeras.wrappers import KerasClassifier

class AgentAnnotator():
    def __init__(self, predictor_address, attacks_address):
        self.ml_model = self.__get_ml_model(predictor_address)
        self.attacks = self.__get_attacks(attacks_address)

    @staticmethod
    def __get_ml_model(predictor_address):
        if predictor_address:
            return joblib.load(predictor_address)

        return False

    @staticmethod
    def __get_attacks(attacks_address):
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
        df = pd.DataFrame(columns=flow.parameters.keys(), data=[flow.parameters.values()])
        df.replace('', np.nan, inplace=True)
        y_pred = self.ml_model.predict(df)
        y_pred_classes = np.argmax(y_pred, axis=1)
        flow.add_parameter("Prediction", str(y_pred_classes[0]))
        flow.add_parameter("Prediction_Confidence" , str(y_pred[0][y_pred_classes[0]]))

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

