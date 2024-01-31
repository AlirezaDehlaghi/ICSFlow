import logging
import os
import numpy as np
import pandas as pd
from Config import Config
from Helper import Log
from IdsClassifier import load_model, load_labels, generate_model


class ProcessAnnotator:
    def __init__(self, predictor_address, attacks_address):
        (self.ml_model, self.label_index) = self.__get_ml_model(predictor_address)
        self.attacks = self.__get_attacks(attacks_address)

    def is_prediction_enabled(self):
        if self.ml_model:
            return True
        else:
            return False

    @staticmethod
    def __get_ml_model(predictor_address):

        if not predictor_address.strip():
            return False, False

        try:
            label_index_path = Config.Train.labels_index_path(predictor_address)
            if os.path.exists(predictor_address) and os.path.exists(label_index_path):
                model = load_model(predictor_address)
                label_index = load_labels(label_index_path)
                return model, label_index

            if not os.path.exists(predictor_address):
                Log.log(f'Model file: ({predictor_address}) not found!', logging.WARNING)

            if not os.path.exists(label_index_path):
                Log.log(f'Label index file: ({label_index_path}) not found!', logging.WARNING)

            dataset_file = Config.Train.DEFAULT_TRAIN_DATASET
            best_search = Config.Train.BEST_SEARCH_OPTION

            Log.log(f'Try to create model and index_label using file: ({dataset_file})', logging.INFO)
            Log.log(f'Creating model using option (best_search = {best_search})', logging.INFO)

            if not os.path.exists(dataset_file):
                raise Exception(f'File ({dataset_file}) not found!')

            generate_model(input_dataset=dataset_file, output_model_name=predictor_address,
                           output_label_index_name=label_index_path, best_search=best_search)

            model = load_model(predictor_address)
            label_index = load_labels(label_index_path)

            return model, label_index

        except Exception as e:
            Log.log(e, logging.ERROR)
            Log.log(f'Unable to load model and label_index!', logging.ERROR)
            # return False, False
            raise e

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

    def process(self, flow):
        if self.ml_model:
            self.__predict_label(flow)

        if self.attacks:
            self.__set_label(flow)

    def __predict_label(self, flow):
        # df = pd.DataFrame(columns=flow.parameters.keys(), data=[flow.parameters.values()])
        # df.replace('', np.nan, inplace=True)
        # y_pred = self.ml_model.predict_proba(df, verbose=0)
        # y_pred_classes = np.argmax(y_pred, axis=0)
        # flow.add_parameter(Config.Texts.Prediction, self.label_index[str(y_pred_classes)])
        # flow.add_parameter(Config.Texts.prediction_confidence, str(y_pred[y_pred_classes]))

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

