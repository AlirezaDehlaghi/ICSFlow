import logging
import os
from abc import ABC

import numpy as np
import pandas as pd
from Config import Config
from Helper import Log
from IdsClassifier import load_model, load_labels, generate_model
from src.FlowProcessBase import FlowProcessBase


class FlowAnnotatorIDS(FlowProcessBase, ABC):

    def _pre_setup(self):
        predictor_address = self.data_address
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

            self.model = load_model(predictor_address)
            self.label_index = load_labels(label_index_path)

        except Exception as e:
            Log.log(e, logging.ERROR)
            Log.log(f'Unable to load model and label_index!', logging.ERROR)
            # return False, False
            raise e

    def _process(self, flow):
        df = pd.DataFrame(columns=flow.parameters.keys(), data=[flow.parameters.values()])
        # df.replace('', np.nan, inplace=True)
        df.replace('', '0', inplace=True)
        y_pred = self.model.predict_proba(df, verbose=0)
        y_pred_classes = np.argmax(y_pred, axis=0)
        flow.add_parameter(Config.Texts.Prediction, self.label_index[str(y_pred_classes)])
        flow.add_parameter(Config.Texts.prediction_confidence, str(y_pred[y_pred_classes]))

