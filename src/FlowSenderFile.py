import logging
from abc import ABC

from Helper import Log
from src.FlowProcessBase import FlowProcessBase


class FlowSenderFile(FlowProcessBase, ABC):

    def _pre_setup(self):
        file_address = self.data_address
        self.file = Log.setup_new_logger(file_address, logging.Formatter('%(message)s'), file_dir=".", file_ext='.csv')\
            if file_address.strip() else False
        self.FILE_HEADER_PRINTED = False

    def _process(self, flow):
        result = flow.parameters
        if not self.FILE_HEADER_PRINTED:
            self.file.info(','.join(result.keys()))
            self.FILE_HEADER_PRINTED = True

        self.file.info(','.join(result.values()))
