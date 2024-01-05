import logging
from Helper import Log


class ProcessFlowFileWriter:
    def __init__(self, file_address):
        self.file = self.__get_file(file_address)
        self.FILE_HEADER_PRINTED = False

    @staticmethod
    def __get_file(file_address):
        return Log.setup_new_logger(file_address, logging.Formatter('%(message)s'), file_dir="", file_ext='.csv') \
            if file_address.strip() else False

    def process(self, flow):
        if not self.file:
            return

        result = flow.parameters
        if not self.FILE_HEADER_PRINTED:
            self.file.info(','.join(result.keys()))
            self.FILE_HEADER_PRINTED = True

        self.file.info(','.join(result.values()))
