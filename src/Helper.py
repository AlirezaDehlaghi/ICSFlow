import logging
import os
from datetime import datetime
import inspect


# This is help for you


def get_packet_time(pkt_metadata):
    """
    Create a formatted packet time based on meta data received from PCAP file.

    :param pkt_metadata: meta data received from PCAP file.
    :return: formatted packet time.
    """
    return pkt_metadata.sec + pkt_metadata.usec / pow(10, 6)


def format_decimal(value, rnd=3):
    return round(value, rnd)


def format_time(value):
    return str(datetime.fromtimestamp(value))


def average(target):
    if len(target) == 0:
        return ''
    else:
        return format_decimal(sum(target) / len(target), 6)


def maximum(target):
    if len(target) == 0:
        return ''
    else:
        return format_decimal(max(target))


def minimum(target):
    if len(target) == 0:
        return ''
    else:
        return format_decimal(min(target))


class Log:
    event_logger = False

    # COLOR_RED = '\033[91m'
    # COLOR_GREEN = '\033[92m'
    # COLOR_BLUE = '\033[94m'
    # COLOR_CYAN = '\033[96m'
    # COLOR_YELLOW = '\033[93m'
    # COLOR_BOLD = '\033[1m'
    # COLOR_PURPLE = '\033[35m'
    # COLOR_WHITE = '\033[97m'

    log_colors = {
                     logging.NOTSET: '\033[97m',  # white
                     logging.DEBUG: '\033[96m',  # cyan
                     logging.INFO: '\033[92m',  # green
                     logging.WARNING: '\033[93m',  # yellow
                     logging.WARN: '\033[93m',  # yellow
                     logging.ERROR: '\033[91m',  # red
                     logging.CRITICAL: '\033[91m',  # red
                     logging.FATAL: '\033[91m'  # red
    }

    @staticmethod
    def setup_new_logger(name, format_str, level=logging.INFO, file_dir="./logs", file_ext=".log", write_mode="w"):
        """To setup as many loggers as you want"""

        """
        logging.basicConfig(filename="./logs/log-" + self.__name +".log",
                            format='[%(levelname)s] [%(asctime)s] %(message)s ',
                            filemode='w')
                            """
        """To setup as many loggers as you want"""

        if not os.path.exists(file_dir):
            os.makedirs(file_dir)

        file_path = os.path.join(file_dir, name) + file_ext
        handler = logging.FileHandler(file_path, mode=write_mode)
        handler.setFormatter(format_str)

        # Let us Create an object
        logger = logging.getLogger(name)

        # Now we are going to Set the threshold of dataset to DEBUG
        logger.setLevel(level)
        logger.addHandler(handler)
        return logger

    @staticmethod
    def configure_log_files (directory, separate_event_log):

        logging.basicConfig(
            level=logging.WARNING,  # Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(directory, "Main_Log.txt"))  # Set the file name for logging
            ]
        )

        if separate_event_log:
            Log.event_logger = Log.setup_new_logger(
                "Log_events",
                logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'),
                level=logging.WARNING,
                file_dir=directory,
                file_ext='.txt')


    @staticmethod
    def log(text,  level):
        frame = f"[{inspect.currentframe().f_back}]"
        msg = f"{text} {frame}"
        print_msg = f"{Log.log_colors[level]}[{logging.getLevelName(level)}] {text}\033[0m {frame}"

        logger = Log.event_logger if Log.event_logger else logging
        logger.log(level, msg)


        print(print_msg)
