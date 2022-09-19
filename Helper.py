import logging
import os
from datetime import datetime


def setup_logger( name, format_str, level=logging.INFO, file_dir="./logs", file_ext=".log", write_mode="w"):
    """To setup as many loggers as you want"""

    """
    logging.basicConfig(filename="./logs/log-" + self.__name +".log",
                        format='[%(levelname)s] [%(asctime)s] %(message)s ',
                        filemode='w')
                        """
    """To setup as many loggers as you want"""
    file_path = os.path.join(file_dir, name) + file_ext
    handler = logging.FileHandler(file_path, mode=write_mode)
    handler.setFormatter(format_str)

    # Let us Create an object
    logger = logging.getLogger(name)

    # Now we are going to Set the threshold of dataset to DEBUG
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


def get_packet_time(pkt_metadata):
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



