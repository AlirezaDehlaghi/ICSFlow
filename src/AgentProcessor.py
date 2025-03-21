import time
from datetime import datetime
from Config import Config


class AgentProcessor:
    counter = 0

    def __init__(self, output_queue):
        self.__processes = []
        self.output_queue = output_queue

    def add_process(self, process):
        self.__processes.append(process)

    def process(self):
        if self.output_queue.empty():
            time.sleep(2)

        else:
            flow = self.output_queue.get()
            AgentProcessor.counter += 1

            flow.compute_parameters()

            for prc in self.__processes:
                prc.process(flow)

            self.report_progress()

    def report_progress(self):
        """
        Logs progress at regular intervals if verbosity is enabled.
        """
        if Config.RUN.VERBOSE and AgentProcessor.counter % Config.RUN.VERBOSE_PROCESSED_FLOW_STEP == 0:
            print("{}: {} flows sent. ({} flows in the queue) ".format(datetime.now(), AgentProcessor.counter,
                                                                       self.output_queue.qsize()))