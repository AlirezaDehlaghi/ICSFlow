from abc import ABC, abstractmethod


class FlowProcessBase(ABC):
    def __init__(self, data_address):
        self.data_address = data_address

        if self.is_enabled():
            self._pre_setup()

    def is_enabled(self):
        return (self.data_address is not None) and self.data_address.strip()

    @abstractmethod
    def _pre_setup(self):
        pass

    def process(self, flow):
        if self.is_enabled():
            self._process(flow)

    @abstractmethod
    def _process(self, flow):
        pass
