from dual import IAction
from dual.delete import DeleteInterval
from dual.insert import InsertData

from core.merge import Merger
from core.utils.interval import Interval

from core.signatures.deltablob import CopyFromDelta

class ModifyInterval(IAction):
    def __init__(self, pair, interval: Interval, data: bytes):
        super().__init__(pair)
        self.interval = interval
        self.data = data
    
    def run(self):
        DeleteInterval(self.pair, self.interval).run()
        InsertData(self.pair, self.interval.start, self.data).run()
