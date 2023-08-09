from dual import IAction

from core.merge import Merger
from core.utils.interval import Interval


class InsertData(IAction):
    def __init__(self, pair, index: int, data: bytes):
        super().__init__(pair)
        self.index = index
        self.data = data

    def run(self):
        for action in Merger(self.pair).yield_merge():
            if Interval.contains(action.merge_interval, self.index):
                old_actions = [action]
                new_actions = action.insert(self.index, self.data)
                break
        
        if old_actions:
            self.pair.normalize(new_actions)
            self.pair.delta.blob.replace(old_actions, new_actions)