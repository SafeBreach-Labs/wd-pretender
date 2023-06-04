import logging

from dual import IAction
from core.merge import Merger
from core.utils.interval import Interval

class DeleteInterval(IAction):
    def __init__(self, pair, interval: Interval):
        super().__init__(pair)
        self.interval = interval
    
    def run(self):
        old_actions = []
        new_actions = []

        for action in Merger(self.pair).yield_merge():
            intersection = Interval.intersect(self.interval, action.merge_interval)
            
            if intersection:
                old_actions.append(action)
                new_actions.extend(action.slice(intersection))
                
            if action.interval.start > self.interval.end:
                break
        
        if old_actions:
            self.pair.normalize(new_actions)
            self.pair.delta.blob.replace(old_actions, new_actions)

class DeleteIntervals(IAction):
    def __init__(self, pair, intervals: list[Interval]):
        super().__init__(pair)
        self.intervals = intervals

    def add(self, interval: Interval):
        self.intervals.append(interval)

    def run(self):
        align = 0
        self._squeeze()

        for i in self.intervals:
            i += align
            DeleteInterval(self.pair, i).run()
            align -= (i.end - i.start)
    
    def _squeeze(self):
        logging.debug("Squeezing intervals")
        if len(self.intervals) == 0:
            return

        stack = []
        stack.append(self.intervals[0])

        for i in self.intervals[1:]:
            if stack[-1].end == i.start:
                stack[-1].end = i.end
            else:
                stack.append(i)

        self.intervals = stack