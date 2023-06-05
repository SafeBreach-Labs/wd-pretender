import logging

from core.features import Feature

from core.merge import Merger
from core.vdm.pair import Pair

from dual.delete import DeleteIntervals

class BypassEDRRule(Feature):
    def __init__(self, pair: Pair, threat_name: str) -> None:
        super().__init__(pair)
        self.threat_name = threat_name
    
    def run(self):
        deleter = DeleteIntervals(self.pair, [])

        threats = Merger(self.pair).merge()

        logging.info(f"Threats Containing: {self.threat_name}")

        for threat in threats:
            if self.threat_name.lower().encode() in threat.name.lower():
                print(f"\tDeleting => {threat.name}")
                deleter.add(threat.interval)
        deleter.run()

        return super().run()