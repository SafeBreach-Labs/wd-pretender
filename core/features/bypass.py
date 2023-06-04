from features import Feature
from core.vdm.pair import Pair

class BypassEDRRule(Feature):
    def __init__(self, pair: Pair, ) -> None:
        super().__init__(pair)
        