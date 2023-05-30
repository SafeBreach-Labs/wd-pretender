
from core.vdm.pair import Pair

class Feature:
    def __init__(self, pair: Pair) -> None:
        self.pair = pair

    def run(self):
        self.pair.finallize_blob()