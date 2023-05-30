from features import Feature
from core.vdm.pair import Pair

class DeletePEMockFile(Feature):
    def __init__(self, pair: Pair, hstrs: list):
        super().__init__(pair)
        self.hstrs = hstrs

    def run(self):
        print('Do delete PE mock file containing hstrs ...')
        
        # find a signature to modify
        
        # get the interval to modify

        # modify with the new hstrs

        super().run()