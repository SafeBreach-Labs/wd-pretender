import logging

from dual.modify import ModifyInterval

from core.merge import Merger
from core.vdm.pair import Pair
from core.features import Feature
from core.signatures.pehstr import PEHStr

class DeletePEMockFile(Feature):
    def __init__(self, pair: Pair, hstrs: list):
        super().__init__(pair)
        self.hstrs = hstrs

    def run(self):
        logging.info("DeletePEMockFile: Started")
        
        # find a signature to modify
        logging.info("Searching Threat Rule To Modify ...")
        threats = Merger(self.pair).merge()
        threat_to_modify = None

        for threat in threats:
            if threat.signature_counter == 1:
                signature = threat.signatures.__next__()

                if signature.type == PEHStr.Type:
                    logging.info(f"Found Threat Rule: {threat.name}")
                    threat_to_modify = threat
                    break
    
        if not threat_to_modify:
            logging.info("Couln't Find Threat Rule To Modify")
            return False
        
        # get the interval to modify
        threat_begin_interval = threat_to_modify.begin.interval
        interval = threat_to_modify.signatures.__next__().interval
        interval += threat_begin_interval.end
        logging.debug(f"The Signature Interval: {interval}")

        # modify with the new hstrs
        pestr = PEHStr()
        pestr.push('SafeBreack LTD Mock File')
        pestr_bytes = pestr.pack().getvalue()
        
        logging.info('Modifing ...')
        ModifyInterval(self.pair, interval, pestr_bytes).run()
        return super().run()