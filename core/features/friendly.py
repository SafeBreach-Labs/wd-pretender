import logging
import binascii

from dual.modify import ModifyInterval

from core.merge import Merger
from core.vdm.pair import Pair
from core.features import Feature
from core.signatures.friendlyfile import FriendlyFile_SHA256

class AddFriendlyFile(Feature):
    def __init__(self, pair: Pair, hash: bytes) -> None:
        super().__init__(pair)
        self.hash = hash
    
    def run(self):
        threats = Merger(self.pair).merge()
        friendly_files_threat = None
        friendly_file_sha256 = None

        # find firendly file hash to modify
        logging.info("Searching FriendlyFiles Threat ...")
        for threat in threats:
            if b'FriendlyFiles' == threat.name:
                logging.info("FriendlyFiles Threat Found ")
                friendly_files_threat = threat
                break

        if not friendly_files_threat:
            logging.info("Can't Find FriendlyFile Threat")
            return False
        
        # find 0xa0 signature type and modify it to different file.
        for signature in threat.signatures:
            if signature.type == FriendlyFile_SHA256.Type:
                friendly_file_sha256 = signature
                break
        
        if not friendly_file_sha256:
            logging.info("Can't Find SHA256 Hash to Modify")
            return False
        
        # Calculate Interval
        threat_begin_interval = friendly_files_threat.begin.interval
        interval = friendly_file_sha256.interval
        interval += threat_begin_interval.end

        # Modify interval
        new_friendly_file = FriendlyFile_SHA256(self.hash)
        bytes = new_friendly_file.pack().getvalue()

        logging.info(f"Modifing {binascii.hexlify(friendly_file_sha256.data).decode()} => {self.hash.decode()}")
        ModifyInterval(self.pair, interval, bytes).run()

        return super().run()