import glob
import logging

from core.vdm import BaseVdm, DeltaVdm
from core.signatures import Signature
from core.definition_pair import DefinitionPair
from core.signatures.threat import Threat, ThreatBegin, ThreatEnd

class DefinitionUpdate:
    def __init__(self, definition_update_path: str):
        self.update_path = definition_update_path
        self.output_directory = '.'

        logging.info("Initializing DefinitionUpdate")
        self.init_update_payload_files()
        logging.info("Loading Done")

    def init_update_payload_files(self):
        vdm_files = glob.glob(self.update_path + '/*.vdm')

        mpaspair = {}
        mpavpair = {}

        for file in vdm_files:
            if "mpasbase" in file:
                logging.info("Loading mpasbase.vdm")
                mpaspair["mpasbase"] = BaseVdm(file)
            elif "mpasdlta" in file:
                logging.info("Loading mpasdlta.vdm")
                mpaspair["mpasdlta"] = DeltaVdm(file)
            elif "mpavbase" in file:
                logging.info("Loading mpavbase.vdm")
                mpavpair["mpavbase"] = BaseVdm(file)
            elif "mpavdlta" in file:
                logging.info("Loading mpavdlta.vdm")
                mpavpair["mpavdlta"] = DeltaVdm(file)

        self.mpaspair = DefinitionPair(mpaspair["mpasbase"], mpaspair["mpasdlta"])
        self.mpavpair = DefinitionPair(mpavpair["mpavbase"], mpavpair["mpavdlta"])

    def set_output_path(self, path):
        self.output_directory = path

    def export(self):
        logging.info(f"Exporting definitions into: {self.output_directory}")

        self.mpaspair.export(self.output_directory)
        self.mpavpair.export(self.output_directory)

    def delete_match_threat_name(self, name: str):
        print('')
        logging.log(100, f"Delete threats from Anti-Spyware definitions")
        self.mpaspair.delete_all_threats_containing(name)      
        
        logging.log(100, f"Delete threats from Anti-Virus definitions")
        self.mpavpair.delete_all_threats_containing(name)

    def delete_threat_by_id(self, id: int):
        print('')
        logging.log(100, f"Delete threat id= {id} from Anti-Spyware definitions")
        self.mpaspair.delete_threat(id)

        logging.log(100, f"Delete threat id= {id} from Anti-Virus definitions")
        self.mpavpair.delete_threat(id)
    
    def do_dos(self):
        logging.info("Adding dos stub threat into Anti-Virus definitions")
        self.mpavpair.add_dos_threat()