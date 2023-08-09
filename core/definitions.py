import os
import glob
import logging

from core.vdm.pair import Pair
from core.vdm.base import BaseVdm
from core.vdm.delta import DeltaVdm

class Definitions:
    def __init__(self, definitions_path: str):
        self.anti_virus_defs = Pair()
        self.anti_spayware_defs = Pair()
        self.definitons_path = definitions_path
        
        self.init_update_payload_files(self.definitons_path) 

    def init_update_payload_files(self, definitions_path: str):
        vdm_files = glob.glob(definitions_path + '/*.vdm')

        for file in vdm_files:
            lower_name = os.path.basename(file).lower()
            
            if "mpasbase" in lower_name:
                logging.info("Loading mpasbase.vdm")
                self.anti_spayware_defs.base = BaseVdm(file)
            elif "mpasdlta" in lower_name:
                logging.info("Loading mpasdlta.vdm")
                self.anti_spayware_defs.delta = DeltaVdm(file)
            elif "mpavbase" in lower_name:
                logging.info("Loading mpavbase.vdm")
                self.anti_virus_defs.base = BaseVdm(file)
            elif "mpavdlta" in lower_name:
                logging.info("Loading mpavdlta.vdm")
                self.anti_virus_defs.delta = DeltaVdm(file)

    def get_anti_spayware_definitions(self) -> Pair:
        return self.anti_spayware_defs
    
    def get_anti_virus_definitions(self) -> Pair:
        return self.anti_virus_defs
    
    def export(self, path: str):
        logging.info(f"Exporting Definitions into: {path}")
        self.anti_spayware_defs.export(path)
        self.anti_virus_defs.export(path)
        