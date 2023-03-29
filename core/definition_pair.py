import logging
import io

from core.merge import Merger
from core.utils import compute_crc32
from core.vdm import BaseVdm, DeltaVdm
from core.utils.interval import Interval
from core.signatures import Signature
from core.signatures.pehstr import PEHStr
from core.signatures.threat import Threat, ThreatBegin, ThreatEnd
from core.signatures.deltablob import CopyFromDelta, CopyFromBase

class DefinitionPair:
    def __init__(self, basevdm: BaseVdm, deltavdm: DeltaVdm) -> None:
        self.basevdm = basevdm
        self.deltavdm = deltavdm

    def export(self, path: str = None):
        version_msg = f"{self.deltavdm.basename}: {self.deltavdm.version} -> "
        self.basevdm.save(path)
        self.deltavdm.inc_version_build_number()
        logging.info(version_msg + f"{self.deltavdm.version}")
        self.deltavdm.save(path)

    def finallize_blob(self):
        merger = Merger(self.basevdm, self.deltavdm)
        threats = merger.merge()
        threats_stream = threats.pack()
        threats_stream.seek(0, 2)

        self.deltavdm.blob.mergesize = threats_stream.tell()
        self.deltavdm.blob.mergecrc  = compute_crc32(threats_stream)
    
    def add_dos_threat(self):
        

        dos_threat = Threat()
        dos_threat.id = 0x123
        dos_threat.name = b"Safebreach.DOS"
        # threat_begin = ThreatBegin(_id=0x123,
        #                            _unknown1=0x10000,
        #                            _unknown2=0x8,
        #                            _name=b"Safebreach.DOS", 
        #                            _footer=b'\x00\x00\xba\x40\x05\x83\x70\x00\x04\x00')
        # #threat_end = ThreatEnd(_id=0x123)
        
        # raw_data = b'\x02\x00\x02\x00\x02\x00\x00\x01\x00\x2f\x01\x41\x64\x76\x61\x6e\x63\x65\x64\x20\x49\x6e\x76\x69\x73\x69\x62\x6c\x65\x20\x4b\x65\x79\x6c\x6f\x67\x67\x65\x72\x20\x28\x4b\x65\x79\x73\x74\x72\x6f\x6b\x65\x73\x20\x54\x79\x70\x65\x64\x29\x01\x00\x25\x03\x54\x69\x6d\x65\x3a\x90\x02\x10\x57\x69\x6e\x64\x6f\x77\x20\x54\x69\x74\x6c\x65\x3a\x90\x02\x10\x4b\x65\x79\x73\x74\x72\x6f\x6b\x65\x73\x3a\x90\x00\x00\x00'

        # raw_data2 = b'\x0c\x00\x0c\x00\x04\x00\x00\x0a\x00\x20\x03\x00\x53\x4f\x46\x54\x57\x41\x52\x45\x5c\x57\x69\x6e\x73\x6f\x75\x6c\x5c\x90\x02\x02\x4b\x65\x79\x6c\x6f\x67\x67\x65\x72\x90\x00\x02\x00\x0d\x01\x2e\x64\x6c\x6c\x00\x53\x65\x74\x48\x6f\x6f\x6b\x00\x02\x00\x29\x03\x41\x63\x74\x69\x76\x65\x20\x4b\x65\x79\x20\x4c\x6f\x67\x67\x65\x72\x20\x52\x65\x70\x6f\x72\x74\x90\x02\x14\x2e\x61\x64\x64\x72\x65\x73\x73\x2e\x63\x6f\x6d\x90\x00\x02\x00\x2a\x03\x54\x6f\x74\x61\x6c\x57\x69\x6e\x90\x02\x10\x41\x63\x74\x69\x76\x65\x20\x4b\x65\x79\x20\x4c\x6f\x67\x67\x65\x72\x3a\x20\x4b\x65\x79\x73\x74\x72\x6f\x6b\x65\x73\x90\x00\x00\x00'

        #
        #sig2 = Signature(0x78, raw_data2)
        sig = PEHStr()
        sig.push("This is program cannot be run in DOS mode")

        dos_threat.push(sig)
        #dos_threat.push(sig2)

        self.deltavdm.insert_signature_as_action(dos_threat.pack_bytes())

        self.finallize_blob()

    def delete_threat(self, id:int = None, name:bytes = None, finallize_blob:bool = True):
        merger = Merger(self.basevdm, self.deltavdm)
        threats  = merger.merge()
        threat = threats.get(id, name)

        if not threat:
            return

        interval = threat.interval
        self.__internal_delete_threat(interval)
                
        if finallize_blob:
            self.finallize_blob()

    def delete_all_threats_containing(self, name):
        merger = Merger(self.basevdm, self.deltavdm)
        threats  = merger.merge()
        
        fix_value = 0

        for threat in threats.match(name):
            print(f"      Deleting -> {threat.name}")
            threat.interval += fix_value
            self.__internal_delete_threat(threat.interval)
            fix_value -= threat.size

        self.finallize_blob()

    def insert_threat(self, threat: Threat):
        self.deltavdm.insert_signature_as_action(threat)

    def __internal_delete_threat(self, _threat_interval: Interval):
        merger = Merger(self.basevdm, self.deltavdm)
        old_actions = []
        new_actions = []

        for action in merger.yield_merge():
            if Interval.overlaps(action.merge_interval, _threat_interval):
                intersection = Interval.intersect(action.merge_interval, _threat_interval)

                _cur_new_actions = action.slice(intersection)
                self.__normalize_actions(_cur_new_actions)

                old_actions.append(action)
                new_actions.extend(_cur_new_actions)
                    
            if action.interval.start > _threat_interval.end:
                break
        
        if old_actions:
            self.deltavdm.blob.replace(old_actions, new_actions)
    
    def __normalize_actions(self, _actions):
        for i, new_action in enumerate(_actions):
            if new_action.type == CopyFromBase.Type and new_action.size < 6:
                current_offset = self.basevdm.signatures.tell()
                
                self.basevdm.signatures.seek(new_action.offset)
                _data = self.basevdm.signatures.read(new_action.size)
                
                self.basevdm.signatures.seek(current_offset)
                
                #_action = CopyFromDelta(_data)
                #_action.set_merge_position(new_action.merge_pos)
                
                _actions[i] = CopyFromDelta(_data)