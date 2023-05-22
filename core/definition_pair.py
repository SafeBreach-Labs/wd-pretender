import logging

from core.merge import Merger
from core.utils import compute_crc32
from core.vdm import BaseVdm, DeltaVdm
from core.utils.interval import Interval
from core.signatures import Signature
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
        
        begin = ThreatBegin(_id=0x123, _counter=1, _category=8, _name=b'Safebreach.DOS', _sections=[0x4001], _footer=b'\x05\x82\x70\x00\x04\x00')
        end = ThreatEnd(0x123)

        dos_threat.begin = begin
        dos_threat.end = end

        raw_data2= b'\x01\x00\x01\x00\x01\x00\x00\x01\x00\x27\x01!This program cannot be run in DOS mode\x00\x00'
        
        sig2 = Signature(0x78, raw_data2)
    
        dos_threat.push(sig2)

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
            print(f"~~~~ fix: {fix_value} ~~~~~")

        self.finallize_blob()

    def insert_threat(self, threat: Threat):
        self.deltavdm.insert_signature_as_action(threat)

    def __internal_delete_threat(self, _threat_interval: Interval):
        merger = Merger(self.basevdm, self.deltavdm)
        old_actions = []
        new_actions = []

        for action in merger.yield_merge():
            if Interval.overlaps(action.merge_interval, _threat_interval):
                print(action)
                print(f'Action Interval: {action.interval}')
                print(f'Action Merge Interval: {action.merge_interval} vs Threat Interval: {_threat_interval}')
                intersection = Interval.intersect(action.merge_interval, _threat_interval)

                _cur_new_actions = action.slice(intersection)
                self.__normalize_actions(_cur_new_actions)

                old_actions.append(action)
                new_actions.extend(_cur_new_actions)
                    
            if action.interval.start > _threat_interval.end:
                break
        
        if old_actions:
            print("old actions:")
            for old in old_actions:
                print(old)

            print("-------------------- new actions ----------------------")
            for new in new_actions:
                print(new)
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