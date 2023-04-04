import io
import logging

from core.merge import Merger
from core.utils import intersect
from core.vdm import BaseVdm, DeltaVdm
from core.signatures.deltablob import CopyFromDelta, COPY_FROM_BASE

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
        merge = merger.merge()

        blob = self.deltavdm.extract_blob()
        blob.mrgsize = merge.length
        blob.mrgcrc  = merge.crc32

        self.deltavdm.set_delta_blob(blob)
    
    def delete_threat(self, id:int = None, name:bytes = None, finallize_blob:bool = True):
        merger = Merger(self.basevdm, self.deltavdm)
        merge  = merger.merge()
        threat_position = merge.get_threat(id, name).position
        
        self.__internal_delete_threat(merger, threat_position, 0)
                
        if finallize_blob:
            self.finallize_blob()

    def delete_all_threats_containing(self, name):
        merger = Merger(self.basevdm, self.deltavdm)
        merge  = merger.merge()
        
        fix_value = 0
        total_delta = 0
        
        for threat in merge.get_threats_containing(name):
            print(f"      Deleting -> {threat.name}")
            threat.fix_position(fix_value)
            total_delta += self.__internal_delete_threat(merger, threat.position, total_delta)
            fix_value -= threat.size

        self.finallize_blob()

    def __internal_delete_threat(self, merger: Merger, threat_pos: tuple, delta_seed: int) -> int:
        remainder = 0
        total_delta = delta_seed

        for action in merger.yield_merge():

            if action.merge_overlap(threat_pos):
                intersection = intersect(threat_pos, action.merge_pos)
                new_actions, cur_delta = action.slice_range(intersection)
                total_delta += cur_delta

                for i, new_action in enumerate(new_actions):
                    if new_action.type == COPY_FROM_BASE and new_action.size < 6:
                        current_offset = self.basevdm.signatures.tell()
                        self.basevdm.signatures.seek(new_action.offset)
                        _data = self.basevdm.signatures.read(new_action.size)
                        self.basevdm.signatures.seek(current_offset)
                        _action = CopyFromDelta(_data)
                        _action.set_merge_position(new_action.merge_pos)
                        new_actions[i] = _action
                        
                action.fix_position(remainder)
                remainder += self.deltavdm.replace_actions(action, new_actions)
            
            if action.merge_start > threat_pos[1]:
                break
            
        return total_delta