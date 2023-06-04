import logging

from dual.add import AddThreat
from dual.modify import ModifyInterval
from dual.delete import DeleteInterval, DeleteIntervals

from core.vdm.base import BaseVdm
from core.vdm.delta import DeltaVdm

from core.merge import Merger
from core.signatures import Signature
from core.signatures.threat import Threat, ThreatBegin, ThreatEnd
from core.signatures.deltablob import Action, CopyFromDelta

class Pair:
    def __init__(self, basevdm: BaseVdm = None, deltavdm: DeltaVdm = None):
        self.basevdm = basevdm
        self.deltavdm = deltavdm

    def delete_match(self, name: bytes):
        threats = Merger(self.basevdm, self.deltavdm).merge()
        deleter = DeleteIntervals(self, [])

        for threat in threats.match(name):
            print(f"      Deleting => {threat.name}")
            deleter.add(threat.interval)

        deleter.run()
        self.finallize_blob()

    def delete_threat(self, id: int = None, name: bytes = None):
        threat = self.merge().get(id, name)

        if threat:
            del_action = DeleteInterval(self, threat.interval)
            del_action.run()

        self.finallize_blob()

    def merge(self):
        return Merger(self.basevdm, self.deltavdm).merge()

    def normalize(self, actions: list[Action]):
        for i, new_action in enumerate(actions):
            if new_action.type and new_action.size < 6:
                current_offset = self.basevdm.signatures.tell()
                self.basevdm.signatures.seek(new_action.offset)
                data = self.basevdm.signatures.read(new_action.size)
                self.basevdm.signatures.seek(current_offset)
                actions[i] = CopyFromDelta(data)

    def export(self, path: str = None):
        self.basevdm.save(path)
        self.deltavdm.inc_version_build_number()
        self.deltavdm.save(path)

    def finallize_blob(self):
        merger = Merger(self)
        threats = merger.merge()

        self.deltavdm.blob.mergesize = threats.size()
        self.deltavdm.blob.mergecrc  = threats.crc32()
    
    @property
    def delta(self):
        return self.deltavdm
    
    @delta.setter
    def delta(self, delta: DeltaVdm):
        self.deltavdm = delta

    @property
    def base(self):
        return self.basevdm
    
    @base.setter
    def base(self, base: BaseVdm):
        self.basevdm = base