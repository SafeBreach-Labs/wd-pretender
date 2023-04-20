import logging

from dual.add import AddThreat
from dual.delete import DeleteInterval, DeleteIntervals
from dual.modify import ModifyInterval

from core.merge import Merger
from core.vdm import BaseVdm, DeltaVdm
from core.utils.interval import Interval

from core.signatures import Signature
from core.signatures.deltablob import Action, CopyFromDelta
from core.signatures.threat import Threat, ThreatBegin, ThreatEnd

class VdmPair:
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
        
        begin = ThreatBegin(id=0x133, category=34, name=b"Safebreach.DOS", footer=b'\x70\x00\x04\x00')
        end = ThreatEnd(_id=0x133)
        dos_threat = Threat()
        dos_threat.begin = begin
        dos_threat.end = end

        dos_hstr = Signature(0x78, b'\x01\x00\x01\x00\x01\x00\x00\x01\x00\x27\x01!This program cannot be run in DOS mode\x00\x00')
        
        dos_threat.push(dos_hstr)
       
        AddThreat(self, dos_threat).run()
        self.finallize_blob()

    def delete_test(self):
        threats = Merger(self.basevdm, self.deltavdm).merge()
        stream = threats.get_stream()
        stream.seek(0)
        target = None

        deleter = DeleteIntervals(self, [])

        while True:
            signature = Signature.read_one(stream)

            if not signature:
                break
            
            if signature.type == 0xbd:#0x96:
                if signature.name in ['LuaFuncHelper', 'TechniqueTracker', 'BMLuaLib']:
                    continue
                logging.info(signature.__str__())
                deleter.add(signature.interval)
        
        deleter.run()
        self.finallize_blob()

        # if target:
        #     logging.info("Starting modification ...")
        #     new_data = b'\x96\x2a\x00\x00\x00\x00\x26\x00\x53\x49\x47\x41\x54\x54\x52\x3a\x4d\x6f\x6e\x69\x74\x6f\x72\x69\x6e\x67\x54\x6f\x6f\x6c\x3a\x57\x69\x6e\x33\x32\x2f\x41\x63\x74\x75\x61\x6c\x53\x78\x78'
        #     logging.info(new_data)
        #     ModifyInterval(self, signature.interval, new_data).run()
        #     self.finallize_blob()
        
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
            
            ModifyInterval(self, brute_interval, b'\x83\x59\x00\x04\x00\x29\x11\x00\x00\x00\x00\x00\xff\xff\xff\xff\x06\x00\x00\x00\x3f\x78\x6d\x6c\x90\x00').run()
            
        self.finallize_blob()

    def delete_match(self, name: bytes):
        threats = Merger(self.basevdm, self.deltavdm).merge()
        deleter = DeleteIntervals(self, [])

        for threat in threats.match(name):
            print(f"      Deleting -> {threat.name}")
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