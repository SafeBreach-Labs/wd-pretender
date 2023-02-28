import io

from core.signatures.base_signatures import BaseSignatures
from core.signatures.deltablob import COPY_FROM_BASE
from core.vdm import BaseVdm, DeltaVdm

class Merger:
    def __init__(self, basevdm: BaseVdm, deltavdm: DeltaVdm):
        self.basevdm = basevdm
        self.deltavdm = deltavdm

    def yield_merge(self):
        merge_stream = io.BytesIO()
        basesigs = self.basevdm.signatures

        for action in self.deltavdm.get_actions():
            start = merge_stream.tell()

            if action.type == COPY_FROM_BASE:
                basesigs.seek(action.offset)
                data = basesigs.read(action.size)
                merge_stream.write(data)
            else:
                merge_stream.write(action.data)
            
            end = merge_stream.tell()

            action.set_merge_position((start, end))

            yield action
        
    def merge(self):
        merge_stream = io.BytesIO()
        basesigs = self.basevdm.signatures

        for action in self.deltavdm.get_actions():
            if action.type == COPY_FROM_BASE:
                basesigs.seek(action.offset)
                data = basesigs.read(action.size)
                merge_stream.write(data)
            else:
                merge_stream.write(action.data)
        
        return BaseSignatures(merge_stream)
    
    