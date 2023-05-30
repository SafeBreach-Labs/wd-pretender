import io

from core.vdm.pair import Pair
from core.signatures.threat import Threats
from core.signatures.deltablob import Action
from core.signatures.deltablob import CopyFromBase

class Merger:
    def __init__(self, pair: Pair):
        self.pair = pair

    def yield_merge(self) -> Action:
        merge_stream = io.BytesIO()
        basesigs = self.pair.base.signatures

        for action in self.pair.delta.blob.actions:
            start = merge_stream.tell()

            if action.type == CopyFromBase.Type:
                basesigs.seek(action.offset)
                data = basesigs.read(action.size)
                merge_stream.write(data)
            else:
                merge_stream.write(action.data)
            
            end = merge_stream.tell()

            action.merge_interval = (start, end)

            yield action
        
    def merge(self):
        merge_stream = io.BytesIO()
        basesigs = self.pair.base.signatures

        for action in self.pair.delta.blob.actions:
            if action.type == CopyFromBase.Type:
                basesigs.seek(action.offset)
                data = basesigs.read(action.size)
                merge_stream.write(data)
            else:
                merge_stream.write(action.data)
        
        return Threats(merge_stream)
    
    