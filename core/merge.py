import io

from core.signatures import DeltaBlob, BaseSignatures
from core.vdm import DeltaVdm, BaseVdm

class SignatureMerger:
    @staticmethod
    def do_merge(base: BaseVdm, delta: DeltaVdm) -> BaseSignatures:
        merge_stream = io.BytesIO()

        blob = delta.signatures.find(DeltaBlob.Type)
        bstream  = base.signatures.stream

        for action in blob.actions:
            if action.type == DeltaBlob.Action.Types.COPY_FROM_BASE.value:
                bstream.seek(action.offset)
                data = bstream.read(action.size)
                merge_stream.write(data)
            else:
                merge_stream.write(action.data)
        
        merge_stream.seek(0)
        return BaseSignatures(merge_stream)
