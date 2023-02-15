import io

from core.signatures import DeltaBlob, BlobAction, SigsContainer

class SignatureMerger:
    def __init__(self, base_container: SigsContainer, blob: DeltaBlob) -> None:
        self.base = base_container
        self.blob = blob

    def do_merge(self) -> SigsContainer:
        merge_stream = io.BytesIO()
        base_stream  = self.base.stream

        for action in self.blob.actions:
            if action.type == BlobAction.Types.COPY_FROM_BASE:
                base_stream.seek(action.data)
                data = base_stream.read(action.size)
                merge_stream.write(data)
            else:
                merge_stream.write(action.data)
        
        merge_stream.seek(0)
        return SigsContainer(merge_stream)
