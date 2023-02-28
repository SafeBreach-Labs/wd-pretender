from io import BytesIO

from core.signatures.deltablob import DELTA_BLOB_TYPE
from core.signatures.deltablob import DeltaBlob
from core.signatures import Signatures

class DeltaSignatures(Signatures):
    def __init__(self, signatures_stream: BytesIO) -> None:
        super().__init__(signatures_stream)

    def set_delta_blob(self, blob_stream: BytesIO):
        new_stream = BytesIO()
        
        for signature in self.values:
            if signature.type != DELTA_BLOB_TYPE:
                new_stream.write(signature.pack().getvalue())
            else:
                new_stream.write(blob_stream.getvalue())

        self.signatures_stream = new_stream
        
    def get_delta_blob(self) -> DeltaBlob:
        for signature in self.values:
            if signature.type == DELTA_BLOB_TYPE:
                return signature
        
        return None
            