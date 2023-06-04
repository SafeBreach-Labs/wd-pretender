import io
import logging

from core.vdm import VDM
from core.signatures import Signature
from core.signatures.deltablob import Blob, CopyFromDelta

class DeltaVdm(VDM):
    def __init__(self, path: str):
        super().__init__(path)
        self._signatures = self.rmdx.signatures_stream
        self._signatures.seek(0)

        self._blob_rec_info = Signature.read_one(self._signatures)
        self._blob          = Signature.read_one(self._signatures)

    def pack(self) -> io.BytesIO:
        blob_rec_data = self._blob_rec_info.pack().getvalue()
        blob_data = self._blob.pack().getvalue()

        return io.BytesIO(blob_rec_data + blob_data)

    def insert_signature_as_action(self, signature: bytes):
        action = CopyFromDelta(signature)
        self._blob.push(action)

    @property
    def blob(self) -> Blob:
        return self._blob

    def inc_version_build_number(self):
        cur_version = self.version.split(b'.')
        
        # convert the build number to int and inc by 1
        build_number = int(cur_version[2])
        build_number = str(build_number + 1).encode()

        cur_version[2]  = build_number
        new_version     = b'.'.join(cur_version)

        logging.info(f"{self.basename}: {self.version.decode()} => {new_version.decode()}")

        self.version = new_version