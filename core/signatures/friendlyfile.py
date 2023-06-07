import binascii

from core.signatures import Signature

class FriendlyFile_SHA256(Signature):
    Type = 0xa0
    def __init__(self, sha256_hash: bytes = None):
        self._hash = sha256_hash
        _data = self._pack_data_bytes()
        super().__init__(_type=self.Type, _data=_data)

    def _pack_data_bytes(self) -> bytes:
        return binascii.unhexlify(self._hash)
        