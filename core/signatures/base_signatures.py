from io import BytesIO

from core.signatures.threat import Threat, THREAT_TYPE
from core.signatures import Signatures

class BaseSignatures(Signatures):
    def __init__(self, signatures_stream: BytesIO) -> None:
        super().__init__(signatures_stream)

    def get_threat(self, id:int = None, name:str = None) -> Threat:
        for signature in self.values:
            if signature.type == THREAT_TYPE:
                if id:
                    if signature.id == id:
                        return signature
                elif name:
                    if signature.name == name:
                        return signature
        return None

    def get_threats_containing(self, name: bytes) -> Threat:
        for signature in self.values:
            if signature.type == THREAT_TYPE:
                if name.lower() in signature.name.lower():
                    yield signature

    @property
    def threats(self):
        return self.values