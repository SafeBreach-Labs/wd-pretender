import os
import shutil

from core.vdm import VDM
from core.signatures.threat import Threats

class BaseVdm(VDM):
    def __init__(self, path: str):
        super().__init__(path)
        self._signatures = self.rmdx.signatures_stream
        self._threats = Threats(self._signatures)

    def save(self, path=None):
        if path:
            outfile = os.path.join(path, os.path.basename(self.path))
            shutil.copy(self.path, outfile)

    @property
    def signatures(self):
        return self._signatures

    @property
    def threats(self):
        return self.signatures.values