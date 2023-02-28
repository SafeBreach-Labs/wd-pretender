import struct
import binascii

from io import BytesIO

from ctypes import Structure
from ctypes import c_uint8, c_uint16, c_uint32
from collections.abc import Callable

from core.signatures import Signature
from core.utils import memcpy, setter

THREAT_TYPE = 0x5c

class Threat(Signature):
    class Header(Structure):
        _fields_ = [
            ("ThreatId", c_uint32),
            ("Unknown1", c_uint32),
            ("Unknown2", c_uint16),
            ("ThreatNameLength", c_uint16)
        ]

    def __init__(self, stype: c_uint8, slength: c_uint32, sdata: bytes):
        super().__init__(stype, slength, sdata)
        self.name = self.data.read(self.name_length)
        self.threat_stream = BytesIO()

    def handle(self, _stream: BytesIO, read_next_signature: Callable[[BytesIO], Signature]):
        while True:
            signature = read_next_signature(_stream)
            sig_data = signature.pack().getvalue()
            sig_length = len(sig_data)
            self.threat_stream.write(sig_data)
            self.position = (self.position[0], self.position[1] + sig_length)

            if signature.type == 0x5d:
                break

    def pack(self) -> BytesIO:
        packed_stream = BytesIO() 
        packed_stream.write(super().pack().getvalue())
        packed_stream.write(self.threat_stream.getvalue())
        return packed_stream
    
    @property
    def name_length(self):
        return self.header.ThreatNameLength

    @property
    def id(self):
        return self.header.ThreatId
    
    @property
    def size(self):
        data = self.pack()
        data.seek(0, 2)
        return data.tell()

    def __str__(self) -> str:
        return "[{}] ID: {} position: {}".format(self.name ,hex(self.header.ThreatId), hex(self.position[0]))  
