import struct
import binascii 

from io import BytesIO
from ctypes import c_uint8, c_uint32
from collections.abc import Callable
from ctypes import Structure, pointer

from core.utils import memcpy, setter, compute_crc32

class Signature:
    class Header(Structure):
        _fields_ = []

    def __init__(self, stype: c_uint8, slength: c_uint32, data: bytes):
        self.type   = stype 
        self.length = slength
        self.data = BytesIO(data)
        self._pos = (-1, -1)

        self.header = self.Header()
        self._memcpy_header()
        
    def handle(self, signatures_stream: BytesIO, read_func: Callable[[BytesIO], object]):
        pass

    def parse(self):
        pass

    def pack(self) -> BytesIO:
        packed_stream = BytesIO()
        packed_stream.write(struct.pack("<I", (self.length << 8) + self.type))
        packed_stream.write(self.data.getvalue())
        packed_stream.seek(0)
        return packed_stream

    def fix_position(self, n: int):
        self.position = (self.position[0] + n, self.position[1] + n)

    @property
    def position(self) -> tuple:
        return self._pos
    
    @position.setter
    def position(self, position: tuple):
        self._pos = position

    def _header_setter(self, packed_value: bytes, offset: int):
        setter(self.data,
               packed_value,
               offset)
        self._memcpy_header()

    def _memcpy_header(self):
        memcpy(self.data,
               0,
               pointer(self.header),
               self.Header)

    def __str__(self) -> str:
        return "[{}]".format(hex(self.type))

class Signatures:
    def __init__(self, signatures_stream: BytesIO):
        self.signatures_stream = signatures_stream
    
    def tell(self):
        return self.signatures_stream.tell()

    def seek(self, offset: int):
        self.signatures_stream.seek(offset)

    def read(self, size: int = -1):
        return self.signatures_stream.read(size)

    def value(self):
        return self.signatures_stream.getvalue()
    
    def find(self, data: bytes) -> tuple:
        signatures_data = self.value()
        index = signatures_data.find(data)
        
        if index >= 0:
            return (index, index + len(data))
        
        return None

    def read_signature_from_stream(self, signature_stream: BytesIO) -> Signature:
        from core.signatures.types import SIG_TYPES

        start = signature_stream.tell()
        header_data = signature_stream.read(4)
        
        if not header_data:
            return None
        
        header_data, = struct.unpack("<I", header_data)

        stype   = header_data & 0xff 
        slength = header_data >> 8
        sdata   = signature_stream.read(slength)

        if stype in SIG_TYPES:
            signature = SIG_TYPES[stype](stype, slength, sdata)
        else:
            signature = Signature(stype, slength, sdata)

        end = signature_stream.tell()
        signature.position = (start, end)
        
        return signature

    @property
    def values(self):
        self.signatures_stream.seek(0)

        while True:
            signature = self.read_signature_from_stream(self.signatures_stream)

            if signature is None:
                break
                
            signature.handle(self.signatures_stream, self.read_signature_from_stream)
            yield signature
    
    @property
    def length(self):
        self.signatures_stream.seek(0, 2)
        return self.signatures_stream.tell()
    
    @property
    def crc32(self):
        self.signatures_stream.seek(0)
        return compute_crc32(self.signatures_stream)