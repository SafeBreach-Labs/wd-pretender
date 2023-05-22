import struct

from io import BytesIO
from ctypes import c_uint8, c_uint32

from core.utils.interval import Interval

class Signature:
    def __init__(self, _type: c_uint8 = 0, _data: bytes = b''):
        self._type   = _type
        self._length = len(_data)

        # data doesn't contain the signature header (type, length)
        self._data = BytesIO(_data)
        
        # interval within the data stream 2-dim vector
        self._interval = Interval()
    
    def from_buffer(self, _data: bytes):
        self.data = _data
    
    def pack(self) -> BytesIO:
        packed_stream = BytesIO()
        packed_stream.write(self.__pack_header_bytes())
        packed_stream.write(self._pack_data_bytes())
        return packed_stream

    @staticmethod
    def read_one(_stream: BytesIO):
        from core.signatures.types import SIG_TYPES

        start = _stream.tell()
        header_data = _stream.read(4)
        
        if not header_data:
            return None
        
        header_data, = struct.unpack("<I", header_data)

        stype   = header_data & 0xff 
        slength = header_data >> 8
        sdata   = _stream.read(slength)
   
        if stype in SIG_TYPES:
            signature = SIG_TYPES[stype]()
        else:
            signature = Signature()
            signature.type = stype

        signature.length = slength
        signature.from_buffer(sdata)

        end = _stream.tell()
        signature.interval = (start, end)
        
        return signature

    @property
    def size(self):
        return len(self.data) + 4

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, _type: c_uint8):
        self._type = _type

    @property
    def length(self):
        return self._length
    
    @length.setter
    def length(self, _length: c_uint32):
        self._length = _length

    @property
    def data(self):
        return self._data.getvalue()
    
    @data.setter
    def data(self, _data: bytes):
        self._data = BytesIO(_data)

    @property
    def interval(self) -> Interval:
        return self._interval
    
    @interval.setter
    def interval(self, _interval: tuple):
        self._interval = Interval(*_interval)

    def _pack_data_bytes(self) -> bytes:
        return self.data

    def __pack_header_bytes(self):
        return struct.pack("<I", (self.length << 8) + self.type)

    def __str__(self) -> str:
        return "[{}]".format(hex(self.type))
