import struct

from io import BytesIO
from ctypes import c_uint16, c_uint32

from core.signatures import Signature
from core.utils.interval import Interval


class HStr:
    def __init__(self, _str: str = ''):        
        self._str = _str
        self._length = len(_str)

    def pack_bytes(self):
        return struct.pack("<HB", 0x1, self._length) + self._str.encode()

    @property
    def size(self):
        return len(self.pack_bytes())

    @property
    def value(self):
        return self._str
    
    @value.setter
    def value(self, _str: str):
        self._str = _str
        self._length = len(_str)

class PEHStr(Signature):
    Type = 0x61
    def __init__(self, _n_strings: c_uint16 = 0):
        self._unknown1 = 1 
        self._unknown2 = 1 
        self._number_of_strings = _n_strings
        self._unknown3 = 0
        self._values = []

        _data = self._pack_data_bytes()

        super().__init__(_type=self.Type, _data=_data)

    def push(self, _value: str):
        hstr = HStr(_value)
        self._values.append(hstr)
        self._number_of_strings += 1
        self.length = self.length + hstr.size

    def _pack_data_bytes(self) -> bytes:
        _data = b''
        for s in self._values:
            _data += s.pack_bytes()

        return struct.pack("<HHHB", self._unknown1, self._unknown2, self._number_of_strings, self._unknown3) + _data
        