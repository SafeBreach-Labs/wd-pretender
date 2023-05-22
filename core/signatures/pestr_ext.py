import struct

from ctypes import c_uint16

from core.signatures import Signature

class HSTR_EXT():
    def __init__(self, _bytes: bytes):
        self._len = len(_bytes)
        self._bytes = _bytes

    def pack_bytes(self):
        return struct.pack("<BBBB", 1, 0, self._len, 1) + self._bytes

    @property
    def size(self):
        return len(self.pack_bytes() + self._bytes)

class PEHSTR_EXT(Signature):
    Type = 0x78
    def __init__(self,
                 _unknown1: c_uint16 = 0,
                 _unknown2: c_uint16 = 0,
                 _number_of_strs: c_uint16 = 0):
        self._unknown1 = _number_of_strs
        self._unknown2 = _number_of_strs
        self._unknown3 = 0
        self._number_of_strings = _number_of_strs
        self._values = []

        _data = self._pack_data_bytes()

        super().__init__(_type=self.Type, _data=_data)

    def push(self, _value: bytes):
        hstr = HSTR_EXT(_value)
        self._values.append(hstr)
        self._number_of_strings += 1
        self._unknown1 = self._number_of_strings
        self._unknown2 = self._number_of_strings
        self.length = self.length + hstr.size

    def _pack_data_bytes(self) -> bytes:
        _data = b''
        for s in self._values:
            _data += s.pack_bytes()

        return struct.pack("<HHHB", self._unknown1, self._unknown2, self._number_of_strings, self._unknown3) + _data