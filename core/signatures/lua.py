import struct

from typing import Union
from ctypes import c_uint8

from core.signatures import Signature

class LUAStandAlone(Signature):
    Type = 0xbd
    def __init__(self, name: Union[bytes, str] = ''):
        self.u1 = 0
        self.u2 = 0
        
        self.compiled_lua = b''
        self.name = name
        
        _data = self._pack_data_bytes()
        super().__init__(self.Type, _data=_data)
    
    def from_buffer(self, _data: bytes):
        super().from_buffer(_data)
        self._data.seek(0)

        name_size, u1, u2, c_lua_size = struct.unpack("<BBHI", self._data.read(8))
        
        if name_size:
            self.name = self._data.read(name_size)

        self._data.seek(c_lua_size, 2)
        self.compiled_lua = self._data.read(c_lua_size)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name: Union[bytes, str]):
        if isinstance(name, bytes):
            self._name = name.split(b'\x00', 1)[0].decode()
        elif isinstance(name, str):
            self._name = name
        else:
            raise Exception("Must be bytes | str")

    def _pack_data_bytes(self):
        name_size = len(self.name) + 1
        compiled_lua_size = len(self.compiled_lua)
        header = struct.pack("<BBHI", name_size, self.u1, self.u2, compiled_lua_size)
        lua_name = self.name.encode() + b'\x00'
        
        return header + lua_name + self.compiled_lua
    
    def __str__(self) -> str:
        return f'{[self.name]}, interval: {self.interval.__str__()}'