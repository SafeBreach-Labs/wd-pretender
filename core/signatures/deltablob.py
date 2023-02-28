import io
import struct
import binascii

from collections.abc import Sequence
from ctypes import Structure, sizeof, memmove, pointer
from ctypes import c_uint8, c_uint16, c_uint32

from core.utils import overlap, memcpy, setter
from core.signatures import Signature

DELTA_BLOB_TYPE = 0x73

COPY_FROM_BASE = 1
COPY_FROM_DELTA = 0

class Action:
    def __init__(self, type: c_uint8, size: c_uint16) -> None:
        self.type = type
        self.size = size
        self.data = b''
        self.offset = -1
        self.action_pos = (0, 0)
        self.merge_pos = (0, 0)

    def merge_overlap(self, pos: tuple) -> bool:
        return overlap(pos, self.merge_pos)

    def action_overlap(self, pos: tuple) -> bool:
        return overlap(pos, self.action_pos)

    def set_action_position(self, pos: tuple):
        self.action_pos = pos

    def set_merge_position(self, pos: tuple):
        self.merge_pos = pos

    def slice_range(self, position: tuple) -> tuple:
        raise NotImplementedError

    def fix_position(self, reminder: int):
        self.action_pos = (self.action_pos[0] + reminder, self.action_pos[1] + reminder)
    
    def fix_merge_position(self, value):
        self.merge_pos = (self.merge_start + value, self.merge_end + value)

    def pack_bytes(self) -> bytes:
        raise NotImplementedError    
    
    @property
    def merge_start(self):
        return self.merge_pos[0]

    @property
    def merge_end(self):
        return self.merge_pos[1]
    
    @property
    def action_start(self):
        return self.action_pos[0]

    @property
    def action_end(self):
        return self.action_pos[1]

    def __str__(self) -> str:
        title = 'COPY_FROM_BASE' if self.type else 'COPY_FROM_DELTA'
        msg = f"[{title}] -> size: {hex(self.size)}, "
        
        if self.type:
            msg += f"offset: {hex(self.offset)}, "
        else:
            msg += f"data: {self.data}, "
    
        msg += f"merge_range: ({hex(self.merge_start)}, {hex(self.merge_end)})"

        return msg  

class CopyFromDelta(Action):
    def __init__(self, data: bytes) -> None:
        super().__init__(COPY_FROM_DELTA, len(data))
        self.data = data

    def slice_range(self, _range: tuple) -> Sequence:
        new_actions = []
        delta = -self.size
        sliced_data = b''

        if self.merge_start < _range[0]:
            sliced_data += self.data[0: (_range[0] - self.merge_start)]

        if self.merge_end > _range[1]:
            sliced_data += self.data[_range[1] - self.merge_start:]

        if sliced_data:
            delta += len(sliced_data)
            new_action = CopyFromDelta(sliced_data)
            new_action.set_merge_position((self.merge_start, self.merge_end + delta))
            new_actions.append(new_action)

        return (new_actions, delta)

    def pack_bytes(self):
        return struct.pack("<H", self.size) + self.data

class CopyFromBase(Action):
    def __init__(self, type: c_uint8, size: c_uint16, offset: c_uint32) -> None:
        super().__init__(type, size)
        self.offset = offset

    def pack_bytes(self):
        x = (self.size - 6) | 0x8000
        return struct.pack("<HI", x, self.offset)
    
    def slice_range(self, _range: tuple) -> Sequence:
        new_actions = []
        offset = self.offset
        delta = -self.size

        if self.merge_start < _range[0]:
            cur_size = _range[0] - self.merge_start
            delta += cur_size

            new_action = CopyFromBase(self.type, cur_size, offset)
            new_action.set_merge_position((self.merge_start, self.merge_end + delta))
            new_actions.append(new_action)
            offset += cur_size
            
        if self.merge_end > _range[1]:
            cur_size = self.merge_end - _range[1]
            offset += (_range[1] - _range[0])
            cur_start = self.merge_end + delta
            delta += cur_size

            new_action = CopyFromBase(self.type, cur_size, offset)
            new_action.set_merge_position((cur_start, cur_start + cur_size))

            new_actions.append(new_action)
        
        return (new_actions, delta)

class DeltaBlob(Signature):
    class Header(Structure):
        _fields_ = [
            ("MergeSize", c_uint32),
            ("MergeCrc", c_uint32)
        ]

    def __init__(self, stype: c_uint8, slength: c_uint32, sdata: bytes):
        super().__init__(stype, slength, sdata)
    
    def pack(self) -> io.BytesIO:
        return super().pack()

    def set_actions(self, action_stream: io.BytesIO):
        self.data = action_stream

    def replace(self, action: Action, with_actions: Sequence[Action]):
        self.data.seek(0)
        
        new_stream = io.BytesIO()
        new_stream.write(self.data.read(8))
        new_stream.write(self.data.read(action.action_start - 8))

        new_actions_length = 0

        for i in with_actions:
            action_data = i.pack_bytes()
            new_actions_length += len(action_data)
            new_stream.write(action_data)

        self.data.seek(action.action_end)
        new_stream.write(self.data.read())
        
        new_stream.seek(0)
        self.set_actions(new_stream)

        data = self.data.getvalue()
        self.length = len(data)
        
        return new_actions_length - action.action_end + action.action_start

    @property
    def actions(self):
        self.data.seek(8)

        while True:
            action = self.__read_next_action()

            if action is None:
                break

            yield action

    @property
    def mrgsize(self) -> c_uint32:
        return self.header.MergeSize
    
    @mrgsize.setter
    def mrgsize(self, size: c_uint32):
        packed_value = struct.pack("<I", size)
        self._header_setter(packed_value, DeltaBlob.Header.MergeSize.offset)
        self._memcpy_header()
    
    @property
    def mrgcrc(self) -> c_uint32:
        return self.header.MergeCrc
    
    @mrgcrc.setter
    def mrgcrc(self, crc: c_uint32):
        packed_value = struct.pack("<I", crc)
        self._header_setter(packed_value, DeltaBlob.Header.MergeCrc.offset)
        self._memcpy_header()

    def __read_next_action(self):
        pos_start = self.data.tell()
        header = self.data.read(2)

        if not header:
            return None
        
        header, = struct.unpack("<H", header)
        _type = header >> 15
        
        if _type == COPY_FROM_BASE:
            _size = (header & 0x7fff) + 6
            _offset, = struct.unpack("<I", self.data.read(4))
            action = CopyFromBase(_type, _size, _offset)
        else:
            _size = header
            _data = self.data.read(_size)
            action = CopyFromDelta(_data)

        pos_end = self.data.tell()
        action.set_action_position((pos_start, pos_end))

        return action

 