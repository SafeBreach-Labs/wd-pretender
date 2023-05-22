import io
import struct

from numpy import array
from ctypes import c_uint8, c_uint16, c_uint32

from core.utils import overlap
from core.signatures import Signature
from core.utils.interval import Interval

class Action:
    UNDEFINED = 0
    LEFT = 1
    RIGHT = 2
    def __init__(self,
                 _type: c_uint8 = 0,
                 _size: c_uint16 = 0,
                 _direction: c_uint8 = UNDEFINED):
        self._type = _type
        self._size = _size

        # interval within the delta blob stream
        self._interval = Interval()
        # interval within the merge signatres
        self._merge_interval = Interval()

        self._direction = _direction

    def slice(self, _interval: Interval):
        raise NotImplementedError
    
    def pack_bytes(self) -> bytes:
        raise NotImplementedError    
    
    @staticmethod
    def read_one(_stream: io.BytesIO):
        pos_start = _stream.tell()
        header = _stream.read(2)

        if not header:
            return None
        
        header, = struct.unpack("<H", header)
        _type = header >> 15
        
        if _type == CopyFromBase.Type:
            _size = (header & 0x7fff) + 6
            _offset, = struct.unpack("<I", _stream.read(4))
            action = CopyFromBase(_size, _offset)
        else:
            _size = header
            _data = _stream.read(_size)
            action = CopyFromDelta(_data)

        pos_end = _stream.tell()
        action.interval = (pos_start, pos_end)

        return action

    @property
    def interval(self) -> Interval:
        return self._interval
    
    @interval.setter
    def interval(self, _pos: tuple):
        self._interval = Interval(*_pos)

    @property
    def merge_interval(self) -> Interval:
        return self._merge_interval
    
    @merge_interval.setter
    def merge_interval(self, _pos: tuple):
        self._merge_interval = Interval(*_pos)

    @property
    def type(self):
        return self._type
    
    @type.setter
    def type(self, _type: c_uint8):
        self._type = _type

    @property
    def size(self):
        return self._size
    
    @size.setter
    def size(self, _size: c_uint16):
        self._size = _size

    def __str__(self) -> str:
        title = 'COPY_FROM_BASE' if self.type else 'COPY_FROM_DELTA'
        msg = f"[{title}] -> size: {hex(self.size)}, "
        return msg  

class CopyFromDelta(Action):
    Type = 0
    def __init__(self, data: bytes) -> None:
        super().__init__(self.Type, len(data))
        self.data = data

    def insert(self, index: int, data: bytes):
        if index == self.merge_interval.start:
            return [CopyFromDelta(data + self.data)]
        elif index == self.merge_interval.end:
            return [CopyFromDelta(self.data + data)]
        else:
            relative_index = index-self.merge_interval.start
            first = self.data[0: relative_index]
            last = self.data[relative_index:]
            return [CopyFromDelta(first + data + last)]

    def slice(self, _interval: Interval):
        new_actions = []
        sliced_data = b''

        if self.merge_interval.start < _interval.start:
            sliced_data += self.data[0: (_interval.start - self.merge_interval.start)]

        if self.merge_interval.end > _interval.end:
            sliced_data += self.data[_interval.end - self.merge_interval.start:]

        if sliced_data:
            new_action = CopyFromDelta(sliced_data)
            new_actions.append(new_action)

        return new_actions

    def pack_bytes(self):
        return struct.pack("<H", self.size) + self.data

    def __str__(self):
        return f'[CopyFromDelta] -> size: {hex(self._size)}, data: {self.data}' 

class CopyFromBase(Action):
    Type = 1
    def __init__(self, _size: c_uint16, _offset: c_uint32) -> None:
        super().__init__(self.Type, _size)
        self.offset = _offset

    def insert(self, index: int, data: bytes):
        if index == self.merge_interval.start:
            return [CopyFromDelta(data), CopyFromBase(self.size, self.offset)]
        elif index == self.merge_interval.end:
            return [CopyFromBase(self.size, self.offset), CopyFromDelta(data)]
        else:
            first_size = index - self.merge_interval.start
            last_size = self.merge_interval.end - index
            last_offset = self.offset + first_size

            first = CopyFromBase(first_size, self.offset)
            last = CopyFromBase(last_size, last_offset)
            return [first, CopyFromDelta(data), last]
        
    def slice(self, _interval: Interval):
        new_actions = []
        offset = self.offset
        delta = -self.size

        if self.merge_interval.start < _interval.start:
            cur_size = _interval.start - self.merge_interval.start
            delta += cur_size

            new_actions.append(CopyFromBase(cur_size, offset))
            offset += cur_size
            
        if self.merge_interval.end > _interval.end:
            cur_size = self.merge_interval.end - _interval.end
            offset += (_interval.end - _interval.start)
            delta += cur_size

            new_actions.append(CopyFromBase(cur_size, offset))
        
        return new_actions

    def pack_bytes(self):
        x = (self.size - 6) | 0x8000
        return struct.pack("<HI", x, self.offset)
    
    def __str__(self):
        return f'[CopyFromBase] -> size: {hex(self._size)}, offset: {hex(self.offset)}'       

class Blob(Signature):
    TYPE = 0x73
    def __init__(self,
                _mergesize: c_uint32 = 0,
                _mergecrc: c_uint32 = 0,
                _actions_data: bytes = b''):
        self._mergesize   = _mergesize
        self._mergecrc    = _mergecrc
        self._actios_data = io.BytesIO(_actions_data)

        _data = self._pack_data_bytes()

        super().__init__(_type=self.TYPE, _data=_data)
    
    def from_buffer(self, _data: bytes):
        super().from_buffer(_data)
        self._data.seek(0)

        self._mergesize, self._mergecrc = struct.unpack("<II", self._data.read(8))
        self._actios_data = io.BytesIO(self._data.read())

    def push(self, _action: Action):
        new_stream = io.BytesIO()

        _action_data = _action.pack_bytes()
        _action_size = len(_action_data)

        new_stream.write(_action_data)
        new_stream.write(self._actios_data.getvalue())
        self._actios_data = new_stream

        self.length = self.length + _action_size

    def pop(self):
        pass
    
    def replace(self, _old_actions: list[Action], _new_actions: list[Action]):
        self._actios_data.seek(0)

        _remove_interval = Interval(_old_actions[0].interval.start, _old_actions[-1].interval.end)
        
        new_stream = io.BytesIO()
        new_stream.write(self._actios_data.read(_remove_interval.start))

        for _action in _new_actions:
            action_data = _action.pack_bytes()
            new_stream.write(action_data)

        self._actios_data.seek(_remove_interval.end)
        new_stream.write(self._actios_data.read())
        
        self._actios_data = new_stream
        self.length = len(self._pack_data_bytes())

    @property
    def actions(self):
        self._actios_data.seek(0)
        
        while True:
            action = Action.read_one(self._actios_data)
           
            if action is None:
                break

            yield action

    @property
    def mergesize(self):
        return self._mergesize
    
    @mergesize.setter
    def mergesize(self, _size: c_uint32):
        self._mergesize = _size
    
    @property
    def mergecrc(self):
        return self._mergecrc
    
    @mergecrc.setter
    def mergecrc(self, _crc: c_uint32):
        self._mergecrc = _crc

    def _pack_data_bytes(self) -> bytes:
        return struct.pack("<II", self._mergesize, self._mergecrc) + self._actios_data.getvalue()

 