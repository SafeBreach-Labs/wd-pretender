import struct

from io import BytesIO
from ctypes import c_uint8, c_uint16, c_uint32

from core.signatures import Signature
from core.utils.interval import Interval
from core.utils import compute_crc32

class ThreatBegin(Signature):
    TYPE = 0x5c
    def __init__(self,
                id: c_uint32 = 0,
                unknown1: c_uint16 = 0,
                counter: c_uint16 = 1,
                category: c_uint16 = 0,
                name: bytes = b'',
                unknown2: c_uint16 = 0,
                resources: list[c_uint16] = list(),
                sevirity_id: c_uint8 = 5,
                action: c_uint8 = 0x81,
                footer: bytes = b'\x24\x00\x04\x00'):
        self._id           = id
        self._unknown1     = unknown1
        self._counter      = counter
        self._category     = category
        self._name_length  = len(name)
        self._name         = name
        self._unknown2     = unknown2
        self._sevirity_id  = sevirity_id
        self._action       = action

        if resources:
            self._sections = resources
        else:
            self._sections = [0x4000]
        self._footer = footer
        
        _data = self._pack_data_bytes()

        super().__init__(_type=self.TYPE, _data=_data)

    def from_buffer(self, _data: bytes):
        super().from_buffer(_data)
        self._data.seek(0)

        self._id, \
        self._unknown1, \
        self._unknown2, \
        self._name_length = struct.unpack("<IIHH", self._data.read(12))
        
        self._name = self._data.read(self._name_length)
        self._footer = self._data.read()
    
    def inc_signature_counter(self):
        if self._sections[self._counter - 1] < 0x7fff:
            self._sections[self._counter - 1] += 1
        else:
            self._counter += 1
            self._sections.append(0x4001)

    @property
    def name(self):
        return self._name
    
    @name.setter
    def name(self, _name: bytes):
        self._name_length = len(_name)
        self._name = _name

    @property
    def id(self):
        return self._id
    
    @id.setter
    def id(self, _id: c_uint32):
        self._id = _id

    @property
    def unknown1(self):
        return self._unknown1
    
    @unknown1.setter
    def unknown1(self, _value: c_uint32):
        self._unknown1 = _value

    @property
    def unknown2(self):
        return self._unknown2

    @unknown2.setter
    def unknown2(self, _value: c_uint16):
        self._unknown2 = _value

    def _pack_data_bytes(self):
        first_header = struct.pack("<IHHHHH", self._id, self._unknown1, self._counter, self._category, len(self._name), self._unknown2)
        secend_header = struct.pack("H" * len(self._sections), *self._sections) + struct.pack("<BB", self._sevirity_id, self._action)

        return first_header + self._name + secend_header + self._footer
        
    def __str__(self) -> str:
        return "[{}] ID: {}".format(self.name ,hex(self.id))  

class ThreatEnd(Signature):
    TYPE = 0x5d
    def __init__(self, _id: c_uint32 = 0):
        self._id = _id
        _data = self._pack_data_bytes()
        super().__init__(self.TYPE, _data=_data)

    def from_buffer(self, _data: bytes):
        super().from_buffer(_data)
        self._data.seek(0)
        self._id, = struct.unpack("<I", self._data.read(4))

    @property
    def id(self):
        return self._id
    
    @id.setter
    def id(self, _id: c_uint32):
        self._id = _id 

    def _pack_data_bytes(self):
        return struct.pack("<I", self._id)
    
class Threat:
    def __init__(self,
                _threat_begin: ThreatBegin = ThreatBegin(),
                _threat_end: ThreatEnd = ThreatEnd()):
        self._threat_begin = _threat_begin
        self._threat_end   = _threat_end
        self._signatures   = BytesIO()

        self._interval = Interval(_threat_begin.interval.start, _threat_end.interval.end)

    def push(self, _signature: Signature):
        self._signatures.seek(0, 2)
        self._signatures.write(_signature.pack().getvalue())
        self._threat_begin.inc_signature_counter()
    
    def pop(self):
        self._signatures.seek(0)
        cur_sig = Signature.read_one(self._signatures)

        if cur_sig:
            self._signatures = BytesIO(self._signatures.read())

        return cur_sig

    def pack_bytes(self):
        return self._threat_begin.pack().getvalue() + self._signatures.getvalue() + self._threat_end.pack().getvalue()

    @staticmethod
    def read_one(_stream: BytesIO):
        _threat = Threat()
        _threat_begin  = Signature.read_one(_stream)

        if not _threat_begin or _threat_begin.type != ThreatBegin.TYPE:
            return None
        
        _threat.begin = _threat_begin        

        while True:
            _sig = Signature.read_one(_stream)
            
            if _sig.type == ThreatEnd.TYPE and _sig.id == _threat_begin.id:
                _threat.end = _sig
                break

            _threat.push(_sig)
        
        return _threat

    @property
    def signatures(self):
        self._signatures.seek(0)

        while True:
            _sig = Signature.read_one(self._signatures)
            
            if not _sig:
                break

            yield _sig

    @property
    def interval(self):
        return self._interval

    @interval.setter
    def interval(self, _interval):
        if isinstance(_interval, Interval):
            self._interval = _interval
        elif isinstance(_interval, tuple):
            self._interval = Interval(*_interval)

    @property
    def size(self):
        _threat_begin_size = self._threat_begin.size
        _signatures_size = len(self._signatures.getvalue())
        _threat_end_size = self._threat_end.size
        return _threat_begin_size + _signatures_size + _threat_end_size
    
    @property
    def name(self):
        return self._threat_begin.name
    
    @name.setter
    def name(self, _name: bytes):
        self._threat_begin.name = _name

    @property
    def id(self):
        return self._threat_begin.id
    
    @id.setter
    def id(self, _id: c_uint32):
        self._threat_begin.id = _id
        self._threat_end.id = _id

    @property
    def begin(self):
        return self._threat_begin

    @begin.setter
    def begin(self, _threat_begin: ThreatBegin):
        self._threat_begin = _threat_begin

    @property
    def end(self):
        return self._threat_end

    @end.setter
    def end(self, _threat_end: ThreatEnd):
        self._threat_end = _threat_end

class Threats:
    def __init__(self, _threats_stream: BytesIO = BytesIO()):
        self._threats = _threats_stream
    
    def add(self, _threat: Threat):
        self._threats.seek(0, 2)
        self._threats.write(_threat.pack_bytes())

    def match(self, _name: bytes) -> Threat:
        for _threat in self.__iter__():
            if _name.lower() in _threat.name.lower():
                yield _threat

    def get(self, _id: c_uint32 = None, _name: bytes = None) -> Threat:
        for _threat in self.__iter__():
            if _id:
                if _threat.id == _id:
                    return _threat
            elif _name:
                if _threat.name == _name:
                    return _threat
        return None
    
    def match(self, _name: bytes) -> Threat:
        for _threat in self.__iter__():
            if _name.lower() in _threat.name.lower():
                yield _threat

    def get_stream(self):
        return self._threats
    
    def pack(self) -> BytesIO:
        self._threats.seek(0)
        return self._threats
    
    def size(self):
        self._threats.seek(0, 2)
        return self._threats.tell()

    def crc32(self):
        self._threats.seek(0)
        return compute_crc32(self._threats)

    def __iter__(self):
        self._threats.seek(0)

        while True:
            start = self._threats.tell()
            _cur_threat = Threat.read_one(self._threats)
            end = self._threats.tell()

            if not _cur_threat: 
                break
            
            _cur_threat.interval = (start, end)
            yield _cur_threat
    