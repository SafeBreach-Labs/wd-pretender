import struct

from io import BytesIO
from ctypes import c_uint16, c_uint32

from core.signatures import Signature
from core.utils.interval import Interval

class ThreatBegin(Signature):
    TYPE = 0x5c
    def __init__(self,
                _id: c_uint32 = 0,
                _unknown1: c_uint32 = 0,
                _unknown2: c_uint16 = 0,
                _name: bytes = b'',
                _footer: bytes = b'\x00\x00\x05\x40\x05\x82\x24\x00\x04\x00'):
        self._id          = _id
        self._unknown1    = _unknown1
        self._unknown2    = _unknown2
        self._name_length = len(_name)
        self._name        = _name
        self._footer      = _footer
        
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
        return struct.pack("<IIHI", 
                            self._id, 
                            self._unknown1,
                            self._unknown2,
                            self._name_length) + self._name + self._footer
        
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

        print(f"begin_size: {hex(_threat_begin_size)} + raw_size: {hex(_signatures_size)} + end_size: {hex(_threat_end_size)}")
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
                print(f'threat interval = {_threat.interval}')
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

    def pack(self) -> BytesIO:
        self._threats.seek(0)
        return self._threats
    
    def __iter__(self):
        self._threats.seek(0)

        while True:
            start = self._threats.tell()
            _cur_threat = Threat.read_one(self._threats)
            end = self._threats.tell()

            if not _cur_threat: 
                break
            
            _cur_threat.interval = (start, end)
            #print(f'__iter__:interval = {_cur_threat.interval}')
            yield _cur_threat
    