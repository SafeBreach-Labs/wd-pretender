import io
import enum
import struct

from ctypes import c_uint8, c_uint16, c_uint32
from ctypes import Structure, pointer, sizeof, memmove

class Signature:
    def __init__(self, stype: c_uint8, slength: c_uint32, sdata: bytes):
        self.type   = stype 
        self.length = slength
        self.data = sdata
        self.parse()

    def pack(self) -> bytes:
        header = struct.pack("<I", (self.length << 8) + self.type)
        return header + self.data
    
    def parse(self):
        pass

    def __str__(self) -> str:
        return "[{}]".format(self.type)

class DeltaBlob(Signature):
    Type = 0x73
    class HeaderStruct(Structure):
        _fields_ = [
            ("MergeSize", c_uint32),
            ("MergeCrc", c_uint32)
        ]

    class Action:
        Types = enum.Enum('Types', {('COPY_FROM_DELTA', 0), ('COPY_FROM_BASE', 1)})

        def __init__(self, type: c_uint8, size: c_uint16) -> None:
            self.type = type
            self.size = size
    
    class CopyFromDelta(Action):
        def __init__(self, type: c_uint8, size: c_uint16, data: bytes) -> None:
            super().__init__(type, size)
            self.data = data
    
    class CopyFromBase(Action):
        def __init__(self, type: c_uint8, size: c_uint16, offset: c_uint32) -> None:
            super().__init__(type, size)
            self.offset = offset

    def __init__(self, stype: c_uint8, slength: c_uint32, sdata: bytes):
        self.header = DeltaBlob.HeaderStruct()
        self.header_size = sizeof(self.header)
        self.actions = []
        super().__init__(stype, slength, sdata)
        
    @property
    def mrgsize(self) -> c_uint32:
        return self.header.MergeSize
    
    @mrgsize.setter
    def mrgsize(self, size: c_uint32):
        self.header.MergeSize = size
    
    @property
    def mrgcrc(self) -> c_uint32:
        return self.header.MergeCrc
    
    @mrgcrc.setter
    def mrgcrc(self, crc: c_uint32):
        self.header.MergeCrc = crc
    
    def parse(self):
        memmove(pointer(self.header), self.data, self.header_size)
        
        blob_stream = io.BytesIO(self.data[self.header_size:])
        
        while True:
            action = self.__read_blob_action(blob_stream)

            if action is None:
                break

            self.actions.append(action)

    def __read_blob_action(self, stream: io.BytesIO):
        header = stream.read(2)

        if not header:
            return None
        
        header, = struct.unpack("<H", header)
        _type = header >> 15
        
        if _type == DeltaBlob.Action.Types.COPY_FROM_BASE.value:
            _size = (header & 0x7fff) + 6
            _offset, = struct.unpack("<I", stream.read(4))
            action = DeltaBlob.CopyFromBase(_type, _size, _offset)
        else:
            _size = header
            _data = stream.read(_size)
            action = DeltaBlob.CopyFromDelta(_type, _size, _data)

        return action

class Threat(Signature):
    Type = 0x5c

    class HeaderStruct(Structure):
        _pack_ = 1
        _fields_ = [
            ("ThreatId", c_uint32),
            ("Unknown1", c_uint32),
            ("SignaturesCount", c_uint16),
            ("ThreatNameLength", c_uint16)
        ]

    def __init__(self, stype: c_uint8, slength: c_uint32, sdata: bytes):
        self.header = Threat.HeaderStruct()
        self.header_size = sizeof(self.header)
        self.name = None
        super().__init__(stype, slength, sdata)

    def parse(self):
        memmove(pointer(self.header), self.data, self.header_size)
        
        self.name = self.data[self.header_size: self.header_size + self.header.ThreatNameLength]
        
        if b':' not in self.name:
            self.category, = struct.unpack("<H", self.name[:2])
            self.name = self.name[2:]


    def __str__(self) -> str:
        return "[{}] ID: {}, Signatures Inside: {}".format(self.name ,hex(self.header.ThreatId), self.header.SignaturesCount)  

SIG_TYPES = {
    0x5c: Threat,
    0x73: DeltaBlob
}

class Signatures:
    def __init__(self, stream: io.BytesIO) -> None:
        self._stream = stream
        self.signatures = []

    @property
    def stream(self) -> io.BytesIO:
        self._stream.seek(0)
        return self._stream

    @property
    def length(self) -> c_uint32:
        self._stream.seek(0, 2)
        return self._stream.tell()

    def parse(self):
        signatures_stream = self.stream
        
        while True:
            curr_signature = self.__read_signature_from_stream(signatures_stream)
            
            if curr_signature is None:
                break
            
            self.handle_signature(curr_signature)
            self.signatures.append(curr_signature)

    def pack(self) -> bytes:
        packed_bytes = b''

        for signature in self.signatures:
            packed_bytes += signature.pack()

        return packed_bytes

    def find(self, sigid: c_uint8) -> Signature:
        _signature = None

        for signature in self.signatures:
            if signature.type == sigid:
                _signature = signature
                break

        return _signature

    def handle_signature(self, signature: Signature):
        pass
    
    def __read_signature_from_stream(self, stream: io.BytesIO) -> Signature:
        header_data = stream.read(4)
        
        if not header_data:
            return None
        
        header_data, = struct.unpack("<I", header_data)

        stype   = header_data & 0xff 
        slength = header_data >> 8
        sdata   = stream.read(slength)

        if stype in SIG_TYPES:
            signature = SIG_TYPES[stype](stype, slength, sdata)
        else:
            signature = Signature(stype, slength, sdata)

        return signature

    def __iter__(self):
        return self.signatures.__iter__()

class DeltaSignatures(Signatures):
    def __init__(self, stream: io.BytesIO) -> None:
        super().__init__(stream)
        self.parse()

class BaseSignatures(Signatures):
    def __init__(self, stream: io.BytesIO) -> None:
        super().__init__(stream)
        self.threats = []

    def handle_signature(self, signature: Signature):
        if signature.type == 0x5c:
            self.threats.append(signature)