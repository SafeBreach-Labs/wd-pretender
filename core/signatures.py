import io
import enum
import ctypes
import struct

class BlobAction:
    Types = enum.Enum('Types', {('COPY_FROM_DELTA', 0), ('COPY_FROM_BASE', 1)})

    def __init__(self, action_header: bytes):
        header, = struct.unpack("<H", action_header)
        
        if header >> 15:
            self.type = self.Types.COPY_FROM_BASE
            self.size = (header & 0x7fff) + 6
        else:
            self.type = self.Types.COPY_FROM_DELTA
            self.size = header

    def set_data(self, data):
        self.data = data 

class Signature:
    def __init__(self, stype: ctypes.c_uint8, slength: ctypes.c_uint32, sdata: bytes):
        self.type   = stype 
        self.length = slength
        self.data = sdata

    def pack(self) -> bytes:
        header = struct.pack("<I", (self.length << 8) + self.type)
        return header + self.data
    
    def parse(self):
        pass

class DeltaBlob(Signature):
    class HeaderStruct(ctypes.Structure):
        _fields_ = [
            ("MergeSize", ctypes.c_uint32),
            ("MergeCrc", ctypes.c_uint32)
        ]

    def __init__(self, stype: ctypes.c_uint8, slength: ctypes.c_uint32, sdata: bytes):
        super().__init__(stype, slength, sdata)
        self.header = None
        self.actions = []
        self.parse()
    
    @property
    def mrgsize(self) -> ctypes.c_uint32:
        return self.header.contents.MergeSize
    
    @mrgsize.setter
    def mrgsize(self, size: ctypes.c_uint32):
        self.header.contents.MergeSize = size
    
    @property
    def mrgcrc(self) -> ctypes.c_uint32:
        return self.header.contents.MergeCrc
    
    @mrgcrc.setter
    def mrgcrc(self, crc: ctypes.c_uint32):
        self.header.contents.MergeCrc = crc
    
    def parse(self):
        self.header = ctypes.cast(self.data, ctypes.POINTER(DeltaBlob.HeaderStruct))
        blob_stream = io.BytesIO(self.data[8:])
        
        while True:
            action_header = blob_stream.read(2)
            
            if not action_header:
                break

            blob_action = BlobAction(action_header)
            
            if blob_action.type == BlobAction.Types.COPY_FROM_DELTA:
                data = blob_stream.read(blob_action.size)
            else: 
                # the data here is acutlly the offset to copy from original base
                data, = struct.unpack("<I", blob_stream.read(4))

            blob_action.set_data(data)
            self.actions.append(blob_action)

SIG_TYPES = {
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
    def length(self) -> ctypes.c_uint32:
        self._stream.seek(0, 2)
        return self._stream.tell()

    def parse(self):
        signatures_stream = self.stream
        
        while True:
            curr_signature = self.__read_signature_from_stream(signatures_stream)
            
            if curr_signature is None:
                break

            self.signatures.append(curr_signature)

    def pack(self) -> bytes:
        packed_bytes = b''

        for signature in self.signatures:
            packed_bytes += signature.pack()

        return packed_bytes

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

class Delta(Signatures):
    def __init__(self, stream: io.BytesIO) -> None:
        super().__init__(stream)
        self.parse()

    def do_extract_blob(self) -> DeltaBlob:
        blob = None

        for signature in self.signatures:
            if signature.type == 0x73:
                blob = signature
                break

        return blob
        