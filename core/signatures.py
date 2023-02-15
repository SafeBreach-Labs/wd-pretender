import io
import enum
import ctypes
import struct

class SignatureHeader(ctypes.Structure):
    _fields_ = [
        ("Type", ctypes.c_uint32, 8),
        ("Length", ctypes.c_uint32, 24)
    ]

class SignatureDeltaBlobRecInfoHeader(ctypes.Structure):
    _fields_ = [
        ("Unknown", ctypes.c_uint32 * 19)
    ]

class SignatureDeltaBlobHeader(ctypes.Structure):
    _fields_ = [
        ("MergeSize", ctypes.c_uint32),
        ("MergeCrc", ctypes.c_uint32),
    ]

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

class DeltaBlob:
    def __init__(self, blob_stream: io.BytesIO):
        self.actions = []

        while True:
            action_header = blob_stream.read(2)
            
            if not action_header:
                break

            blob_action = BlobAction(action_header)
            
            if blob_action.type == BlobAction.Types.COPY_FROM_DELTA:
                data = blob_stream.read(blob_action.size)
            else: 
                # the data here is acutlly the offset to copy from original base
                data, = struct.unpack("<I", blob_action.read(4))

            blob_action.set_data(data)
            self.actions.append(blob_action)

SIG_TYPES = {
    0x73: SignatureDeltaBlobHeader,
    0x74: SignatureDeltaBlobRecInfoHeader
}

class Signature:
    def __init__(self, header_data: bytes):
        header_data, = struct.unpack("<I", header_data)

        self.header        = SignatureHeader()
        self.header.Type   = header_data & 0xff 
        self.header.Length = header_data >> 8

        self.internal_header = None
        
    def finalize(self, data: bytes):
        self.__do_parse_internal_signature(data)

    def __do_parse_internal_signature(self, signature_inner_data):
        if self.header.Type in SIG_TYPES:
            self.internal_header = SIG_TYPES[self.header.Type]()

            ctypes.memmove(ctypes.pointer(self.internal_header),
                           signature_inner_data,
                           ctypes.sizeof(self.internal_header))

            self.internal_data = signature_inner_data[ctypes.sizeof(self.internal_header):]
        else:
            self.internal_data = signature_inner_data

class SigsContainer:
    def __init__(self, signatures_stream: io.BytesIO) -> None:
        self.signatures = []

        while True:
            header_data = signatures_stream.read(4)

            if not header_data:
                break
            
            current_signature = Signature(header_data)
            signature_data = signatures_stream.read(current_signature.header.Length)
            current_signature.finalize(signature_data)

            self.signatures.append(current_signature)        

    def __iter__(self):
        return self.signatures.__iter__()
