import io
import enum
import ctypes
import struct

from core.utils import compute_crc32


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
    def __init__(self, blob_data: bytes):
        self.actions = []
        self.merge_size, self.merge_crc = struct.unpack("<II", blob_data[:8])
        self._blob = io.BytesIO(blob_data[8:])

    @property
    def blob(self):
        self._blob.seek(0)
        return self._blob

    def parse(self):
        blob_stream = self.blob

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

class Signature:
    def __init__(self, header_data: bytes):
        header_data, = struct.unpack("<I", header_data)

        self.type   = header_data & 0xff 
        self.length = header_data >> 8
        
    def finalize(self, data: bytes):
        self.__do_parse_internal_signature(data)

    def __do_parse_internal_signature(self, signature_inner_data):
        if self.type in SIG_TYPES:
            self.data = SIG_TYPES[self.type](signature_inner_data)
        else:
            self.data = signature_inner_data

class SigsContainer:
    def __init__(self, signatures_stream: io.BytesIO) -> None:
        self._stream = signatures_stream
        self.signatures = []

    @property
    def stream(self) -> io.BytesIO:
        self._stream.seek(0)
        return self._stream

    @property
    def crc32(self):
        return compute_crc32(self.stream)

    def parse(self):
        signatures_stream = self.stream
        
        while True:
            header_data = signatures_stream.read(4)

            if not header_data:
                break
            
            current_signature = Signature(header_data)
            signature_data = signatures_stream.read(current_signature.length)
            current_signature.finalize(signature_data)

            self.signatures.append(current_signature)

    def __iter__(self):
        return self.signatures.__iter__()
