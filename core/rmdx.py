import io
import ctypes

from core.utils import *
from core.signatures import Signatures

class RmdxStruct(ctypes.Structure):
    _fields_ = [
        ("Signature", ctypes.c_uint32),
        ("Timestamp", ctypes.c_uint32),
        ("Unknown1", ctypes.c_uint32),
        ("Options", ctypes.c_uint32),
        ("Unknown2", ctypes.c_uint32),
        ("Unknown3", ctypes.c_uint32),
        ("CompressedDataOffset", ctypes.c_uint32),
        ("DecompressedDataSize", ctypes.c_uint32)
    ]

class CompressedDataHeaderStruct(ctypes.Structure):
    _fields_ = [
        ("CompressedSize", ctypes.c_uint32),
        ("CompressedCrc", ctypes.c_uint32),
    ]

class RmdxBuilder:
    def __init__(self, signatures: Signatures) -> None:
        self.signatures = signatures.pack()

    def build(self) -> bytes:
        csigs = compress(self.signatures)
        return csigs

class RMDX:
    def __init__(self, rmdx_data: io.BytesIO):
        
        buffer = rmdx_data.read(0x20)
        self.rmdx_header = RmdxStruct()
        ctypes.memmove(ctypes.pointer(self.rmdx_header), buffer, ctypes.sizeof(self.rmdx_header))

        coffset = self.rmdx_header.CompressedDataOffset
        
        # irrelevant data
        rmdx_data.read(coffset - 0x20) 

        buffer = rmdx_data.read(8)
        self.cdata_header = CompressedDataHeaderStruct()
        ctypes.memmove(ctypes.pointer(self.cdata_header), buffer, ctypes.sizeof(self.cdata_header))
        
        self.cdata = rmdx_data.read(self.cdata_header.CompressedSize)
    
    def do_extract_signatures(self) -> bytes:
        return decompress(self.cdata)
    
    def validate_crc(self) -> bool:
        compressed_data = io.BytesIO(self.cdata)
        return self.cdata_header.CompressedCrc == compute_crc32(compressed_data)
