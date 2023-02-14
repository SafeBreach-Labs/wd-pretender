import io
import ctypes

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

class RMDX:
    def __init__(self, rmdx_data: io.BytesIO):
        header = rmdx_data.read(0x20)
        self.rmdx_header = ctypes.cast(header, ctypes.POINTER(RmdxStruct))
        compressed_offset = self.rmdx_header.contents.CompressedDataOffset
        
        # irrelevant data
        rmdx_data.read(compressed_offset - 0x20) 
        cdata_header = rmdx_data.read(8)

        self.compressed_data_header = ctypes.cast(cdata_header, ctypes.POINTER(CompressedDataHeaderStruct))
        self.compressed_data = rmdx_data.read(self.compressed_data_header.contents.CompressedSize)
        