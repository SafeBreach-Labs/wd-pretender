import io
import copy

from ctypes import memmove, sizeof, pointer, Structure, c_uint32

from core.utils import *
from core.signatures import Signatures

class RmdxStruct(Structure):
    _fields_ = [
        ("Signature", c_uint32),
        ("Timestamp", c_uint32),
        ("Unknown1", c_uint32),
        ("Options", c_uint32),
        ("Unknown2", c_uint32),
        ("Unknown3", c_uint32),
        ("CompressedDataOffset", c_uint32),
        ("DecompressedDataSize", c_uint32),
        ("UnknownArray", c_uint32 * 8)
    ]

class CompressedDataHeaderStruct(Structure):
    _fields_ = [
        ("CompressedSize", c_uint32),
        ("CompressedCrc", c_uint32),
    ]

class RMDX:
    def __init__(self, **kwargs) -> None:
        self.header = RmdxStruct()
        self.unknown_data = b''
        self.compress_header = CompressedDataHeaderStruct()

        if 'stream' in kwargs:
            self.stream = kwargs["stream"]
            self.__init_from_stream(kwargs["stream"])
            
    def __init_from_stream(self, stream: io.BytesIO):
        buffer = stream.read(0x40)
        memmove(pointer(self.header), buffer, sizeof(self.header))

        compress_offset = self.header.CompressedDataOffset
        self.unknown_data = stream.read(compress_offset - 0x40)
        
        buffer = stream.read(8)
        memmove(pointer(self.compress_header), buffer, sizeof(self.compress_header))
        self.cdata = stream.read(self.compress_header.CompressedSize)
    
    def do_extract_signatures(self) -> io.BytesIO:
        return decompress(self.cdata)
    
    def validate_crc(self) -> bool:
        compressed_data = io.BytesIO(self.cdata)
        return self.cdata_header.CompressedCrc == compute_crc32(compressed_data)
    
    def pack(self):
        header = bytes(self.header)
        cheader = bytes(self.compress_header)

        return header + self.unknown_data + cheader + self.cdata

# class RmdxBuilder:
#     def __init__(self, signatures: Signatures, template: RMDX) -> None:
#         self.template = template
#         self.signatures = signatures.pack()


#     @staticmethod
#     def build(self, deltavdm: DeltaVdm, ) -> RMDX:
#         rmdx = copy.deepcopy(self.template)
#         rmdx.header.DecompressedDataSize = len(self.signatures)
        
#         csigs = compress(self.signatures)
        
#         rmdx.cdata = csigs
#         rmdx.compress_header.CompressedSize = len(csigs)
#         rmdx.compress_header.CompressedCrc = compute_crc32(io.BytesIO(csigs))
#         print(hex(rmdx.compress_header.CompressedCrc))

#         return rmdx