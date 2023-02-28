import io
import struct
import binascii

from ctypes import Structure, c_uint32
from ctypes import memmove, sizeof, pointer, addressof

from core.utils import compute_crc32, compress, decompress
from core.utils import memcpy, setter

class RMDX:
    class Header(Structure):
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

    class CompressedDataHeader(Structure):
        _fields_ = [
            ("CompressedSize", c_uint32),
            ("CompressedCrc", c_uint32),
        ]

    def __init__(self, stream: io.BytesIO) -> None: 
        self.rmdx_stream = stream
        
        self.header          = RMDX.Header()
        self.compress_header = RMDX.CompressedDataHeader()

        self.__memcpy_rmdx_header()
        self.__memcpy_compressed_header()
        
        compressed_bytes = self.__read_compressed_bytes()
        signatures_bytes = decompress(compressed_bytes)
        self.signatures_stream = io.BytesIO(signatures_bytes)
    
    def get_signatures(self) -> io.BytesIO:
        self.signatures_stream.seek(0)
        return self.signatures_stream

    def set_signatures(self, signatures_stream: io.BytesIO):
        self.signatures_stream = signatures_stream

        raw_signatures = signatures_stream.getvalue()
        compressed_signatures = compress(raw_signatures)

        self.CompressedCrc  = compute_crc32(io.BytesIO(compressed_signatures))
        self.CompressedSize = len(compressed_signatures)
        self.DecompressedDataSize = len(raw_signatures)
        
        new_rmdx_stream = io.BytesIO()

        # read all the data before compressed data
        self.rmdx_stream.seek(0)

        buffer_size = self.CompressedDataOffset + 8
        buffer = self.rmdx_stream.read(buffer_size)

        new_rmdx_stream.write(buffer)
        new_rmdx_stream.write(compressed_signatures)

        self.rmdx_stream = new_rmdx_stream
    
    def pack(self) -> io.BytesIO:
        return self.rmdx_stream.getvalue()

    @property
    def CompressedCrc(self):
        return self.compress_header.CompressedCrc

    @CompressedCrc.setter
    def CompressedCrc(self, value):
        packed_value = struct.pack("<I", value)
        self.__compressed_data_header_setter(packed_value, RMDX.CompressedDataHeader.CompressedCrc.offset)
        self.__memcpy_compressed_header()

    @property
    def CompressedSize(self):
        return self.compress_header.CompressedSize

    @CompressedSize.setter
    def CompressedSize(self, value):    
        packed_value = struct.pack("<I", value)
        self.__compressed_data_header_setter(packed_value, RMDX.CompressedDataHeader.CompressedSize.offset)
        self.__memcpy_compressed_header()

    @property
    def CompressedDataOffset(self):
        return self.header.CompressedDataOffset

    @property
    def DecompressedDataSize(self):
        return self.header.DecompressedDataSize
        
    @DecompressedDataSize.setter
    def DecompressedDataSize(self, value):
        packed_value = struct.pack("<I", value)
        self.__rmdx_header_setter(packed_value, RMDX.Header.DecompressedDataSize.offset)  
        self.__memcpy_rmdx_header()

    def __read_compressed_bytes(self) -> bytes:
        self.rmdx_stream.seek(self.CompressedDataOffset + 8)
        self.rmdx_stream.seek(self.CompressedDataOffset + 8)
        return self.rmdx_stream.read(self.CompressedSize)
    
    def __rmdx_header_setter(self, packed_value, moffset):
        setter(self.rmdx_stream,
               packed_value,
               moffset)
        self.__memcpy_rmdx_header()

    def __compressed_data_header_setter(self, packed_value, moffset):
        setter(self.rmdx_stream,
                packed_value, 
                self.CompressedDataOffset + moffset)
        self.__memcpy_compressed_header()

    def __memcpy_rmdx_header(self):
        memcpy(self.rmdx_stream,
                0,
                pointer(self.header),
                RMDX.Header)

    def __memcpy_compressed_header(self):
        memcpy(self.rmdx_stream, 
                self.CompressedDataOffset,
                pointer(self.compress_header),
                RMDX.CompressedDataHeader)

