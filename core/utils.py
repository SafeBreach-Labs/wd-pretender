import io
import zlib
import struct
import binascii

from core.crctables import *

def internal_compute_crc32(data, firstFour):

    cbLength = len(data)
    index = 0
    iterationNumber = cbLength // 8 

    if cbLength < 4:
        cbRunningLength = 0
    else:
        cbRunningLength = (cbLength//8)*8
    cbEndUnalignedBytes = cbLength - cbRunningLength

    
    for i in range(0, iterationNumber):
        firstFour ^= struct.unpack('I', data[index:index+4])[0] 
        index+=4
        dw2nd32 = struct.unpack('I',data[index:index+4])[0]
        dwCRC = CrcTableOffset40[(dw2nd32 >> 16) & 0x000000FF] ^ CrcTableOffset48[(dw2nd32 >> 8) & 0x000000FF]  ^ CrcTableOffset72[(firstFour >> 16) & 0x000000FF] ^ CrcTableOffset80[(firstFour >> 8) & 0x000000FF] ^ CrcTableOffset32[dw2nd32 >> 24] ^ CrcTableOffset64[firstFour >> 24] ^ CrcTableOffset56[dw2nd32 & 0x000000FF] ^ CrcTableOffset88[firstFour & 0x000000FF]
        index += 4
        firstFour = dwCRC

    try:

        for i in range(0,cbEndUnalignedBytes):
        
            dwCRC = CrcTableOffset32[(dwCRC ^ struct.unpack('B',data[index:index+1])[0]) & 0x000000FF] ^ (dwCRC >> 8)
            index += 1
    except:
        dwCRC = firstFour
        print("[-]excpetion")
    return dwCRC


def compute_crc32(stream: io.BytesIO) -> int:
    crc32 = -1

    while True:
        partial = stream.read(0x400000)

        if partial == b'':
            break
        
        crc32 = internal_compute_crc32(partial, crc32)

    return crc32

def compress(data: bytes) -> bytes:
    cdata = zlib.compress(data)[2:]
    return cdata

def decompress(data: bytes) -> io.BytesIO:
    decompressed_data = zlib.decompress(b"\x78\x9c" + data)
    return io.BytesIO(decompressed_data)
