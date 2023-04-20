import io
import zlib
import struct

from ctypes import Structure, sizeof, memmove

from core.utils.crctables import *

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
    stream.seek(0)
    crc32 = -1

    while True:
        partial = stream.read(0x400000)

        if partial == b'':
            break
        
        crc32 = internal_compute_crc32(partial, crc32)

    return crc32

def compress(data: bytes) -> bytes:
    return zlib.compress(data)[2:]

def decompress(data: bytes) -> bytes:
    return zlib.decompress(b"\x78\x9c" + data)

def overlap(vec1: tuple, vec2: tuple) -> bool:
    return vec1[1] >= vec2[0] and vec2[1] > vec1[0]

def setter(_stream: io.BytesIO, _value: bytes, _offset: int):
    _stream.seek(_offset)
    _stream.write(_value)

def memcpy(_stream: io.BytesIO, _offset: int, _pointer: object, _strcuture: Structure):
    _stream.seek(_offset)
    
    s = _strcuture()
    s_size = sizeof(s)
    s_data = _stream.read(s_size)

    memmove(_pointer, s_data, s_size)

def intersect(_range1: tuple, _range2: tuple):
    _start = max(_range1[0], _range2[0])
    _end   = min(_range1[1], _range2[1])

    return (_start, _end)

def version_banner():
    return "\n\t-- Defender-Pretender: v1.0.0 (Safebreach Labs) --\n"