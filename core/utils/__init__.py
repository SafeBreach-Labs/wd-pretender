import io
import zlib

from ctypes import Structure, sizeof, memmove

def compute_crc32(stream: io.BytesIO) -> int:
    stream.seek(0)
    crc32 = 0

    while True:
        partial = stream.read(0x400000)

        if partial == b'':
            break
        
        crc32 = zlib.crc32(partial, crc32)

    return 0xffffffff - crc32

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