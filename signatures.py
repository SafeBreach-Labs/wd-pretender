import io
import enum
import ctypes

class SignatureHeader(ctypes.Structure):
    _fields_ = [
        ("Type", ctypes.c_uint32, 8),
        ("Length", ctypes.c_uint32, 24)
    ]

class SignatureDeltaBlobRecInfoHeader(SignatureHeader):
    _fields_ = [
        ("Unknown", ctypes.c_uint32 * 19)
    ]

class SignatureDeltaBlobHeader(SignatureHeader):
    _fields_ = [
        ("MergeSize", ctypes.c_uint32),
        ("MergeCrc", ctypes.c_uint32),
    ]

class BlobActionCopyFromBase(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint16, 15),
        ("Type", ctypes.c_uint16, 1),
    ]

    def finalize(self, **kwargs):
        self.Size += 6
        if "offset" in kwargs:
            self.Offset = kwargs["offset"]

class BlobActionCopyFromDelta(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_uint16)
    ]

    def finalize(self, **kwargs):
        if "data" in kwargs:
            self.data = kwargs["data"]

class BlobAction(ctypes.Union):
    _fields_ = [
        ("base", BlobActionCopyFromBase),
        ("delta", BlobActionCopyFromDelta),
    ]

class BaseSignature:
    def __init__(self, header: SignatureHeader, raw_signature: bytes):
        self.base_header = header
        self.raw = raw_signature

class SignatureDeltaBlob(BaseSignature):
    def __init__(self, header: SignatureHeader, raw_signature: bytes):
        super().__init__(header, raw_signature)

        self.header = SignatureDeltaBlobHeader()
        inner_header_size = ctypes.sizeof(self.header) - ctypes.sizeof(self.base_header)
        ctypes.memmove(ctypes.pointer(self.header), raw_signature, inner_header_size)

        self.blob_data = io.BytesIO(raw_signature[inner_header_size:])

class SignatureDeltaBlobRecInfo(BaseSignature):
    def __init__(self, header: SignatureHeader, raw_signature: bytes):
        super().__init__(header, raw_signature)

        self.header = SignatureDeltaBlobRecInfoHeader()
        inner_header_size = ctypes.sizeof(self.header) - ctypes.sizeof(self.base_header)
        ctypes.memmove(ctypes.pointer(self.header), raw_signature, inner_header_size)

SIG_TYPES = {
    0x73: SignatureDeltaBlob,
    0x74: SignatureDeltaBlobRecInfo
}

class Signatures:
    def __init__(self, raw_stream: io.BytesIO) -> None:
        self._internal_sigs = []

        while True:
            current_hdr = raw_stream.read(4)

            if not current_hdr:
                break
            
            sig_header = SignatureHeader()
            ctypes.memmove(ctypes.pointer(sig_header), current_hdr, ctypes.sizeof(sig_header))
            buffer = raw_stream.read(sig_header.Length)

            if sig_header.Type in SIG_TYPES:
                sigobj = SIG_TYPES[sig_header.Type](sig_header, buffer)
            else:
                sigobj = BaseSignature(sig_header, buffer)
            
            self._internal_sigs.append(sigobj)        

    def __iter__(self):
        return self._internal_sigs.__iter__()

# # SIGNATURE_TYPE_DELTA_BLOB_RECINFO
# class DeltaBlobRecInfo(SignatureBase):
#     pass