import io
import pefile
import struct
import shutil
import binascii

from core.signatures import DeltaSignatures, BaseSignatures
from core.rmdx import RMDX

class VDM:
    def __init__(self, path: str):
        self.path = path
        self.pe = pefile.PE(self.path)

        self.__extract_rmdx_from_resources()
        self.signatures_stream = self.rmdx.do_extract_signatures()
        
    @property
    def version(self) -> bytes:
        # Get the version info resource
        version_info = self.pe.FileInfo[0]
        # Get the string table entry for the "FileVersion" key
        string_table = version_info[0].StringTable[0]
        
        return string_table.entries[b"FileVersion"]

    @version.setter
    def version(self, new_version: bytes):
        # Get the version info resource
        version_info = self.pe.FileInfo[0]
        vs_fixedfileinfo = self.pe.VS_FIXEDFILEINFO[0]

        # Get the string table entry for the "FileVersion" key
        string_table = version_info[0].StringTable[0]
        string_table.entries[b'FileVersion']    = new_version
        string_table.entries[b'ProductVersion'] = new_version

        ms, ls = self.__convert_bytes_version_to_msls(new_version)
        vs_fixedfileinfo.FileVersionMS = ms
        vs_fixedfileinfo.FileVersionLS = ls

    def do_inc_version_build_number(self):
        cur_version = self.version.split(b'.')
        
        # convert the build number to int and inc by 1
        build_number = int(cur_version[2])
        build_number = str(build_number + 1).encode()

        cur_version[2]  = build_number
        new_version     = b'.'.join(cur_version)

        self.version = new_version

    # def overide_rmdx(self, rmdx: RMDX):
    #     for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
    #         if resource_type.name is not None and resource_type.name.__str__() == "RT_RCDATA":
    #             for resource_id in resource_type.directory.entries:
    #                 if resource_id.struct.Id == 1000:
    #                     data_rva = resource_id.directory.entries[0].data.struct.OffsetToData

    #     self.pe.set_bytes_at_rva(data_rva, rmdx.pack())

    def save(self, outfile=None):

        self.pe.write(self.path + '.patched')
        self.pe.close()
        
        if outfile:
            shutil.move(self.path + '.patched', outfile)
        else:
            shutil.move(self.path + '.patched', self.path)

        # reopen vdm file
        self.pe = pefile.PE(self.path)

    def __extract_rmdx_from_resources(self):
        """
            looks for RT_RCDATA resource type with resource entry which has the id 1000
        """
        for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None and resource_type.name.__str__() == "RT_RCDATA":
                for resource_id in resource_type.directory.entries:
                    if resource_id.struct.Id == 1000:
                        data_rva = resource_id.directory.entries[0].data.struct.OffsetToData
                        size = resource_id.directory.entries[0].data.struct.Size

                        data = self.pe.get_memory_mapped_image()[data_rva:data_rva+size]                
                        self.rmdx = RMDX(stream=io.BytesIO(data))

    def __convert_bytes_version_to_msls(self, version: bytes):
        version_list = version.split(b'.')
        version_list = list(map(lambda x: int(x), version_list))

        ms = int(binascii.hexlify((struct.pack('>2H', *version_list[:2]))), base=16)
        ls = int(binascii.hexlify((struct.pack('>2H', *version_list[2:]))), base=16)

        return ms, ls


class DeltaVdm(VDM):
    def __init__(self, path: str):
        super().__init__(path)
        self.signatures = DeltaSignatures(self.signatures_stream)

class BaseVdm(VDM):
    def __init__(self, path: str):
        super().__init__(path)
        self.signatures = BaseSignatures(self.signatures_stream)

def main():
    delta = DeltaVdm(r"C:\Users\omeratt\work\research\defender\updates\1.381.1691.0\forged\1.381.1699.0\updatepayload\mpasdlta.vdm")
    rmdx = delta.rmdx
    print(rmdx.validate_crc())
    
    for sig in delta.signatures:
        if sig.base_header.Type == 0x73:
            print(binascii.hexlify(sig.blob_data[:2]))

if __name__ == "__main__":
    main()