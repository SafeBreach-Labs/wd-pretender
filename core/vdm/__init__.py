import io
import os
import pefile
import struct
import shutil
import binascii

from core.rmdx import RMDX

class VDM:
    def __init__(self, path: str):
        self.pe       = pefile.PE(path)
        self.path     = path
        self.basename = os.path.basename(self.path)

        self.rmdx_rva, self.rmdx_size = self.get_rmdx_offset_and_size()
        rmdx_data = self.pe.get_data(self.rmdx_rva, self.rmdx_size)
        rmdx_stream = io.BytesIO(rmdx_data)

        self.rmdx = RMDX(rmdx_stream)

        if not self.rmdx:
            raise Exception("Failed to find RMDX")
        
    def pack(self):
        raise NotImplementedError

    def save(self, path=None):
        self.__update_pe_rmdx()
        
        if path:
            outfile = os.path.join(path, os.path.basename(self.path))
            self.pe.write(outfile)
            self.pe.close()
        else:
            shutil.move(self.path + '.patched', self.path)

        # reopen vdm file
        self.pe = pefile.PE(self.path)

    def get_rmdx_offset_and_size(self):
        for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None and resource_type.name.__str__() == "RT_RCDATA":
                for resource_id in resource_type.directory.entries:
                    if resource_id.struct.Id == 1000:
                        data_rva = resource_id.directory.entries[0].data.struct.OffsetToData
                        size = resource_id.directory.entries[0].data.struct.Size
                        return data_rva, size

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

    def __update_pe_rmdx(self):
        self.rmdx.set_signatures(self.pack())
        rmdx_data = self.rmdx.pack()

        for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None and resource_type.name.__str__() == "RT_RCDATA":
                for resource_id in resource_type.directory.entries:
                    if resource_id.struct.Id == 1000:
                        resource_id.directory.entries[0].data.struct.Size = len(rmdx_data)

        self.pe.set_bytes_at_rva(self.rmdx_rva, rmdx_data)
        

    def __convert_bytes_version_to_msls(self, version: bytes):
        version_list = version.split(b'.')
        version_list = list(map(lambda x: int(x), version_list))

        ms = int(binascii.hexlify((struct.pack('>2H', *version_list[:2]))), base=16)
        ls = int(binascii.hexlify((struct.pack('>2H', *version_list[2:]))), base=16)

        return ms, ls