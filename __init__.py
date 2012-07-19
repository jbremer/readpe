import filemgr, ctypes, struct
from winobj import *

class PE:
    """Library to handle with Portable Executable files."""

    def __init__(self, fname):
        """Initialize a new PE File Instance."""
        self.f = filemgr.FileManager(fname)

    def _parse(self, cls, offset, length=None):
        """Parse a pre-defined Object."""
        # if no length is given, just read the entire object from disk
        if length is None:
            buf = self.f.read(offset, ctypes.sizeof(cls))
        # if a length is given, then we have to pad the end of the structure
        else:
            buf = self.f.read(offset, length) + \
                '\x00' * (ctypes.sizeof(cls) - length)

        # parse the buffer
        return cls.from_buffer_copy(buf)

    def parse(self):
        """Parse the PE File."""
        # read the Image DOS Header
        self.image_dos_header = self._parse(IMAGE_DOS_HEADER, 0)

        # check the e_magic value
        if self.image_dos_header.e_magic != IMAGE_DOS_SIGNATURE:
            # perhaps a ZM executable?
            if self.image_dos_header.e_magic == IMAGE_DOSZM_SIGNATURE:
                raise Exception('ZM Executable, not MZ!')
            else:
                raise Exception('Unknown binary type')

        # check if the e_lfanew is valid
        if self.image_dos_header.e_lfanew < 0 or \
                self.image_dos_header.e_lfanew > self.f.fsize:
            raise Exception('Invalid DOS Header')

        # read the Image Nt Headers
        self.image_nt_headers = self._parse(IMAGE_NT_HEADERS,
            self.image_dos_header.e_lfanew)

        if self.image_nt_headers.Signature in (IMAGE_NE_SIGNATURE,
                IMAGE_LE_SIGNATURE, IMAGE_LX_SIGNATURE):
            raise Exception('Invalid Nt Headers Signature')
        elif self.image_nt_headers.Signature != IMAGE_NT_SIGNATURE:
            raise Exception('Unknown Nt Headers Signature')

        # parse the Image File Header
        self.image_nt_headers.file_header = self._parse(IMAGE_FILE_HEADER,
            self.image_dos_header.e_lfanew + ctypes.sizeof(IMAGE_NT_HEADERS))

        # check the Machine type
        if not self.image_nt_headers.file_header.Machine in (
                IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64,
                IMAGE_FILE_MACHINE_AMD64):
            raise Exception('Invalid Machine type')

        # 32 or 64 bit binary?
        if self.image_nt_headers.file_header.Machine == \
                IMAGE_FILE_MACHINE_I386:
            self.x86, self.x64 = True, False
        else:
            self.x86, self.x64 = False, True

        # parse the Image Optional Header
        cls = IMAGE_OPTIONAL_HEADER if self.x86 else IMAGE_OPTIONAL_HEADER64
        self.image_nt_headers.optional_header = self._parse(cls,
            self.image_nt_headers.file_header.SizeOfOptionalHeader)

        # table to link the magic to the correct arch, with True being x86
        # and False being x64
        tbl = {IMAGE_NT_OPTIONAL_HDR32_MAGIC: True,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC: False}
        arch = tbl.get(self.image_nt_headers.optional_header.Magic, None)
        if self.x86 and arch is not True or self.x64 and arch is not False:
            raise Exception('Optional Header Magic is incorrect')
