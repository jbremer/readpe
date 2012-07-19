import filemgr, winobj, ctypes

class PE:
    """Library to handle with Portable Executable files."""

    def __init__(self, fname):
        """Initialize a new PE File Instance."""

        self.f = filemgr.FileManager(fname)

    def _parse(self, cls, offset, size=None, persistent=True):
        """Parse a pre-defined Object."""
        # determine the correct size
        if size is None:
            size = ctypes.sizeof(cls)
        # is this offset within the reach of the file?
        if offset + size > self.f.fsize:
            raise Exception('Incorrect offset')
        # read and parse the buffer
        return cls.from_buffer_copy(self.f.read(offset, size, persistent))

    def parse(self):
        """Parse the PE File."""
        # read the Image DOS Header
        self._image_dos_header = self._parse(winobj.IMAGE_DOS_HEADER, 0)

        # check the e_magic value
        if self._image_dos_header.e_magic != IMAGE_DOS_SIGNATURE:
            # perhaps a ZM executable?
            if self._image_dos_header.e_magic == IMAGE_DOSZM_SIGNATURE:
                raise Exception('ZM Executable, not MZ!')
            else:
                raise Exception('Unknown binary type')

        # check if the e_lfanew is valid
        if self._image_dos_header.e_lfanew < 0 or \
                self._image_dos_header > self.f.fsize:
            raise Exception('Invalid DOS Header')


