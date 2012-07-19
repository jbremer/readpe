import mmap

def roundup2(value):
    """Round a value up to the next power of two."""
    # http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2Float
    value -= 1
    value |= value >> 1
    value |= value >> 2
    value |= value >> 4
    value |= value >> 8
    value |= value >> 16
    value |= value >> 32
    return value + 1

class FileManager:
    """Layer to manage all file operations."""

    def __init__(self, fname):
        self.fname = fname
        self.fp = file(fname, 'rb')
        self.mmap = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)
        self.fsize = self.mmap.size()

    def read(self, offset, length):
        """Read a chunk from file at a given offset."""
        self.mmap.seek(offset)
        return self.mmap.read(length)
