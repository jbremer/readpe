import mmap

def roundup2(value):
    """Round a value up to the next power of two."""
    # http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2Float
    value -= 1
    value |= v >> 1
    value |= v >> 2
    value |= v >> 4
    value |= v >> 8
    value |= v >> 16
    value |= v >> 32
    return value + 1

class FileManager:
    """Layer to manage all file operations."""

    def __init__(self, fname):
        self.fname = fname
        self.fp = open(fname, 'rb')
        self.mmap = mmap.mmap(self.fp.fileno(), 4096)
        self.fsize = self.mmap.size()
        self.cache = {}

    def read(self, offset, length, persistent=True):
        """Read a chunk from file at a given offset.

        If persistent is set to True, then it will cache the data found at the
        address for later uses, otherwise it will be released after returning.
        """
        ret = ''
        # we cache each 4K block
        start = offset & ~0xfff
        end = roundup2(offset + length)
        # enumerate each block
        for idx in xrange(start, end + 1, 0x1000):
            # retrieve each 4K block
            if not idx in self.cache:
                self.mmap.seek(idx)
                buf = self.mmap.read(0x1000)
                if persistent:
                    self.cache[idx] = buf
            else:
                buf = self.cache[idx]
            # calculate the correct size
            s, e = 0, 0x1000
            if offset > idx:
                s = offset - idx
            if end < idx + 0x1000:
                e = idx + 0x1000 - end
            # append the buffer
            ret += buf[s:e]
        return ret
