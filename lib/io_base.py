import io
import struct

class StreamWrapper():
    def __init__(self, fh=b""):
        if isinstance(fh, bytes) or isinstance(fh, bytearray):
            self.fh = io.BytesIO(fh)
        elif hasattr(fh, "makefile"):
            self.fh = fh.makefile("rwb")
        else:
            self.fh = fh

    def seek(self, pos, whence=0):
        return self.fh.seek(pos, whence)

    def tell(self):
        return self.fh.tell()

    def read(self, length):
        buf = self.fh.read(length)
        if len(buf) < length:
            if len(buf) == 0:
                raise EOFError("Hit EOF after %d/%d bytes" % (len(buf), length))
            else:
                raise IOError("Hit EOF after %d/%d bytes" % (len(buf), length))
        else:
            return buf

    def write(self, buf):
        return self.fh.write(buf)

    def flush(self):
        return self.fh.flush()

class BinaryReader(StreamWrapper):
    def _read_fmt(self, length, fmt):
        return struct.unpack(fmt, self.read(length))[0]

    def read_u8(self):
        return self._read_fmt(1, "B")

    def read_u16_le(self):
        return self._read_fmt(2, "<H")

    def read_u16_be(self):
        return self._read_fmt(2, ">H")

    def read_u32_le(self):
        return self._read_fmt(4, "<L")

    def read_u32_be(self):
        return self._read_fmt(4, ">L")

    def read_u64_le(self):
        return self._read_fmt(8, "<Q")

    def read_u64_be(self):
        return self._read_fmt(8, ">Q")

class BinaryWriter(StreamWrapper):
    def _write_fmt(self, fmt, *args):
        return self.write(struct.pack(fmt, *args))

    def write_u8(self, val):
        return self._write_fmt("B", val)

    def write_u16_le(self, val):
        return self._write_fmt("<H", val)

    def write_u16_be(self, val):
        return self._write_fmt(">H", val)

    def write_u32_le(self, val):
        return self._write_fmt("<L", val)

    def write_u32_be(self, val):
        return self._write_fmt(">L", val)

    def write_u64_le(self, val):
        return self._write_fmt("<Q", val)

    def write_u64_be(self, val):
        return self._write_fmt(">Q", val)

class BinaryStream(BinaryReader, BinaryWriter):
    pass
