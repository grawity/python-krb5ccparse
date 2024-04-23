from dataclasses import dataclass
from .io_base import BinaryReader, BinaryWriter

# The default name type
KRB5_NT_PRINCIPAL = 1

@dataclass
class Principal:
    nametype: int
    components: list[bytes]
    realm: bytes

    def unparse(self):
        return b"@".join([b"/".join(self.components), self.realm]).decode()

@dataclass
class Keyblock:
    enctype: int
    data: bytes

@dataclass
class Address:
    addrtype: int
    data: bytes

@dataclass
class Authdata:
    addrtype: int
    data: bytes

class KrbBinaryReader(BinaryReader):
    # Turns out *nothing* is common between the two formats. Principals have
    # their name_type in a different place. Even 'data' has a 32-bit length in
    # ccache and 16-bit length in keytab.

    _uses_native_endian = True

    def read_u16(self):
        if self._uses_native_endian:
            return self._read_fmt(2, "H")
        else:
            return self.read_u16_be()

    def read_u32(self):
        if self._uses_native_endian:
            return self._read_fmt(4, "L")
        else:
            return self.read_u32_be()

    def read_s32(self):
        if self._uses_native_endian:
            return self._read_fmt(4, "l")
        else:
            return self._read_fmt(4, ">l")

    def read_time(self):
        return self.read_u32()

    def tell_eof(self):
        start_pos = self.tell()
        self.seek(0, 2)
        end_pos = self.tell()
        self.seek(start_pos)
        return end_pos

class KrbBinaryWriter(BinaryWriter):
    _uses_native_endian = True

    def write_u16(self, value):
        if self._uses_native_endian:
            return self._write_fmt("H", value)
        else:
            return self.write_u16_be(value)

    def write_u32(self, value):
        if self._uses_native_endian:
            return self._write_fmt("L", value)
        else:
            return self.write_u32_be(value)

    def write_s32(self, value):
        if self._uses_native_endian:
            return self._write_fmt("l", value)
        else:
            return self._write_fmt(">l", value)

    def write_time(self, value):
        self.write_u32(value)
