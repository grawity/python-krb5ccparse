from dataclasses import dataclass
from .krb_base import *

# Format documentation:
#   https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html
#   https://www.gnu.org/software/shishi/manual/html_node/The-Keytab-Binary-File-Format.html

@dataclass
class KeytabEntry:
    principal: Principal
    timestamp: int
    kvno: int
    enctype: int
    keydata: bytes

@dataclass
class Keytab:
    version: int
    entries: list[KeytabEntry]

class KeytabReader(KrbBinaryReader):
    _version = None

    def read_data(self):
        length = self.read_u16()
        value = self.read(length)
        return value

    def read_principal(self):
        n_components = self.read_u16()
        if self._version == 1:
            n_components -= 1
        realm = self.read_data()
        components = []
        for i in range(n_components):
            components.append(self.read_data())
        name_type = KRB5_NT_PRINCIPAL
        if self._version >= 2:
            name_type = self.read_u32()
        return Principal(name_type, components, realm)

    def read_entry(self, length):
        end_pos = self.tell() + length
        principal = self.read_principal()
        timestamp = self.read_time()
        kvno = self.read_u8()
        enctype = self.read_u16()
        keydata = self.read_data()
        if end_pos - self.tell() >= 4:
            kvno = self.read_u32()
        # Skip to end of the slot
        self.seek(end_pos)
        return KeytabEntry(principal, timestamp, kvno, enctype, keydata)

    def read_keytab(self):
        magic = self.read_u8()
        if magic != 5:
            raise IOError("Format version {magic} not recognized")
        version = self.read_u8()
        if not (1 <= version <= 2):
            raise IOError("Format version {magic}.{version} not recognized")
        self._version = version
        self._uses_native_endian = (self._version == 1)
        end_pos = self.tell_eof()
        entries = []
        while self.tell() < end_pos:
            length = self.read_s32()
            if length > 0:
                entries.append(self.read_entry(length))
            elif length < 0:
                # Skip empty slot
                self.read(-length)
            else:
                break
        return Keytab(version, entries)

class KeytabWriter(KrbBinaryWriter):
    _version = None

    def write_data(self, data):
        self.write_u16(len(data))
        self.write(data)

    def write_principal(self, princ):
        n_components = len(princ.components)
        if self._version == 1:
            n_components += 1
        self.write_u16(n_components)
        self.write_data(princ.realm)
        for x in princ.components:
            self.write_data(x)
        if self._version >= 2:
            self.write_u32(princ.nametype)

    def write_entry(self, entry):
        self.write_principal(entry.principal)
        self.write_time(entry.timestamp)
        self.write_u8(min(entry.kvno, 0xFF))
        self.write_u16(entry.enctype)
        self.write_data(entry.keydata)
        if True or entry.kvno > 0xFF:
            self.write_u32(entry.kvno)

    def write_keytab(self, keytab):
        self.write_u8(5)
        self.write_u8(keytab.version)
        self._version = keytab.version
        self._uses_native_endian = (self._version == 1)
        for x in keytab.entries:
            tmp = KeytabWriter()
            tmp._version = self._version
            tmp._uses_native_endian = self._uses_native_endian
            tmp.write_entry(x)
            self.write_s32(tmp.tell())
            self.write_entry(x)

if __name__ == "__main__":
    import argparse
    import os
    from pprint import pprint

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--keytab", default="/etc/krb5.keytab",
                        help="path to the keytab")
    parser.add_argument("-o", "--output", default="/dev/null",
                        help="path to the output file")
    args = parser.parse_args()

    with open(args.keytab, "rb") as fh:
        keytab = KeytabReader(fh).read_keytab()

    pprint(keytab)

    with open(args.output, "wb") as fh:
        KeytabWriter(fh).write_keytab(keytab)
