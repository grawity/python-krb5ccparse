from .krb_base import KrbBinaryReader, KRB5_NT_PRINCIPAL

# Format documentation:
#   https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html
#   https://www.gnu.org/software/shishi/manual/html_node/The-Keytab-Binary-File-Format.html

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

    def read_entry(self, size):
        end_pos = self.tell() + size
        entry = {}
        entry["principal"] = self.read_principal()
        entry["timestamp"] = self.read_u32()
        entry["kvno"] = self.read_u8()
        entry["enctype"] = self.read_u16()
        entry["key"] = self.read_data()
        if end_pos - self.tell() >= 4:
            # optional extension
            entry["kvno"] = self.read_u32()
        self.seek(end_pos)
        return entry

    def read_keytab(self):
        magic = self.read_u8()
        if magic != 5:
            raise IOError("Format version {magic} not recognized")
        version = self.read_u8()
        if not (1 <= version <= 2):
            raise IOError("Format version {magic}.{version} not recognized")
        self._version = version
        self._uses_native_endian = (self._version == 1)

        while True:
            try:
                length = self.read_s32()
                if length > 0:
                    yield self.read_entry(length)
                elif length < 0:
                    _ = self.read(-length)
                else:
                    break
            except EOFError:
                break
