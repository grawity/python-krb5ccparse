from dataclasses import dataclass
from pprint import pprint
from .krb_base import *

# Format documentation:
#   https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html

@dataclass
class CachedCredential:
    client: Principal
    server: Principal
    keyblock: Keyblock
    authtime: int
    starttime: int
    endtime: int
    renewtime: int
    is_skey: int
    ticket_flags: int
    addresses: list[Address]
    authdata: list[Authdata]
    ticket: bytes
    second_ticket: bytes

@dataclass
class Cache:
    version: int
    header: list
    default_princ: Principal
    credentials: list

class CacheReader(KrbBinaryReader):
    _version = None

    def read_data(self):
        length = self.read_u32()
        value = self.read(length)
        return value

    def read_principal(self):
        name_type = KRB5_NT_PRINCIPAL
        if self._version >= 2:
            name_type = self.read_u32()
        n_components = self.read_u32()
        if self._version == 1:
            n_components -= 1
        realm = self.read_data()
        components = []
        for i in range(n_components):
            components.append(self.read_data())
        return Principal(name_type, components, realm)

    def read_keyblock(self):
        if self._version == 3:
            enctype2 = self.read_u16()
        enctype = self.read_u16()
        keydata = self.read_data()
        return Keyblock(enctype, keydata)

    def read_address(self):
        addrtype = self.read_u16()
        addrdata = self.read_data()
        return Address(addrtype, addrdata)

    def read_authdata(self):
        adtype = self.read_u16()
        adata = self.read_data()
        return Authdata(adtype, adata)

    def read_time(self):
        return self.read_u32()

    def read_credential(self):
        entry = {}
        entry["client"] = self.read_principal()
        entry["server"] = self.read_principal()
        entry["keyblock"] = self.read_keyblock()
        entry["authtime"] = self.read_time()
        entry["starttime"] = self.read_time()
        entry["endtime"] = self.read_time()
        entry["renewtime"] = self.read_time()
        entry["is_skey"] = self.read_u8()
        entry["ticket_flags"] = self.read_u32()
        entry["addresses"] = []
        n_addresses = self.read_u32()
        for x in range(n_addresses):
            entry["addresses"].append(self.read_address())
        entry["authdata"] = []
        n_authdata = self.read_u32()
        for x in range(n_authdata):
            entry["authdata"].append(self.read_authdata())
        entry["ticket"] = self.read_data()
        entry["second_ticket"] = self.read_data()
        return CachedCredential(**entry)

    def read_header(self):
        hdr_length = self.read_u16()
        end_pos = self.tell() + hdr_length
        fields = []
        while self.tell() < end_pos:
            tlv_tag = self.read_u16()
            tlv_length = self.read_u16()
            tlv_value = self.read(tlv_length)
            fields.append((tlv_tag, tlv_value))
        return fields

    def read_cache(self):
        magic = self.read_u8()
        if magic != 5:
            raise IOError("Format version {magic} not recognized")
        version = self.read_u8()
        if not (1 <= version <= 4):
            raise IOError("Format version {magic}.{version} not recognized")
        self._version = version
        self._uses_native_endian = (self._version <= 2)
        header = []
        if self._version == 4:
            header = self.read_header()
        default_princ = self.read_principal()
        end_pos = self.tell_eof()
        credentials = []
        while self.tell() < end_pos:
            credentials.append(self.read_credential())
        if self.tell() < end_pos:
            raise IOError("Leftover data after last entry")
        return Cache(version,
                     header,
                     default_princ,
                     credentials)

if __name__ == "__main__":
    import argparse
    import os

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--principal", action="append", default=[],
                        help="principal to erase tickets for")
    args = parser.parse_args()

    try:
        cctype, ccname = os.environ["KRB5CCNAME"].split(":", 1)
    except KeyError:
        cctype, ccname = "FILE", "/tmp/krb5cc_%d" % os.getuid()

    with open(ccname, "rb") as fh:
        cr = CacheReader(fh)
        c = cr.read_cache()
        pprint(c)
