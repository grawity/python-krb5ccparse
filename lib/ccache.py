from dataclasses import dataclass
from .krb_base import *

# Format documentation:
#   https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html

@dataclass
class HeaderField:
    tag: int
    value: bytes

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

    def read_credential(self):
        client = self.read_principal()
        server = self.read_principal()
        keyblock = self.read_keyblock()
        authtime = self.read_time()
        starttime = self.read_time()
        endtime = self.read_time()
        renewtime = self.read_time()
        is_skey = bool(self.read_u8())
        ticket_flags = self.read_u32()
        n_addresses = self.read_u32()
        addresses = []
        for x in range(n_addresses):
            addresses.append(self.read_address())
        n_authdata = self.read_u32()
        authdata = []
        for x in range(n_authdata):
            authdata.append(self.read_authdata())
        ticket = self.read_data()
        second_ticket = self.read_data()
        return CachedCredential(client, server, keyblock, authtime,
                                starttime, endtime, renewtime, is_skey,
                                ticket_flags, addresses, authdata,
                                ticket, second_ticket)

    def read_header(self):
        hdr_length = self.read_u16()
        end_pos = self.tell() + hdr_length
        fields = []
        while self.tell() < end_pos:
            tag = self.read_u16()
            length = self.read_u16()
            value = self.read(length)
            fields.append(HeaderField(tag, value))
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

class CacheWriter(KrbBinaryWriter):
    def write_data(self, data):
        self.write_u32(len(data))
        self.write(data)

    def write_principal(self, princ):
        if self._version >= 2:
            self.write_u32(princ.nametype)
        n_components = len(princ.components)
        if self._version == 1:
            n_components += 1
        self.write_u32(n_components)
        self.write_data(princ.realm)
        for x in princ.components:
            self.write_data(x)

    def write_keyblock(self, keyblock):
        if self._version == 3:
            self.write_u16(keyblock.enctype)
        self.write_u16(keyblock.enctype)
        self.write_data(keyblock.data)

    def write_address(self, address):
        self.write_u16(address.addrtype)
        self.write_data(address.data)

    def write_authdata(self, authdata):
        self.write_u16(authdata.adtype)
        self.write_data(authdata.data)

    def write_credential(self, cred):
        self.write_principal(cred.client)
        self.write_principal(cred.server)
        self.write_keyblock(cred.keyblock)
        self.write_time(cred.authtime)
        self.write_time(cred.starttime)
        self.write_time(cred.endtime)
        self.write_time(cred.renewtime)
        self.write_u8(cred.is_skey)
        self.write_u32(cred.ticket_flags)
        self.write_u32(len(cred.addresses))
        for x in cred.addresses:
            self.write_address(x)
        self.write_u32(len(cred.authdata))
        for x in cred.authdata:
            self.write_authdata(x)
        self.write_data(cred.ticket)
        self.write_data(cred.second_ticket)

    def write_header(self, header):
        hdr_length = sum([2 + 2 + len(x.value) for x in header])
        self.write_u16(hdr_length)
        for x in header:
            self.write_u16(x.tag)
            self.write_u16(len(x.value))
            self.write(x.value)

    def write_cache(self, cache: Cache):
        self.write_u8(5)
        self.write_u8(cache.version)
        self._version = cache.version
        self._uses_native_endian = (self._version <= 2)
        if self._version == 4:
            self.write_header(cache.header)
        else:
            assert not cache.header
        self.write_principal(cache.default_princ)
        for cred in cache.credentials:
            self.write_credential(cred)

if __name__ == "__main__":
    import argparse
    import os
    from pprint import pprint

    # Assuming it hasn't been overwritten system-wide
    default_cache = os.environ.get("KRB5CCNAME",
                                   "FILE:/tmp/krb5cc_%d" % os.getuid())

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cache", default=default_cache,
                        help="path to the credential cache")
    parser.add_argument("-o", "--output",
                        help="output file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="dump the cache contents to stdout")
    parser.add_argument("-p", "--principal", action="append", default=[],
                        help="principal to erase tickets for")
    args = parser.parse_args()

    exclude = {*args.principal}

    ccspec = args.cache or os.environ.get("KRB5CCNAME",
                                          "FILE:/tmp/krb5cc_%d" % os.getuid())

    if ":" in ccspec:
        cctype, ccname = ccspec.split(":", 1)
        if cctype != "FILE":
            raise RuntimeError("Only FILE: caches are supported")
    else:
        cctype, ccname = "FILE", ccspec

    with open(ccname, "rb") as fh:
        cache = CacheReader(fh).read_cache()

    if args.verbose:
        pprint(cache)

    creds = []
    for cred in cache.credentials:
        name, realm = cred.server.unparse().rsplit("@", 1)
        if {f"{name}", f"{name}@{realm}"} & exclude:
            print(f"Skipping ticket for {name}@{realm}")
            continue
        creds.append(cred)
    cache.credentials = creds

    with open(args.output or ccname, "wb") as fh:
        os.fchmod(fh.fileno(), 0o600)
        CacheWriter(fh).write_cache(cache)
