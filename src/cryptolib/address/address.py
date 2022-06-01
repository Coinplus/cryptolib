from cryptolib.address.address_version import AddressVersion,\
    PUBKEY_ADDRESS_MAIN, LitecoinAddressVersion, BitcoinCashAddressVersion
from cryptolib.hash160 import hash_160
from cryptolib.base58 import decode_base58check, encode_base58check,\
    Base58DecodingError, base58decode, base58encode
from cryptolib.base32 import decode_base32check, encode_base32check_from256,\
    Base32DecodingError , bech32_decode_bitcoincash
from cryptolib.address.runmode import TESTNET, MAIN, BITCOINCASH_MAIN
from cryptolib.base256 import base256encode, base256decode
from cryptolib.openssl.ecdsa import KEY, BN_bin2bn, EC_NID_secp256k1, BN_CTX_new, EC_POINT_new, EC_POINT_mul, EC_POINT_point2oct, POINT_CONVERSION_COMPRESSED
from cryptolib.sha256 import doublesha256
import base64
import ctypes
import sys


class InvalidBitcoinAddress(Exception):
    pass

class InvalidBitcoinCashAddress(Exception):
    pass

class InvalidLitecoinAddress(Exception):
    pass


class BitcoinAddress(object):
    """
       hash160 (bytestring of length 20)
       address_version (instance of AddressVersion)
    """

    def __init__(self, hash160, address_version):
        self.hash160 = hash160
        self.address_version = address_version

    @classmethod
    def from_publickey(cls, public_key, runmode):
        return cls(hash_160(public_key), AddressVersion.from_runmode(runmode))
        
    @classmethod
    def from_p2sh_script(cls, script, runmode):
        return cls(hash_160(script), AddressVersion.from_runmode(runmode, True))

    @classmethod
    def from_bytestring(cls, bytestr):
        if (len(bytestr) != 21):
            raise InvalidBitcoinAddress("BitcoinAddress.from_base58addr(): incorrect length")
        return cls(hash160=bytestr[1:], address_version=AddressVersion.from_byte(bytestr[0]))

    @classmethod
    def from_base58addr(cls, base58addrstr):
        try:
            bytestr = decode_base58check(base58addrstr)
        except Base58DecodingError as e:
            raise InvalidBitcoinAddress("Unable to decode base58check : %s" % (str(e)))
        if len(bytestr) != 21:
            raise InvalidBitcoinAddress("Invalid length : %d" % (len(bytestr)))
        return cls.from_bytestring(bytestr)

    def to_base58addr(self):
        return encode_base58check(self.address_version.to_bytes() + self.hash160, preserve_leading_zeros=True)

    def to_bytestring(self):
        return self.address_version.to_bytes() + self.hash160

    def to_hexstring(self):
        return self.to_bytestring().hex()

    def get_hash160(self):
        return self.hash160

    def get_addr_version(self):
        return self.address_version

    def is_valid_on(self, runmode=MAIN):
        return self.address_version.is_valid_on(runmode)

    @staticmethod
    def is_valid(address_str, runmode=MAIN):
        try:
            addr = BitcoinAddress.from_base58addr(address_str)
        except InvalidBitcoinAddress:
            # raise
            return False
        return addr.is_valid_on(runmode)

    def __repr__(self):
        return "Address(%s,%s)" % (str(self.address_version), self.to_base58addr())

    def __hash__(self):
        return hash((self.address_version, self.hash160))

    def __eq__(self, other):
        return (self.address_version == other.address_version) and (self.hash160 == other.hash160)

class LitecoinAddress(BitcoinAddress):

    @classmethod
    def from_publickey(cls, public_key, runmode):
        return cls(hash_160(public_key), LitecoinAddressVersion.from_runmode(runmode))
        
    @classmethod
    def from_p2sh_script(cls, script, runmode):
        return cls(hash_160(script), LitecoinAddressVersion.from_runmode(runmode, True))

    @classmethod
    def from_bytestring(cls, bytestr):
        if (len(bytestr) != 21):
            raise InvalidLitecoinAddress("LitecoinAddress.from_base58addr(): incorrect length")
        return cls(hash160=bytestr[1:], address_version=LitecoinAddressVersion.from_byte(bytestr[0]))

    @classmethod
    def from_base58addr(cls, base58addrstr):
        try:
            bytestr = decode_base58check(base58addrstr)
        except Base58DecodingError as e:
            raise InvalidLitecoinAddress("Unable to decode base58check : %s" % (str(e)))
        if len(bytestr) != 21:
            raise InvalidLitecoinAddress("Invalid length : %d" % (len(bytestr)))
        return cls.from_bytestring(bytestr)
    def __repr__(self):
        return "LitecoinAddress(%s,%s)" % (str(self.address_version), self.to_base58addr())
    @staticmethod
    def is_valid(address_str, runmode=MAIN):
        try:
            addr = LitecoinAddress.from_base58addr(address_str)
        except InvalidLitecoinAddress:
            # raise
            return False
        return addr.is_valid_on(runmode)


class BitcoinCashAddress(BitcoinAddress):

    def __init__(self, hash, address_version):
        self.hash= hash
        self.address_version = address_version
        
    @classmethod
    def from_publickey(cls, public_key, runmode, ):
        return cls(hash_160(public_key), BitcoinCashAddressVersion.from_runmode(runmode))

    @classmethod
    def from_p2sh_script(cls, script, runmode):
        return cls(hash_160(script), BitcoinCashAddressVersion.from_runmode(runmode, True))

    @classmethod
    def from_bytestring(cls, hdr,  bytestr):
        return cls(hash=bytestr[1:], address_version=BitcoinCashAddressVersion.from_byte(prefix=hdr, value=bytestr[0]))

    @classmethod
    def from_base58addr(cls, base58addrstr):
        raise NotImplemented()

    def to_base32addr(self):
        prefix = self.address_version.prefix
        bytes = self.address_version.to_bytes()
        hash = self.hash
        return encode_base32check_from256(prefix, bytes + hash)


    @classmethod
    def from_base32addr(cls, base32addrstr):
        
        try:
            hdr, bytestr = decode_base32check(base32addrstr)
        except Base32DecodingError as e:
            raise InvalidBitcoinCashAddress("Unable to decode base32check : %s" % (str(e)))
        return cls.from_bytestring(hdr, bytestr)

    def __repr__(self):
        return "BitcoinCashAddress(%s,%s)" % (str(self.address_version), self.to_base32addr())

    @staticmethod
    def is_valid(address_str, runmode=BITCOINCASH_MAIN):
        try:
            addr = BitcoinCashAddress.from_base32addr(address_str)
        except InvalidBitcoinCashAddress:
            # raise
            return False
        return addr.is_valid_on(runmode)

if __name__ == "__main__":
    print(BitcoinAddress.from_base58addr("15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"))
    print(BitcoinAddress.from_base58addr("n4MsBRWD7VxKGsqYRSLaFZC6hQrsrKLaZo"))
    assert BitcoinAddress.is_valid("n4MsBRWD7VxKGsqYRSLaFZC6hQrsrKLaZo", TESTNET)
    assert not BitcoinAddress.is_valid("n4NsBRWD7VxKGsqYRSLaFZC6hQrsrKLaZo", TESTNET)
    print(BitcoinAddress.is_valid("1H5azJoKoYd92DxjXX7k7gejpbLVMAczAi", MAIN))
    print(BitcoinAddress.is_valid("1H1hQVMZ6bpyGNWboJQT4aouDSksBnZWL3", MAIN))
    print(BitcoinAddress.from_base58addr("n4MsBRWD7VxKGsqYRSLaFZC6hQrsrKLaZo"))
    print(BitcoinAddress.from_base58addr("1H5azJoKoYd92DxjXX7k7gejpbLVMAczAi"))
    print(BitcoinAddress.from_base58addr("1H5azJoKoYd92DxjXX7k7gejpbLVMAczAi").to_base58addr())
    print(BitcoinAddress.from_base58addr("1H5azJoKoYd92DxjXX7k7gejpbLVMAczAi").to_hexstring())
    print(BitcoinAddress.from_base58addr("n4MsBRWD7VxKGsqYRSLaFZC6hQrsrKLaZo").to_base58addr())
    print(BitcoinAddress(bytes.fromhex("00600c55b16851c4f9d0e2c82fa161ac8190e04c"), AddressVersion(PUBKEY_ADDRESS_MAIN)))
    print(BitcoinAddress(bytes.fromhex("00602005b16851c4f9d0e2c82fa161ac8190e04c"), AddressVersion(PUBKEY_ADDRESS_MAIN)))
    print(BitcoinAddress.is_valid("112z9tWej11X94khKKzofFgWbdhiXLeHPD", MAIN))
    print(BitcoinAddress.is_valid("1111MJe7b4ZnktoPZabb6DLAKfac8tvx", MAIN))
    print(BitcoinAddress.is_valid("1H5azJoKoYd92DxjXX7k7gejpbLVMAczAi", MAIN))
    print(BitcoinAddress.is_valid("1H1hQVMZ6bpyGNWboJQT4aouDSksBnZWL3", MAIN))
 
    from cryptolib.address.address_version import SCRIPT_ADDRESS_MAIN
    print(BitcoinAddress(bytes.fromhex("00600c55b16851c4f9d0e2c82fa161ac8190e04c"), AddressVersion(SCRIPT_ADDRESS_MAIN)))
    from cryptolib.address.address_version import SCRIPT_ADDRESS_TEST
    print(BitcoinAddress(bytes.fromhex("00602005b16851c4f9d0e2c82fa161ac8190e04c"), AddressVersion(SCRIPT_ADDRESS_TEST)))
 
 
    print(BitcoinAddress.from_base58addr("15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"))
    print(LitecoinAddress.from_base58addr("LbNoDTssWGQFMr7UUDNYscBe5c7SjmfTtx"))
    print(LitecoinAddress.from_base58addr("37wuCzXnGVkQQ3fCgY5KkAtKy6EoYB7QUf"))
    print(LitecoinAddress.from_base58addr("2N9DXdnjWYaSRFxZLczWNNa3ovb2JiRQxus"))
    print(LitecoinAddress.from_base58addr("mhpdxi7eL25ZQZxy4Yo5TE7BXsQoV7YhKa"))
    print(LitecoinAddress.from_base58addr("2NDaAX1ADcukSWPZAxykkSBKWKF8hXWx9Bv"))
     
    print(LitecoinAddress.from_base58addr("MEUDdsSCt2rG6bH2ic2K274eeeq81ohx9p"))
     
    print("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a")
    print(BitcoinCashAddress.from_base32addr("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"))
    try : 
        print(BitcoinCashAddress.from_base32addr("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b"))
    except InvalidBitcoinCashAddress as e:
        print ("Address invalid: OK")
    print(BitcoinCashAddress.from_publickey(bytes.fromhex("02a6f17fdf17597d181ee746e84daaf41fa0be1a2e4557c173f378540ced7d348f"), runmode="bitcoincash"))


    
    def convertprivatekeytowif(privkey_b256, NETWORK=MAIN, COMPRESSED_PUB=True, Litecoin=False):
        if NETWORK == MAIN :
            if Litecoin:
                first = b"\xb0"
            else:
                first = b"\x80"
        elif NETWORK == TESTNET:
            first = b"\xef"
        privkey = first + privkey_b256
        if COMPRESSED_PUB:
            privkey = privkey + b"\x01"
        privkey = privkey + doublesha256(privkey)[:4]
            
        privkey_num = base256decode(privkey)
        privkey_wif = base58encode(privkey_num)
    
        return privkey_wif

    def getpubkey_from_privkey(privkey_256):
        private_key= BN_bin2bn(privkey_256, len(privkey_256), None)
    
        curve = EC_NID_secp256k1()
        group = curve.group
        ctx = BN_CTX_new()
    
        pub_key =    EC_POINT_new(group)
    
        ok = EC_POINT_mul(group, pub_key, private_key, None, None, ctx)
        mb = ctypes.create_string_buffer(33)
        EC_POINT_point2oct(group, pub_key, POINT_CONVERSION_COMPRESSED, mb, 33, ctx)
        publickey = mb.raw 
        return publickey


    expectedaddress = "bitcoincash:qq8a07g99pt4plk5tm524rguwap0hamg8yvu8rj622"



    cashprivatekey = "L5GFy7RVBtwaXNG95zx4f5vw3z1ewaeU7XiFUR9NcGZamAZy31JA"
    print(base64.b16encode(base256encode(base58decode(cashprivatekey))))
    privkey = base256encode(base58decode(cashprivatekey))[1:-5]
    print(base64.b16encode(doublesha256(base256encode(base58decode(cashprivatekey))[:-4])))
    print(base64.b16encode(privkey))
    
    
    k = KEY()
    k.set_privkey_b256(privkey)

    print("pubkey1",base64.b16encode(k.get_pubkey()))
    print("pubkey2",base64.b16encode(getpubkey_from_privkey(privkey)))


    print(convertprivatekeytowif(privkey))
    print("expected:",expectedaddress)
    print(BitcoinCashAddress.from_publickey(k.get_pubkey(), runmode="bitcoincash"))






