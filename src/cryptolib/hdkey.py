from cryptolib.entropy.system import get_system_entropy
from cryptolib.openssl.sslrandom import ssl_RAND_add, ssl_RAND_bytes
from cryptolib.openssl.ecdsa import N, EC_NID_secp256k1, EC_POINT_new, KEY, EC_POINT_oct2point, BN_CTX_new, \
    EC_POINT_add, POINT_CONVERSION_COMPRESSED, EC_POINT_point2oct
from cryptolib.openssl import ecdsa
import hmac
import hashlib
from cryptolib.base256 import base256decode, base256encode
import struct
from cryptolib.hash160 import hash_160
from cryptolib.base58 import base58check, decode_base58check, ChecksumError
from cryptolib.address.address import BitcoinAddress
from cryptolib.address.runmode import MAIN, TESTNET
from cryptolib.base58 import encode_base58check
from cryptolib.hex import bytes2hex
import ctypes

class InvalidHDKey(Exception):
    pass

# MAIN codes
HDKEY_PUBLIC = b"\x04\x88\xb2\x1e"
HDKEY_PRIVATE = b"\x04\x88\xad\xe4"

class HDKey():

    def __init__(self, keydata, chain_code, depth=0, n=0, is_public=False, parent_fingerprint=b'\x00\x00\x00\x00'):
        """
        Attributes
            keydata: 32bytes      base256encode(self.private_key)
            chain_code: 32bytes 
        """
        self.keydata = keydata
        self.chain_code = chain_code
        self.key = ecdsa.KEY()
        self.is_public = is_public
        if is_public:
            self.key.set_pubkey(self.keydata)
        else:
            self.key.set_privkey_b256(self.keydata)
        self.depth = depth
        self.n = n
        self.parent_fingerprint = parent_fingerprint

    @classmethod
    def generate(cls):
        # generate 256 bits of secure entropy
        for bytes, entropy in get_system_entropy():
            ssl_RAND_add(bytes, entropy)
        seed = ssl_RAND_bytes(32)
        return cls.from_seed(seed)

    @classmethod
    def from_seed(cls, seed):
        digest = hmac.new(key=b'Bitcoin seed', msg=seed, digestmod=hashlib.sha512).digest()
        secret, chain_code = digest[:32], digest[32:]
        return HDKey(secret, chain_code)
    
    def child(self, n, is_hardened=False):
        assert (0 <= n < 0x80000000)
        if is_hardened:
            n |= 0x80000000
        if self.is_public and is_hardened:
            raise Exception("Unable to derive hardened child from public key")
        if is_hardened:
            msg = b"\x00" + self.keydata + struct.pack(">I", n)
        else:
            msg = self.key.get_pubkey() + struct.pack(">I", n)
        digest = hmac.new(key=self.chain_code,
                          msg=msg,
                          digestmod=hashlib.sha512).digest()
        secret, chain_code = digest[:32], digest[32:]
        if self.is_public:
            curve = EC_NID_secp256k1()
            ctx = BN_CTX_new()
            pub_key = EC_POINT_new(curve.group)
            EC_POINT_oct2point(curve.group, pub_key, self.keydata, 33, ctx)
            
            key2 = KEY()
            key2.set_privkey_b256(secret, True)
            
            addkey = EC_POINT_new(curve.group)
            EC_POINT_oct2point(curve.group, addkey, key2.get_pubkey(), 33, ctx)
            result = EC_POINT_new(curve.group)
            ok = EC_POINT_add(curve.group, result, pub_key, addkey, ctx)
            mb = ctypes.create_string_buffer(33)
            EC_POINT_point2oct(curve.group, result, POINT_CONVERSION_COMPRESSED, mb, 33, ctx)
            child_keydata = mb.raw 
        else:
            child_keydata = base256encode((base256decode(self.keydata) + base256decode(secret)) % N)
        return HDKey(child_keydata, chain_code, self.depth + 1, n, self.is_public, self.fingerprint())

    def hd_pubkey(self):
        return HDKey(self.key.get_pubkey(), self.chain_code, self.depth, self.n, True, self.parent_fingerprint)

    def pubkey(self):
        return self.key.get_pubkey()

    def privatekey_b58(self, runmode=MAIN):
        prefix = {MAIN: b"\x80", TESTNET: b"\xef"}[runmode]
        # Add 0x01 as address is derived from compressed public key
        return encode_base58check(prefix + self.key.get_privkey_b256() + b"\x01")

    def address(self, runmode=MAIN):
        return BitcoinAddress.from_publickey(self.pubkey(), runmode)

    def fingerprint(self):
        return hash_160(self.key.get_pubkey())[:4]

    def __repr__(self):
        return ("<self:depth=%d,n=%d,is_public=%s,chain_code=%s,keydata=%s,parent_fingerprint=%s>" % 
                (self.depth, self.n, self.is_public, bytes2hex(self.chain_code), bytes2hex(self.keydata),
                 self.parent_fingerprint))


    def binserialize(self):
        version_bytes = HDKEY_PUBLIC if self.is_public else HDKEY_PRIVATE
        keydata = self.keydata if self.is_public else b"\x00" + self.keydata 
        return (version_bytes
                + struct.pack("B", self.depth)
                + self.parent_fingerprint
                + struct.pack(">I", self.n)
                + self.chain_code
                + keydata)

    def serialize(self):
        # print "+++" + self.binserialize().encode("hex")
        return base58check(self.binserialize())
    
    @classmethod
    def deserialize(self, base58str):
        try:
            binstr = decode_base58check(base58str, False)
        except ChecksumError as e:
            raise InvalidHDKey(str(e))
            
        if len(binstr) != 78:
            raise InvalidHDKey("incorrect serialized length : %d" % (len(binstr)))
        version_bytes, depth, parent_fingerprint, n, chain_code, keydata = (struct.unpack(">4sB4sI32s33s", binstr))
        if version_bytes not in [HDKEY_PUBLIC, HDKEY_PRIVATE]:
            raise InvalidHDKey("invalid version bytes %s" % (repr(version_bytes)))
        if version_bytes == HDKEY_PUBLIC:
            is_public = True
        elif version_bytes == HDKEY_PRIVATE:
            is_public = False
            if keydata[0] != 0:
                raise InvalidHDKey("invalid private key: expected 0")
            keydata = keydata[1:]
        return HDKey(keydata, chain_code, depth, n, is_public, parent_fingerprint)
    
    @classmethod
    def is_valid(self, base58str):
        try:
            result = HDKey.deserialize(base58str)
        except InvalidHDKey:
            return False
        return True

if __name__ == '__main__':
    from cryptolib.hex import hex2bytes
    
    # k = HDPrivateKey.generate()
    # print k
    # print k.child(0).serialize()
    # print k.child(1).serialize()

    # print k.serialize()
    k = HDKey.from_seed(hex2bytes(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
    # xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
    # xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
    print ("1", k.child(1).serialize())
    # xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U
    # xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U

    # xprv9vHkqa6EV4sPYMqyMUFyesUBVT6Ni3uEGwSm4gdijJ3AfrWZ33ZzPSNeQZAXyHbNWMttoegSPouRgagoX2JcpuFwqgD14zc2KkL5M2HhmdB
    # xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt
    print("----------")
    print(k.privatekey_b58())
    
    print (HDKey.deserialize("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"))

    print (HDKey.deserialize("xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"))
    
    
