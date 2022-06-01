import cryptolib
from cryptolib.address.address import BitcoinAddress, LitecoinAddress, BitcoinCashAddress
from cryptolib.openssl.ecdsa import KEY
from cryptolib.sha256 import doublesha256
from cryptolib.openssl.ecdsa import *
import ctypes
import hashlib
from cryptolib.address.runmode import TESTNET, MAIN, BITCOINCASH_MAIN, BITCOINCASH_TEST
from random import SystemRandom
import sha3
import crc16
import base64
from cryptolib.base256 import base256decode, base256encode
from cryptolib.base58 import base58encode, encode_base58check, bitcoin_b58chars_values, bitcoin_b58chars
from cryptolib.hash160 import hash_160
from cryptolib.openssl import pyed25519
import struct
from cryptolib.tezos_dune import convertprivatekeytowif_xtz_secp256k1, generate_address_frompublickey_xtz_secp256k1,\
    generate_address_frompublickey_dun_secp256k1, convertprivatekeytowif_dun_secp256k1
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey,\
    EllipticCurvePrivateNumbers, SECP256K1, EllipticCurvePublicKeyWithSerialization,\
    EllipticCurvePrivateKeyWithSerialization, derive_private_key
from cryptography.hazmat.backends.openssl import backend
POINT_CONVERSION_UNCOMPRESSED = 4
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding,\
    PrivateFormat, NoEncryption
import subprocess 
import os
import math
# external random program is expected to print 32 bytes in hexa form with no extra space or character.

import configparser
 
global hashlib_has_scrypt
if hasattr(hashlib, "scrypt"):
    hashlib_has_scrypt = True
else:
    hashlib_has_scrypt = False

if not hashlib_has_scrypt:
    import scrypt

def scrypt_fct(data):
    global hashlib_has_scrypt
    if hashlib_has_scrypt:
        if type(data) == str:
            tobehashed = bytes(data, "ascii")
        elif type(data) == bytes:
            tobehashed = data
        else:
            raise Exception("unknow type, bytes or str required")  
        return hashlib.scrypt(tobehashed, salt=b"", n=16384, r=8, p=8, maxmem=0, dklen=32)
    else:
        if type(data) == str:
            tobehashed = data 
        elif type(data) == bytes:
            tobehashed = data.decode("ascii")
        else:
            raise Exception("unknow type, bytes or str required")  
        return scrypt.hash(tobehashed,"",N=16384,r=8,p=8,buflen=32)
        
class Random():
    bufsize = 1024
    random_rawdata = b''
    def __init__(self, external_program=None):
        if external_program == None:
            external_program = "__cryptolib__/FakeGetRandom.exe"
            print("WARING: USING SYSTEM RANDOM NOT TPM RANDOM")
        self.external_program = external_program
        self.sysrandom = SystemRandom()
    def get_random_b256(self, size):
        necessary_bytes =  size
        while len(self.random_rawdata) < necessary_bytes:
            self.call_random_program()
        randdata = self.random_rawdata[:necessary_bytes]
        self.random_rawdata = self.random_rawdata[necessary_bytes:]

        randdata_2 = self.get_random_from_system(size, 256)
        r = [(b1 + b2) %256 for b1, b2 in zip(randdata,randdata_2)]
        return bytes(bytearray(r))

    def get_random_b58(self, size):
        necessary_bytes =  math.ceil(size * 5.85798 /8)
        while len(self.random_rawdata) < necessary_bytes:
            self.call_random_program()
        randdata = self.random_rawdata[:necessary_bytes]
        self.random_rawdata = self.random_rawdata[necessary_bytes:]
        random_b58_1 = [ bitcoin_b58chars_values[b58] for b58 in base58encode(base256decode(randdata), leading_zeros=size)[-size:]]
        assert len(random_b58_1) == size
        random_b58_2 = self.get_random_from_system(size)
        r = [(b1 + b2) %58 for b1, b2 in zip(random_b58_1,random_b58_2)]
        return ''.join([bitcoin_b58chars[b] for b in r])

    def randrange(self, f, t=None):
        if t is None:
            t = f
            f = 0
        return self.sysrandom.randrange(f, t)
    def get_random_from_system(self, size, base=58):
        random_list = [self.sysrandom.randrange(0,base) for _ in range(size)]
        return random_list
    
    def call_random_program(self):
        print("CALL RANDOM EXTERNAL")
        external_program = self.external_program.replace("__cryptolib__", os.path.dirname(__file__))
        if not os.path.isfile(external_program):
            raise Exception("The Random generator executable in random.ini do not exist, check that '%s' is valid."%external_program)
        proc = subprocess.Popen([external_program, "%s"%self.bufsize], stdout=subprocess.PIPE)
        
        output = proc.stdout.read().strip().splitlines()
        output = b"".join(filter (lambda x:all(map(lambda c: 48 <= c <= 57 or 97 <= c <= 102, x) ),output))
        randb16string = bytearray(filter(lambda c: 48 <= c <= 57 or 97 <= c <= 102, output))
        r = base64.b16decode(randb16string, True)
        self.random_rawdata = self.random_rawdata + r
        

class NO_EXTERNAL_Random():
    bufsize = 1024
    random_rawdata = b''
    def __init__(self, external_program=None):
        self.sysrandom = SystemRandom()
    def get_random_b256(self, size):
        randdata_2 = self.get_random_from_system(size, 256)
        r = [b2 %256 for b2 in randdata_2]
        return bytes(bytearray(r))

    def get_random_b58(self, size):
        necessary_bytes =  math.ceil(size * 5.85798 /8)
        random_b58_2 = self.get_random_from_system(size)
        r = [b2 %58 for b2 in random_b58_2]
        return ''.join([bitcoin_b58chars[b] for b in r])

    def randrange(self, f, t=None):
        if t is None:
            t = f
            f = 0
        return self.sysrandom.randrange(f, t)
    def get_random_from_system(self, size, base=58):
        random_list = [self.sysrandom.randrange(0,base) for _ in range(size)]
        return random_list
    
        
def get_random_from_external_program(size, external_program):
    def call_random_program():
        external_program = external_program.replace("__cryptolib__", os.path.dirname(__file__))
        if not os.path.isfile(external_program):
            raise Exception("The Random generator executable in random.ini do not exist, check that '%s' is valid."%external_program)
        proc = subprocess.Popen([external_program], stdout=subprocess.PIPE)
        randb16string = b""
        c = proc.stdout.read(1)
        while b"0" <= c <= b"9" or b"a" <= c <= b"f":
            randb16string += c
            c = proc.stdout.read(1)
        r = base64.b16decode(randb16string, True)
        return r
    random_list = []
    while len(random_list) < size:
        r = call_random_program()
        assert len(r) == 32
        for b58 in base58encode(base256decode(r)):
            # we get base 
            random_list.append(bitcoin_b58chars_values[b58])
            if len(random_list) == size:
                break
    return random_list
    
def get_random_from_system(size):
    rnd = SystemRandom()
    random_list = [rnd.randrange(0,58) for _ in range(size)]
    return random_list
    
def random_b58(l):
    r1 = get_random_from_external_program(l)
    r2 = get_random_from_system(l)
    r = [(b1 + b2) %58 for b1, b2 in zip(r1,r2)]
    return ''.join([bitcoin_b58chars[b] for b in r])



def generate_passpoint_fromsecret(secret_b58, times=1):
    hashed_secret = scrypt_fct(secret_b58)
    curve = EC_NID_secp256k1()
    group = curve.group
    ctx = BN_CTX_new()
    passpoint = EC_POINT_new(group)
    secret_bn = BN_bin2bn(hashed_secret, len(hashed_secret), None)

    

    ok = EC_POINT_mul(group, passpoint, secret_bn, None, None, ctx)
    mb = ctypes.create_string_buffer(33)
    EC_POINT_point2oct(group, passpoint, POINT_CONVERSION_COMPRESSED, mb, 33, ctx)
    passpoint_num = cryptolib.base256.base256decode(mb.raw)
    print(mb.raw.hex())
    passpoint_b58 = cryptolib.base58.base58encode(passpoint_num)

    BN_free(secret_bn)
    EC_POINT_free(passpoint)

    del curve, group, ctx, passpoint, secret_bn, ok, mb 
    return passpoint_b58

def generate_randombytes_and_passpoint(num_random58, random_instance):
    secret_b58 = random_instance.get_random_b58(num_random58)

    return secret_b58, generate_passpoint_fromsecret(secret_b58)
    
def generate_address_frompublickey_btc(publickey, runmode=MAIN):
    address = BitcoinAddress.from_publickey(publickey, runmode).to_base58addr()
    return address

def generate_address_frompublickey_ltc(publickey, runmode=MAIN):
    address = LitecoinAddress.from_publickey(publickey, runmode).to_base58addr()
    return address

def generate_address_frompublickey_xrp(publickey):
    hpk =  b"\x00" +hash_160(publickey)
    address = encode_base58check( hpk, preserve_leading_zeros=True, ripple=True)
    return address

def generate_pem_frompublickey(publickey):
    pem = Encoding.PEM
    form = PublicFormat.SubjectPublicKeyInfo
    key = EllipticCurvePublicKey.from_encoded_point(data=publickey,curve=SECP256K1())
    return key.public_bytes(encoding=pem, format=form).decode("ascii")

def compute_privatekey_pem(secret1_b58, secret2_b58):
    privkey, publickey = compute_privatekey(secret1_b58, secret2_b58)
    
    privpem, pubpem = generate_pem_fromprivatekey (privkey)
    assert generate_pem_frompublickey(publickey) == pubpem
    
    return privpem, pubpem, publickey



def generate_pem_fromprivatekey(private):
    pem = Encoding.PEM
    form = PublicFormat.SubjectPublicKeyInfo
    formpriv = PrivateFormat.TraditionalOpenSSL
    ppp = int(private.hex(),16)
    key = derive_private_key(backend=backend, curve=SECP256K1(),private_value=ppp)
    pubpem =  key.public_key().public_bytes(encoding=pem, format=form) 
    return key.private_bytes(encoding=pem, format=formpriv, encryption_algorithm=NoEncryption()).decode("ascii") , pubpem.decode("ascii")



def generate_address_frompublickey_bch(publickey, runmode=MAIN):
    publickey 
    if runmode == MAIN:
        run = BITCOINCASH_MAIN
    if runmode == TESTNET:
        run = BITCOINCASH_TEST
    address = BitcoinCashAddress.from_publickey(publickey, run).to_base32addr()
    return address

def ethereum_checksum_verify(addr):
    if len(addr) != 42 :
        raise Exception("wrong length")
    if addr[:2] != "0x" :
        raise Exception("should start with 0x")
    if checksum_encode(addr[2:]) != addr:
        raise Exception("wrong checksum")
    return True
    
    
def checksum_encode(addr_hex): # Takes a 40-byte hex address as input
    o = ''
    addr_hex_low = addr_hex.lower()
    v = cryptolib.base256.base256decode(sha3.keccak_256(addr_hex_low.encode("ascii")).digest())
    for i, c in enumerate(addr_hex_low):
        if c in '0123456789':
            o += c
        else:
            o += c.upper() if (v & (2**(255 - 4*i))) else c.lower()
    return '0x'+o



def generate_address_frompublickey_eth(publickey):

    curve = EC_NID_secp256k1()
    group = curve.group
    ctx = BN_CTX_new()
    publickey_point = EC_POINT_new(group)

    EC_POINT_oct2point(group, publickey_point, publickey, len(publickey), ctx)
    mb = ctypes.create_string_buffer(65)
    EC_POINT_point2oct(group, publickey_point, POINT_CONVERSION_UNCOMPRESSED, mb, 65, ctx)
    address = sha3.keccak_256(mb.raw[1:]).hexdigest()[24:]
    
    return checksum_encode(address)

def compute_public_key(passpoint1_b58, passpoint2_b58, compressed=True):

    passpoint1_num = cryptolib.base58.base58decode(passpoint1_b58)
    passpoint1_b256 = cryptolib.base256.base256encode(passpoint1_num)
    passpoint2_num = cryptolib.base58.base58decode(passpoint2_b58)
    passpoint2_b256 = cryptolib.base256.base256encode(passpoint2_num)


    curve = EC_NID_secp256k1()
    group = curve.group
    ctx = BN_CTX_new()
    
    passpoint1 = EC_POINT_new(group)
    passpoint2 = EC_POINT_new(group)
    pub_key =    EC_POINT_new(group)

    EC_POINT_oct2point(group, passpoint1, passpoint1_b256, len(passpoint1_b256), ctx)
    EC_POINT_oct2point(group, passpoint2, passpoint2_b256, len(passpoint2_b256), ctx)

    ok = EC_POINT_add(group, pub_key, passpoint1, passpoint2, ctx)

    if compressed :
        lenpubk = 33
        COMPRESSION_STAT = POINT_CONVERSION_COMPRESSED
    else:
        lenpubk = 65
        COMPRESSION_STAT = POINT_CONVERSION_UNCOMPRESSED
      
    mb = ctypes.create_string_buffer(lenpubk)

    EC_POINT_point2oct(group, pub_key, COMPRESSION_STAT, mb, lenpubk, ctx)
      
    pub = mb.raw[:]
    print(pub)
    del curve, group, ctx, passpoint1, passpoint2, pub_key, ok, mb     
    return pub


def convertwiftoprivatekey(wif58):
    b256 = cryptolib.base58.base58decode(wif58)
    wif = cryptolib.base256.base256encode(b256)
    
    assert wif[-4:] == doublesha256(wif[:-4])[:4]
    COMPRESSED_PUB = wif[:-4][-1] == b'\x01'
    if wif [0] ==  0xb0:
        Litecoin = True
        NETWORK = MAIN
    elif  wif [0] ==  0x80:
        Litecoin = False
        NETWORK = MAIN
    elif wif [0] ==  0xef:
        NETWORK = TESTNET
        Litecoin = None
    return bytes(wif [1:-5]) , NETWORK, COMPRESSED_PUB, Litecoin

def convertprivatekeytowif_xrp(privkey_b256):
    privkey = b"\x22" + privkey_b256
    privkey = privkey + doublesha256(privkey)[:4]

    privkey_num = cryptolib.base256.base256decode(privkey)
    privkey_wif = cryptolib.base58.base58encode(privkey_num, ripple=True)

    return privkey_wif
def convert_wifxrp_to_privatekey(privkey_wif):
    
    privkey = cryptolib.base58.decode_base58check(privkey_wif, ripple=True)
    assert privkey[0] == 34
    return privkey[1:]


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
        
    privkey_num = cryptolib.base256.base256decode(privkey)
    privkey_wif = cryptolib.base58.base58encode(privkey_num)

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

def compute_privatekey(secret1_b58, secret2_b58, compressed=True):

    hashed_secret1 = scrypt_fct(secret1_b58)
    hashed_secret2 = scrypt_fct(secret2_b58)

    curve = EC_NID_secp256k1()
    group = curve.group
    ctx = BN_CTX_new()

    secret1_bn = BN_bin2bn(hashed_secret1, len(hashed_secret1), None)
    
    secret2_bn = BN_bin2bn(hashed_secret2, len(hashed_secret2), None)
    pub_key =    EC_POINT_new(group)
    
    n_order = BN_new()
    private_key = BN_new()
    BN_dec2bn(ctypes.byref(n_order), bytes(str(N),"ascii"))
    BN_mod_add(private_key, secret1_bn, secret2_bn, n_order, ctx)

    nbytes = BN_num_bytes(private_key)
    mb_secret = ctypes.create_string_buffer(nbytes)
    privkey_bin = ctypes.c_char_p(ctypes.addressof(mb_secret))
    n = BN_bn2bin(private_key, privkey_bin) 
    
    privkey = b"\x00"*(32-len(mb_secret.raw))+ mb_secret.raw[:]

    ok = EC_POINT_mul(group, pub_key, private_key, None, None, ctx)

    
    if compressed :
        lenpubk = 33
        COMPRESSION_STAT = POINT_CONVERSION_COMPRESSED
    else:
        lenpubk = 65
        COMPRESSION_STAT = POINT_CONVERSION_UNCOMPRESSED
      
    mb = ctypes.create_string_buffer(lenpubk)

    EC_POINT_point2oct(group, pub_key, COMPRESSION_STAT, mb, lenpubk, ctx)
    
    
    publickey = mb.raw [:]
    del curve, group, mb, mb_secret, ctx, private_key, n_order
    return privkey, publickey




def compute_privatekeywif_and_address_btc(secret1_b58, secret2_b58, runmode=MAIN):
    privkey, publickey = compute_privatekey(secret1_b58, secret2_b58)
    
    privatekey_wif = convertprivatekeytowif (privkey, runmode)

    address = generate_address_frompublickey_btc(publickey, runmode)
    
    return privatekey_wif, address, publickey

def compute_privatekeywif_and_address_bch(secret1_b58, secret2_b58, runmode):
    privkey, publickey = compute_privatekey(secret1_b58, secret2_b58)
    
    privatekey_wif = convertprivatekeytowif (privkey, runmode)

    address = generate_address_frompublickey_bch(publickey, runmode)
    
    return privatekey_wif, address, publickey
    
def compute_privatekeywif_and_address_xrp(secret1_b58, secret2_b58):
    privkey, publickey = compute_privatekey(secret1_b58, secret2_b58)
    
    privatekey_wif = convertprivatekeytowif_xrp (privkey)

    address = generate_address_frompublickey_xrp(publickey)
    
    return privatekey_wif, address, publickey
    
def compute_privatekeywif_and_address_xtz(secret1_b58, secret2_b58):
    privkey, publickey = compute_privatekey(secret1_b58, secret2_b58)
    privatekey_wif = convertprivatekeytowif_xtz_secp256k1 (privkey)
    address = generate_address_frompublickey_xtz_secp256k1(publickey)
    return privatekey_wif, address, publickey
def compute_privatekeywif_and_address_dun(secret1_b58, secret2_b58):
    privkey, publickey = compute_privatekey(secret1_b58, secret2_b58)
    privatekey_wif = convertprivatekeytowif_dun_secp256k1 (privkey)
    address = generate_address_frompublickey_dun_secp256k1(publickey)
    return privatekey_wif, address, publickey
    
def compute_privatekeywif_and_address_ltc(secret1_b58, secret2_b58, runmode=MAIN):
    privkey, publickey = compute_privatekey(secret1_b58, secret2_b58)
    privatekey_wif = convertprivatekeytowif (privkey, runmode, Litecoin=True)

    address = generate_address_frompublickey_ltc(publickey)
    
    return privatekey_wif, address, publickey
    

#####
#ED25519

def generate_randombytes_and_passpoint_xlm(num_random58):
    secret_b58 = random_b58(num_random58)

    return secret_b58, generate_passpoint_fromsecret_ed25519(secret_b58)

def compute_privatekey_ed25519(secret1_b58, secret2_b58):

    hashed_secret1 = scrypt_fct(secret1_b58)
    hashed_secret2 = scrypt_fct(secret2_b58)
    n1 = base256decode(hashed_secret1) % pyed25519.p
    n2 = base256decode(hashed_secret2) % pyed25519.p

    
    n3 = pyed25519.scalar_add(n1,n2)
    pub = pyed25519.compressed_public_key(n3)
    priv = base256encode(n3)
    
    
    return priv, pub

def compute_public_key_ed25519(passpoint1_b58, passpoint2_b58):

    passpoint1_num = cryptolib.base58.base58decode(passpoint1_b58)
    passpoint1_b256 = cryptolib.base256.base256encode(passpoint1_num)
    passpoint2_num = cryptolib.base58.base58decode(passpoint2_b58)
    passpoint2_b256 = cryptolib.base256.base256encode(passpoint2_num)

    p3_b256 = pyed25519.add_compressed_public_key(passpoint1_b256, passpoint2_b256)

    return p3_b256


def generate_passpoint_fromsecret_ed25519(secret_b58):
    hashed_secret = scrypt_fct(secret_b58)
    n = base256decode(hashed_secret) % pyed25519.p
    passp = pyed25519.compressed_public_key(n)
    passpoint_num = cryptolib.base256.base256decode(passp)
    passpoint_b58 = cryptolib.base58.base58encode(passpoint_num)
    
    return passpoint_b58

def calculate_checksum(payload):
    # This code calculates CRC16-XModem checksum of payload
    checksum = crc16.crc16xmodem(payload)
    checksum = struct.pack('H', checksum)
    return checksum

def compute_privatekeywif_and_address_xlm(secret1_b58, secret2_b58):
    priv, pub = compute_privatekey_ed25519(secret1_b58, secret2_b58)
    
    payload = b"\x90"+priv
    privatekey = base64.b32encode(payload + calculate_checksum(payload)).decode("ascii")
    
    return privatekey,generate_address_frompublickey_xlm(pub), pub

###

def generate_address_frompublickey_xlm(pk):
    print("Warning NOT IMPLEM generate_address_frompublickey_xlm")
    payload = b"\x30"+pk
    address_xlm = base64.b32encode(payload + calculate_checksum(payload)).decode("ascii")
    return address_xlm




if __name__ == "__main__":
    import gc, sys
    rand = Random("./FakeGetRandom.exe")
    for i in range(100):
        generate_randombytes_and_passpoint(28, rand)
    
    sys.exit(0)


    print(hashlib.scrypt(bytes("1", "ascii"), salt=b"", n=16384, r=8, p=8, maxmem=0, dklen=32))

    print(random_b58(200))
    k, net, com, lit = convertwiftoprivatekey("T5unZhrNdbhSZ5WGzVgwqMtPwYhKswsuC5gUtVzFcxPW9hLjqQGW")
    print(base64.b16encode(k), net , com , lit)
    print(k)
    print(base64.b16encode(getpubkey_from_privkey(k)))



    print(random_b58(200))

    
    k, net, com, lit = convertwiftoprivatekey("T9ivk2ytWsa2ngjugKSpPYCtgr7oBQGHsTUE8oUwEi24UYMeaHbQ")
    print(base64.b16encode(getpubkey_from_privkey(k)))
    k, net, com, lit = convertwiftoprivatekey("T9KJW9Ua2ozqC8jRBwDkKFwJf8TrzJPLQ5fyKZ6YQEsrpigas2q8")
    print(base64.b16encode(getpubkey_from_privkey(k)))
    k, net, com, lit = convertwiftoprivatekey("T7XBCzsp1R2ADZSzDb44oCpuN3PTnq8DwkAUVt6aC12YyQUMVQWE")
    print(base64.b16encode(getpubkey_from_privkey(k)))
    k, net, com, lit = convertwiftoprivatekey("T3ti3Q1WpxAy8SEuSANvJf5XvFabcPCsefmECbGiPznG7auNvVr4")
    print(base64.b16encode(getpubkey_from_privkey(k)))
    k, net, com, lit = convertwiftoprivatekey("T9QLcNteVfx5GzjczUQbrkxYGfjypwVe3ZLXp62Kw5NR23eKtZsT")
    print(base64.b16encode(getpubkey_from_privkey(k)))
    
    pk,pubk = compute_privatekey("toto","titi")
    print(base64.b16encode(pk))
    
    
    h = base64.b16decode(b"db85a4075289e9f2a466e48950437159213e40bded3842a9996ba83235a51f29",True)
    
    
#     sec = base64.b32decode(b"SBDP6RB6FKRR5WDNV4O4DONB2NVPVLVHZNBOVPCUPL3LBB52YFOVGJ7P")[1:-2]
#     
#     
#     signature = pyed25519.sign_old(sec, h)
#     print(base64.b64encode(signature))
    
    bn3, pub = compute_privatekey_ed25519("yDGCugFRfGcGf3vCsZENUwvCGtM3","MN82tHR5BwP8Ti")
    print(compute_privatekeywif_and_address_xlm("yDGCugFRfGcGf3vCsZENUwvCGtM3","MN82tHR5BwP8Ti"))
    n3 = base256decode(bn3)
    print(bn3,base64.b32decode(b"SBC5IHXG2TUNYX3R7BFVZMYVNBIY5XJBXYGLF4VPGK2QLMPVLOTVXFDL")[1:-2])
    if False:
        assert bn3 == base64.b32decode(b"SBC5IHXG2TUNYX3R7BFVZMYVNBIY5XJBXYGLF4VPGK2QLMPVLOTVXFDL")[1:-2]
    signature = pyed25519.sign(n3, h)
    print(base64.b64encode(signature))


    for currency in ["BTC","BCH","LTC","ETH","XRP","XLM"]:
        print("*"*20)
        print(currency)
        print("*"*20)
        for _ in range(10):
            if currency == "XLM":
                private_key, passpoint1_b58 = generate_randombytes_and_passpoint_xlm(28)
                security_code, passpoint2_b58 = generate_randombytes_and_passpoint_xlm(14)
            else:
                private_key, passpoint1_b58 = generate_randombytes_and_passpoint(28)
                security_code, passpoint2_b58 = generate_randombytes_and_passpoint(14)
            
            secret1_b58 = private_key
            secret2_b58 = security_code
            
            if currency == "BTC":
                privatekey_wif, address, pubkey = compute_privatekeywif_and_address_btc(secret1_b58, secret2_b58, 1)
            if currency == "BCH":
                privatekey_wif, address, pubkey = compute_privatekeywif_and_address_bch(secret1_b58, secret2_b58, 1)
            if currency == "LTC":
                privatekey_wif, address, pubkey = compute_privatekeywif_and_address_ltc(secret1_b58, secret2_b58)
            if currency == "ETH":
                privatekey, pubkey  = compute_privatekey(secret1_b58, secret2_b58)
                privatekey_wif = privatekey.hex()
                address = generate_address_frompublickey_eth(pubkey)
            if currency == "XRP":
                privatekey_wif, address, pubkey = compute_privatekeywif_and_address_xrp(secret1_b58, secret2_b58)
            if currency == "XLM":
                privatekey_wif, address, pubkey = compute_privatekeywif_and_address_xlm(secret1_b58, secret2_b58)
            print(secret1_b58, secret2_b58, address, privatekey_wif)



# 
#     
#     h = base64.b16decode(b"dbaf680d081dfdc99ead84cfea2975fb70cd6ab19d0d9e56078185038ac9e707",True)
#     
#     sec = base64.b32decode(b"SC5I23HXBSV32M7YSGVVON5XABRMRRPGRJO2YGVRIKDHJ763XHGKOMI5")[1:-2]
#     
#     
#     signature = pyed25519.sign_old(sec, h)
#     print(base64.b64encode(signature))
#     






    

