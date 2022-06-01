import ctypes
from cryptolib.openssl.dll import ssl
from ctypes import Structure, c_char_p
from _ctypes import addressof

NID_secp256k1 = 714  # from openssl/obj_mac.h

p = 2**256 - 2**32 - 977
A = 0
B = 7
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
G = [Gx, Gy]
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
H = 1

KEYSIZE = 32

class BN_CTX(Structure):
    _fields_ = [("err_stack", ctypes.c_int),
                ("pool", ctypes.c_void_p), # BN_POOL
                ("stack", ctypes.c_void_p), #BN_STACK
                ("too_many", ctypes.c_int),
                ("used", ctypes.c_uint)]

class BIGNUM(Structure):
    _fields_ = [("d", ctypes.POINTER(ctypes.c_ulong)),
                ("top", ctypes.c_int),
                ("dmax", ctypes.c_int),
                ("neg", ctypes.c_int),
                ("flasg", ctypes.c_int	),
                ]


class EC_POINT(Structure):
    _fields_ = [("meth", ctypes.c_void_p),  #const EC_METHOD *
                ("X", BIGNUM),
                ("Y", BIGNUM),
                ("Z", BIGNUM),
                ("Z_is_one", ctypes.c_int)]


class EC_GROUP(Structure):
    _fields_ = [("a", BIGNUM),
                ("a_is_minus3", ctypes.c_int),
                ("asn1_flag", ctypes.c_int),
                ("asn1_form", ctypes.c_int), #enum point_conversion_form_t
                ("b", BIGNUM),
                ("cofactor", BIGNUM),
                ("curve_name", ctypes.c_int),
                ("extra_data", ctypes.c_void_p), #EC_EXTRA_DATA*
                ("field", BIGNUM),
                ("field_data1", ctypes.c_void_p),
                ("field_data2", ctypes.c_void_p),
                ("field_mod_func", ctypes.c_void_p), #int(*     field_mod_func )(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *)
                ("generator", ctypes.POINTER(EC_POINT)),
                ("meth", ctypes.c_void_p), #const EC_METHOD *
                ("order", BIGNUM),
                ("poly", ctypes.c_int * 6),
                ("seed", ctypes.c_ubyte),
                ("seed_len", ctypes.c_size_t)]

class EC_KEY(Structure):
    _fields_ = [("version", ctypes.c_int),
                ("group", ctypes.c_void_p),
                ("pub_key", ctypes.c_void_p),
                ("priv_key", ctypes.POINTER(BIGNUM)),
                ("enc_flag", ctypes.c_uint),
                ("conv_form", ctypes.c_int),
                ("references", ctypes.c_int),
                ("method_data", ctypes.c_void_p)]
    
class ECDSA_SIG(Structure):
    _fields_ = [("r",ctypes.POINTER(BIGNUM)),
                ("s", ctypes.POINTER(BIGNUM))]



def EC_KEY_new_by_curve_name_check_result(val, func, args):
    if val == 0:
        raise ValueError
    else:
        return ctypes.c_void_p(val)


#EC_KEY_new_by_curve_name
proto = ctypes.CFUNCTYPE(ctypes.POINTER(EC_KEY),ctypes.c_int)
EC_KEY_new_by_curve_name = proto(("EC_KEY_new_by_curve_name",ssl))
EC_KEY_new_by_curve_name.errcheck = EC_KEY_new_by_curve_name_check_result

#BN_dec2bn
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.POINTER(BIGNUM)), ctypes.c_char_p)
BN_dec2bn = proto(("BN_dec2bn", ssl))
def BN_dec2bn_errcheck(result, func, args):
    if not result:
        raise Exception("BN_dec2bn failed")
    return args
BN_dec2bn.errcheck = BN_dec2bn_errcheck

#BN_bin2bn if last BIGNUM is Null, generate a new BIGNUM in res
proto = ctypes.CFUNCTYPE(ctypes.POINTER(BIGNUM), ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(BIGNUM))
BN_bin2bn = proto(("BN_bin2bn", ssl))


#ECDSA_SIG *ECDSA_SIG_new(void);
proto = ctypes.CFUNCTYPE(ctypes.POINTER(ECDSA_SIG))
ECDSA_SIG_new = proto(("ECDSA_SIG_new", ssl))

#ECDSA_SIG*     d2i_ECDSA_SIG(ECDSA_SIG **sig, const unsigned char **pp, long len);
proto = ctypes.CFUNCTYPE(ctypes.POINTER(ECDSA_SIG), ctypes.POINTER(ctypes.POINTER(ECDSA_SIG)), ctypes.POINTER(ctypes.c_char_p), ctypes.c_int)
d2i_ECDSA_SIG = proto(("d2i_ECDSA_SIG", ssl))

#void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
#proto = ctypes.CFUNCTYPE(None, ctypes.POINTER(ECDSA_SIG), ctypes.POINTER(ctypes.POINTER(BIGNUM)), ctypes.POINTER(ctypes.POINTER(BIGNUM)))
#ECDSA_SIG_get0 = proto(("ECDSA_SIG_get0", ssl))



#EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
proto = ctypes.CFUNCTYPE(ctypes.POINTER(EC_GROUP), ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BN_CTX))
EC_GROUP_new_curve_GFp = proto(("EC_GROUP_new_curve_GFp", ssl))

#BN_bn2bin
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(BIGNUM), ctypes.c_char_p)
BN_bn2bin = proto(("BN_bn2bin", ssl))

#BN_bn2dec
proto = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.POINTER(BIGNUM))
paramflags = ((1, "BIGNUM"),)
BN_bn2dec = proto(("BN_bn2dec", ssl), paramflags)
def BN_bn2dec_errcheck(result, func, args):
    print (result)
    
    if not result:
        raise Exception("set_secret: BN_bin2bn failed")
    return args
BN_bn2dec.errcheck = BN_bn2dec_errcheck

#BN_CTX_new
proto = ctypes.CFUNCTYPE(ctypes.POINTER(BN_CTX))
BN_CTX_new = proto(("BN_CTX_new", ssl))

#EC_KEY_get0_private_key
proto = ctypes.CFUNCTYPE(ctypes.POINTER(BIGNUM), ctypes.POINTER(EC_KEY))
EC_KEY_get0_private_key = proto(("EC_KEY_get0_private_key", ssl))

#EC_KEY_new_by_curve_name
proto = ctypes.CFUNCTYPE(ctypes.POINTER(EC_KEY), ctypes.c_int)
def EC_KEY_new_by_curve_name_errcheck(result, func, args):
    if not result:
        raise Exception("EC_KEY_new_by_curve_name failed")
    return args
EC_KEY_new_by_curve_name = proto(("EC_KEY_new_by_curve_name", ssl))
EC_KEY_new_by_curve_name.errcheck = EC_KEY_new_by_curve_name_errcheck

#EC_KEY_new
proto = ctypes.CFUNCTYPE(ctypes.POINTER(EC_KEY), ctypes.c_int)
EC_KEY_new = proto(("EC_KEY_new", ssl))

#EC_KEY_generate_key
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_KEY))
EC_KEY_generate_key = proto(("EC_KEY_generate_key", ssl))

#EC_POINT_set_affine_coordinates_GFp
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_GROUP), ctypes.POINTER(EC_POINT), ctypes.POINTER(BIGNUM),
                         ctypes.POINTER(BIGNUM), ctypes.POINTER(BN_CTX))
EC_POINT_set_affine_coordinates_GFp = proto(("EC_POINT_set_affine_coordinates_GFp", ssl))

#EC_KEY_free
proto = ctypes.CFUNCTYPE(None, ctypes.POINTER(EC_KEY))
EC_KEY_free = proto(("EC_KEY_free", ssl))

#EC_KEY_set_group
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_KEY), ctypes.POINTER(EC_GROUP))
EC_KEY_set_group = proto(("EC_KEY_set_group", ssl))

#EC_KEY_get0_group
proto = ctypes.CFUNCTYPE(ctypes.POINTER(EC_GROUP), ctypes.POINTER(EC_KEY))
EC_KEY_get0_group = proto(("EC_KEY_get0_group", ssl))

#EC_POINT_new
proto = ctypes.CFUNCTYPE(ctypes.POINTER(EC_POINT), ctypes.POINTER(EC_GROUP))
EC_POINT_new = proto(("EC_POINT_new", ssl))

#BN_new
proto = ctypes.CFUNCTYPE(ctypes.POINTER(BIGNUM))
BN_new = proto(("BN_new", ssl))

#EC_POINT_mul
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_GROUP), ctypes.POINTER(EC_POINT), ctypes.POINTER(BIGNUM),
                         ctypes.POINTER(EC_POINT), ctypes.POINTER(BIGNUM), ctypes.POINTER(BN_CTX))
EC_POINT_mul = proto(("EC_POINT_mul", ssl))

#EC_KEY_set_private_key 
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_KEY), ctypes.POINTER(BIGNUM))
EC_KEY_set_private_key = proto(("EC_KEY_set_private_key", ssl))

#EC_KEY_set_public_key
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_KEY), ctypes.POINTER(EC_POINT))
EC_KEY_set_public_key = proto(("EC_KEY_set_public_key", ssl))

#EC_POINT_free
proto = ctypes.CFUNCTYPE(None, ctypes.POINTER(EC_POINT))
EC_POINT_free = proto(("EC_POINT_free", ssl))

#BN_CTX_free
proto = ctypes.CFUNCTYPE(None, ctypes.POINTER(BN_CTX))
BN_CTX_free = proto(("BN_CTX_free", ssl))

#BN_num_bits
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(BIGNUM))
BN_num_bits = proto(("BN_num_bits", ssl))

#BN_clear_free
proto = ctypes.CFUNCTYPE(None, ctypes.POINTER(BIGNUM))
BN_clear_free = proto(("BN_clear_free", ssl))

#i2d_ECPrivateKey
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_KEY), ctypes.POINTER(ctypes.c_char_p))
i2d_ECPrivateKey = proto(("i2d_ECPrivateKey", ssl))

#EC_KEY_set_conv_form
proto = ctypes.CFUNCTYPE(None, ctypes.POINTER(EC_KEY), ctypes.c_int)
EC_KEY_set_conv_form = proto(("EC_KEY_set_conv_form", ssl))

#i2o_ECPublicKey
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_KEY), ctypes.POINTER(ctypes.c_char_p))
i2o_ECPublicKey = proto(("i2o_ECPublicKey", ssl))

#d2i_ECPrivateKey
proto = ctypes.CFUNCTYPE(ctypes.POINTER(EC_KEY), ctypes.POINTER(ctypes.POINTER(EC_KEY)), ctypes.POINTER(ctypes.c_char_p), ctypes.c_long)
d2i_ECPrivateKey = proto(("d2i_ECPrivateKey", ssl))

#EC_GROUP_set_generator
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_GROUP), ctypes.POINTER(EC_POINT), ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM))
EC_GROUP_set_generator = proto(("EC_GROUP_set_generator", ssl))

#o2i_ECPublicKey
proto = ctypes.CFUNCTYPE(ctypes.POINTER(EC_KEY), ctypes.POINTER(ctypes.POINTER(EC_KEY)), ctypes.POINTER(ctypes.c_char_p), ctypes.c_long)
o2i_ECPublicKey = proto(("o2i_ECPublicKey", ssl))

#ECDSA_size
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_KEY))
ECDSA_size = proto(("ECDSA_size", ssl))

#ECDSA_sign
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,  ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(EC_KEY))
ECDSA_sign = proto(("ECDSA_sign", ssl))

#ECDSA_verify
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(EC_KEY))
ECDSA_verify = proto(("ECDSA_verify", ssl))

#BN_free
proto = ctypes.CFUNCTYPE(None, ctypes.POINTER(BIGNUM))
BN_free = proto(("BN_free", ssl))

#EC_POINT_mul
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_GROUP), ctypes.POINTER(EC_POINT), ctypes.POINTER(BIGNUM),
                         ctypes.POINTER(EC_POINT), ctypes.POINTER(BIGNUM), ctypes.POINTER(BN_CTX))
EC_POINT_mul = proto(("EC_POINT_mul", ssl))

#EC_POINT_oct2point
proto = ctypes.CFUNCTYPE(ctypes.c_int,ctypes.POINTER(EC_GROUP), ctypes.POINTER(EC_POINT),ctypes.c_char_p,  ctypes.c_int, ctypes.POINTER(BN_CTX))
EC_POINT_oct2point = proto(("EC_POINT_oct2point", ssl))

#EC_POINT_point2oct
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_GROUP), ctypes.POINTER(EC_POINT), ctypes.c_int,
        ctypes.c_char_p,  ctypes.c_int, ctypes.POINTER(BN_CTX))
EC_POINT_point2oct = proto(("EC_POINT_point2oct", ssl))

#BN_mul
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BN_CTX))
BN_mul = proto(("BN_mul", ssl))

#BN_nnmod
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BN_CTX))
BN_nnmod = proto(("BN_nnmod", ssl))

#BN_mod_mul a1 = (a2 * a3) % a4
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BN_CTX))
BN_mod_mul = proto(("BN_mod_mul", ssl))
#int BN_mod_add(BIGNUM *r, BIGNUM *a, BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BIGNUM), ctypes.POINTER(BN_CTX))
BN_mod_add = proto(("BN_mod_add", ssl))

#EC_POINT_add a1 = (a2 * a3) % a4
proto = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(EC_GROUP), ctypes.POINTER(EC_POINT),ctypes.POINTER(EC_POINT),ctypes.POINTER(EC_POINT), ctypes.POINTER(BN_CTX))
EC_POINT_add = proto(("EC_POINT_add", ssl))


def BN_num_bytes(a):
    return ((BN_num_bits(a) + 7) // 8)


POINT_CONVERSION_COMPRESSED = 2
POINT_CONVERSION_UNCOMPRESSED = 4


def get_ssl_errors():
    name = "                                                                              "
    c_name = ctypes.c_char_p(name)
    r1 = -1
    errors = ""
    while r1:
        ssl.ERR_load_crypto_strings()
        r1 = ssl.ERR_get_error()
        ssl.ERR_error_string(r1, c_name)
        errors += c_name.value + "\n"
    return errors



def EC_KEY_regenerate_key(key, bn_privkey):
    """ Generate a private key from just the secret parameter"""
    ctx = 0
    pub_key = 0
    try:
        group = EC_KEY_get0_group(key)
        ctx = BN_CTX_new()
        if not ctx:
            raise Exception("EC_KEY_regenerate_key: BN_CTX_new failed\n" + get_ssl_errors())
        pub_key = EC_POINT_new(group)
        if not pub_key:
            raise Exception("EC_KEY_regenerate_key: EC_POINT_new failed\n" + get_ssl_errors())
        q = EC_POINT_new(group)
        m = BN_new()
#        EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
        ok = EC_POINT_mul(group, pub_key, bn_privkey, None, None, ctx)
        if not ok:
            raise Exception("EC_KEY_regenerate_key: EC_POINT_mul failed\n" + get_ssl_errors())
        EC_KEY_set_private_key(key, bn_privkey)
        EC_KEY_set_public_key(key, pub_key)
    finally:
        if pub_key:
            EC_POINT_free(pub_key)
        if ctx:
            BN_CTX_free(ctx)
    return (1)


class EC_NID_secp256k1():
    """ Setup NID_secp256k1 curve, as it is not packaged by default on CentOS for EC_KEY_new_by_curve_name"""

    def __init__(self):
        ctx = BN_CTX_new()
        # Creatrion of the openssl big number from the constants
        bn_p = BN_new()
        bn_a = BN_new()
        bn_b = BN_new()
        bn_x = BN_new()
        bn_y = BN_new()
        bn_order = BN_new()
        bn_cofactor = BN_new()
        BN_dec2bn(ctypes.byref(bn_x), bytes(str(Gx),"ascii"))
        BN_dec2bn(ctypes.byref(bn_p), bytes(str(p),"ascii"))
        BN_dec2bn(ctypes.byref(bn_a), bytes(str(A),"ascii"))
        BN_dec2bn(ctypes.byref(bn_b), bytes(str(B),"ascii"))
        BN_dec2bn(ctypes.byref(bn_y), bytes(str(Gy),"ascii"))
        BN_dec2bn(ctypes.byref(bn_order), bytes(str(N),"ascii"))
        BN_dec2bn(ctypes.byref(bn_cofactor), bytes(str(H),"ascii"))

        # Creation of the Curve
        group = EC_GROUP_new_curve_GFp(bn_p, bn_a, bn_b, ctx)
        if group == 0:
            raise Exception("Error: EC_GROUP_new_curve_GFp, " + get_ssl_errors())
        point = EC_POINT_new(group)
        if point == 0:
            raise Exception("Error: EC_POINT_new, " + get_ssl_errors())
            # EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
        ret = EC_POINT_set_affine_coordinates_GFp(group, point, bn_x, bn_y, ctx)
        if ret == 0:
            raise Exception("Error: BN_set_word, " + get_ssl_errors())
        ret = EC_GROUP_set_generator(group, point, bn_order, bn_cofactor)
        if ret == 0:
            raise Exception("Error: EC_GROUP_set_generator, " + get_ssl_errors())

        # different way
        #point = ssl.EC_POINT_bn2point(group, bn_g, 0,  0)
        #ssl.EC_GROUP_set_generator(group, point, bn_order, bn_cofactor)

        self.group = group
        BN_free(bn_p)
        BN_free(bn_a)
        BN_free(bn_b)
        BN_free(bn_x)
        BN_free(bn_y)
        BN_free(bn_order)
        BN_free(bn_cofactor)
        EC_POINT_free(point)
        self.EC_GROUP_free = ssl.EC_GROUP_free  # keep a ref as __del__ can't use globals

    def getkey(self):
        key = EC_KEY_new()
        EC_KEY_set_group(key, self.group)
        return ctypes.cast(key, ctypes.c_void_p)

    def __del__(self):
        ssl.EC_GROUP_free(self.group)


class KEY:

    def __init__(self, ):
        self.k = EC_KEY_new_by_curve_name(NID_secp256k1)
        '''if self.k is None:
            self.group = EC_NID_secp256k1()
            self.k = self.group.getkey()'''
        # keep a reference to ssl.EC_KEY_free, as __del__ can't use global
        # variables (globals may allready be deleted)
        self.EC_KEY_free = EC_KEY_free

    def __del__(self):
        self.EC_KEY_free(self.k)

    def set_compressed(self):
        EC_KEY_set_conv_form(self.k, POINT_CONVERSION_COMPRESSED)

    def generate(self, compressed=True):
        EC_KEY_generate_key(self.k)
        if compressed:
            self.set_compressed()

    def set_privkey(self, key, compressed=True):
        keyp = c_char_p(key)
        d2i_ECPrivateKey(ctypes.byref(self.k), ctypes.byref(keyp), len(key))
        if compressed:
            self.set_compressed()

    def set_pubkey(self, key):
        keyp = c_char_p(key)
        o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(keyp), len(key))

    def get_privkey(self):
        size = i2d_ECPrivateKey(self.k, None)
        mb_pri = ctypes.create_string_buffer(size)
        addr = ctypes.c_char_p(ctypes.addressof(mb_pri))
        i2d_ECPrivateKey(self.k, ctypes.byref(addr))
        return mb_pri.raw

    def get_privkey_b256(self):
        bn = EC_KEY_get0_private_key(self.k)
        if not bn:
            raise Exception("EC_KEY_get0_private_key failed")
        nbytes = BN_num_bytes(bn)
        mb_secret = ctypes.create_string_buffer(nbytes)
        addr = ctypes.c_char_p(ctypes.addressof(mb_secret))
        n = BN_bn2bin(bn, addr)
        return mb_secret.raw

    def set_privkey_b256(self, b256privkey, compressed=True):
        if len(b256privkey) != KEYSIZE:
            raise Exception("set_secret: secret must be 32 bytes")
        bn = BN_bin2bn(b256privkey, KEYSIZE, None)
        EC_KEY_regenerate_key(self.k, bn)
        BN_clear_free(bn)
        if compressed:
            self.set_compressed()

    def get_pubkey(self):
        size = i2o_ECPublicKey(self.k, None)
        mb = ctypes.create_string_buffer(size)
        addr = ctypes.c_char_p(ctypes.addressof(mb))
        i2o_ECPublicKey(self.k, ctypes.byref(addr))
        return mb.raw


    def sign(self, hash_to_sign_b):
        sig_size = ECDSA_size(self.k)
        assert isinstance(hash_to_sign_b, bytes)
        mb_sig = ctypes.create_string_buffer(sig_size)
        sig_size0 = ctypes.c_uint()
        assert 1 == ECDSA_sign(0, hash_to_sign_b, len(hash_to_sign_b), mb_sig, ctypes.byref(sig_size0), self.k)
        return mb_sig.raw[:sig_size0.value]

    def verify(self, hash_to_verify_b, sig):
        assert isinstance(hash_to_verify_b, bytes)
        return ECDSA_verify(0, hash_to_verify_b, len(hash_to_verify_b), sig, len(sig), self.k)



def secp256k1_add(P, Q):
    if P[0] % p == 0 and P[1] % p == 0:
        return Q
    if Q[0] % p == 0 and Q[1] % p == 0:
        return P

    if P[0] == Q[0] and P[1] == Q[1]:
        if P[1] == 0:
            return [0, 0]
        l = (3 * P[0]**2) * modInv((2 * P[1]), p)
    elif P[0] == Q[0]:
        return [0, 0]
    else:
        l = (P[1] - Q[1]) * modInv((P[0] - Q[0]), p)

    x = l**2 - (P[0] + Q[0])
    y = l * (Q[0] - x) - Q[1]
    return [x % p, y % p]
def secp256k1_mul(s, P):
    Q = (0, 0)  # Neutral element
    while s > 0:
        if s & 1:
            Q = secp256k1_add(Q, P)
        P = secp256k1_add(P, P)
        s >>= 1
    return Q


def secp256k1_compress(P):
    comp = bytes([2 + (P[1] & 1)]) + P[0].to_bytes(32, "big")
    assert P == list(secp256k1_uncompress(comp))
    return comp

def secp256k1_uncompress(P):

    x = int.from_bytes(P[1:33],"big")
    y = pow(x ** 3 + 7, (p+1)//4, p)
    if y % 2 != P[0] % 2:
        y = (p - y) % p
    return x, y

def modInv(n, p):
    return pow(n, p - 2, p)


if __name__ == '__main__':
    def hexstr(data):
        return ("".join("%02x" % c for c in data))

    key = KEY()
    key.generate()

    key2 = KEY()
    key2.generate()
    key2.set_privkey(key.get_privkey())
    sig = key2.sign(b"oakzpodkpozakoda")
    print("sig", hexstr(sig))

    key3 = KEY()
    key3.set_pubkey(key.get_pubkey())
    print("pubkey", hexstr(key.get_pubkey()))
    print("verify:", key3.verify(b"oakzpodkpozakoda", sig))

    # sig: 3046022100bcddcd93b53cf9e95919e0e7bdd7dcbf0e86e2902c68de72b769bcfe6468c906022100fe4fd8eeb810a1a9cf547d99fe71768ad579bff16035e68690a1eca4ab9ab91401
    # pubkey:
    # 048791c5168db93734e67f00a12560594cc9945c70862b55382774bbbd215e373ec6f48d956895adcb77b439d5a1baf82c0ae7b3924d56fbc7a7f4f3b41f65745f

    key4 = KEY()
    key4.generate()
    secret = key4.get_privkey_b256()
    print("secret:", hexstr(secret))
    sig4 = key4.sign(b"hello ok")
    print("sig4:", hexstr(sig4))

    key5 = KEY()
    print(hexstr(secret))
    key5.set_privkey_b256(secret)
    print("verify5:", key5.verify(b"hello ok", sig4))

