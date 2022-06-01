from cryptolib import base58
import hashlib


def tb(l):
    return b''.join(map(lambda x: x.to_bytes(1, 'big'), l))

def base58_encode(v: bytes, prefix: bytes, tezos=True) -> bytes:
    if tezos :
        base58_encodings = base58_encodings_xtz
    else:
        base58_encodings = base58_encodings_dun
    try:
        encoding = next(
            encoding
            for encoding in base58_encodings
            if len(v) == encoding[3] and prefix == encoding[0]
        )
    except StopIteration:
        raise ValueError('Invalid encoding, prefix or length mismatch.')

    return base58.encode_base58check(encoding[2] + v)

base58_encodings_dun = [
    #    Encoded   |               Decoded             |
    # prefix | len | prefix                      | len | Data type
    (b"B",     51,   tb([1, 52]),                  32,   u"block hash"),
    (b"o",     51,   tb([5, 116]),                 32,   u"operation hash"),
    (b"Lo",    52,   tb([133, 233]),               32,   u"operation list hash"),
    (b"LLo",   53,   tb([29, 159, 109]),           32,   u"operation list list hash"),
    (b"P",     51,   tb([2, 170]),                 32,   u"protocol hash"),
    (b"Co",    52,   tb([79, 199]),                32,   u"context hash"),

    (b"tz1",   36,   tb([6, 161, 159]),            20,   u"ed25519 public key hash"),
    (b"tz2",   36,   tb([6, 161, 161]),            20,   u"secp256k1 public key hash"),
    (b"tz3",   36,   tb([6, 161, 164]),            20,   u"p256 public key hash"),
    (b"dn1",   36,   tb([4, 177, 1]),              20,   u"ed25519 public key hash"),
    (b"dn2",   36,   tb([4, 177, 3]),              20,   u"secp256k1 public key hash"),
    (b"dn3",   36,   tb([4, 177, 6]),              20,   u"p256 public key hash"),
    (b"KT1",   36,   tb([2, 90, 121]),             20,   u"Originated address"),

    (b"id",    30,   tb([153, 103]),               16,   u"cryptobox public key hash"),

    (b"edsk",  54,   tb([13, 15, 58, 7]),          32,   u"ed25519 seed"),
    (b"edpk",  54,   tb([13, 15, 37, 217]),        32,   u"ed25519 public key"),
    (b"spsk",  54,   tb([17, 162, 224, 201]),      32,   u"secp256k1 secret key"),
    (b"p2sk",  54,   tb([16, 81, 238, 189]),       32,   u"p256 secret key"),

    (b"edesk", 88,   tb([7, 90, 60, 179, 41]),     56,   u"ed25519 encrypted seed"),
    (b"spesk", 88,   tb([9, 237, 241, 174, 150]),  56,   u"secp256k1 encrypted secret key"),
    (b"p2esk", 88,   tb([9, 48, 57, 115, 171]),    56,   u"p256_encrypted_secret_key"),

    (b"sppk",  55,   tb([3, 254, 226, 86]),        33,   u"secp256k1 public key"),
    (b"p2pk",  55,   tb([3, 178, 139, 127]),       33,   u"p256 public key"),
    (b"SSp",   53,   tb([38, 248, 136]),           33,   u"secp256k1 scalar"),
    (b"GSp",   53,   tb([5, 92, 0]),               33,   u"secp256k1 element"),

    (b"edsk",  98,   tb([43, 246, 78, 7]),         64,   u"ed25519 secret key"),
    (b"edsig", 99,   tb([9, 245, 205, 134, 18]),   64,   u"ed25519 signature"),
    (b"spsig", 99,   tb([13, 115, 101, 19, 63]),   64,   u"secp256k1 signature"),
    (b"p2sig", 98,   tb([54, 240, 44, 52]),        64,   u"p256 signature"),
    (b"sig",   96,   tb([4, 130, 43]),             64,   u"generic signature"),

    (b'Net',   15,   tb([87, 82, 0]),              4,    u"chain id")
]


base58_encodings_xtz = [
    #    Encoded   |               Decoded             |
    # prefix | len | prefix                      | len | Data type
    (b"B",     51,   tb([1, 52]),                  32,   u"block hash"),
    (b"o",     51,   tb([5, 116]),                 32,   u"operation hash"),
    (b"Lo",    52,   tb([133, 233]),               32,   u"operation list hash"),
    (b"LLo",   53,   tb([29, 159, 109]),           32,   u"operation list list hash"),
    (b"P",     51,   tb([2, 170]),                 32,   u"protocol hash"),
    (b"Co",    52,   tb([79, 199]),                32,   u"context hash"),

    (b"tz1",   36,   tb([6, 161, 159]),            20,   u"ed25519 public key hash"),
    (b"tz2",   36,   tb([6, 161, 161]),            20,   u"secp256k1 public key hash"),
    (b"tz3",   36,   tb([6, 161, 164]),            20,   u"p256 public key hash"),
    (b"KT1",   36,   tb([2, 90, 121]),             20,   u"Originated address"),

    (b"id",    30,   tb([153, 103]),               16,   u"cryptobox public key hash"),

    (b"edsk",  54,   tb([13, 15, 58, 7]),          32,   u"ed25519 seed"),
    (b"edpk",  54,   tb([13, 15, 37, 217]),        32,   u"ed25519 public key"),
    (b"spsk",  54,   tb([17, 162, 224, 201]),      32,   u"secp256k1 secret key"),
    (b"p2sk",  54,   tb([16, 81, 238, 189]),       32,   u"p256 secret key"),

    (b"edesk", 88,   tb([7, 90, 60, 179, 41]),     56,   u"ed25519 encrypted seed"),
    (b"spesk", 88,   tb([9, 237, 241, 174, 150]),  56,   u"secp256k1 encrypted secret key"),
    (b"p2esk", 88,   tb([9, 48, 57, 115, 171]),    56,   u"p256_encrypted_secret_key"),

    (b"sppk",  55,   tb([3, 254, 226, 86]),        33,   u"secp256k1 public key"),
    (b"p2pk",  55,   tb([3, 178, 139, 127]),       33,   u"p256 public key"),
    (b"SSp",   53,   tb([38, 248, 136]),           33,   u"secp256k1 scalar"),
    (b"GSp",   53,   tb([5, 92, 0]),               33,   u"secp256k1 element"),

    (b"edsk",  98,   tb([43, 246, 78, 7]),         64,   u"ed25519 secret key"),
    (b"edsig", 99,   tb([9, 245, 205, 134, 18]),   64,   u"ed25519 signature"),
    (b"spsig", 99,   tb([13, 115, 101, 19, 63]),   64,   u"secp256k1 signature"),
    (b"p2sig", 98,   tb([54, 240, 44, 52]),        64,   u"p256 signature"),
    (b"sig",   96,   tb([4, 130, 43]),             64,   u"generic signature"),

    (b'Net',   15,   tb([87, 82, 0]),              4,    u"chain id")
]

def generate_address_frompublickey_dun_secp256k1(publickey):
    kh = hashlib.blake2b(publickey,  digest_size=20).digest()
    return base58_encode(kh, b"dn2", tezos=False)
def generate_address_frompublickey_xtz_secp256k1(publickey):
    kh = hashlib.blake2b(publickey,  digest_size=20).digest()
    return base58_encode(kh, b"tz2", tezos=True)
def convertprivatekeytowif_xtz_secp256k1(privkey):
    return "unencrypted:"+base58_encode(privkey, b"spsk", tezos=True)
def convertprivatekeytowif_dun_secp256k1(privkey):
    return "unencrypted:"+base58_encode(privkey, b"spsk", tezos=False)
