from cryptolib.utils import count_leading_values
from cryptolib.base256 import base256encode, base256decode
from cryptolib.sha256 import doublesha256, sha256checksum
import base64

b32chars_bytes = b'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

class Base32DecodingError(Exception):
    pass

def bech32_decode_bitcoincash(bech_s):
    """Validate a Bech32 string, and determine HRP and data."""
    
    if type(bech_s) == bytes:
        bech = bech_s
    else:
        bech = bytes(bech_s, "ascii")
    if ((any(x < 33 or x > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        raise Base32DecodingError()
    bech = bech.lower()
    pos = bech.rfind(b':')
    if pos < 1 or pos + 9 > len(bech) or len(bech) > 90:
        raise Base32DecodingError()
    if not all(x in b32chars_bytes for x in bech[pos+1:]):
        raise Base32DecodingError()
    hrp = bech[:pos]
    data = [b32chars_bytes.find(x) for x in bech[pos+1:]]
    if not bech32_verify_checksum_bitcoincash(hrp, data):
        raise Base32DecodingError()

    return (hrp, data[:-8])



def decode_base32check(data):
    """Verify the checksum + decode """
    hrp, dd = bech32_decode_bitcoincash(data)
    return hrp, bytes(convertbits(dd,5,8,False))


class ChecksumError(Base32DecodingError):
    pass


def base32decode(b32str):
    data_l = list(map(lambda x: b32chars_bytes.find(x),b32str))
    b = bytes(convertbits(data_l,5,8))    
    return b


def bech32_polymod_bitcoincash(values):
    GEN = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]
    chk = 1
    for v in values:
        b = (chk >> 35)
        chk = ((chk & 0x07ffffffff ) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand_bitcoincash(s):
    return [x & 0x1f for x in s] + [0] #+ [ord(x) & 31 for x in s]


def bech32_verify_checksum_bitcoincash(hrp, data):
    return bech32_polymod_bitcoincash(bech32_hrp_expand_bitcoincash(hrp) + data) == 1


def bech32_create_checksum_bitcoincash(hrp, data):
    values = bech32_hrp_expand_bitcoincash(hrp) + list(data)
    polymod = bech32_polymod_bitcoincash(values + [0,0,0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5 * (7 - i)) & 31 for i in range(8)]


def encode_base32check_from256(hrp, data):
    data_l = list(data)
    data_ll = convertbits(data_l, 8, 5)
    return encode_base32check_from32(hrp, bytes(map(lambda x: b32chars_bytes[x] , data_ll))) 


def encode_base32check_from32(hrp, data):
    data_l = list(map(lambda x: b32chars_bytes.find(x),data))
    chksum = bech32_create_checksum_bitcoincash(hrp, data_l)
    return bytes(list(hrp)+list(b":")+ [b32chars_bytes[d] for d in data_l+chksum]).decode("utf-8")


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

if __name__ == '__main__':
    print(bech32_decode_bitcoincash("bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn"))
    print(bech32_decode_bitcoincash("bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"))
    print(b"bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq")
    nadr = encode_base32check_from32(b"bitcoincash",b"ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq"[:-8])
    print(nadr)
    print(bech32_decode_bitcoincash(nadr))
    print(b"bitcoincash:qq8a07g99pt4plk5tm524rguwap0hamg8yvu8rj622")
    nadr = encode_base32check_from32(b"bitcoincash",b"qq8a07g99pt4plk5tm524rguwap0hamg8yvu8rj622"[:-8])
 
 
     
    print("0x000FD7F905285750FED45EE8AA8D1C7742FBF7683966FFA579")
     
    num, zeros = base32decode(b"qq8a07g99pt4plk5tm524rguwap0hamg8yvu8rj622")
     
    print(base64.b16encode(base256encode(num)), zeros)
    ##    
    
    #print(nadr)
    #print(bech32_decode_bitcoincash(nadr))
    data = base32decode(b"qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"[:-8])[:-1]
    print(data)
    
    print(encode_base32check_from256(b"bitcoincash", data) )
    print(encode_base32check_from32(b"bitcoincash", b"qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"[:-8]) )
