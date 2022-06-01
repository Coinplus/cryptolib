from cryptolib.utils import count_leading_values
from cryptolib.sha256 import doublesha256, sha256checksum
from cryptolib.base256 import base256encode, base256decode

bitcoin_b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
bitcoin_b58chars_values = dict((c, val) for val, c in enumerate(bitcoin_b58chars))
ripple_b58chars = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
ripple_b58chars_values = dict((c, val) for val, c in enumerate(ripple_b58chars))
class Base58DecodingError(Exception):
    pass


class ChecksumError(Base58DecodingError):
    pass


def base58encode(value, leading_zeros=None, ripple=False, length=None):
    b58chars = ripple_b58chars if ripple else  bitcoin_b58chars
        
    result = ""
    while value != 0:
        div, mod = divmod(value, 58)
        result = b58chars[mod] + result
        value = div
    if leading_zeros:
        return b58chars[0] * leading_zeros + result
    if length is not None:
        result = b58chars[0] * (length-len(result)) + result
    return result


def base58decode(b58str, ripple=False):
    b58chars_values = ripple_b58chars_values if ripple else  bitcoin_b58chars_values
    value = 0
    for c in b58str:
        if c not in b58chars_values:
            raise Base58DecodingError("Invalid character: %s" % (c))
        value = value * 58 + b58chars_values[c]
    return (value)


def solo_check(string, size=1):
    check = int.from_bytes(doublesha256(string.encode("ascii")), "little") % 58**size
    return string + base58encode(check, length=size)

def verify_solo_check(string, size=1):
    raw = string[:-size]
    check = int.from_bytes(doublesha256(raw.encode("ascii")), "little") % 58**size
    return base58encode(check, length=size) == string[-size:]

def base58check(content):
    data = content + sha256checksum(content)
    return (base58encode(base256decode(data)))

def count_leading_base58_zeros(b58str, ripple):
    b58chars = ripple_b58chars if ripple else  bitcoin_b58chars
    return count_leading_values(b58str, b58chars[0])

def decode_base58check(data, preserve_leading_zeros=True, ripple=False):
    """Verify the checksum + decode """
    raw = preserve_leading_zeros and bytes(count_leading_base58_zeros(data, ripple) * [0]) or b""
    raw += base256encode(base58decode(data, ripple=ripple), pad=None)
    '''if len(raw) != 25:
        raise Base58DecodingError("base58check: format error")'''
    content, check = raw[:-4], raw[-4:]
    digest2 = doublesha256(content)
    if (digest2[:4] != check):
        raise ChecksumError("base58check: checksum error %s != %s" % (digest2[:4].hex(), check.hex()))
    return (content)

def encode_base58check(content, preserve_leading_zeros=True, ripple=False):
    """ Encode a bytestring (bid endian) as base58 with checksum.

        preserve_leading_zeros: argument used for MAIN bitcoin addresses (e.g.ADDRESSVERSION == 0)
        to preserve base256 leading zeros as base58 zeros ('1').
        For example:
            addrversion=00,hash160=00602005b16851c4f9d0e2c82fa161ac8190e04c will give the bitcoin address:
            112z9tWej11X94khKKzofFgWbdhiXLeHPD
    """
    data = content + doublesha256(content)[:4]
    leading_zeros = None
    if preserve_leading_zeros:
        leading_zeros = count_leading_values(data, 0)
    return (base58encode(base256decode(data), leading_zeros=leading_zeros, ripple=ripple))


if __name__ == '__main__':
    # print base58encode(726378263726783267836783)
    # print base58decode("9eDfMUZG7gNxGN")
    # print decode_base58check("1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp").encode("hex")

    # print hex(170271043970117126209146686412412226333644335735617898907)
    print(hex(base58decode("1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp")))
    print(encode_base58check(b"\x00"*21))
    print(encode_base58check(b"\x00"+b"\xff"*20))
    for x in range(0,256):
      print(x, encode_base58check(b"\x00"+b"\x00"*19+bytearray([x])))
      if len(encode_base58check(b"\x00"+b"\x00"*19+bytearray([x]))) == 26:
          print("SUCCESS")
