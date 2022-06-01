import base64
import hashlib
import hmac
import datetime
import time
import sys
import struct


def hotp_make(secret, input):
    """
    :param secret: shared secret (base32)
    :param input: msg to transform (6 digits)
    :return: OTP, 6 digits
    """
    h = hmac.new(
        base64.b32decode(secret, casefold=True),
        struct.pack(">Q", input),
        hashlib.sha1,
    ).digest()
    o = ord(h[19]) & 0xf
    h2 = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1000000
    return h2


def totp_make(secret, for_time=None, window=30):
    """
    :param secret: shared secret (base32)
    :param for_time: optional time at which to generate TOTP
    :param window: period of validity for TOTP (defaults to 30s)
    :return: TOTP, 6 digits, token
    """
    if for_time is None:
        for_time = datetime.datetime.now()
    i = time.mktime(for_time.timetuple())
    intervals = int(i / window)
    return hotp_make(secret, intervals)


if __name__ == "__main__":
    secret = "AAAAAAAAAAAAAAAA"
    unixtime = 0
    if len(sys.argv) > 1:
        unixtime = int(sys.argv[1])
    if unixtime > 1:
        date = datetime.datetime.fromtimestamp(unixtime)
    else:
        date = datetime.datetime.now()
    print("TOTP token for secret '%s' at '%s' is: %s" % (
        secret, date, totp_make(secret, for_time=date)))
