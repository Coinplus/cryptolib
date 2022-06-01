import hashlib


def hash_160(public_key):
    hash256 = hashlib.sha256(public_key).digest()
    return hashlib.new('ripemd160', hash256).digest()
