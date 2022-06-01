

def base256encode(value, pad=32):
    """ Return a big endian (most significant byte first) bytestring from an integer."""
    result_bytes = []
    while value != 0:
        div, mod = divmod(value, 256)
        result_bytes.append(mod)
        value = div
    if pad:
        result_bytes += [0] * max(pad - len(result_bytes), 0)
    return bytes(reversed(result_bytes))


def base256decode(bytestr):
    """ Return an integer from a big endian (most significant byte first) bytestring."""
    value = 0
    for b in bytestr:
        value = value * 256 + b
    return (value)



if __name__ == '__main__':
    import binascii
    print (base256decode(binascii.unhexlify('4ab7e67d62e4b4e3c82600fdc4664bb4a76f2106a0dc1c1d211c0c1a2f2e9f40')))
    print (binascii.hexlify(base256encode(33796074590083941317384414994321501485336775833483418286710219101736656609088)))
    