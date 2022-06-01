# code inspired by electrum
from cryptolib.hex import bytes2hex, hex2bytes
import struct
from cryptolib.base256 import base256decode


def op_push(i):
    if i < 0x4c:
        return struct.pack("B", i)
    elif i < 0xff:
        return b'\x4c' + struct.pack("B", i)
    elif i < 0xffff:
        return b'\x4d' + struct.pack("<H", i) 
    else:
        return b'\x4e' + struct.pack("<I", i)


class EnumException(Exception):
    pass


class Enumeration:
    '''enum-like type
    From the Python Cookbook, downloaded from http://code.activestate.com/recipes/67107/
    '''
    def __init__(self, name, enumList):
        self.__doc__ = name
        lookup = { }
        reverseLookup = { }
        i = 0
        uniqueNames = [ ]
        uniqueValues = [ ]
        for x in enumList:
            if type(x) == tuple:
                x, i = x
            if type(x) != str:
                raise EnumException("enum name is not a string: " + x)
            if type(i) != int:
                raise EnumException("enum value is not an integer: " + i)
            if x in uniqueNames:
                raise EnumException("enum name is not unique: " + x)
            if i in uniqueValues:
                raise EnumException("enum value is not unique for " + x)
            uniqueNames.append(x)
            uniqueValues.append(i)
            lookup[x] = i
            reverseLookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverseLookup = reverseLookup
    def __getattr__(self, attr):
        if attr not in self.lookup:
            raise AttributeError
        return self.lookup[attr]
    def whatis(self, value):
        return self.reverseLookup[value]


opcodes = Enumeration("Opcodes", [
    ("OP_0", 0), ("OP_PUSHDATA1",76), "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE", "OP_RESERVED",
    "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7",
    "OP_8", "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF", "OP_ELSE", "OP_ENDIF", "OP_VERIFY",
    "OP_RETURN", "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP", "OP_2OVER", "OP_2ROT", "OP_2SWAP",
    "OP_IFDUP", "OP_DEPTH", "OP_DROP", "OP_DUP", "OP_NIP", "OP_OVER", "OP_PICK", "OP_ROLL", "OP_ROT",
    "OP_SWAP", "OP_TUCK", "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE", "OP_INVERT", "OP_AND",
    "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY", "OP_RESERVED1", "OP_RESERVED2", "OP_1ADD", "OP_1SUB", "OP_2MUL",
    "OP_2DIV", "OP_NEGATE", "OP_ABS", "OP_NOT", "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV",
    "OP_MOD", "OP_LSHIFT", "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR",
    "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL", "OP_LESSTHAN",
    "OP_GREATERTHAN", "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX",
    "OP_WITHIN", "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160",
    "OP_HASH256", "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    ("OP_SINGLEBYTE_END", 0xF0),
    ("OP_DOUBLEBYTE_BEGIN", 0xF000),
    "OP_PUBKEY", "OP_PUBKEYHASH",
    ("OP_INVALIDOPCODE", 0xFFFF),
])


def multisig_script(public_keys, m):
    n = len(public_keys)
    assert n <= 15
    assert m <= n
    op_m = bytes([opcodes.OP_1 + m - 1])
    op_n = bytes([opcodes.OP_1 + n - 1])
    keylist = [op_push(len(k)) + k for k in public_keys]
    return op_m + b''.join(keylist) + op_n + b'\xae'   #ae=OP_CHECKMULTISIG


def bytestring_compare(a, b):
    for i in len(a):
        if a[i] == b[i]:
            continue
        else:
            return (a[i] - b[i])
    return 0
        
if __name__ == '__main__':
    from cryptolib.hdkey import HDKey
    from cryptolib.bitcoin.address import BitcoinAddress
    from cryptolib.bitcoin.runmode import MAIN
    
    k1 = HDKey.deserialize("xpub661MyMwAqRbcEqF2ycCvWhtSfxhFZrLu4roRL61XiPzoET4jexyaSs3G86qupAj3kqcwY9XeiokwTq7S32SkESWqMidF5JjCWKxVfcM4wR8")
    k2 = HDKey.deserialize("xpub661MyMwAqRbcFQRGTdCeLFUHL6khFFiADBY8cTvjDMcjHAZU1AxNMGmbjik4Lzyf3Tn6YKnDFtajt2PDSFYvNoFgdDKeuD6sg3MzA1h9CQQ")
    
    for i in range(1000):
#        print ("--------", k1.child(i).pubkey())
        """"025b70c5545f2ca46a3ada301b40c4c33f58df71995c8dbf46fc5e97647f23e67b
            023c84d084c5f8754a01d2489017d9ec043376f251e35d701d55a32b5bd9c988a5
            
            m/0/0/1
            02f5583482b853e74774bb025724dac579a358fd309129d140b242cae6d7301780
            03de70454dc903ce9fe62ccb3a55904bfbf3639a0f7555666c8285bef427c4a8b5

            m/0/0/2
            0394f77a5c0d3cace35c9530d749e5192fbce7f88d800503c34b08d75468e4d065
            02c1cdb4fa6425a65dc81f6b4e0a03a01e48309df3c931e4843d2f4f4fbf6c2df9
        """
        #print (bytes2hex(k1.child(0).child(i).pubkey()))
        #print (bytes2hex(k2.child(0).child(i).pubkey()))
        public_keys = sorted([k2.child(0).child(i).pubkey(), k1.child(0).child(i).pubkey()], key=lambda s: base256decode(s))
        #s = multisig_script(, 2)
        s2 = multisig_script(public_keys, 2)
        addr = BitcoinAddress.from_p2sh_script(s2, MAIN)
        print (addr.to_base58addr())
    
    