import hashlib
from cryptolib.address.address import BitcoinAddress
from cryptolib.openssl.ecdsa import KEY
from cryptolib.address.runmode import TESTNET, MAIN
from random import SystemRandom
from cryptolib.base58 import encode_base58check
import binascii

BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
#b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def privatekey_b58(key, runmode=MAIN):
    prefix = {MAIN: b"\x80", TESTNET: b"\xef"}[runmode]
    # Add 0x01 as address is derived from compressed public key
    return encode_base58check(prefix + key.get_privkey_b256())


def Candidate():
    """
    Generate a random, well-formed mini private key.
    """
    random = SystemRandom()
    return('%s%s' % ('S', ''.join(
        [BASE58[random.randrange(0, len(BASE58))] for i in range(29)])))


def GenerateKeys(numKeys=10):
    """
    Generate mini private keys and output the mini key as well as the full
    private key. numKeys is The number of keys to generate, and
    """
    keysGenerated = 0
    totalCandidates = 0
    while keysGenerated < numKeys:
        try:
            cand = Candidate()
            # Do typo check
            t = '%s?' % cand
            # Take one round of SHA256
            candHash = hashlib.sha256(t.encode()).digest()
            # Check if the first eight bits of the hash are 0
            if candHash[0] == 0:
                privateKey = GetPrivateKey(cand)
                key = KEY()
                key.set_privkey_b256(binascii.unhexlify(privateKey), False)
                privateKey_long = privatekey_b58(key, runmode=MAIN)
                address = BitcoinAddress.from_publickey(key.get_pubkey(), MAIN).to_base58addr()

                print(('mini private key: %s\naddress: %s\nprivake key: %s\n' %
                      (cand, address, privateKey_long)))
                if not CheckShortKey(cand):
                    raise Exception('Invalid!')
                keysGenerated += 1
            totalCandidates += 1
        except KeyboardInterrupt:
            break
    print(('\n%s: %i\n%s: %i\n%s: %.1f' %
          ('Keys Generated', keysGenerated,
           'Total Candidates', totalCandidates,
           'Reject Percentage',
           100 * (1.0 - keysGenerated / float(totalCandidates)))))


def GetPrivateKey(shortKey):
    """
    Returns the hexadecimal representation of the private key corresponding
    to the given short key.
    """
    if CheckShortKey(shortKey):
        return hashlib.sha256(shortKey.encode()).hexdigest()
    else:
        print('Typo detected in private key!')
        return None


def CheckShortKey(shortKey):
    """
    Checks for typos in the short key.
    """
    if len(shortKey) != 30:
        return False
    t = '%s?' % shortKey
    tHash = hashlib.sha256(t.encode()).digest()
    # Check to see that first byte is \x00
    if tHash[0] == 0:
        return True
    return False

print(GenerateKeys(5))
