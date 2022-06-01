import random

from cryptolib.crypto import random_b58
from cryptolib.sharing.common import extended_gcd, make_zp_value_type, lagrange, Polynomial
from cryptolib.base58 import base58encode, encode_base58check, bitcoin_b58chars_values, bitcoin_b58chars, base58decode

p14 = 4875194084160298409672797
p28 = 23767517358231570773047645414309870043308402671871
p29 = 1378516006777431104836763434029972462511887354953893
max14 = 58**14
VERBOSE=0


class ReconstructionError(Exception):
    pass

def shamir_reconstruct_base58(shares, modulus, length):
    """ Reconstructs the secret using Lagrange polynomial interpolation.
        Params
            shares: [(int_x, base58_y) , ...]
            modulus:
            length: (of base58)
        Returns
            secret: string """
    V = make_zp_value_type(modulus)
    recovershares = [Share(x, V(base58decode(b58y))) for x, b58y in shares]
    
    s = shamir_reconstruct(recovershares, modulus)
    return base58encode(s, length=length)
    
def shamir_reconstruct(shares, modulus):
    """ Reconstructs the secret using Lagrange polynomial interpolation.
        Params
            shares: list of Share (at least 2 Shares as k > 1 for SSSS)
        Returns
            secret: string """
    if len(shares) < 2:
        raise ReconstructionError('Shares are not correct, reconstruction did not work.')
    secret_int = lagrange(shares, modulus)
    return secret_int


class Share(object):
    def __init__(self, x, y):
        """ 
        This data structure can be a Shamir or an IDA share, containing 
        its x, which is the index, and its y=P(x) which is the share.
        Params
            x: int
            y: field.ZpValue
        """
        self.x = x
        self.y = y
        
    def __eq__(self, other):
        if type(other) is not type(self):
            return False
        if self.x == other.x and self.y == other.y:
            return True
        return False
    

    def __repr__(self):
        rep = '['+type(self).__name__+'] '
        rep += 'Index x = '+str(self.x)+', Share y = P(x) = '+str(self.y)
        return rep

class ShamirSharer(object):
    def __init__(self, rand_source=random.SystemRandom(), prime=186656847850553718541328329082447202544255493182466124110756684855815008420043):
        """ Sets the source of randomness for the Shamir Sharer.
            Params
                rand_source: SystemRandom or FakeRandom """
        self.rand_source = rand_source
        self.prime = prime
    
    def share(self, secret, n, k):
        """ Shares the secret in n shares with a threshold of k shares.
            Params
                secret: string
                n: int
                k: int
            Returns
                shares: list of Share """
        if type(secret) == str:
            secret_int = decodeb256(secret)
        elif type(secret) == int:
            secret_int = secret
        else:
            raise Exception("wrong secret type")
            
        coefficients = self.generate_coefficients(secret_int, k)
        P = Polynomial(coefficients, modulus=self.prime)
        shares = []
        for x in range(1, n+1): #int
            y = P(x) #ZpValue
            assert y.value < self.prime
            shares.append(Share(x, y))
        return shares
    
    def generate_coefficients(self, secret_int, k):
        """ Returns the coefficients suitable to build a polynomial 
            for the Shamir secret sharing of the secret. These are basically
            random numbers between 1 and the Prime number used in the SSSS
            (which is the prime above 2**256)
            Params
                secret_int: int
                k: int (order or polynomial)
            Returns
                coefficients: list of value_type """
        coefficients = [secret_int] #secret is the first coefficient
        for _ in range(k - 1): #generates random coefficients for the polynomial
            coeff = self.rand_source.randrange(1, self.prime)
            coefficients.append(coeff)
        return coefficients


def create(m, l ):

    r58 = random_b58(l)
    if VERBOSE:
        print("secret", r58)
    r = base58decode(r58)
    ss = ShamirSharer(prime = m)
    shares = ss.share(r, 3,2)

    card1 = base58encode(shares[0].y.value, length=14)
    card2 = base58encode(shares[1].y.value, length=14)
    card3 = base58encode(shares[2].y.value, length=14)

    if VERBOSE:
        print(card1, shares[0].y.value,base58decode(card1))
        print(card2, shares[1].y.value,base58decode(card2))
        print(card3, shares[2].y.value,base58decode(card3))

    V = make_zp_value_type(m)
    recovershares = [Share(1, V(base58decode(card1))), Share(2, V(base58decode(card2)))]

    s = shamir_reconstruct(recovershares, m)
    if VERBOSE:
        print("secret", r58)
        print ("reconstruct", base58encode(s, length=l))
    assert base58encode(s, length=l) == r58



if __name__ == "__main__":
    num = 10000
    import sys
    for i in range (num):
        sys.stdout.write(f"\r{i}/{num}".format(i,num))
        create(p14, 14)
        create(p28, 28)
    print('')
