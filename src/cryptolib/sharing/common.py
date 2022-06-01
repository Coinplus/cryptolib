from functools import reduce
from operator import mul
import random
def extended_gcd(n1, n2):
    """ Returns (bezout_a, bezout_b, gcd) using the extended euclidean algorithm.
        Params
            n1: int
            n2: int
        Returns
            bezout_a: int
            bezout_b: int
            gcd: int """
    x = 0
    x_old = 1
    y = 1
    y_old  = 0
    while n2 != 0:
        Q = n1 // n2 #quotient
        n1, n2 = n2, n1%n2
        x, x_old = x_old - Q*x, x
        y, y_old = y_old - Q*y, y
    bezout_a = x_old
    bezout_b = y_old
    gcd = n1
    return (bezout_a, bezout_b, gcd)

def miller_rabin(n, k=30, r=random.SystemRandom()):
    if n == 2:
        return True
    if not n & 1:
        return False

    def check(a, s, d, n):
        x = pow(a, d, n)
        if x == 1:
            return True
        for i in range(s - 1):
            if x == n - 1:
                return True
            x = pow(x, 2, n)
        return x == n - 1

    s = 0
    d = n - 1

    while d % 2 == 0:
        d >>= 1
        s += 1

    for i in range(k):
        a = r.randrange(2, n - 1)
        if not check(a, s, d, n):
            return False
    return True

def lagrange(points, modulus):
    """ Evaluation at x=0 without computing the polynomial 
        Params
            points: list of Share
        Returns
            y: int """
    V = make_zp_value_type(modulus)
    ls = []
    for i, pj in enumerate(points):
        factors = []
        for j, pm in enumerate(points):
            if i != j:
                factors.append((V(0) - V(pm.x)) / (V(pj.x) - V(pm.x)))
        l = reduce(mul, factors)
        ls.append(l)
    L = map(mul, ls, [p.y for p in points])
    y = int(sum(L, V(0)))
    return y

def make_zp_value_type(modulus):
    class ZpValue(object):
        def __init__(self, value):
            assert (0 <= value < modulus)
            self.value = value
        def __neg__(self):
            return ZpValue((-self.value) % modulus)
        def __add__(self, other):
            return ZpValue((self.value + other.value) % modulus)
        def __cmp__(self, other):
            return cmp(self.value, other.value)
        def __eq__(self, other):
            if type(other) is not type(self):
                return False
            return self.value == other.value
        def __hash__(self):
            return hash(self.value)
        def __sub__(self, other):
            return ZpValue((self.value - other.value) % modulus)
        def __mul__(self, other):
            return ZpValue((self.value * other.value) % modulus)
        def __pow__(self, other):
            return ZpValue(pow(self.value, other.value, modulus))
        def __str__(self):
            return str(self.value)
        def __repr__(self):
            return 'V('+repr(self.value)+')'
        def __invert__(self):
            if self.value == 0:
                raise ZeroDivisionError()
            bezout_a, _, _ = extended_gcd(self.value, modulus)
            return ZpValue(bezout_a % modulus)
        def __truediv__(self, other):
            return self * ~other
        def __int__(self):
            return self.value
    return ZpValue
    
class ZpField(object):
    """ZpZ field with the given modulus"""
    def __init__(self, modulus=186656847850553718541328329082447202544255493182466124110756684855815008420043):
        self.modulus = modulus #default modulus is prime following 2**256
        self.value_type = make_zp_value_type(self.modulus)
        

class Polynomial(object):
    def __init__(self, coefs, zero=0, modulus = 186656847850553718541328329082447202544255493182466124110756684855815008420043):
        self.V = make_zp_value_type(modulus)
        """ Params
                coefs: list of ints (Highest degree first)
                zero: int """
        n = len(coefs)
        self.coefs = [self.V(coefs[n-1-i]) for i in range(n)] or [zero]
        self.zero = self.V(zero)

    def __call__(self, x):
        """ Evaluates the polynomial at x, using Horner's method.
            Params
                x: int
            Returns
                y: ZpValue """
        x = self.V(x) 
        y = self.coefs[0]
        for coef in self.coefs[1:]:
            y = y*x + coef
        return y

    def __eq__(self, other):
        """ Equal operation.
            Params
                other: Polynomial
            Returns
                Boolean """
        if type(other) is not type(self):
            return False
        return self.coefs == other.coefs and self.zero == other.zero

    def __add__(self, other):
        """ Add operation.
            Params
                other: Polynomial
            Returns
                Polynomial """
        assert type(other) is Polynomial
        L1 = len(self.coefs)
        L2 = len(other.coefs)
        coefs = [self.zero] * max(L1, L2)
        for i in range(L1):
            coefs[i + len(coefs) - L1] = self.coefs[i]
        for i in range(L2):
            coefs[i + len(coefs) - L2] += other.coefs[i]
        return Polynomial([int(c) for c in coefs], int(self.zero))

    def __mul__(self, other):
        """ Multiply operation.
            Params
                other: Polynomial, int
            Returns
                Polynomial """
        if type(other) in (int, long):
            coefs = [c * other for c in self.coefs]
        elif type(other) is Polynomial:
            L1 = len(self.coefs)
            L2 = len(other.coefs)
            coefs = [self.zero] * (L1+L2-1)
            for i in range(L1):
                for j in range(L2):
                    coefs[i+j] += self.coefs[i] * other.coefs[j]
        else:
            raise BadTypeError('Other is not a scalar or a polynomial.')
        return Polynomial([int(c) for c in coefs], int(self.zero))
        
    def __repr__(self):
        def repr_degree(degree):
            if degree == 0:
                return ''
            elif degree == 1:
                return ' x  +  '
            else:
                return  ' x^'+str(degree)+'  +  '
        deg = len(self.coefs) - 1
        rep = '['+type(self).__name__+'] '
        for i, c in enumerate(self.coefs):
            rep += str(c) + repr_degree(deg - i)
        return rep

if __name__ == "__main__":
    t = False
    c14 = 58**14
    while not t :
        c14 += 1
        t = miller_rabin(c14)
    t = False
    c28 = 58**28
    while not t :
        c28 += 1
        t = miller_rabin(c28)
    c29 = 58**29
    t = False
    while not t :
        c29 += 1
        t = miller_rabin(c29, k=300)
        print(t)
    print(c14)
    print(c28)
    print(c29)
