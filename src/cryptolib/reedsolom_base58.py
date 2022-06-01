#different primitive polynomial and non-zero first consecutive root (fcr).
import itertools
N = 59
field_charac = 58
generator = 2 # also 6,8,10,11,13,14,18,23,24 etc...


class ReedSolomonError(Exception):
    pass


def normalize(poly):
    pos = 0
    while pos < len(poly) and poly[pos] == 0:
        pos += 1
    poly = poly[pos:]
    if poly == []:
        poly.append(0)
    return poly

def gf_pow(value, power):
    return (pow(value, power) % N)


def gf_poly_mul(coefs1, coefs2):
    res_coefs = [0] * (len(coefs1)+len(coefs2)-1)
    for j in range(0, len(coefs1)):
        for i in range(0, len(coefs2)):
            res_coefs[(i+j)] = (res_coefs[(i+j)] + coefs1[j] * coefs2[i]) % N
    return res_coefs

def gf_poly_add(coefs1, coefs2):
    res_coefs = [0] * max(len(coefs1), len( coefs2))
    for i in range(0, len(coefs1)):
        res_coefs[i + len(res_coefs) - len(coefs1)] = coefs1[i]
    for i in range(0, len(coefs2)):
        res_coefs[i + len(res_coefs) - len(coefs2)] = (res_coefs[i + len(res_coefs) - len(coefs2)] + coefs2[i])  % N
    return normalize(res_coefs)

def gf_poly_sub(coefs1, coefs2):
    res_coefs = [0] * max(len(coefs1), len( coefs2))
    for i in range(0, len(coefs1)):
        res_coefs[i + len(res_coefs) - len(coefs1)] = coefs1[i]
    for i in range(0, len(coefs2)):
        res_coefs[i + len(res_coefs) - len(coefs2)] = (res_coefs[i + len(res_coefs) - len(coefs2)] - coefs2[i])  % N
    return normalize(res_coefs)

def gf_poly_div(coefs1, coefs2):
    if len(coefs1) < len(coefs2):
        return [0], coefs1
    divisor = []
    remain = list(coefs1)
    for i in range(len(coefs1) - len(coefs2) + 1):
        div = remain[i]
        if div != 0:
            for j in range(0, len(coefs2)):
                remain[i + j] = (remain[i + j] - div * coefs2[j]) % N
        divisor.append(div)
    return divisor, normalize(remain)

def gf_poly_scale(coefs1, number):
    return [(c * number) % N for c in coefs1]


def rs_generator_poly(nsym, fcr=0, generator=2):
    '''Generate an irreducible generator polynomial (necessary to encode a message into Reed-Solomon)'''
    g = [1]
    for i in range(nsym):
        g = gf_poly_mul(g, [1, (-gf_pow(generator, i+fcr)) % N])
    return g

def gf_poly_eval(coefs1, x):
    val = coefs1[0]
    for c in coefs1[1:]:
        val = (val*x + c) % N
    return val


def extended_gcd(n1, n2):
    """Return (bezout_a, bezout_b, gcd) using the extended euclidean algorithm."""
    x, lastx = 0, 1
    y, lasty = 1, 0
    while n2 != 0:
        quotient = n1 // n2
        n1, n2 = n2, n1 % n2
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    bezout_a = lastx
    bezout_b = lasty
    gcd = n1
    return (bezout_a, bezout_b, gcd)


def gf_inverse(n):
    bezout_a, _, _ = extended_gcd(n, 59)
    return bezout_a % 59

def rs_encode_msg(msg_in, nsym, fcr=0, generator=2):
    '''Reed-Solomon main encoding function, using polynomial division (Extended Synthetic Division, the fastest algorithm available to my knowledge), better explained at http://research.swtch.com/field'''
    global field_charac
    if (len(msg_in) + nsym) > field_charac: raise ValueError("Message is too long (%i when max is %i)" % (len(msg_in)+nsym, field_charac))
    gen = rs_generator_poly(nsym, fcr, generator)
    msg_padded = msg_in + [0] * (len(gen)-1)
    _div, remain = gf_poly_div(msg_padded, gen)
    #poly = gf_poly_sub(msg_padded, remain)
    #return poly
    return msg_in, [(-r) % N for r in  remain ]

def rs_calc_syndromes(msg, nsym, fcr=0, generator=2):
    '''Given the received codeword msg and the number of error correcting symbols (nsym), computes the syndromes polynomial.
    Mathematically, it's essentially equivalent to a Fourrier Transform (Chien search being the inverse).
    '''
    # Note the "[0] +" : we add a 0 coefficient for the lowest degree (the constant). This effectively shifts the syndrome, and will shift every computations depending on the syndromes (such as the errors locator polynomial, errors evaluator polynomial, etc. but not the errors positions).
    # This is not necessary as anyway syndromes are defined such as there are only non-zero coefficients (the only 0 is the shift of the constant here) and subsequent computations will/must account for the shift by skipping the first iteration (eg, the often seen range(1, n-k+1)), but you can also avoid prepending the 0 coeff and adapt every subsequent computations to start from 0 instead of 1.
    return [gf_poly_eval(msg, gf_pow(generator, i+fcr)) for i in range(nsym)]
    #E = C - D
    #D = C - E


def disprecancy2(synd, err_locator, n, L):
    delta = synd[n]
    for i in range(1, L+1):
        if -i-1 >= -len(err_locator): # we could allow the err_locator poly to start with zeros also
            delta = (delta + err_locator[-i-1] * synd[n - i]) % N
    return delta

def rs_find_error_locator(synd, nsym, erase_loc=None, erase_count=0):
    '''Find error/errata locator and evaluator polynomials with Berlekamp-Massey algorithm'''
    err_loc = [1] # This is the main variable we want to fill, also called Sigma in other notations or more formally the errors/errata locator polynomial.
    old_loc = [1] # BM is an iterative algorithm, and we need the errata locator polynomial of the previous iteration in order to update other necessary variables.
    delta_prev = 1
    m = 1
    L = 0
    for i in range(nsym): # generally: nsym-erase_count == len(synd), except when you input a partial erase_loc and using the full syndrome instead of the Forney syndrome, in which case nsym-erase_count is more correct (len(synd) will fail badly with IndexError).
        delta = disprecancy2(synd, err_loc, i, L)
        if delta == 0:
            m += 1
        elif L * 2 <= nsym:
            temp = list(err_loc)
            err_loc = gf_poly_sub(err_loc, gf_poly_mul([delta * gf_inverse(delta_prev)] + [0] * (m), old_loc))
            L = i + 1 - L
            old_loc = temp
            delta_prev = delta
            m = 1
        else:
            err_loc = gf_poly_sub(err_loc, gf_poly_mul([delta * gf_inverse(delta_prev)] + [0] * (m), old_loc))
            m += 1
            #C(x) = C(x) - d b^{-1} x^m B(x);
            #m = m + 1;
            print ("=>", i, "3")

    err_loc = list(itertools.dropwhile(lambda x: x == 0, err_loc)) # drop leading 0s, else errs will not be of the correct size
    errs = len(err_loc) - 1
    if (errs-erase_count) * 2 > nsym:
        raise ReedSolomonError("Too many errors to correct")
    return err_loc


def rs_find_errors(err_loc, nmess, generator=2):
    '''Find the roots (ie, where evaluation = zero) of error polynomial by bruteforce trial, this is a sort of Chien's search (but less efficient, Chien's search is a way to evaluate the polynomial such that each evaluation only takes constant time).'''
    # nmess = length of whole codeword (message + ecc symbols)
    errs = len(err_loc) - 1
    err_pos = []
    for i in range(nmess): # normally we should try all 2^8 possible values, but here we optimize to just check the interesting symbols
        if gf_poly_eval(err_loc, gf_pow(generator, i)) == 0: # It's a 0? Bingo, it's a root of the error locator polynomial, in other terms this is the location of an error
            err_pos.append(nmess - 1 - i)
    # Sanity check: the number of errors/errata positions found should be exactly the same as the length of the errata locator polynomial
    if len(err_pos) != errs:
        # TODO: to decode messages+ecc with length n > 255, we may try to use a bruteforce approach: the correct positions ARE in the final array j, but the problem is because we are above the Galois Field's range, there is a wraparound so that for example if j should be [0, 1, 2, 3], we will also get [255, 256, 257, 258] (because 258 % 255 == 3, same for the other values), so we can't discriminate. The issue is that fixing any errs_nb errors among those will always give a correct output message (in the sense that the syndrome will be all 0), so we may not even be able to check if that's correct or not, so I'm not sure the bruteforce approach may even be possible.
        raise ReedSolomonError("Too many (or few) errors found by Chien Search for the errata locator polynomial!")
    return err_pos


def rs_find_errata_locator(e_pos, generator=2):
    '''Compute the erasures/errors/errata locator polynomial from the erasures/errors/errata positions (the positions must be relative to the x coefficient, eg: "hello worldxxxxxxxxx" is tampered to "h_ll_ worldxxxxxxxxx" with xxxxxxxxx being the ecc of length n-k=9, here the string positions are [1, 4], but the coefficients are reversed since the ecc characters are placed as the first coefficients of the polynomial, thus the coefficients of the erased characters are n-1 - [1, 4] = [18, 15] = erasures_loc to be specified as an argument.'''
    # See: http://ocw.usu.edu/Electrical_and_Computer_Engineering/Error_Control_Coding/lecture7.pdf and Blahut, Richard E. "Transform techniques for error control codes." IBM Journal of Research and development 23.3 (1979): 299-315. http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.92.600&rep=rep1&type=pdf and also a MatLab implementation here: http://www.mathworks.com/matlabcentral/fileexchange/23567-reed-solomon-errors-and-erasures-decoder/content//RS_E_E_DEC.m
    e_loc = [1] # just to init because we will multiply, so it must be 1 so that the multiplication starts correctly without nulling any term
    # erasures_loc is very simple to compute: erasures_loc = prod(1 - x*alpha**i) for i in erasures_pos and where alpha is the alpha chosen to evaluate polynomials (here in this library it's gf(3)). To generate c*x where c is a constant, we simply generate a Polynomial([c, 0]) where 0 is the constant and c is positionned to be the coefficient for x^1.
    for i in e_pos:
        e_loc = gf_poly_mul( e_loc, [(-gf_pow(generator, i) % 59), 1] )
        #e_loc = gf_poly_mul( e_loc, gf_poly_add([1], [gf_pow(generator, i), 0]) )
    return e_loc


def rs_find_error_evaluator(synd, err_loc, nsym):
    '''Compute the error (or erasures if you supply sigma=erasures locator polynomial, or errata) evaluator polynomial Omega from the syndrome and the error/erasures/errata locator Sigma. Omega is already computed at the same time as Sigma inside the Berlekamp-Massey implemented above, but in case you modify Sigma, you can recompute Omega afterwards using this method, or just ensure that Omega computed by BM is correct given Sigma.'''
    # Omega(x) = [ Synd(x) * Error_loc(x) ] mod x^(n-k+1)
    _, remainder = gf_poly_div( gf_poly_mul(synd + [0], err_loc), ([1] + [0]*(nsym+1)) ) # first multiply syndromes * errata_locator, then do a polynomial division to truncate the polynomial to the required length

    # Faster way that is equivalent
    #remainder = gf_poly_mul(synd, err_loc) # first multiply the syndromes with the errata locator polynomial
    #remainder = remainder[len(remainder)-(nsym+1):] # then divide by a polynomial of the length we want, which is equivalent to slicing the list (which represents the polynomial)
    return remainder

def rs_correct_errata(msg_in, synd, err_pos, generator=2): # err_pos is a list of the positions of the errors/erasures/errata
    '''Forney algorithm, computes the values (error magnitude) to correct the input message.'''
    #global field_charac
    msg = msg_in
    # calculate errata locator polynomial to correct both errors and erasures (by combining the errors positions given by the error locator polynomial found by BM with the erasures positions given by caller)
    coef_pos = [len(msg) - 1 - p for p in err_pos] # need to convert the positions to coefficients degrees for the errata locator algo to work (eg: instead of [0, 1, 2] it will become [len(msg)-1, len(msg)-2, len(msg) -3])
    err_loc = rs_find_errata_locator(coef_pos, generator)
    err_eval = rs_find_error_evaluator(synd[::-1], err_loc, len(err_loc)-1)[::-1]
    X = [] # will store the position of the errors
    for i in range(len(coef_pos)):
        #l = 58 - coef_pos[i]
        X.append( gf_pow(generator, coef_pos[i]) )
        #X.append(coef_pos[i])

    # Forney algorithm: compute the magnitudes
    E = [0] * len(msg) # will store the values that need to be corrected (substracted) to the message containing errors. This is sometimes called the error magnitude polynomial.
    Xlength = len(X)

    # see https://www.cs.duke.edu/courses/spring11/cps296.3/decoding_rs.pdf
    for i, Xi in enumerate(X):
        Xi_inv = gf_inverse(Xi)

        err_loc_prime_tmp = []
        for j in range(Xlength):
            if j != i:
                err_loc_prime_tmp.append( (1 - Xi_inv *  X[j]) % 59 )

        err_loc_prime = 1
        for coef in err_loc_prime_tmp:
            err_loc_prime = (err_loc_prime * coef) % 59
        # equivalent to: err_loc_prime = functools.reduce(gf_mul, err_loc_prime_tmp, 1)

        # Compute y (evaluation of the errata evaluator polynomial)
        # This is a more faithful translation of the theoretical equation contrary to the old forney method. Here it is exactly copy/pasted from the included presentation decoding_rs.pdf: Yl = omega(Xl.inverse()) / prod(1 - Xj*Xl.inverse()) for j in len(X) (in the paper it's for j in s, but it's useless when len(X) < s because we compute neutral terms 1 for nothing, and wrong when correcting more than s erasures or erasures+errors since it prevents computing all required terms).
        # Thus here this method works with erasures too because firstly we fixed the equation to be like the theoretical one (don't know why it was modified in _old_forney(), if it's an optimization, it doesn't enhance anything), and secondly because we removed the product bound on s, which prevented computing errors and erasures above the s=(n-k)//2 bound.
        y = gf_poly_eval(err_eval[::-1], Xi_inv) # numerator of the Forney algorithm (errata evaluator evaluated)
        y = (gf_pow(Xi, 1) *  y) % 59 # adjust to fcr parameter

        # Compute the magnitude
        magnitude = (y * gf_inverse(err_loc_prime)  % 59) # magnitude value of the error, calculated by the Forney algorithm (an equation in fact): dividing the errata evaluator with the errata locator derivative gives us the errata magnitude (ie, value to repair) the ith symbol
        E[err_pos[i]] = magnitude # store the magnitude for this error into the magnitude polynomial

    # Apply the correction of values to get our message corrected! (note that the ecc bytes also gets corrected!)
    # (this isn't the Forney algorithm, we just apply the result of decoding here)
    msg = gf_poly_sub(msg, E) # equivalent to Ci = Ri - Ei where Ci is the correct message, Ri the received (senseword) message, and Ei the errata magnitudes (minus is replaced by XOR since it's equivalent in GF(2^p)). So in fact here we substract from the received message the errors magnitude, which logically corrects the value to what it should be.
    return msg

def rs_correct_msg(msg_in, nsym, fcr=0, generator=2, erase_pos=None):
    '''Reed-Solomon main decoding function'''
    global field_charac
    if len(msg_in) > field_charac:
        # Note that it is in fact possible to encode/decode messages that are longer than field_charac, but because this will be above the field, this will generate more error positions during Chien Search than it should, because this will generate duplicate values, which should normally be prevented thank's to the prime polynomial reduction (eg, because it can't discriminate between error at position 1 or 256, both being exactly equal under galois field 2^8). So it's really not advised to do it, but it's possible (but then you're not guaranted to be able to correct any error/erasure on symbols with a position above the length of field_charac -- if you really need a bigger message without chunking, then you should better enlarge c_exp so that you get a bigger field).
        raise ValueError("Message is too long (%i when max is %i)" % (len(msg_in), field_charac))

    # prepare the syndrome polynomial using only errors (ie: errors = characters that were either replaced by null byte or changed to another character, but we don't know their positions)
    synd = rs_calc_syndromes(msg_in, nsym, fcr, generator)
    if max(synd) == 0:
        return msg_in[:-nsym], msg_in[-nsym:]  # no errors

    # compute the error locator polynomial using Berlekamp-Massey
    err_loc = rs_find_error_locator(synd, nsym) #, erase_count=len(erase_pos)
    # locate the message errors using Chien search (or bruteforce search)
    err_pos = rs_find_errors(err_loc[::-1], len(msg_in), generator)
    if err_pos is None:
        raise ReedSolomonError("Could not locate error")

    # Find errors values and apply them to correct the message
    # compute errata evaluator and errata magnitude polynomials, then correct errors and erasures
    msg_in = rs_correct_errata(msg_in, synd, err_pos, generator) # note that we here use the original syndrome, not the forney syndrome (because we will correct both errors and erasures, so we need the full syndrome)
    # check if the final message is fully repaired
    synd = rs_calc_syndromes(msg_in, nsym, fcr, generator)
    if max(synd) > 0:
        raise ReedSolomonError("Could not correct message")
    # return the successfully decoded message
    return msg_in[:-nsym], msg_in[-nsym:] # also return the corrected ecc block so that the user can check()


b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz+'
b58chars_values = dict((c, val) for val, c in enumerate(b58chars))


class ReedSolomonBase58(object):
    def __init__(self, nsym=10, nsize=255, generator=2):
        self.nsym = nsym # number of ecc symbols
        self.nsize = nsize # maximum length of one chunk
        self.generator = generator # generator integer, must be prime

    def encode(self, data):
        assert len(data) <= self.nsize
        base58values = [b58chars_values[c] for c in data]
        _msgin, ecc = rs_encode_msg(base58values, self.nsym, 0, generator=self.generator)
        return data + "/" + "".join([b58chars[e] for e in ecc])

    def decode(self, data, erase_pos=None, only_erasures=False):
        assert len(data) <= self.nsize
        msg, ecc = data.split("/")
        base59values = [b58chars_values[c] for c in msg] + [b58chars_values[c] for c in ecc]
        fixed_msg, fixed_ecc = rs_correct_msg(base59values, self.nsym, fcr=0, generator=self.generator)
        return "".join([b58chars[v] for v in fixed_msg])


if __name__ == '__main__':
    rs = ReedSolomonBase58(nsym=20)
    print (rs.encode("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"))
    #print (rs.decode("4J98A2WpEZ73CNmQviecrnyiWrnqRhWNLy/wngn7nBxAL"))
    """print (rs.decode("4J98A1WpEZ73CNmQviecrnyiWrnqRhWNLy/wngn7nBxAL"))
    print ("****************")
    print (rs.decode("4J98c1WpEZ73CNmQviecrnyiWrnqRhWNLy/wngn7nBxAL"))# ==> bug
    print (rs.decode("4J98A1WpEZ73CNmQviecrnyiWrnqRhWNLy/vngn7nBxAL"))"""

    #print (rs.decode("3J98t1WpEZ73CNmQviecrRyiWrnqRhWNLy/T5WC7rgdRcvGFVzczEdx"))
