#!/usr/bin/env python
import os
import random

try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False


# GMP's powmod has greater overhead than Python's pow, but is faster.
# From a quick experiment on our machine, this seems to be the break even:
_USE_MOD_FROM_GMP_SIZE = (1 << (8*2))


def gcd(a, b):
    """Compute the greatest common divisor (gcd) using the Euclid algorithm"""
    if a == b:
        return a
    if a > b:
        return gcd(a - b, b)
    elif b > a:
        return gcd(a, b - a)

def nonrec_gcd(a, b):
    """Compute the greatest common divisor (gcd) using the Euclid algorithm with
    a non-recursive approach"""
    if a < b:
        a = a + b
        b = a - b
        a = a - b
    if b == 0:
        return a
    while a % b != 0:
        a = a + b
        b = a - b
        a = a - b
        b = b % a
    return b

def powmod(a, b, c):
    """
    Uses GMP, if available, to do a^b mod c where a, b, c
    are integers.
    :return int: (a ** b) % c
    """
    if a == 1:
        return 1
    if not HAVE_GMP or max(a, b, c) < _USE_MOD_FROM_GMP_SIZE:
        return pow(a, b, c)
    else:
        return int(gmpy2.powmod(a, b, c))


def invert(a, b):
    """
    The multiplicitive inverse of a in the integers modulo b.
    :return int: x, where a * x == 1 mod b
    """
    if HAVE_GMP:
        return int(gmpy2.invert(a, b))
    else:
        # http://code.activestate.com/recipes/576737-inverse-modulo-p/
        for d in range(1, b):
            r = (d * a) % b
            if r == 1:
                break
        else:
            raise ValueError('%d has no inverse mod %d' % (a, b))
        return d

def inverse_mod(a, m):
  """Inverse of a mod m."""

  if a < 0 or m <= a:
    a = a % m

  # From Ferguson and Schneier, roughly:

  c, d = a, m
  uc, vc, ud, vd = 1, 0, 0, 1
  while c != 0:
    q, c, d = divmod(d, c) + (c,)
    uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc

  # At this point, d is the GCD, and ud*a+vd*m = d.
  # If d == 1, this means that ud is a inverse.

  assert d == 1
  if ud > 0:
    return ud
  else:
    return ud + m

def randomnumber(n, inf=1):
    return random.SystemRandom().randrange(inf, n)

def is_prime(p):
    return gmpy2.is_prime(p)

def getprimeover(N):
    """Return a random N-bit prime number using the System's best
    Cryptographic random source.
    Use GMP if available, otherwise fallback to PyCrypto
    """
    if HAVE_GMP:
        randfunc = random.SystemRandom()
        r = gmpy2.mpz(randfunc.getrandbits(N))
        r = gmpy2.bit_set(r, N - 1)
        return int(gmpy2.next_prime(r))
    elif HAVE_CRYPTO:
        return number.getPrime(N, os.urandom)
    else:
        raise NotImplementedError("No pure python implementation sorry")


def isqrt(N):
    """ returns the integer square root of N """
    if HAVE_GMP:
        return int(gmpy2.isqrt(N))
    else:
        return improved_i_sqrt(N)


def improved_i_sqrt(n):
    """ taken from 
    http://stackoverflow.com/questions/15390807/integer-square-root-in-python 
    Thanks, mathmandan """
    assert n >= 0
    if n == 0:
        return 0
    i = n.bit_length() >> 1    # i = floor( (1 + floor(log_2(n))) / 2 )
    m = 1 << i    # m = 2^i
    #
    # Fact: (2^(i + 1))^2 > n, so m has at least as many bits
    # as the floor of the square root of n.
    #
    # Proof: (2^(i+1))^2 = 2^(2i + 2) >= 2^(floor(log_2(n)) + 2)
    # >= 2^(ceil(log_2(n) + 1) >= 2^(log_2(n) + 1) > 2^(log_2(n)) = n. QED.
    #
    while (m << i) > n: # (m<<i) = m*(2^i) = m*m
        m >>= 1
        i -= 1
    d = n - (m << i) # d = n-m^2
    for k in range(i-1, -1, -1):
        j = 1 << k
        new_diff = d - (((m<<1) | j) << k) # n-(m+2^k)^2 = n-m^2-2*m*2^k-2^(2k)
        if new_diff >= 0:
            d = new_diff
            m |= j
    return m
