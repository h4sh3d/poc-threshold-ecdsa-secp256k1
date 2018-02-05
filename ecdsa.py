#!/usr/bin/env python
import utils
import gmpy2
import hashlib

P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# ELLIPTIC CURVE POINT ARITHMETIC
INFINITY = float("inf")
ZERO = (INFINITY, INFINITY)

def is_zero(p):
    x, y = p
    return x == INFINITY

def neg(p):
    x, y = p
    return x, -y

def contains_point(p):
    x, y = p
    return (y * y - (x * x * x + a * x + b)) % P == 0

def point_double(p):
    # print("double")
    if is_zero(p): return ZERO
    px, py = p
    lmbda = ((3 * px * px + a) * utils.inverse_mod(2 * py, P)) % P
    rx = (lmbda * lmbda - 2 * px) % P
    ry = (lmbda * (px - rx) - py) % P
    return rx, ry

def point_add(p, q):
    # print("add")
    px, py = p
    qx, qy = q
    if is_zero(p): return q
    if is_zero(q): return p
    if px == qx:
      if (py + qy) % P == 0:
        return ZERO
      else:
        return point_double(p)
    lmbda = ((qy - py) * utils.inverse_mod(qx - px, P)) % P
    rx = (lmbda * lmbda - px - qx) % P
    ry = (lmbda * (px - rx) - py) % P
    return rx, ry

def point_mult(p, scalar):
    """Multiply a point by an integer."""

    def leftmost_bit(x):
      assert x > 0
      result = 1
      while result <= x:
        result = 2 * result
      return result // 2

    e = scalar
    if n:
      e = e % n
    if e == 0:
      return ZERO
    if is_zero(p):
      return ZERO
    assert e > 0

    # From X9.62 D.3.2:

    e3 = 3 * e
    negative_self = neg(p)
    i = leftmost_bit(e3) // 2
    result = p
    while i > 1:
      result = point_double(result)
      if (e3 & i) != 0 and (e & i) == 0:
        result = point_add(result, p)
      if (e3 & i) == 0 and (e & i) != 0:
        result = point_add(result, negative_self)
      i = i // 2

    return result

def key_gen(g=G):
    d = utils.randomnumber(n-1)
    Q = get_pub(d, g)
    return Q, d

def gen_priv():
    return utils.randomnumber(n-1)

def aggregate(*keys):
    k = 0
    for key in keys:
        k = k + key % n
    return k

def get_pub(priv, g=G):
    return point_mult(g, priv)

def sign(e, g, n, d):
    while True:
        k = utils.randomnumber(n-1)
        x, y = point_mult(g, k)
        if x % n != 0:
            break
    r = x
    s = utils.invert(k, n) * (e + r * d) % n
    return r, s

def verify(sig, e, pub, g, n):
    r, s = sig
    w = utils.invert(s, n)
    u1 = e * w % n
    u2 = r * w % n
    x, y = point_add(point_mult(g, u1), point_mult(pub, u2))
    return r == x

def expand_pub(point):
    l = 64
    x, y = point
    xs = '%x' % x
    ys = '%x' % y
    px = '0' * (l - len(xs))
    py = '0' * (l - len(ys))
    return '04%s%s%s%s' % (px, xs, py, ys)

def recover_pub(s):
    prefix = s[:2]
    if prefix == "04":
        x = s[2:66]
        y = s[66:]
        return long(x, 16), long(y, 16)
    return (None, None)

def test():
    # G x 2313 = 
    res = (0x8199C9D61224F51FE6DCDC333869D86095C0BD8E210D2D7F8FED2804A89AADF9, 
        0xBE89724F5CBD2384AE9BBD73F030DC74A158EE7D2A9D292DDAAE30574B1EC89B)
    print(contains_point(res))
    # print(point_mult(G, 2313))
    # print(res)
    print(point_mult(G, 2313) == res)

    # resdouble = (
        # 0xFCCC6C53DBB615C0324647998F2C4F3ED47E84E3BDE5A500E025AFF4AECA9C6C, 
        # 0x41768DB0A342DC7B5164428C0FCF238B5EA71182D562D6D22551CFA7B4E13394)
    print(point_add(res, res) == point_double(res))

    # G x 78439 =
    res2 = (0xA92DDF0D702330BD535FBB5F9C0EC4E04A4C8427ECA4E33818D663FF0FD2A74E, 
        0xF9F45EB21C5A2395097EB0336F2683A3662E03E312B7A52BC98E20F105E0FF9)
    print(contains_point(res2))
    print(point_mult(G, 78439) == res2)

    resadd = (0xB425DFAB6C95A64F0ACE24DAFF4440CE02EEF71EB7127DC4924D0869F10E4C1B, 
        0x1B16D85927660387414111493AAF0CF0B6B3B83F4F6E5EF9EFBD3CAEBE4F7AF0)
    print(contains_point(resadd))
    print(point_add(res, res2) == resadd)
    
    i = 3
    j = 10

    x = point_mult(G, i)
    y = point_mult(x, j)
    z = point_mult(G, i*j)
    print(y, z)
    print(y == z)

def run_ecdsa():
    priv = 0xf8dcb8663acbd64296da17d9692a8971286cee1c41621660ab5d925767df7cc5
    res = point_mult(G, priv)
    rec = recover_pub("0473b7aaf653110c20d3c42c18017b8243d6f5a99cb84fba0cbc5ef3ffb74ffc01a9571fb974d6337a86f37e1cb5a8aa293caaf070971bf7e4ac7f1047f03133de")

    print res
    print rec
    print res == rec

    pub, priv = key_gen(G)
    message = "Hello world"
    h = hashlib.sha256()
    h.update(message.encode("utf-8"))
    m = long(h.hexdigest(), 16)
    sig = sign(m, G, n, priv)
    print(sig)
    print(verify(sig, m, pub, G, n))
    h.update("an other one".encode("utf-8"))
    m = long(h.hexdigest(), 16)
    print(verify(sig, m, pub, G, n))

if __name__ == "__main__":
    print("ECDSA")
    # test()
    # run_ecdsa()

    k1 = utils.randomnumber(n-1, inf=1)
    z1 = utils.invert(k1, n)

    k2 = utils.randomnumber(n-1, inf=1)
    z2 = utils.invert(k2, n)

    r2 = point_mult(G, k2)
    r = point_mult(r2, k1)
    r1 = point_mult(r, z1)

    print r2
    print r
    print r1


    
