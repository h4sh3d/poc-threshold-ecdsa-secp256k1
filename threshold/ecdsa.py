#!/usr/bin/env python
import utils
import gmpy2
import hashlib

P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
G = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# Q = (54379786300132370429723006923123955340547200771646061271742923755949804875713, 113932782109590228098458430342911281933415527056336636870639345750680884388709)
# R = (6346039914906481324269259190395418186472180440216908592214472891569913080871, 75019491305234530532211445444575436698665605953287938325397858278107996616478)

# RE = (0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5, 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A)
# RE1 = (89565891926547004231252920425935692360644145829622209833684329913297188986597, 12158399299693830322967808612713398636155367887041628176798871954788371653930)

double_g = (0xC8333020C4688A754BF3AD462F1E9F1FAC80649A463AE4D4C1AFD48D20FCCFF, 0xB7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777)


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

def key_gen(g):
    d = utils.randomnumber(n-1)
    Q = point_mult(g, d)
    return Q, d

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

def test():
    # G x 2313 = 
    res = (0x8199C9D61224F51FE6DCDC333869D86095C0BD8E210D2D7F8FED2804A89AADF9, 0xBE89724F5CBD2384AE9BBD73F030DC74A158EE7D2A9D292DDAAE30574B1EC89B)
    print(contains_point(res))
    # print(point_mult(G, 2313))
    # print(res)
    print(point_mult(G, 2313) == res)

    # resdouble = (0xFCCC6C53DBB615C0324647998F2C4F3ED47E84E3BDE5A500E025AFF4AECA9C6C, 0x41768DB0A342DC7B5164428C0FCF238B5EA71182D562D6D22551CFA7B4E13394)
    print(point_add(res, res) == point_double(res))

    # G x 78439 =
    res2 = (0xA92DDF0D702330BD535FBB5F9C0EC4E04A4C8427ECA4E33818D663FF0FD2A74E, 0xF9F45EB21C5A2395097EB0336F2683A3662E03E312B7A52BC98E20F105E0FF9)
    print(contains_point(res2))
    print(point_mult(G, 78439) == res2)

    resadd = (0xB425DFAB6C95A64F0ACE24DAFF4440CE02EEF71EB7127DC4924D0869F10E4C1B, 0x1B16D85927660387414111493AAF0CF0B6B3B83F4F6E5EF9EFBD3CAEBE4F7AF0)
    print(contains_point(resadd))
    print(point_add(res, res2) == resadd)    

if __name__ == "__main__":
    print("ECDSA")
    # test()

    pub, priv = key_gen(G)
    message = "Hello world"
    h = hashlib.sha256()
    h.update(message.encode("utf-8"))
    m = long(h.hexdigest(), 16)
    sig = sign(m, G, n, priv)
    print(sig)
    print(verify(sig, m, pub, G, n))
    print(point_double(G) == double_g)
