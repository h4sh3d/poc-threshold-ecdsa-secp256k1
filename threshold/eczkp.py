#!/usr/bin/env python
import utils
import ecdsa
import paillier
import hashlib

def rnd_inv(n):
    while True:
        b = utils.randomnumber(n)
        if utils.nonrec_gcd(b, n) == 1:
            return b

def gen_params(bits):
    while True:
        ptildprim = utils.randomnumber(pow(2,bits>>1))
        qtildprim = utils.randomnumber(pow(2,bits>>1))
        ptild = (2 * ptildprim + 1)
        qtild = (qtildprim + 1)
        if utils.is_prime(ptild) and utils.is_prime(qtild):
            break
    ntild = ptild * qtild
    pq = ptildprim * qtildprim
    while True:
        h2 = utils.randomnumber(ntild)
        if utils.nonrec_gcd(h2, ntild) == 1 and utils.powmod(h2, pq, ntild) == 1:
            break
    x = utils.randomnumber(pq)
    h1 = utils.powmod(h2, x, ntild)
    return ntild, h1, h2

def pi(c, d, w1, w2, m1, m2, r1, r2, x1, x2, zkp, ka_pub):
    Ntild, h1, h2 = zkp
    pkn, g = ka_pub
    n3 = pow(ecdsa.n, 3)
    n3ntild = n3 * Ntild
    alpha = utils.randomnumber(n3)
    beta = rnd_inv(pkn)
    gamma = utils.randomnumber(n3ntild)
    p1 = utils.randomnumber(ecdsa.n * Ntild)
    delta = utils.randomnumber(n3)
    mu = rnd_inv(pkn)
    nu = utils.randomnumber(n3ntild)
    p2 = utils.randomnumber(ecdsa.n * Ntild)
    p3 = utils.randomnumber(ecdsa.n)
    epsilon = utils.randomnumber(ecdsa.n)
    n2 = pkn * pkn

    z1 = (pow(h1, x1, Ntild) * pow(h2, p1, Ntild)) % Ntild
    u1 = ecdsa.point_mult(c, alpha)
    u2 = (pow(g, alpha, n2) * pow(beta, pkn, n2)) % n2
    u3 = (pow(h1, alpha, Ntild) * pow(h2, gamma, Ntild)) % Ntild

    z2 = (pow(h1, x2, Ntild) * pow(h2, p2, Ntild)) % Ntild
    y = ecdsa.point_mult(d, x2 + p3)
    v1 = ecdsa.point_mult(d, delta + epsilon)
    v2 = ecdsa.point_add(ecdsa.point_mult(w2, alpha), ecdsa.point_mult(d, epsilon))

    v3 = (pow(g, delta, n2) * pow(mu, pkn, n2)) % n2
    v4 = (pow(h1, delta, Ntild) * pow(h2, nu, Ntild)) % Ntild

    h = hashlib.sha256()
    h.update(ecdsa.expand_pub(c))
    h.update(ecdsa.expand_pub(w1))
    h.update(ecdsa.expand_pub(d))
    h.update(ecdsa.expand_pub(w2))
    h.update(str(m1))
    h.update(str(m2))
    h.update(str(z1))
    h.update(ecdsa.expand_pub(u1))
    h.update(str(u2))
    h.update(str(u3))
    h.update(str(z2))
    h.update(ecdsa.expand_pub(y))
    h.update(ecdsa.expand_pub(v1))
    h.update(ecdsa.expand_pub(v2))
    h.update(str(v3))
    h.update(str(v4))
    e = long(h.hexdigest(), 16)
    
    s1 = e * x1 + alpha
    s2 = (pow(r1, e, pkn) * beta) % pkn
    s3 = e * p1 + gamma

    t1 = e * x2 + delta
    t2 = (e * p3 + epsilon) % ecdsa.n
    t3 = (pow(r2, e, n2) * mu) % n2
    t4 = e * p2 + nu

    return z1, z2, y, e, s1, s2, s3, t1, t2, t3, t4

def pi_verify(pi, c, d, w1, w2, m1, m2, zkp, ka_pub):
    ntild, h1, h2 = zkp
    z1, z2, y, e, s1, s2, s3, t1, t2, t3, t4 = pi
    n, g = ka_pub
    n2 = n * n
    n3 = pow(ecdsa.n, 3)
    if s1 > n3 or t1 > n3:
        return False

    minuse = (e * -1) % ecdsa.n

    u1prim = ecdsa.point_add(ecdsa.point_mult(c, s1), ecdsa.point_mult(w1, minuse))
    u2inv = utils.inverse_mod(m1, n2)
    u2prim = (pow(g, s1, n2) * pow(s2, n, n2) * pow(u2inv, e, n2)) % n2
    u3inv = utils.inverse_mod(z1, ntild)
    u3prim = (pow(h1, s1, ntild) * pow(h2, s3, ntild) * pow(u3inv, e, ntild)) % ntild
    v1prim = ecdsa.point_add(ecdsa.point_mult(d, t1 + t2), ecdsa.point_mult(y, minuse))
    v2prim = ecdsa.point_add(
        ecdsa.point_add(ecdsa.point_mult(w2, s1), ecdsa.point_mult(d, t2)), 
        ecdsa.point_mult(y, minuse))
    v3inv = utils.inverse_mod(m2, n2)
    v3prim = (pow(g, t1, n2) * pow(t3, n, n2) * pow(v3inv, e, n2)) % n2
    v4inv = utils.inverse_mod(z2, ntild)
    v4prim = (pow(h1, t1, ntild) * pow(h2, t4, ntild) * pow(v4inv, e, ntild)) % ntild

    h = hashlib.sha256()
    h.update(ecdsa.expand_pub(c))
    h.update(ecdsa.expand_pub(w1))
    h.update(ecdsa.expand_pub(d))
    h.update(ecdsa.expand_pub(w2))
    h.update(str(m1))
    h.update(str(m2))
    h.update(str(z1))
    h.update(ecdsa.expand_pub(u1prim))
    h.update(str(u2prim))
    h.update(str(u3prim))
    h.update(str(z2))
    h.update(ecdsa.expand_pub(y))
    h.update(ecdsa.expand_pub(v1prim))
    h.update(ecdsa.expand_pub(v2prim))
    h.update(str(v3prim))
    h.update(str(v4prim))
    eprime = long(h.hexdigest(), 16)

    print "\n****************************************"
    print "Verifying Pi zkp:"
    print "e", e
    print "e'", eprime
    print "****************************************"

    return e == eprime

def pi2(c, d, w1, w2, m1, m2, m3, m4, r1, r2, x1, x2, x3, x4, x5, zkp, ka_pub, kb_pub):
    pkn, g = ka_pub
    pkn2 = pkn * pkn
    pknprim, gprim = kb_pub
    pknprim2 = pknprim * pknprim
    ntild, h1, h2 = zkp
    n3 = pow(ecdsa.n, 3)
    n5 = pow(ecdsa.n, 5)
    n6 = pow(ecdsa.n, 6)
    n7 = pow(ecdsa.n, 7)
    n8 = pow(ecdsa.n, 8)
    n3ntild = n3 * ntild
    nntild = ecdsa.n * ntild

    if pkn <= n8:
        return False
    if pknprim <= n6:
        return False

    alpha = utils.randomnumber(n3)
    beta = rnd_inv(pknprim)
    gamma = utils.randomnumber(n3ntild)
    p1 = utils.randomnumber(nntild)

    delta = utils.randomnumber(n3)
    mu = rnd_inv(pkn)
    nu = utils.randomnumber(n3ntild)
    p2 = utils.randomnumber(nntild)
    p3 = utils.randomnumber(ecdsa.n)
    p4 = utils.randomnumber(n5 * ntild)
    epsilon = utils.randomnumber(ecdsa.n)
    sigma = utils.randomnumber(n7)
    tau = utils.randomnumber(n7 * ntild)

    z1 = (pow(h1, x1, ntild) * pow(h2, p1, ntild)) % ntild
    u1 = ecdsa.point_mult(c, alpha)
    u2 = (pow(gprim, alpha, pknprim2) * pow(beta, pknprim, pknprim2)) % pknprim2
    u3 = (pow(h1, alpha, ntild) * pow(h2, gamma, ntild)) % ntild

    z2 = (pow(h1, x2, ntild) * pow(h2, p2, ntild)) % ntild
    y = ecdsa.point_mult(d, x2 + p3)
    v1 = ecdsa.point_mult(d, delta + epsilon)
    v2 = ecdsa.point_add(ecdsa.point_mult(w2, alpha), ecdsa.point_mult(d, epsilon))

    v3 = (pow(m3, alpha, pkn2) * pow(m4, delta, pkn2) * 
        pow(g, ecdsa.n * sigma, pkn2) * pow(mu, pkn, pkn2)) % pkn2
    
    v4 = (pow(h1, delta, ntild) * pow(h2, nu, ntild)) % ntild
    z3 = (pow(h1, x3, ntild) * pow(h2, p4, ntild)) % ntild
    v5 = (pow(h1, sigma, ntild) * pow(h2, tau, ntild)) % ntild

    h = hashlib.sha512()
    h.update(ecdsa.expand_pub(c))
    h.update(ecdsa.expand_pub(w1))
    h.update(ecdsa.expand_pub(d))
    h.update(ecdsa.expand_pub(w2))
    h.update(str(m1))
    h.update(str(m2))
    h.update(str(z1))
    h.update(ecdsa.expand_pub(u1))
    h.update(str(u2))
    h.update(str(u3))
    h.update(str(z2))
    h.update(str(z3))
    h.update(ecdsa.expand_pub(y))
    h.update(ecdsa.expand_pub(v1))
    h.update(ecdsa.expand_pub(v2))
    h.update(str(v3))
    h.update(str(v4))
    h.update(str(v5))
    e = long(h.hexdigest(), 16)

    s1 = e * x1 + alpha
    s2 = (pow(r1, e, pknprim) * beta) % pknprim
    s3 = e * p1 + gamma
    s4 = e * x1 * x4 + alpha

    t1 = e * x2 + delta
    t2 = (e * p3 + epsilon) % ecdsa.n
    t3 = (pow(r2, e, pkn) * mu) % pkn
    t4 = e * p2 + nu
    t5 = e * x3 + sigma
    t6 = e * p4 + tau
    t7 = e * x2 * x5 + delta

    return z1, z2, z3, y, e, s1, s2, s3, s4, t1, t2, t3, t4, t5, t6, t7

def pi2_verify(pi2, c, d, w1, w2, m1, m2, m3, m4, zkp, ka_pub, kb_pub):
    z1, z2, z3, y, e, s1, s2, s3, s4, t1, t2, t3, t4, t5, t6, t7 = pi2
    pkn, g = ka_pub
    pkn2 = pkn * pkn
    pknprim, gprim = kb_pub
    pknprim2 = pknprim * pknprim
    ntild, h1, h2 = zkp

    minuse = (e * -1) % ecdsa.n

    u1prim = ecdsa.point_add(ecdsa.point_mult(c, s1), ecdsa.point_mult(w1, minuse))
    u2inv = utils.inverse_mod(m1, pknprim2)
    u2prim = (pow(gprim, s1, pknprim2) * pow(s2, pknprim, pknprim2) * pow(u2inv, e, pknprim2)) % pknprim2
    u3inv = utils.inverse_mod(z1, ntild)
    u3prim = (pow(h1, s1, ntild) * pow(h2, s3, ntild) * pow(u3inv, e, ntild)) % ntild
    v1prim = ecdsa.point_add(ecdsa.point_mult(d, t1 + t2), ecdsa.point_mult(y, minuse))
    v2prim = ecdsa.point_add(
        ecdsa.point_add(ecdsa.point_mult(w2, s1), ecdsa.point_mult(d, t2)), 
        ecdsa.point_mult(y, minuse))
    v3inv = utils.inverse_mod(m2, pkn2)
    v3prim = (pow(m3, s4, pkn2) * pow(m4, t7, pkn2) * pow(g, ecdsa.n * t5, pkn2) * 
        pow(t3, pkn, pkn2) * pow(v3inv, e, pkn2)) % pkn2
    v4inv = utils.inverse_mod(z2, ntild)
    v4prim = (pow(h1, t1, ntild) * pow(h2, t4, ntild) * pow(v4inv, e, ntild)) % ntild
    v5inv = utils.inverse_mod(z3, ntild)
    v5prim = (pow(h1, t5, ntild) * pow(h2, t6, ntild) * pow(v5inv, e, ntild)) % ntild

    h = hashlib.sha512()
    h.update(ecdsa.expand_pub(c))
    h.update(ecdsa.expand_pub(w1))
    h.update(ecdsa.expand_pub(d))
    h.update(ecdsa.expand_pub(w2))
    h.update(str(m1))
    h.update(str(m2))
    h.update(str(z1))
    h.update(ecdsa.expand_pub(u1prim))
    h.update(str(u2prim))
    h.update(str(u3prim))
    h.update(str(z2))
    h.update(str(z3))
    h.update(ecdsa.expand_pub(y))
    h.update(ecdsa.expand_pub(v1prim))
    h.update(ecdsa.expand_pub(v2prim))
    h.update(str(v3prim))
    h.update(str(v4prim))
    h.update(str(v5prim))
    eprime = long(h.hexdigest(), 16)

    print "\n****************************************"
    print "Verifying Pi' zkp:"
    print "e", e
    print "e'", eprime
    print "****************************************\n"

    return e == eprime

if __name__ == "__main__":
    print("ECDSA Zero-Knowledge Proof")
    pk, sk = paillier.gen_key()
    pkn, pkg = pk
    if not pkn > pow(ecdsa.n, 8):
        exit(1)
    zkp = gen_params(1024)
    n, h1, h2 = zkp

    # res = pi(1,2,3,4,5,6,1,2,1,2, n, h1, h2, pk)
    # print(res)
