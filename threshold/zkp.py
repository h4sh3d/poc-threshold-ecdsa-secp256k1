#!/usr/bin/env python
import utils
import dsa
import paillier
import hashlib

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

def pi(c, d, w1, w2, m1, m2, r1, r2, x1, x2, n, h1, h2, ka_pub):
    pkn, g = ka_pub
    q3 = pow(dsa.Q, 3)
    q3n = q3 * n
    alpha = utils.randomnumber(q3)
    beta = rnd_inv(pkn)
    gamma = utils.randomnumber(q3n)
    p1 = utils.randomnumber(dsa.Q * n)
    delta = utils.randomnumber(q3)
    mu = rnd_inv(pkn)
    vu = utils.randomnumber(q3n)
    p2 = utils.randomnumber(dsa.Q * n)
    p3 = utils.randomnumber(dsa.Q)
    epsilon = utils.randomnumber(dsa.Q)
    n2 = pkn * pkn

    z1 = (pow(h1, x1, n) * pow(h2, p1, n)) % n
    u1 = pow(c, alpha, dsa.P)
    u2 = (pow(g, alpha, n2) * pow(beta, pkn, n2)) % n2
    u3 = (pow(h1, alpha, n) * pow(h2, gamma, n)) % n

    z2 = (pow(h1, x2, n) * pow(h2, p2, n)) % n
    y = pow(d, x2 + p3, dsa.P)
    v1 = pow(d, delta + epsilon, dsa.P)
    v2 = (pow(w2, alpha, dsa.P) * pow(d, epsilon, dsa.P)) % dsa.P
    v3 = (pow(g, delta, n2) * pow(mu, pkn, n2)) % n2
    v4 = (pow(h1, delta, n) * pow(h2, vu, n)) % n

    h = hashlib.sha256()
    h.update(str(c))
    h.update(str(w1))
    h.update(str(d))
    h.update(str(w2))
    h.update(str(m1))
    h.update(str(m2))
    h.update(str(z1))
    h.update(str(u1))
    h.update(str(u2))
    h.update(str(u3))
    h.update(str(z2))
    h.update(str(y))
    h.update(str(v1))
    h.update(str(v2))
    h.update(str(v3))
    h.update(str(v4))
    e = long(h.hexdigest(), 16)
    
    s1 = e * x1 + alpha
    s2 = (pow(r1, e, pkn) * beta) % pkn
    s3 = e * p1 + gamma

    t1 = e * x2 + delta
    t2 = (e * p3 + epsilon) % dsa.Q
    t3 = (pow(r2, e, n2) * mu) % n2
    t4 = e * p2 + vu

    return z1, u1, u2, u3, z2, y, v1, v2, v3, v4, s1, s2, s3, t1, t2, t3, t4, e

def pi_verify(pi, c, d, w1, w2, m1, m2, ntild, h1, h2, ka_pub):
    z1, u1, u2, u3, z2, y, v1, v2, v3, v4, s1, s2, s3, t1, t2, t3, t4, e = pi
    n, g = ka_pub
    n2 = n * n
    q3 = pow(dsa.Q, 3)
    if s1 > q3 or t1 > q3:
        # print("+1")
        return False
    if not pow(c, s1, dsa.P) == (pow(w1, e, dsa.P) * u1) % dsa.P:
        # print("+2")
        return False
    if not ((pow(g, s1, n2) * pow(s2, n, n2)) % n2) == ((pow(m1, e, n2) * u2) % n2):
        # print("+3")
        return False
    verif1 = (pow(h1, s1, ntild) * pow(h2, s3, ntild)) % ntild
    verif2 = (pow(z1, e, ntild) * u3) % ntild
    if not verif1 == verif2:
        # print("+4")
        return False
    if not pow(d, (t1 + t2) % dsa.Q, dsa.P) == ((pow(y, e, dsa.P) * v1) % dsa.P):
        # print("+5")
        return False
    verif1 = (pow(w2, s1, dsa.P) * pow(d, t2, dsa.P)) % dsa.P
    verif2 = (pow(y, e, dsa.P) * v2) % dsa.P
    if not verif1 == verif2:
        # print("+6")
        return False
    if not (pow(g, t1, n2) * pow(t3, n, n2)) % n2 == (pow(m2, e, n2) * v3) % n2:
        # print("+7")
        return False
    verif1 = (pow(h1, t1, ntild) * pow(h2, t4, ntild)) % ntild
    if not verif1 == (pow(z2, e, ntild) * v4) % ntild:
        # print("+8")
        return False
    return True

def pi2(c, d, w1, w2, m1, m2, m3, m4, r1, r2, x1, x2, x3, zkpparam, ka_pub, kb_pub):
    pkn, g = ka_pub
    pkn2 = pkn * pkn
    pknprim, gprim = kb_pub
    pknprim2 = pknprim * pknprim
    ntild, h1, h2 = zkpparam
    q3 = pow(dsa.Q, 3)
    q3ntild = q3 * ntild
    qntild = dsa.Q * ntild
    alpha = utils.randomnumber(q3)
    beta = rnd_inv(pknprim)
    gamma = utils.randomnumber(q3ntild)
    p1 = utils.randomnumber(qntild)
    delta = utils.randomnumber(q3)
    mu = rnd_inv(pkn)
    vu = utils.randomnumber(q3ntild)
    p2 = utils.randomnumber(qntild)
    p3 = utils.randomnumber(dsa.Q)
    p4 = utils.randomnumber(pow(dsa.Q, 5) * ntild)
    epsilon = utils.randomnumber(dsa.Q)
    sigma = utils.randomnumber(pow(dsa.Q, 7))
    tau = utils.randomnumber(pow(dsa.Q, 7) * ntild)

    z1 = pow(h1, x1, ntild) * pow(h2, p1, ntild) % ntild
    u1 = pow(c, alpha, dsa.P)
    u2 = (pow(gprim, alpha, pknprim2) * pow(beta, pknprim, pknprim2)) % pknprim2
    u3 = (pow(h1, alpha, ntild) * pow(h2, gamma, ntild)) % ntild

    z2 = (pow(h1, x2, ntild) * pow(h2, p2, ntild)) % ntild
    y = pow(d, x2 + p3, dsa.P)
    v1 = pow(d, delta + epsilon, dsa.P)
    v2 = (pow(w2, alpha, dsa.P) * pow(d, epsilon, dsa.P)) % dsa.P
    v3 = (pow(m3, alpha, pkn2) * pow(m4, delta, pkn2) * pow(g, dsa.Q * sigma, pkn2) * pow(mu, pkn, pkn2)) % pkn2
    v4 = (pow(h1, delta, ntild) * pow(h2, vu, ntild)) % ntild
    z3 = (pow(h1, x3, ntild) * pow(h2, p4, ntild)) % ntild
    v5 = (pow(h1, sigma, ntild) * pow(h2, tau, ntild)) % ntild

    h = hashlib.sha256()
    h.update(str(c))
    h.update(str(w1))
    h.update(str(d))
    h.update(str(w2))
    h.update(str(m1))
    h.update(str(m2))
    h.update(str(z1))
    h.update(str(u1))
    h.update(str(u2))
    h.update(str(u3))
    h.update(str(z2))
    h.update(str(z3))
    h.update(str(y))
    h.update(str(v1))
    h.update(str(v2))
    h.update(str(v3))
    h.update(str(v4))
    h.update(str(v5))
    e = long(h.hexdigest(), 16)

    s1 = e * x1 + alpha
    s2 = (pow(r1, e, pknprim) * beta) % pknprim
    s3 = e * p1 + gamma

    t1 = e * x2 + delta
    t2 = (e * p3 + epsilon) % dsa.Q
    t3 = (pow(r2, e, pkn) * mu) % pkn
    t4 = e * p2 + vu
    t5 = e * x3 + sigma
    t6 = e * p4 + tau

    return z1, u1, u2, u3, z2, z3, y, v1, v2, v3, v4, v5, s1, s2, s3, t1, t2, t3, t4, t5, t6, e

def pi2_verify(pi2, c, d, w1, w2, m1, m2, m3, m4, zkpparam, ka_pub, kb_pub):
    z1, u1, u2, u3, z2, z3, y, v1, v2, v3, v4, v5, s1, s2, s3, t1, t2, t3, t4, t5, t6, e = pi2
    pkn, g = ka_pub
    pkn2 = pkn * pkn
    pknprim, gprim = kb_pub
    pknprim2 = pknprim * pknprim
    ntild, h1, h2 = zkpparam

    q3 = pow(dsa.Q, 3)
    q7 = pow(dsa.Q, 7)
    # if s1 > q3 or t1 > q3:
    #     print("+1")
    #     return False
    # if t5 > q7:
    #     print(t5)
    #     print(q7)
    #     print("+2")
    #     return False
    if not pow(c, s1, dsa.P) == (pow(w1, e, dsa.P) * u1) % dsa.P:
        print("+3")
        return False
    verif1 = (pow(gprim, s1, pknprim2) * pow(s2, pknprim, pknprim2)) % pknprim2
    verif2 = (pow(m1, e, pknprim2) * u2) % pknprim2
    if not verif1 == verif2:
        print("+4")
        return False
    if not (pow(h1, s1, ntild) * pow(h2, s3, ntild)) % ntild == (pow(z1, e, ntild) * u3) % ntild:
        print("+5")
        return False
    if not (pow(d, t1 + t2, dsa.P)) == (pow(y, e, dsa.P) * v1) % dsa.P:
        print("+6")
        return False
    verif1 = (pow(m3, s1, pkn2) * pow(m4, t1, pkn2) * pow(g, dsa.Q * t5, pkn2) * pow(t3, pkn, pkn2)) % pkn2
    verif2 = (pow(m2, e, pkn2) * v3) % pkn2
    if not verif1 == verif2:
        print("+7")
        return False
    return True

def rnd_inv(n):
    while True:
        b = utils.randomnumber(n)
        if utils.nonrec_gcd(b, n) == 1:
            return b

if __name__ == "__main__":
    print("Zero-Knowledge Proof")
    pk, sk = paillier.gen_key()
    pkn, pkg = pk
    if not pkn > pow(dsa.Q, 8):
        exit(1)
    zkpparam = gen_params(1024)
    n, h1, h2 = zkpparam

    res = pi(1,2,3,4,5,6,1,2,1,2, n, h1, h2, pk)
    print(res)

    print(pi_verify(res, 1,2,3,4,5,6, n, h1, h2, pk))
