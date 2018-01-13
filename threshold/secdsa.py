#!/usr/bin/env python
import hashlib
import paillier
import ecdsa
import eczkp
import utils

def alice_round_1(m, x1, y1, ka_pub, ka_priv):
    k1 = utils.randomnumber(ecdsa.n-1, inf=1)
    z1 = utils.invert(k1, ecdsa.n)
    alpha, r1 = paillier.encrypt(z1, ka_pub)
    zeta, r2 = paillier.encrypt(x1 * z1 % ecdsa.n, ka_pub)
    return k1, z1, alpha, zeta, r1, r2

def bob_round_1(alpha, zeta):
    k2 = utils.randomnumber(ecdsa.n-1, inf=1)
    r2 = ecdsa.point_mult(ecdsa.G, k2)
    return k2, r2

def alice_round_2(alpha, zeta, r2, k1, y1, z1, x1, zkp, ka_pub, rr1, rr2):
    Ntild, h1, h2 = zkp
    eta1 = z1
    eta2 = (x1 * z1) % ecdsa.n
    r = ecdsa.point_mult(r2, k1)
    
    c = r
    d = ecdsa.G
    w1 = r2
    w2 = y1
    m1 = alpha
    m2 = zeta
    x1 = eta1
    x2 = eta2
    r1 = rr1
    r2 = rr2

    pi = eczkp.pi(c, d, w1, w2, m1, m2, r1, r2, x1, x2, zkp, ka_pub)
    return r, pi

def bob_round_2(pi, m, alpha, zeta, r, k2, x2, r2, y1, y2, ka_pub, kb_pub, zkp):
    n, g = ka_pub
    n2 = n * n

    rq = r[0] % ecdsa.n
    if rq == 0:
        print("signature failed, retry")
        exit(1)

    z2 = utils.invert(k2, ecdsa.n)
    x2z2 = (x2 * z2) % ecdsa.n
    x3 = utils.randomnumber(pow(ecdsa.n, 5)-1, inf=1)

    if not eczkp.pi_verify(pi, r, ecdsa.G, r2, y1, alpha, zeta, zkp, ka_pub):
        print "Error: zkp failed"
        exit(1)

    mu1 = paillier.mult(alpha, m * z2, n2)
    mu2 = paillier.mult(zeta, rq * x2z2, n2)
    mu3, rnumb = paillier.encrypt(x3 * ecdsa.n, ka_pub)
    mu = paillier.add(paillier.add(mu1, mu2, n2), mu3, n2)

    muprim, rmuprim = paillier.encrypt(z2, kb_pub)

    c = r2
    d = ecdsa.G
    w1 = ecdsa.G
    w2 = y2
    m1 = muprim # ENCRYPTED Z2
    m2 = mu # ENCRYPTED RESULT
    m3 = alpha # ENCRYPTED Z1
    m4 = zeta # ENCRYPTED X1Z1
    r1 = rmuprim
    r2 = rnumb
    x1 = z2
    x2 = x2z2
    x4 = m
    x5 = rq
    # x1 = (m * z2) % ecdsa.n
    # x2 = (rq * x2z2) % ecdsa.n

    pi2 = eczkp.pi2(c, d, w1, w2, m1, m2, m3, m4, r1, r2, x1, x2, x3, x4, x5, zkp, ka_pub, kb_pub)
    if not pi2:
        print "Error: zkp failed"
        exit(1)

    return mu, muprim, pi2

def alice_round_3(pi2, r, r2, y2, mup, mu, alpha, zeta, zkp, ka_priv, kb_pub):
    n, p, q, g, lmdba, mupaillier = ka_priv
    ka_pub = (n, g)
    rf = r[0] % ecdsa.n

    c = r2
    d = ecdsa.G
    w1 = ecdsa.G
    w2 = y2
    m1 = mup
    m2 = mu
    m3 = alpha
    m4 = zeta

    if not eczkp.pi2_verify(pi2, c, d, w1, w2, m1, m2, m3, m4, zkp, ka_pub, kb_pub):
        print "Error: zkp 2 failed"
        exit(1)

    s = paillier.decrypt(mu, ka_priv) % ecdsa.n
    if s == 0:
        print("signature failed, retry")
        exit(1)

    return rf, s


def run_secdsa():
    # Aclice
    x1 = utils.randomnumber(ecdsa.n, inf=2)
    y1 = ecdsa.get_pub(x1)
    ka_pub, ka_priv = paillier.gen_key()

    # Bob
    x2 = utils.randomnumber(ecdsa.n, inf=2)
    y2 = ecdsa.get_pub(x2)
    kb_pub, kb_priv = paillier.gen_key()

    zkp = eczkp.gen_params(1024)

    pub = ecdsa.get_pub(x1 * x2 % ecdsa.n)
    # pub_a = ecdsa.point_mult(y2, x1)
    # pub_b = ecdsa.point_mult(y1, x2)

    # Message hash
    message = "hello"
    h = hashlib.sha256()
    h.update(message.encode("utf-8"))
    m = long(h.hexdigest(), 16)
    print message
    print m

    # ALICE ROUND 1
    k1, z1, alpha, zeta, rr1, rr2 = alice_round_1(m, x1, y1, ka_pub, ka_priv)
    # BOB ROUND 1
    k2, r2 = bob_round_1(alpha, zeta)

    # ALICE ROUND 2
    r, pi = alice_round_2(alpha, zeta, r2, k1, y1, z1, x1, zkp, ka_pub, rr1, rr2)
    # BOB ROUND 2
    mu, mup, pi2 = bob_round_2(pi, m, alpha, zeta, r, k2, x2, r2, y1, y2, ka_pub, kb_pub, zkp)

    # ALICE ROUND 3 (final)
    sig = alice_round_3(pi2, r, r2, y2, mup, mu, alpha, zeta, zkp, ka_priv, kb_pub)

    print sig
    r, s = sig
    print ecdsa.verify(sig, m, pub, ecdsa.G, ecdsa.n)
    
    # h = hashlib.sha256()
    # h.update("an other one".encode("utf-8"))
    # m = long(h.hexdigest(), 16)
    # print(dsa.verify(m, sig, y_a))
    

if __name__ == "__main__":
    print("S-ECDSA")
    run_secdsa()
