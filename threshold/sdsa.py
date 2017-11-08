#!/usr/bin/env python
import hashlib
import paillier
import dsa
import zkp
import utils

def alice_round_1(m, x1, y1, ka_pub, ka_priv):
    k1 = utils.randomnumber(dsa.Q-1, inf=2)
    z1 = utils.invert(k1, dsa.Q)
    alpha, r1 = paillier.encrypt(z1, ka_pub)
    zeta, r2 = paillier.encrypt(x1 * z1 % dsa.Q, ka_pub)
    return k1, z1, alpha, zeta, r1, r2

def bob_round_1(alpha, zeta):
    k2 = utils.randomnumber(dsa.Q-1, inf=2)
    r2 = utils.powmod(dsa.G, k2, dsa.P)
    return k2, r2

def alice_round_2(alpha, zeta, r2, k1, y1, z1, x1, zkpa, ka_pub, rr1, rr2):
    N, h1, h2 = zkpa
    eta1 = z1
    eta2 = (x1 * z1) % dsa.Q
    r = utils.powmod(r2, k1, dsa.P)
    
    c = r
    d = dsa.G
    w1 = r2
    w2 = y1
    m1 = alpha
    m2 = zeta
    x1 = eta1
    x2 = eta2
    r1 = rr1
    r2 = rr2

    pi = zkp.pi(c, d, w1, w2, m1, m2, r1, r2, x1, x2, N, h1, h2, ka_pub)
    return r, pi

def bob_round_2(pi, m, alpha, zeta, r, k2, x2, r2, y1, y2, ka_pub, kb_pub, zkpa, zkpb):
    n2 = n * n
    rq = r % dsa.Q
    N, h1, h2 = zkpa
    if rq == 0:
        print("signature failed, retry")
    z2 = utils.invert(k2, dsa.Q)
    c = utils.randomnumber(pow(dsa.Q, 5)-1, inf=1)

    if not zkp.pi_verify(pi, r, dsa.G, r2, y1, alpha, zeta, N, h1, h2, ka_pub):
        return False

    mu1 = paillier.mult(alpha, m * z2, n2)
    mu2 = paillier.mult(zeta, rq * x2 * z2, n2)
    mu3, rnumb = paillier.encrypt(c * dsa.Q, ka_pub)
    mu = paillier.add(paillier.add(mu1, mu2, n2), mu3, n2)

    muprim, rmuprim = paillier.encrypt(z2, kb_pub)

    c = r2
    d = dsa.G
    w1 = dsa.G
    w2 = y2
    m1 = muprim
    m2 = mu
    m3 = alpha
    m4 = zeta
    r1 = rmuprim
    r2 = rnumb
    x1 = z2
    x2 = x2 * z2
    x3 = c

    pi2 = zkp.pi2(c, d, w1, w2, m1, m2, m3, m4, r1, r2, x1, x2, x3, zkpb, ka_pub, kb_pub)

    return mu, muprim, pi2

if __name__ == "__main__":
    print("S-DSA")
    # Aclice
    x1 = utils.randomnumber(dsa.Q, inf=2)
    y1 = dsa.gen_pub(x1, dsa.G, dsa.P, dsa.Q)
    ka_pub, ka_priv = paillier.gen_key()
    zkpa = zkp.gen_params(1024)

    # Bob
    x2 = utils.randomnumber(dsa.Q, inf=2)
    y2 = dsa.gen_pub(x2, dsa.G, dsa.P, dsa.Q)
    kb_pub, kb_priv = paillier.gen_key()

    y_x = dsa.gen_pub(x1 * x2 % dsa.Q, dsa.G, dsa.P, dsa.Q)
    y_a = utils.powmod(y2, x1, dsa.P)
    y_b = utils.powmod(y1, x2, dsa.P)

    message = "hello"
    h = hashlib.sha256()
    h.update(message.encode("utf-8"))
    m = long(h.hexdigest(), 16)

    n, g = ka_pub
    n2 = n * n
    # x1e = paillier.encrypt(x1, kb_pub)
    # xe = utils.powmod(x1e, x2, n * n)
    # x = paillier.decrypt(xe, n, kb_priv) % dsa.Q

    # ALICE ROUND 1
    k1, z1, alpha, zeta, rr1, rr2 = alice_round_1(m, x1, y1, ka_pub, ka_priv)
    k2, r2 = bob_round_1(alpha, zeta)
    r, pi = alice_round_2(alpha, zeta, r2, k1, y1, z1, x1, zkpa, ka_pub, rr1, rr2)
    zkpb = zkp.gen_params(1024)
    br2 = bob_round_2(pi, m, alpha, zeta, r, k2, x2, r2, y1, y2, ka_pub, kb_pub, zkpa, zkpb)
    mu, mup, pi2 = br2

    k = k1 * k2
    rtest = utils.powmod(dsa.G, k, dsa.P) % dsa.Q
    r = r % dsa.Q

    c = r2
    d = dsa.G
    w1 = dsa.G
    w2 = y2
    m1 = mup
    m2 = mu
    m3 = alpha
    m4 = zeta
    print(zkp.pi2_verify(pi2, c, d, w1, w2, m1, m2, m3, m4, zkpb, ka_pub, kb_pub))

    # print(rtest == r)
    # print(z1 * z2 * k % dsa.Q == 1)
    # print(paillier.decrypt(paillier.encrypt(z1, ka_pub), n, ka_priv) == z1)
    # print(paillier.decrypt(alpha, n, ka_priv) == z1)
    # print(paillier.decrypt(paillier.mult(alpha, z2, n2), n, ka_priv) == z1 * z2)
    
    s = paillier.decrypt(mu, ka_priv) % dsa.Q
    print(r, s)
    print(dsa.verify(m, r, s, dsa.P, dsa.Q, dsa.G, y_a))
    h.update("an other one".encode("utf-8"))
    m = long(h.hexdigest(), 16)
    print(dsa.verify(m, r, s, dsa.P, dsa.Q, dsa.G, y_a))

    # res = dsa.sign(m, dsa.P, dsa.Q, dsa.G, x1*x2%dsa.Q)
    # print(res)
    # r, s = res
    # print(dsa.verify(m, r, s, dsa.P, dsa.Q, dsa.G, y_a))
