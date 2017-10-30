#!/usr/bin/env python
import hashlib
import paillier
import dsa
import utils


def alice_round_1(m, x1, y1, ka_pub, ka_priv):
    k1 = utils.randomnumber(dsa.Q-1, inf=2)
    z1 = utils.invert(k1, dsa.Q)
    alpha = paillier.encrypt(z1, ka_pub)
    beta = paillier.encrypt(x1 * z1 % dsa.Q, ka_pub)
    return k1, z1, alpha, beta

def bob_round_1(alpha, beta):
    k2 = utils.randomnumber(dsa.Q-1, inf=2)
    r2 = utils.powmod(dsa.G, k2, dsa.P)
    return k2, r2

def alice_round_2(alpha, beta, r2, k1):
    return utils.powmod(r2, k1, dsa.P)

def bob_round_2(m, alpha, beta, r, k2, x2, ka_pub, kb_pub):
    n, g = ka_pub
    n2 = n * n
    rq = r % dsa.Q
    if rq == 0:
        print("signature failed, retry")
    z2 = utils.invert(k2, dsa.Q)
    c = utils.randomnumber(pow(dsa.Q, 5)-1, inf=1)
    mu1 = paillier.mult(alpha, m * z2, n2)
    mu2 = paillier.mult(beta, rq * x2 * z2, n2)
    mu3 = paillier.encrypt(c * dsa.Q, ka_pub)
    mu = paillier.add(paillier.add(mu1, mu2, n2), mu3, n2)
    # mu = paillier.add(mu1, mu2, n2)
    return mu, paillier.encrypt(z2, kb_pub), z2

if __name__ == "__main__":
    print("S-DSA")
    # Aclice
    x1 = utils.randomnumber(dsa.Q, inf=2)
    y1 = dsa.gen_pub(x1, dsa.G, dsa.P, dsa.Q)
    ka_pub, ka_priv = paillier.gen_key()

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
    k1, z1, alpha, beta = alice_round_1(m, x1, y1, ka_pub, ka_priv)
    k2, r2 = bob_round_1(alpha, beta)
    r = alice_round_2(alpha, beta, r2, k1)
    mu, mup, z2 = bob_round_2(m, alpha, beta, r, k2, x2, ka_pub, ka_pub)

    k = k1 * k2
    rtest = utils.powmod(dsa.G, k, dsa.P) % dsa.Q
    r = r % dsa.Q

    # print(rtest == r)
    # print(z1 * z2 * k % dsa.Q == 1)
    # print(paillier.decrypt(paillier.encrypt(z1, ka_pub), n, ka_priv) == z1)
    # print(paillier.decrypt(alpha, n, ka_priv) == z1)
    # print(paillier.decrypt(paillier.mult(alpha, z2, n2), n, ka_priv) == z1 * z2)
    
    s = paillier.decrypt(mu, n, ka_priv) % dsa.Q
    print(r, s)
    print(dsa.verify(m, r, s, dsa.P, dsa.Q, dsa.G, y_a))
    h.update("an other one".encode("utf-8"))
    m = long(h.hexdigest(), 16)
    print(dsa.verify(m, r, s, dsa.P, dsa.Q, dsa.G, y_a))

    # res = dsa.sign(m, dsa.P, dsa.Q, dsa.G, x1*x2%dsa.Q)
    # print(res)
    # r, s = res
    # print(dsa.verify(m, r, s, dsa.P, dsa.Q, dsa.G, y_a))
