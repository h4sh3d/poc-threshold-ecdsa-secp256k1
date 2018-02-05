#!/usr/bin/env python
import ecdsa
import hashlib
import binascii
import string

alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
base_count = len(alphabet)

def encode(num):
    """ Returns num in a base58-encoded string """
    encode = ''
    
    if (num < 0):
        return ''
    
    while (num >= base_count):
        mod = num % base_count
        encode = alphabet[mod] + encode
        num = num / base_count

    if (num):
        encode = alphabet[num] + encode

    return encode

def decode(s):
    """ Decodes the base58-encoded string s into an integer """
    decoded = 0
    multi = 1
    s = s[::-1]
    for char in s:
        decoded += multi * alphabet.index(char)
        multi = multi * base_count
        
    return decoded

def get(pub):
    p = ecdsa.expand_pub(pub)

    sha = hashlib.sha256()
    sha.update(p)

    ripemd = hashlib.new('ripemd160')
    ripemd.update(sha.hexdigest())
    rip = "00%s" % ripemd.hexdigest()
    
    sha = hashlib.sha256()
    sha.update(rip)
    sha2 = hashlib.sha256()
    sha2.update(sha.hexdigest())
    checksum = sha2.hexdigest()
    add = "%s%s" % (rip, checksum[:4])

    return "1%s" % encode(long(add, 16))

def priv_to_priv(extended_priv, i):
    priv, chain = extended_priv
    if i >= 0x80000000:
        # Hardened
        k = "%x" % chain
        data = "00%32x%08x" % (priv, i)
        hmac = hashlib.pbkdf2_hmac('sha512', k, data, 100)
        l = binascii.hexlify(hmac)
        key = long(l[:64], 16) + priv % ecdsa.n
        c = long(l[64:], 16)
        return key, c
    else:
        # Not hardened
        k = "%x" % chain
        data = "00%s%08x" % (ecdsa.expand_pub(ecdsa.get_pub(priv)), i)
        hmac = hashlib.pbkdf2_hmac('sha512', k, data, 100)
        l = binascii.hexlify(hmac)
        key = long(l[:64], 16) + priv % ecdsa.n
        c = long(l[64:], 16)
        return key, c

def pub_to_pub(extended_pub, i):
    pub, chain = extended_pub
    if i >= 0x80000000:
        return None, None
    else:
        # Not hardened
        k = "%x" % chain
        data = "00%s%08x" % (ecdsa.expand_pub(pub), i)
        hmac = hashlib.pbkdf2_hmac('sha512', k, data, 100)
        l = binascii.hexlify(hmac)
        point = ecdsa.point_mult(ecdsa.G, long(l[:64], 16))
        c = long(l[64:], 16)
        return ecdsa.point_add(point, pub), c

def test():
    # p = ecdsa.expand_pub(pub)
    # print(p)

    # rec_pub = ecdsa.recover_pub(p)
    # print(rec_pub == pub)

    # print(get(pub))

    chain = ecdsa.gen_priv()
    # Shares
    p1 = ecdsa.gen_priv()
    pub1 = ecdsa.get_pub(p1)
    p2 = ecdsa.gen_priv()
    pub2 = ecdsa.get_pub(p2)
    p3 = ecdsa.gen_priv()
    pub3 = ecdsa.get_pub(p3)
    p4 = ecdsa.gen_priv()
    pub4 = ecdsa.get_pub(p4)


    skmas = ecdsa.aggregate(p1, p2, p3, p4)
    pkmas = ecdsa.get_pub(skmas)
    print(get(pkmas))

    # Compute master pubkey with shares
    pkmas_shares = ecdsa.point_add(ecdsa.point_add(ecdsa.point_add(pub1, pub2),
        pub3), pub4)
    print(get(pkmas_shares))

    i = 1

    # Pubkey derivation
    # each one knows:
    #  - chain code
    #  - master pubkey
    #  - i
    #  - own share
    sha2 = hashlib.sha256()
    m = "%x%s%x" % (chain, ecdsa.expand_pub(pub), i)
    sha2.update(m)
    T = long(sha2.hexdigest(), 16)

    pki = ecdsa.point_mult(pkmas, T)
    # print get(pki)

    # Privkey derivation
    p11 = p1 * T
    p21 = p2
    p31 = p3
    p41 = p4

    pkmas1 = ecdsa.get_pub(ecdsa.aggregate(p11, p21, p31, p41))
    # print(get(pkmas1))

    extended_priv = (skmas, chain)
    extended_pub = (pkmas, chain)
    ext_priv1h = priv_to_priv(extended_priv, 0x80000000)
    ext_priv1 = priv_to_priv(extended_priv, 0x00000001)
    ext_pub1 = pub_to_pub(extended_pub, 0x00000001)
    ext_priv2 = priv_to_priv(ext_priv1, 0x00000001)
    ext_pub2 = pub_to_pub(ext_pub1, 0x00000001)
    print(get(ecdsa.get_pub(ext_priv1[0])))
    print(get(ext_pub1[0]))
    print(get(ecdsa.get_pub(ext_priv2[0])))
    print(get(ext_pub2[0]))

    print("Multiplicatively")
    print(get(ecdsa.get_pub(p1 * p2)))
    print(get(ecdsa.point_mult(pub1, p2)))

class Share(object):
    def __init__(self, chain, master, secret=ecdsa.gen_priv()):
        super(Share, self).__init__()
        self.chain = chain
        self.master = master
        self.secret = secret
        self.master_pub = None

    def pub(self):
        return ecdsa.get_pub(self.secret)

    def address(self):
        return get(self.pub())

    def set_master_pub(self, pub):
        self.master_pub = pub

    def d_pub(self, i):
        if i >= pow(2, 31): # Only not hardened
            raise Exception("Impossible to hardened")
        k = "%x" % self.chain
        data = "00%s%08x" % (ecdsa.expand_pub(self.master_pub), i)
        hmac = hashlib.pbkdf2_hmac('sha256', k, data, 100)
        point = ecdsa.point_mult(self.master_pub, long(binascii.hexlify(hmac), 16))
        data = "%08x" % (i)
        hmac = hashlib.pbkdf2_hmac('sha256', k, data, 100)
        c = long(binascii.hexlify(hmac), 16)
        share = Share(c, self.master, self.secret)
        share.set_master_pub(point)
        return share

    def d_priv(self, i):
        k = "%x" % self.chain
        data = "%08x" % (i)
        hmac = hashlib.pbkdf2_hmac('sha256', k, data, 100)
        c = long(binascii.hexlify(hmac), 16)
        if i >= pow(2, 31): # Hardened
            data = "00%32x%08x" % (self.secret, i) 
        else: # Not hardened
            data = "00%s%08x" % (ecdsa.expand_pub(self.master_pub), i)
        hmac = hashlib.pbkdf2_hmac('sha256', k, data, 100)
        key = long(binascii.hexlify(hmac), 16) * self.secret
        point = ecdsa.point_mult(self.master_pub, long(binascii.hexlify(hmac), 16))
        share = Share(c, self.master, key)
        share.set_master_pub(point)
        return share

    def d(self, index):
        if self.master:
            return self.d_priv(index)
        else:
            return self.d_pub(index)

    def derive(self, path):
        path = string.split(path, "/")
        if path[0] == "m":
            path = path[1:]
            share = self
            for derivation in path:
                if "'" in derivation:
                    i = int(derivation.replace("'", "")) + pow(2, 31)
                    share = share.d(i)
                else:
                    i = int(derivation)
                    share = share.d(i)
            return share
        else:
            return False

class Threshold(object):
    """docstring for Threshold"""
    def __init__(self, *shares):
        super(Threshold, self).__init__()
        self.shares = shares
    
    def get_pub(self):
        p = None
        for share in self.shares:
            if p == None:
                p = share.pub()
                continue
            p = share.compute_master_pub(p)
            # def compute_master_pub(self, point):
            #     return ecdsa.point_mult(point, self.secret)
        return p

    def get_address(self):
        return get(self.get_pub())

if __name__ == "__main__":
    print("=== Threshold addresses ===")

    chain = ecdsa.gen_priv()
    # Shares
    s1 = Share(chain, True, ecdsa.gen_priv())
    s2 = Share(chain, False, ecdsa.gen_priv())
    s3 = Share(chain, False, ecdsa.gen_priv())

    sec = (s1.secret * s2.secret * s3.secret) % ecdsa.n
    pub = ecdsa.get_pub(sec)
    add = get(pub)
    print "Master root public key m/   :", add

    s1.set_master_pub(pub)
    s2.set_master_pub(pub)
    s3.set_master_pub(pub)

    print "\n*** Individual addresses m/ ***"
    print "s1:", s1.address()
    print "s2:", s2.address()
    print "s3:", s3.address()

    print "\n*** Hardened derivation for one share ***"
    print "s1 m/44/0/1  :", get(s1.derive("m/44/0/1").master_pub)
    print "s1 m/44/0/1' :", get(s1.derive("m/44/0/1'").master_pub)

    print "\n*** Master public key m/44/0/1 ***"
    s1 = s1.derive("m/44/0/1")
    s2 = s2.derive("m/44/0/1")
    s3 = s3.derive("m/44/0/1")
    print "s1:", get(s1.master_pub)
    print "s2:", get(s2.master_pub)
    print "s3:", get(s3.master_pub)

    sec = (s1.secret * s2.secret * s3.secret) % ecdsa.n
    pub = ecdsa.get_pub(sec)
    add = get(pub)
    print "\nMaster public key m/44/0/1 :", add
    
    print "\n*** Individual addresses m/44/0/1 ***"
    print "s1:", s1.address()
    print "s2:", s2.address()
    print "s3:", s3.address()
