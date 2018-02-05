#!/usr/bin/env python
import math
import base64
import binascii
import eczkp
import paillier
import ecdsa
from pyasn1.codec.der.decoder import decode
from pyasn1.type import namedtype, univ, tag
from pyasn1.compat.octets import ints2octs, octs2ints
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1_modules import rfc3279

class ZKPParameter(univ.Sequence):
    """Zero-Knowledge proof parameter
    ZKPParameter ::= SEQUENCE {
        modulus            INTEGER,
        h1                 INTEGER,
        h2                 INTEGER
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("h1", univ.Integer()),
        namedtype.NamedType("h2", univ.Integer())
    )

class ECZKPPi(univ.Sequence):
    """Zero-Knowledge proof pi for the (1,2)-threshold ECDSA scheme
    ECZKPPi ::= SEQUENCE {
        version            INTEGER,
        z1                 INTEGER,
        z2                 INTEGER,
        y                  OCTET STRING,
        e                  INTEGER,
        s1                 INTEGER,
        s2                 INTEGER,
        s3                 INTEGER,
        t1                 INTEGER,
        t2                 INTEGER,
        t3                 INTEGER,
        t4                 INTEGER
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("z1", univ.Integer()),
        namedtype.NamedType("z2", univ.Integer()),
        namedtype.NamedType("y", univ.OctetString()),
        namedtype.NamedType("e", univ.Integer()),
        namedtype.NamedType("s1", univ.Integer()),
        namedtype.NamedType("s2", univ.Integer()),
        namedtype.NamedType("s3", univ.Integer()),
        namedtype.NamedType("t1", univ.Integer()),
        namedtype.NamedType("t2", univ.Integer()),
        namedtype.NamedType("t3", univ.Integer()),
        namedtype.NamedType("t4", univ.Integer())
    )

class ECZKPPiPrim(univ.Sequence):
    """Zero-Knowledge proof pi' for the (1,2)-threshold ECDSA scheme
    ECZKPPiPrim ::= SEQUENCE {
        version            INTEGER,
        z1                 INTEGER,
        z2                 INTEGER,
        z3                 INTEGER,
        y                  OCTET STRING,
        e                  INTEGER,
        s1                 INTEGER,
        s2                 INTEGER,
        s3                 INTEGER,
        s4                 INTEGER,
        t1                 INTEGER,
        t2                 INTEGER,
        t3                 INTEGER,
        t4                 INTEGER,
        t5                 INTEGER,
        t6                 INTEGER,
        t7                 INTEGER
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("z1", univ.Integer()),
        namedtype.NamedType("z2", univ.Integer()),
        namedtype.NamedType("z3", univ.Integer()),
        namedtype.NamedType("y", univ.OctetString()),
        namedtype.NamedType("e", univ.Integer()),
        namedtype.NamedType("s1", univ.Integer()),
        namedtype.NamedType("s2", univ.Integer()),
        namedtype.NamedType("s3", univ.Integer()),
        namedtype.NamedType("s4", univ.Integer()),
        namedtype.NamedType("t1", univ.Integer()),
        namedtype.NamedType("t2", univ.Integer()),
        namedtype.NamedType("t3", univ.Integer()),
        namedtype.NamedType("t4", univ.Integer()),
        namedtype.NamedType("t5", univ.Integer()),
        namedtype.NamedType("t6", univ.Integer()),
        namedtype.NamedType("t7", univ.Integer())
    )

def hex_dump(to_encode):
    rr = binascii.hexlify(der_encoder(to_encode))
    jj = 1
    res = ""
    for d1, d2 in zip(rr[::2], rr[1::2]):
        i = str(d1)+str(d2)
        res += '0x'+i+', '
        if jj % 16 == 0:
            res += '\n'
        jj += 1
    print res
    print jj-1

def i2osp(x, xLen):
    if x >= pow(256, xLen):
        raise ValueError("integer too large")
    digits = []

    while x:
        digits.append(int(x % 256))
        x //= 256
    for i in range(xLen - len(digits)):
        digits.append(0)
    return digits[::-1]

def os2ip(X):
    xLen = len(X)
    X = X[::-1]
    x = 0
    for i in range(xLen):
        x += int(X[i]) * pow(256, i)
    return x

def _buildOid(*components):
    output = []
    for x in tuple(components):
        if isinstance(x, univ.ObjectIdentifier):
            output.extend(list(x))
        else:
            output.append(int(x))

    return univ.ObjectIdentifier(output)


def generate_zkp_pem(param):
    modulus, h1, h2 = param
    zkpparam = ZKPParameter()
    zkpparam['modulus'] = modulus
    zkpparam['h1'] = h1
    zkpparam['h2'] = h2

    # print zkpparam.prettyPrint()
    # hex_dump(zkpparam)

    test = Test()
    test['modulus'] = 23
    test['param'] = zkpparam

    hex_dump(test)


    res = "-----BEGIN ZKP PARAMETER-----\n"

    b = base64.b64encode(der_encoder(zkpparam))
    n = 64
    r = [b[i:i+n] for i in range(0, len(b), n)]
    for l in r:
        res += l + "\n"
    res += "-----END ZKP PARAMETER-----\n"
    return res


def gen_zkp(name1):
    param = eczkp.gen_params(1024)

    with open(name1, 'w') as file1:
        generate_zkp_pem(param)
        # file1.write(generate_zkp_pem(param))

def pi_to_pem(pi):
    z1, z2, y, e, s1, s2, s3, t1, t2, t3, t4 = pi
    pipem = ECZKPPi()
    pipem['version'] = 1
    pipem['z1'] = z1
    pipem['z2'] = z2
    pipem['y'] = univ.OctetString(
        hexValue=ecdsa.expand_pub(y)
    )
    print ecdsa.expand_pub(y)
    pipem['e'] = e
    pipem['s1'] = s1
    pipem['s2'] = s2
    pipem['s3'] = s3
    pipem['t1'] = t1
    pipem['t2'] = t2
    pipem['t3'] = t3
    pipem['t4'] = t4

    hex_dump(pipem)

def pi_to_pem2(pi2):
    z1, z2, z3, y, e, s1, s2, s3, s4, t1, t2, t3, t4, t5, t6, t7 = pi2
    pi2pem = ECZKPPiPrim()
    pi2pem['version'] = 1
    pi2pem['z1'] = z1
    pi2pem['z2'] = z2
    pi2pem['z3'] = z3
    pi2pem['y'] = univ.OctetString(
        hexValue=ecdsa.expand_pub(y)
    )
    print ecdsa.expand_pub(y)
    pi2pem['e'] = e
    pi2pem['s1'] = s1
    pi2pem['s2'] = s2
    pi2pem['s3'] = s3
    pi2pem['s4'] = s4
    pi2pem['t1'] = t1
    pi2pem['t2'] = t2
    pi2pem['t3'] = t3
    pi2pem['t4'] = t4
    pi2pem['t5'] = t5
    pi2pem['t6'] = t6
    pi2pem['t7'] = t7

    hex_dump(pi2pem)

class Test(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("param", ZKPParameter())
    )

if __name__ == '__main__':
    gen_zkp('id_zkp')