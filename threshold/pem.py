#!/usr/bin/env python
import math
import base64
import binascii
import ecdsa
import paillier
import eczkp
from pyasn1.codec.der.decoder import decode
from pyasn1.type import namedtype, univ, tag
from pyasn1.compat.octets import ints2octs, octs2ints
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1_modules import rfc3279

class ECPVer(univ.Integer):
    """RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key 
    Infrastructure Certificate and Certificate Revocation List (CRL) Profile
    ECPVer ::= INTEGER {ecpVer1(1)}
    """
    pass

class FieldElement(univ.OctetString):
    """RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key 
    Infrastructure Certificate and Certificate Revocation List (CRL) Profile
    FieldElement ::= OCTET STRING
    """
    pass

class ECPoint(univ.OctetString):
    """RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key 
    Infrastructure Certificate and Certificate Revocation List (CRL) Profile
    ECPoint ::= OCTET STRING
    """
    pass

class Curve(univ.Sequence):
    """RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key 
    Infrastructure Certificate and Certificate Revocation List (CRL) Profile
    Curve ::= SEQUENCE {
        a         FieldElement,
        b         FieldElement,
        seed      BIT STRING OPTIONAL
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("a", FieldElement()),
        namedtype.NamedType("b", FieldElement()),
        namedtype.OptionalNamedType("seed", univ.BitString()),
    )

class FieldID(univ.Sequence):
    """RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key 
    Infrastructure Certificate and Certificate Revocation List (CRL) Profile
    FieldID ::= SEQUENCE {
        fieldType   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY fieldType
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("fieldType", univ.ObjectIdentifier()),
        namedtype.NamedType("parameters", univ.Any()),
    )

class SpecifiedECDomain(univ.Sequence):
    """RFC 3279:  Algorithms and Identifiers for the Internet X.509 Public Key 
    Infrastructure Certificate and Certificate Revocation List (CRL) Profile
    ECParameters ::= SEQUENCE {
        version   ECPVer,          -- version is always 1
        fieldID   FieldID,         -- identifies the finite field over which the curve is defined
        curve     Curve,           -- coefficients a and b of the elliptic curve
        base      ECPoint,         -- specifies the base point P on the elliptic curve
        order     INTEGER,         -- the order n of the base point
        cofactor  INTEGER OPTIONAL -- The integer h = #E(Fq)/n
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", ECPVer()),
        namedtype.NamedType("fieldID", FieldID()),
        namedtype.NamedType("curve", Curve()),
        namedtype.NamedType("base", ECPoint()),
        namedtype.NamedType("order", univ.Integer()),
        namedtype.OptionalNamedType("cofactor", univ.Integer()),
    )

class ECParameters(univ.Choice):
    """RFC 5480: Elliptic Curve Cryptography Subject Public Key Information
    ECParameters ::= CHOICE {
        namedCurve      OBJECT IDENTIFIER
        implicitCurve   NULL
        specifiedCurve  SpecifiedECDomain
     }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("namedCurve", univ.ObjectIdentifier()),
        namedtype.NamedType("implicitCurve", univ.Null()),
        namedtype.NamedType("specifiedCurve", SpecifiedECDomain()),
    )

class ECPrivateKey(univ.Sequence):
    """RFC 5915: Elliptic Curve Private Key Structure
    ECPrivateKey ::= SEQUENCE {
        version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        privateKey     OCTET STRING,
        parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        publicKey  [1] BIT STRING OPTIONAL
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("privateKey", univ.OctetString()),
        namedtype.OptionalNamedType("parameters", 
            ECParameters().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                )),
        namedtype.OptionalNamedType("publicKey", 
            univ.BitString().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
                )),
    )

class HEPublicKey(univ.Sequence):
    """Homomorphic Encryption Public Key Structure
    HEPublicKey ::= SEQUENCE {
        version           INTEGER,
        modulus           INTEGER,  -- p * q
        generator         INTEGER   -- n + 1
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("generator", univ.Integer())
    )

class HEPrivateKey(univ.Sequence):
    """Homomorphic Encryption Private Key Structure
    HEPrivateKey ::= SEQUENCE {
        version           INTEGER,
        modulus           INTEGER,  -- p * q
        prime1            INTEGER,  -- p
        prime2            INTEGER,  -- q
        generator         INTEGER,  -- n + 1
        privateExponent   INTEGER,  -- (p - 1) * (q - 1)
        coefficient       INTEGER   -- (inverse of privateExponent) mod (p * q)
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("prime1", univ.Integer()),
        namedtype.NamedType("prime2", univ.Integer()),
        namedtype.NamedType("generator", univ.Integer()),
        namedtype.NamedType("privateExponent", univ.Integer()),
        namedtype.NamedType("coefficient", univ.Integer())
    )

class HEEncryptedMessage(univ.Sequence):
    """Homomorphic Encrypted Message Structure
    HEEncryptedMessage ::= SEQUENCE {
        message            INTEGER
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("message", univ.Integer())
    )

class ZKPParameter(univ.Sequence):
    """Zero-knowledge proofs parameters
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

class ThresholdECPrivateKey(univ.Sequence):
    """Threshold Elliptic Curve Private Key Structure
    ThresholdECPrivateKey ::= SEQUENCE {
        version              INTEGER,
        privateShare         OCTET STRING,
        privateEnc           HEPrivateKey,
        pairedPublicEnc      HEPublicKey,
        zkpParameters        ZKPParameter,
        pairedPublicShare    OCTET STRING,
        publicKey            OCTET STRING,
        parameters       [0] ECParameters {{ NamedCurve }} OPTIONAL
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("privateShare", univ.OctetString()),
        namedtype.NamedType("privateEnc", HEPrivateKey()),
        namedtype.NamedType("pairedPublicEnc", HEPublicKey()),
        namedtype.NamedType("zkpParameters", ZKPParameter()),
        namedtype.NamedType("pairedPublicShare", univ.OctetString()),
        namedtype.NamedType("publicKey", univ.OctetString()),
        namedtype.OptionalNamedType("parameters", 
            ECParameters().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                )),
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

def generate_ecdsa_pem(pk):
    ecPrivateKey = ECPrivateKey()
    ecPrivateKey['version'] = 1
    ecPrivateKey['privateKey'] = ints2octs(i2osp(pk, 32))
    ecParam = ECParameters().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                ) # 1.3.132.0.10 ansip256k1(10)
    ecParam.setComponentByName("namedCurve", _buildOid(1, 3, 132, 0, 10))
    print ecParam.prettyPrint()

    ecPrivateKey.setComponentByName('parameters', ecParam)
    
    pub = ecdsa.expand_pub(ecdsa.point_mult(ecdsa.G, pk))
    # pb = univ.BitString(long(pub, 16))
    ecPrivateKey.setComponentByName('publicKey', long(pub, 16))

    print ecPrivateKey.prettyPrint()

    res = "-----BEGIN EC PRIVATE KEY-----\n"

    b = base64.b64encode(der_encoder(ecPrivateKey))
    n = 64
    r = [b[i:i+n] for i in range(0, len(b), n)]
    for l in r:
        res += l + "\n"
    res += "-----END EC PRIVATE KEY-----\n"
    return res

def generate_tecdsa_pem(share, pub, pubshare, privEnc, pairedEnc, zkp):
    tecPrivateKey = ThresholdECPrivateKey()
    tecPrivateKey['version'] = 1
    tecPrivateKey['privateShare'] = ints2octs(i2osp(share, 32))
    
    # privateEnc
    privateEnc = HEPrivateKey()
    n, p, q, g, lmbda, mu = privEnc
    privateEnc['version'] = 1
    privateEnc['modulus'] = n
    privateEnc['prime1'] = p
    privateEnc['prime2'] = q
    privateEnc['generator'] = g
    privateEnc['privateExponent'] = lmbda
    privateEnc['coefficient'] = mu
    
    # hex_dump(privateEnc)

    tecPrivateKey.setComponentByName('privateEnc', privateEnc)

    # pairedPublicEnc
    publicEnc = HEPublicKey()
    n, g = pairedEnc
    publicEnc['version'] = 1
    publicEnc['modulus'] = n
    publicEnc['generator'] = g
    
    # hex_dump(publicEnc)

    tecPrivateKey.setComponentByName('pairedPublicEnc', publicEnc)

    n, h1, h2 = zkp
    # zkpParameters
    zkpParameters = ZKPParameter()
    zkpParameters['modulus'] = n
    zkpParameters['h1'] = h1
    zkpParameters['h2'] = h2

    tecPrivateKey.setComponentByName('zkpParameters', zkpParameters)

    tecPrivateKey.setComponentByName('pairedPublicShare', univ.OctetString(
        hexValue=ecdsa.expand_pub(pubshare)
    ))

    tecPrivateKey.setComponentByName('publicKey', univ.OctetString(
        hexValue=pub
    ))

    ecParam = ECParameters().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                ) # 1.3.132.0.10 ansip256k1(10)
    ecParam.setComponentByName("namedCurve", _buildOid(1, 3, 132, 0, 10))
    tecPrivateKey.setComponentByName('parameters', ecParam)

    # print tecPrivateKey.prettyPrint()

    hex_dump(tecPrivateKey)

    res = "-----BEGIN THRESHOLD EC PRIVATE KEY-----\n"

    b = base64.b64encode(der_encoder(tecPrivateKey))
    n = 64
    r = [b[i:i+n] for i in range(0, len(b), n)]
    for l in r:
        res += l + "\n"
    res += "-----END THRESHOLD EC PRIVATE KEY-----\n"
    return res

def parse_ecdsa_pem(name):
    with open(name, 'r') as file:
        b64 = ""
        for line in [x.strip() for x in file.readlines()]:
            # Remove header and footer
            if not "-----" in line:
                b64 = b64 + line
        res = base64.b64decode(b64)
        print "======"
        print res
        # print binascii.hexlify(res)

        received_record, rest_of_substrate = decode(res, asn1Spec=ECPrivateKey())

        for field in received_record:
            print('{} is {}'.format(field, received_record[field]))

        priv = os2ip(octs2ints(received_record['privateKey']))
        print priv
        pub = received_record['publicKey']
        print pub

def parse_tecdsa_pem(name):
    with open(name, 'r') as file:
        b64 = ""
        for line in [x.strip() for x in file.readlines()]:
            # Remove header and footer
            if not "-----" in line:
                b64 = b64 + line
        res = base64.b64decode(b64)
        print "======"

        received_record, rest_of_substrate = decode(res, asn1Spec=ThresholdECPrivateKey())

        # for field in received_record:
        #     print('{} is {}'.format(field, received_record[field]))

        print os2ip(octs2ints(received_record['privateShare']))
        print received_record['privateEnc'].prettyPrint()
        print received_record['pairedPublicEnc'].prettyPrint()

        pub = received_record['publicKey']

def gen_pem(name1, name2):
    pub1, priv1 = ecdsa.key_gen(ecdsa.G)
    pub2, priv2 = ecdsa.key_gen(ecdsa.G)
    
    pub = ecdsa.point_mult(pub1, priv2)
    pub = ecdsa.expand_pub(pub)

    privEncPub, privEncPriv = paillier.gen_key()
    pairedEncPub, pairedEncPriv = paillier.gen_key()

    zkp = eczkp.gen_params(1024)

    generate_tecdsa_pem(priv1, pub, pub2, privEncPriv, pairedEncPub, zkp)
    generate_tecdsa_pem(priv2, pub, pub1, pairedEncPriv, privEncPub, zkp)

    # with open(name1, 'w') as file1:
    #     with open(name2, 'w') as file2:
    #         file1.write(generate_tecdsa_pem(priv1, pub, privEncPriv, pairedEncPub, zkp))
    #         file2.write(generate_tecdsa_pem(priv2, pub, pairedEncPriv, privEncPub, zkp))

def create_enc_message(key):
    enc_message = HEEncryptedMessage()
    c, r = paillier.encrypt(123456789, key)
    enc_message['message'] = c

    hex_dump(enc_message)


if __name__ == '__main__':
    print "PEM"
    gen_pem('id_tecdsa1', 'id_tecdsa2')
    # parse_tecdsa_pem('id_tecdsa1')
    # parse_tecdsa_pem('id_tecdsa2')
