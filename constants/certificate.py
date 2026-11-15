from enum import IntEnum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from constants.uplink import FrameSignatureType

type PrivateKey = RSAPrivateKey | EllipticCurvePrivateKey

class CertificateType(IntEnum):
    HLSA = 0x0
    RSA  = 0x1
    EC   = 0x2

CERTIFICATE_GENERATOR = {
    FrameSignatureType.HLSA:            (CertificateType.HLSA, None,           None),
    FrameSignatureType.RSASSA_PSS_2048: (CertificateType.RSA,  2048,           hashes.SHA256()),
    FrameSignatureType.RSASSA_PSS_4096: (CertificateType.RSA,  4096,           hashes.SHA256()),
    FrameSignatureType.ECDSA_P256:      (CertificateType.EC,   ec.SECP256R1(), hashes.SHA256()),
    FrameSignatureType.ECDSA_P521:      (CertificateType.EC,   ec.SECP521R1(), hashes.SHA512()),
}