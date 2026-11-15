from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from constants.certificate import CERTIFICATE_GENERATOR, CertificateType, PrivateKey
from constants.uplink import FrameSignatureType


def certificate_private(type: FrameSignatureType) -> PrivateKey:
    generator = CERTIFICATE_GENERATOR[type]
    match (generator[0]):
        case CertificateType.RSA:
            return rsa.generate_private_key(
                public_exponent=65537,
                key_size=generator[1],
            )
        case CertificateType.EC:
            return ec.generate_private_key(generator[1])
        case _:
            raise ValueError(f"Unsupported certificate type: {CertificateType(generator[0])}")

def certificate_sign(type: FrameSignatureType, private_key: PrivateKey, data: bytes) -> bytes:
    generator = CERTIFICATE_GENERATOR[type]
    match (generator[0]):
        case CertificateType.RSA:
            return private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(generator[2]),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                generator[2],
            )
        case CertificateType.EC:
            return private_key.sign(
                data,
                ec.ECDSA(generator[2]),
            )
        case _:
            raise ValueError(f"Unsupported certificate type: {CertificateType(generator[0])}")
