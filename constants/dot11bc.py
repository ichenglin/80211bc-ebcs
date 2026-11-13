from enum import IntEnum


class ActionValue(IntEnum):
    EBCS_UPLINK      = 0x33
    EBCS_INFO        = 0x34
    EBCS_TERMINATION = 0x35

class FrameSignatureType(IntEnum):
    HLSA            = 0x0
    RSASSA_PSS_2048 = 0x1
    RSASSA_PSS_4096 = 0x2
    ECDSA_P256      = 0x3
    ECDSA_P521      = 0x4
