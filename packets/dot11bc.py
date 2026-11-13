from enum import IntEnum
from typing import ClassVar

from scapy.all import (
    BitEnumField,
    BitField,
    Dot11,
    FieldLenField,
    Packet,
    StrLenField,
    XByteField,
    bind_layers,
)


class ActionCategory(IntEnum):
    PUBLIC = 0x04

class ActionValue(IntEnum):
    EBCS_UPLINK      = 0x33
    EBCS_INFO        = 0x34
    EBCS_TERMINATION = 0x35

class FrameSignatureType(IntEnum):
    HLSA = 0
    RSASSA_PSS_2048 = 1
    RSASSA_PSS_4096 = 2
    ECDSA_P256 = 3
    ECDSA_P521 = 4

FRAME_SIGNATURE_TYPES = {
    signature_type.value: signature_type.name
    for signature_type in FrameSignatureType
}

class Dot11Bc(Packet):
    """
    Attributes:
        category:                The category of the action (usually PUBLIC)
        action:                  The specific action value  (e.g. uplink, info, termination)

        sta_certificate_present: Indicates if the STA certificate         is present
        frame_tx_time_present:   Indicates if the frame transmission time is present
        frame_count_present:     Indicates if the frame count             is present
        frame_signature_type:    The type of frame signature

        uri:                     The destination URI
        hlp_payload:             The HLP payload
    """

    name = "EBCS Frame"
    fields_desc: ClassVar[list] = [
        XByteField("category", ActionCategory.PUBLIC),
        XByteField("action",   ActionValue.EBCS_UPLINK),

        # control field
        BitField    ("sta_certificate_present", 0, 1),
        BitField    ("frame_tx_time_present",   0, 1),
        BitField    ("frame_count_present",     0, 1),
        BitEnumField("frame_signature_type",    FrameSignatureType.HLSA, 3, FRAME_SIGNATURE_TYPES),
        BitField    ("reserved",                0, 2),
        
        FieldLenField("uri_len", None, length_of="uri", fmt="B"),
        StrLenField  ("uri", b"http://example.com", length_from=lambda pkt: pkt.uri_len),
        
        FieldLenField("payload_len", None, length_of="hlp_payload", fmt="H"),
        StrLenField  ("hlp_payload", b"", length_from=lambda pkt: pkt.payload_len)
    ]

bind_layers(Dot11, Dot11Bc, type=0, subtype=13)