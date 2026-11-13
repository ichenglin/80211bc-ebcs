from enum import IntEnum
from typing import ClassVar

from scapy.all import (
    BitEnumField,
    BitField,
    ConditionalField,
    Dot11Action,
    Field,
    FieldLenField,
    IntField,
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
    HLSA            = 0
    RSASSA_PSS_2048 = 1
    RSASSA_PSS_4096 = 2
    ECDSA_P256      = 3
    ECDSA_P521      = 4

FRAME_SIGNATURE_TYPES = {
    signature_type.value: signature_type.name
    for signature_type in FrameSignatureType
}


class FrameCountField(Field):
    """A six-octet, big-endian unsigned frame count."""

    def __init__(self, name: str, default: int = 0) -> None:
        super().__init__(name, default, "!6s")

    def i2m(self, pkt: Packet, value: int | None) -> bytes:
        return int(value or 0).to_bytes(6, "big")

    def m2i(self, pkt: Packet, value: bytes) -> int:
        return int.from_bytes(value, "big")


class Dot11Bc(Packet):
    """
    Attributes:
        action:                  The specific action value  (e.g. uplink, info, termination)

        sta_certificate_present: Indicates if the STA certificate         is present
        frame_tx_time_present:   Indicates if the frame transmission time is present
        frame_count_present:     Indicates if the frame count             is present
        frame_signature_type:    The type of frame signature

        uri:                     The destination URI
        hlp_payload:             The HLP payload
        sta_certificate:         The optional STA certificate container
        frame_tx_time:           The optional frame transmission time
        frame_count:             The optional frame count
        frame_signature:         The optional frame signature
    """

    name = "EBCS Frame"
    fields_desc: ClassVar[list] = [
        XByteField("action", ActionValue.EBCS_UPLINK),

        # control field
        BitField    ("sta_certificate_present", 0, 1),
        BitField    ("frame_tx_time_present",   0, 1),
        BitField    ("frame_count_present",     0, 1),
        BitEnumField("frame_signature_type",    FrameSignatureType.HLSA, 3, FRAME_SIGNATURE_TYPES),
        BitField    ("reserved",                0, 2),
        
        FieldLenField("uri_len", None, length_of="uri", fmt="B"),
        StrLenField  ("uri", b"http://example.com", length_from=lambda pkt: pkt.uri_len),
        
        FieldLenField("payload_len", None, length_of="hlp_payload", fmt="H"),
        StrLenField  ("hlp_payload", b"", length_from=lambda pkt: pkt.payload_len),

        ConditionalField(
            FieldLenField("sta_certificate_len", None, length_of="sta_certificate", fmt="H"),
            lambda pkt: pkt.sta_certificate_present == 1,
        ),
        ConditionalField(
            StrLenField(
                "sta_certificate",
                b"",
                length_from=lambda pkt: pkt.sta_certificate_len,
            ),
            lambda pkt: pkt.sta_certificate_present == 1,
        ),
        ConditionalField(
            IntField("frame_tx_time", 0),
            lambda pkt: pkt.frame_tx_time_present == 1,
        ),
        ConditionalField(
            FrameCountField("frame_count", 0),
            lambda pkt: pkt.frame_count_present == 1,
        ),
        ConditionalField(
            FieldLenField("frame_signature_len", None, length_of="frame_signature", fmt="H"),
            lambda pkt: pkt.frame_signature_type != FrameSignatureType.HLSA,
        ),
        ConditionalField(
            StrLenField(
                "frame_signature",
                b"",
                length_from=lambda pkt: pkt.frame_signature_len,
            ),
            lambda pkt: pkt.frame_signature_type != FrameSignatureType.HLSA,
        ),
    ]

bind_layers(Dot11Action, Dot11Bc, category=ActionCategory.PUBLIC)
