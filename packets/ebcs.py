from typing import ClassVar

from scapy.all import Dot11, FieldLenField, Packet, StrLenField, XByteField, bind_layers


class EbcsUL(Packet):
    name = "EBCS UL Frame"
    fields_desc: ClassVar[list] = [
        XByteField("category", 0x04),
        XByteField("public_action", 51),
        XByteField("control", 0x00),
        
        FieldLenField("uri_len", None, length_of="uri", fmt="B"),
        StrLenField("uri", b"http://example.com", length_from=lambda pkt: pkt.uri_len),
        
        FieldLenField("payload_len", None, length_of="hlp_payload", fmt="H"),
        StrLenField("hlp_payload", b"", length_from=lambda pkt: pkt.payload_len)
    ]

bind_layers(Dot11, EbcsUL, type=0, subtype=13)