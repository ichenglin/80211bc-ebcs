from typing import ClassVar

from scapy.all import FieldLenField, Packet, StrLenField
from scapy.fields import ByteField

from constants.field import FieldFormat


class UplinkMetadata(Packet):
    name = "Uplink Metadata"
    fields_desc: ClassVar[list] = [
        ByteField    ("meta_type",  None),
        FieldLenField("meta_len",   None, length_of="meta_value", fmt=FieldFormat.UINT8),
        StrLenField  ("meta_value", b"",  length_from=lambda packet: packet.meta_len)
    ]

    def extract_padding(self, payload: bytes) -> tuple[bytes, bytes]:
        # metadata has no nested payload, pass remaining bytes to parent packet
        return b"", payload