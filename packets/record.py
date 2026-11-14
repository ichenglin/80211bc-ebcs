from typing import ClassVar

from scapy.all import TCP, FieldLenField, Packet, StrLenField, bind_layers
from scapy.fields import PacketListField

from constants.field import FieldFormat
from packets.metadata import UplinkMetadata


class UplinkRecord(Packet):
    name = "Uplink Record"
    fields_desc: ClassVar[list] = [
        FieldLenField  ("metadata_count",  None, count_of="metadata_list", fmt=FieldFormat.UINT8),
        PacketListField("metadata_list",   [],   UplinkMetadata, count_from=lambda packet: packet.metadata_count),
        FieldLenField  ("hlp_payload_len", None, length_of="hlp_payload", fmt=FieldFormat.UINT16),
        StrLenField    ("hlp_payload",     b"",  length_from=lambda packet: packet.hlp_payload_len)
    ]

bind_layers(TCP, UplinkRecord)