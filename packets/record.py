from typing import ClassVar

from scapy.all import TCP, FieldLenField, Packet, StrLenField, bind_layers
from scapy.fields import PacketListField

from packets.metadata import UplinkMetadata


class UplinkRecord(Packet):
    name = "Uplink Record"
    fields_desc: ClassVar[list] = [
        FieldLenField  ("metadata_count",  None, count_of="metadata_list", fmt="B"),
        PacketListField("metadata_list",   [],   UplinkMetadata, count_from=lambda pkt: pkt.metadata_count),
        FieldLenField  ("hlp_payload_len", None, length_of="hlp_payload", fmt="H"),
        StrLenField    ("hlp_payload",     "",   length_from=lambda pkt: pkt.hlp_payload_len)
    ]

bind_layers(TCP, UplinkRecord)