from typing import ClassVar

from scapy.all import Dot11Action, Packet, XByteField
from scapy.packet import bind_layers

from constants.dot11 import ActionCategory
from constants.dot11bc import ActionValue


class BcBase(Packet):
    """Base EBCS layer"""

    name = "EBCS Base"
    fields_desc: ClassVar[list] = [
        XByteField("action", ActionValue.EBCS_UPLINK),
    ]

bind_layers(Dot11Action, BcBase, category=ActionCategory.PUBLIC)