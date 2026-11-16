from enum import IntEnum

MAC_BC_HEADER = "01:0F:AC"

class ActionValue(IntEnum):
    EBCS_UPLINK      = 0x33
    EBCS_INFO        = 0x34
    EBCS_TERMINATION = 0x35