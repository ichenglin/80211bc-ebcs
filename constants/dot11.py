from enum import IntEnum


class Dot11Type(IntEnum):
    MANAGEMENT = 0x0

class ManagementSubtype(IntEnum):
    ACTION = 0xd

class ActionCategory(IntEnum):
    PUBLIC = 0x04