from enum import IntEnum


class MetadataType(IntEnum):
    TX_TIME   = 0x00
    COUNT     = 0x01
    SIGNATURE = 0x02
    LOCATION  = 0x03
