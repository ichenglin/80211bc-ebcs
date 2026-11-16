import re

from constants.mac import MAC_BC_HEADER, MAC_PATTERN


def mac_format(mac: str) -> bool:
    return (re.match(MAC_PATTERN, mac) is not None)

def mac_bc(mac: str) -> bool:
    if (not mac_format(mac)):
        return False
    return mac.upper().startswith(MAC_BC_HEADER.upper())