from constants.base import MAC_BC_HEADER


def mac_bc(mac: str) -> bool:
    return mac.upper().startswith(MAC_BC_HEADER.upper())