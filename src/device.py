import os
import time

from dotenv import load_dotenv
from scapy.all import Dot11, Dot11Action, RadioTap, sendp

from constants.base import MAC_BC_HEADER, ActionValue
from constants.dot11 import MAC_BROADCAST, ActionCategory, Dot11Type, ManagementSubtype
from constants.uplink import FieldPresent, FrameSignatureType
from packets.base import BcBase
from packets.uplink import BcUplink

load_dotenv()

def device_main() -> None:
    interface = os.getenv("DEVICE_INTERFACE")
    mac       = os.getenv("DEVICE_MAC")
    frame     = (
        RadioTap() /
        Dot11(
            type   =Dot11Type.MANAGEMENT,
            subtype=ManagementSubtype.ACTION,
            addr1  =MAC_BROADCAST,              # group address
            addr2  =mac,                        # sender STA mac
            addr3  =f"{MAC_BC_HEADER}:01:02:03" # EBCS content mac address
        ) /
        Dot11Action(category=ActionCategory.PUBLIC)   /
        BcBase     (action  =ActionValue.EBCS_UPLINK) /
        BcUplink(
            uri                  =b"localhost:1112",
            hlp_payload          =f"Hello World from {mac}",
            frame_tx_time_present=FieldPresent.PRESENT,
            frame_tx_time        =int(time.time()),
            frame_count_present  =FieldPresent.PRESENT,
            frame_count          =1,
            frame_signature_type =FrameSignatureType.ECDSA_P256,
            frame_signature      =b"Signature"
        )
    )
    frame.show()
    sendp(frame, iface=interface, verbose=False)

if __name__ == "__main__":
    device_main()
