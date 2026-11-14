import os

from dotenv import load_dotenv
from scapy.all import Dot11, Dot11Action, RadioTap, sendp

from constants.base import ActionValue
from constants.dot11 import ActionCategory, Dot11Type, ManagementSubtype
from packets.base import BcBase
from packets.uplink import BcUplink

load_dotenv()

def device_main() -> None:
    frame = (
        RadioTap() /
        Dot11(
            type   =Dot11Type.MANAGEMENT,
            subtype=ManagementSubtype.ACTION,
            addr1  ="ff:ff:ff:ff:ff:ff",     # group address
            addr2  =os.getenv("DEVICE_MAC"), # sender STA mac
            addr3  ="01:0f:ac:01:02:03"      # EBCS content mac address
        ) /
        Dot11Action(category=ActionCategory.PUBLIC)   /
        BcBase     (action  =ActionValue.EBCS_UPLINK) /
        BcUplink(
            uri                  =b"http://localhost:8080",
            hlp_payload          =b"Hello World!",
            frame_tx_time_present=1,
            frame_tx_time        =0x01020304
        )
    )

    frame.show()
    sendp(frame, iface=os.getenv("DEVICE_INTERFACE"), verbose=False)

if __name__ == "__main__":
    device_main()