import os

from dotenv import load_dotenv
from scapy.all import Dot11, RadioTap, sendp

from packets.dot11bc import Dot11Bc

load_dotenv()

frame = (
    RadioTap() /
    Dot11(
        type=0,
        subtype=13,
        addr1="ff:ff:ff:ff:ff:ff",     # group address
        addr2=os.getenv("DEVICE_MAC"), # sender STA mac
        addr3="01:0f:ac:01:02:03"      # EBCS content mac address
    ) /
    Dot11Bc(
        uri=b"http://example.com",
        hlp_payload=b"Hello World!"
    )
)

frame.show()
sendp(frame, iface=os.getenv("DEVICE_INTERFACE"), verbose=False)
