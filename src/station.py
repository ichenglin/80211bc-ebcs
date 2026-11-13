import os

from dotenv import load_dotenv
from scapy.all import Dot11, Packet, sniff

from constants.base import ActionValue
from packets.base import BcBase
from packets.uplink import BcUplink

load_dotenv()

def station_main() -> None:
    print("[*] Listening for EBCS uplink frames...")
    sniff(iface=os.getenv("STATION_INTERFACE"), prn=station_sniff, store=0)

def station_sniff(packet: Packet) -> None:
    if packet.haslayer(BcBase):
        dot11  = packet[Dot11]
        base   = packet[BcBase]
        uplink = packet[BcUplink]
        print(f"\n[+] Captured EBCS Frame from MAC: {dot11.addr2}")
        station_report("Action",               f"{ActionValue(base.action).name} ({base.action})", True)
        station_report("URI",                  uplink.uri.decode("utf-8", errors="ignore"),        True)
        station_report("Payload",              uplink.hlp_payload,                                 True)
        station_report("STA Certificate",      uplink.sta_certificate,      uplink.sta_certificate_present)
        station_report("Frame Tx Time",        uplink.frame_tx_time,        uplink.frame_tx_time_present)
        station_report("Frame Count",          uplink.frame_count,          uplink.frame_count_present)
        station_report("Frame Signature Type", uplink.frame_signature_type, uplink.frame_signature_type)
        station_report("Frame Signature",      uplink.frame_signature,      uplink.frame_signature_type)

def station_report(name: str, value: str, condition: bool) -> None:
    if (not condition):
        return
    print(f"{' ' * 4}- {name:<20}: {value}")

if __name__ == "__main__":
    station_main()