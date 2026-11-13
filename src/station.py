import os

from dotenv import load_dotenv
from scapy.all import Dot11, Packet, sniff

from packets.dot11bc import ActionValue, Dot11Bc

load_dotenv()

def station_main() -> None:
    print("[*] Listening for EBCS uplink frames...")
    sniff(iface=os.getenv("STATION_INTERFACE"), prn=station_sniff, store=0)

def station_sniff(packet: Packet) -> None:
    if packet.haslayer(Dot11Bc):
        ebcs = packet[Dot11Bc]
        print(f"\n[+] Captured EBCS Frame from MAC: {packet[Dot11].addr2}")
        station_report("Action",               f"{ActionValue(ebcs.action).name} ({ebcs.action})", True)
        station_report("URI",                  ebcs.uri.decode("utf-8", errors="ignore"),          True)
        station_report("Payload",              ebcs.hlp_payload,                                   True)
        station_report("STA Certificate",      ebcs.sta_certificate,      ebcs.sta_certificate_present)
        station_report("Frame Tx Time",        ebcs.frame_tx_time,        ebcs.frame_tx_time_present)
        station_report("Frame Count",          ebcs.frame_count,          ebcs.frame_count_present)
        station_report("Frame Signature Type", ebcs.frame_signature_type, ebcs.frame_signature_type)
        station_report("Frame Signature",      ebcs.frame_signature,      ebcs.frame_signature_type)

def station_report(name: str, value: str, condition: bool) -> None:
    if (not condition):
        return
    print(f"\t- {name:<20}: {value}")

if __name__ == "__main__":
    station_main()