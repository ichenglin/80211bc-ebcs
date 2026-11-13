import os

from dotenv import load_dotenv
from scapy.all import Dot11, Packet, sniff

from packets.dot11bc import Dot11Bc

load_dotenv()

def station_main() -> None:
    print("[*] Listening for EBCS uplink frames...")
    sniff(iface=os.getenv("STATION_INTERFACE"), prn=station_sniff, store=0)

def station_sniff(packet: Packet) -> None:
    if packet.haslayer(Dot11Bc):
        ebcs = packet[Dot11Bc]
        print(f"\n[+] Captured EBCS Frame from MAC: {packet[Dot11].addr2}")
        print(f"    - Action: {ebcs.action}")
        print(f"    - URI: {ebcs.uri.decode('utf-8', errors='ignore')}")
        print(f"    - Payload: {ebcs.hlp_payload}")

if __name__ == "__main__":
    station_main()