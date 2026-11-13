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
        
        if ebcs.sta_certificate_present:
            print(f"    - STA Certificate: {ebcs.sta_certificate}")
        if ebcs.frame_tx_time_present:
            print(f"    - Frame Tx Time: {ebcs.frame_tx_time}")
        if ebcs.frame_count_present:
            print(f"    - Frame Count: {ebcs.frame_count}")
        if ebcs.frame_signature_type:
            print(f"    - Frame Signature Type: {ebcs.frame_signature_type}")
            print(f"    - Frame Signature: {ebcs.frame_signature}")

if __name__ == "__main__":
    station_main()