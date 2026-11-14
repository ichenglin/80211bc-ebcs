import os
import socket
from urllib.parse import urlparse

from dotenv import load_dotenv
from scapy.all import IP, TCP, Dot11, Packet, send, sniff

from constants.base import ActionValue
from constants.metadata import MetadataType
from packets.base import BcBase
from packets.metadata import UplinkMetadata
from packets.record import UplinkRecord
from packets.uplink import BcUplink

load_dotenv()

def station_main() -> None:
    print("[*] Listening for EBCS uplink frames...")
    sniff(iface=os.getenv("STATION_INTERFACE"), prn=station_sniff, store=0)

def station_sniff(packet: Packet) -> None:
    if packet.haslayer(BcUplink):
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
        station_forward(packet)

def station_forward(packet: BcUplink) -> None:
    if (os.getenv("FORWARD_ENABLED", "false").lower() != "true"):
        return
    ip, port = station_url(packet)
    metadata = [
        UplinkMetadata(
            meta_type=MetadataType.LOCATION,
            meta_value=os.getenv("STATION_LOCATION")
        )
    ]
    packet = (
        IP (dst  =ip) / 
        TCP(dport=port, flags="PA") /
        UplinkRecord(
            metadata_list=metadata,
            hlp_payload=packet.hlp_payload
        )
    )
    station_report_forward(packet)
    send(packet, iface=os.getenv("FORWARD_INTERFACE"), verbose=False)

def station_url(packet: BcUplink) -> tuple[str, int]:
    url  = urlparse(packet.uri.decode("utf-8", errors="ignore"))
    host = url.hostname
    port = url.port or (443 if url.scheme == 'https' else 80)
    ip   = socket.gethostbyname(host)
    return ip, port

def station_report_forward(packet: Packet) -> None:
    ip     = packet[IP]
    tcp    = packet[TCP]
    record = packet[UplinkRecord]
    print("\n[+] Forwarding packet")
    station_report("IP",      ip.dst,             True)
    station_report("Port",    tcp.dport,          True)
    station_report("Payload", record.hlp_payload, True)
    for index, metadata in enumerate(record.metadata_list, start=1):
        station_report(
            MetadataType(metadata.meta_type).name,
            metadata.meta_value,
            True,
            depth=2
        )

def station_report(name: str, value: str, condition: bool, depth: int = 1) -> None:
    if (not condition):
        return
    offset = 4 * depth
    print(f"{' ' * offset}- {name:<{24 - offset}}: {value}")

if __name__ == "__main__":
    station_main()