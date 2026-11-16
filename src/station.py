import os
import socket
from collections.abc import Callable
from urllib.parse import urlparse

from dotenv import load_dotenv
from scapy.all import IP, TCP, Dot11, Packet, send, sniff

from constants.metadata import MetadataType
from modules.mac import mac_bc
from modules.report import (
    report_station_forward,
    report_station_listen,
    report_station_sniff,
)
from packets.metadata import UplinkMetadata
from packets.record import UplinkRecord
from packets.uplink import BcUplink

load_dotenv()

def station_main() -> None:
    report_station_listen()
    sniff(iface=os.getenv("STATION_INTERFACE"), prn=station_sniff, store=0)

def station_sniff(packet: Packet) -> None:
    if (not station_bc(packet)):
        return
    report_station_sniff(packet)
    station_forward(packet)

def station_forward(packet: BcUplink) -> None:
    location  = os.getenv("STATION_LOCATION")
    interface = os.getenv("FORWARD_INTERFACE")
    enabled   = (os.getenv("FORWARD_ENABLED", "false").lower() == "true")
    if (not enabled):
        return
    uri = station_uri(packet)
    if not uri:
        return
    metadata = []
    station_metadata(metadata, MetadataType.TX_TIME,   lambda: packet.frame_tx_time.to_bytes(4, byteorder="big"), packet.frame_tx_time_present)
    station_metadata(metadata, MetadataType.COUNT,     lambda: packet.frame_count  .to_bytes(6, byteorder="big"), packet.frame_count_present)
    station_metadata(metadata, MetadataType.SIGNATURE, lambda: packet.frame_signature,                            True)
    station_metadata(metadata, MetadataType.LOCATION,  lambda: location,                                          True)
    packet = (
        IP (dst  =uri[0]) /
        TCP(dport=uri[1], flags="PA") /
        UplinkRecord(
            metadata_list=metadata,
            hlp_payload  =packet.hlp_payload
        )
    )
    report_station_forward(packet)
    send(packet, iface=interface, verbose=False)

def station_bc(packet: Packet) -> bool:
    streams = os.getenv("STATION_STREAM").split(",")
    if (not packet.haslayer(Dot11)):
        return False
    addr3 = packet[Dot11].addr3
    if (not addr3):
        return False
    if (not mac_bc(addr3)):
        return False
    if (not packet.haslayer(BcUplink)):
        return False
    return (addr3[9:] in streams)

def station_uri(packet: BcUplink) -> tuple[str, int] | None:
    url  = urlparse(f"//{packet.uri.decode('utf-8', errors='ignore')}")
    host = url.hostname
    port = url.port
    if ((not host) or (not port)):
        return None
    ip = socket.gethostbyname(host)
    return ip, port

def station_metadata(metadata: list[UplinkMetadata], type: MetadataType, value: Callable[[], bytes], present: bool) -> None:
    if (not present):
        return
    metadata.append(UplinkMetadata(meta_type=type, meta_value=value()))

if __name__ == "__main__":
    station_main()
