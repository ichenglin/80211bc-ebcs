import os
import socket
from urllib.parse import urlparse

from dotenv import load_dotenv
from scapy.all import IP, TCP, Packet, send, sniff

from constants.metadata import MetadataType
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
    if packet.haslayer(BcUplink):
        report_station_sniff(packet)
        station_forward(packet)

def station_forward(packet: BcUplink) -> None:
    if (os.getenv("FORWARD_ENABLED", "false").lower() != "true"):
        return
    ip, port = station_url(packet)
    metadata = [
        UplinkMetadata(
            meta_type =MetadataType.LOCATION,
            meta_value=os.getenv("STATION_LOCATION")
        )
    ]
    if packet.frame_tx_time_present:
        metadata.append(
            UplinkMetadata(
                meta_type =MetadataType.TX_TIME,
                meta_value=str(packet.frame_tx_time)
            )
        )
    packet = (
        IP (dst  =ip) / 
        TCP(dport=port, flags="PA") /
        UplinkRecord(
            metadata_list=metadata,
            hlp_payload  =packet.hlp_payload
        )
    )
    report_station_forward(packet)
    send(packet, iface=os.getenv("FORWARD_INTERFACE"), verbose=False)

def station_url(packet: BcUplink) -> tuple[str, int]:
    url  = urlparse(packet.uri.decode("utf-8", errors="ignore"))
    host = url.hostname
    port = url.port or (443 if url.scheme == 'https' else 80)
    ip   = socket.gethostbyname(host)
    return ip, port

if __name__ == "__main__":
    station_main()