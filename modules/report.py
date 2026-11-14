
from scapy.all import IP, TCP, Dot11

from constants.base import ActionValue
from constants.metadata import MetadataType
from packets.base import BcBase
from packets.record import UplinkRecord
from packets.uplink import BcUplink


def report_station_sniff(packet: BcUplink) -> None:
    dot11  = packet[Dot11]
    base   = packet[BcBase]
    uplink = packet[BcUplink]
    print(f"\n[+] Captured EBCS Frame from MAC: {dot11.addr2}")
    report_line("Action",               f"{ActionValue(base.action).name}",          True)
    report_line("URI",                  uplink.uri.decode("utf-8", errors="ignore"), True)
    report_line("Payload",              uplink.hlp_payload,                          True)
    report_line("STA Certificate",      uplink.sta_certificate,      uplink.sta_certificate_present)
    report_line("Frame Tx Time",        uplink.frame_tx_time,        uplink.frame_tx_time_present)
    report_line("Frame Count",          uplink.frame_count,          uplink.frame_count_present)
    report_line("Frame Signature Type", uplink.frame_signature_type, uplink.frame_signature_type)
    report_line("Frame Signature",      uplink.frame_signature,      uplink.frame_signature_type)

def report_station_forward(packet: UplinkRecord) -> None:
    ip     = packet[IP]
    tcp    = packet[TCP]
    record = packet[UplinkRecord]
    print("\n[+] Forwarding packet")
    report_line("IP",      ip.dst,             True)
    report_line("Port",    tcp.dport,          True)
    report_line("Payload", record.hlp_payload, True)
    for metadata in record.metadata_list:
        report_line(
            MetadataType(metadata.meta_type).name,
            metadata.meta_value,
            True,
            depth=2
        )

def report_line(name: str, value: str, condition: bool, depth: int = 1) -> None:
    if (not condition):
        return
    offset = 4 * depth
    print(f"{' ' * offset}- {name:<{24 - offset}}: {value}")