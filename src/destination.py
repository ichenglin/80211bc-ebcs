import os

from dotenv import load_dotenv
from scapy.all import IP, TCP, sniff
from scapy.packet import Packet

from modules.report import report_destination_listen, report_destination_sniff
from packets.record import UplinkRecord

load_dotenv()

def destination_main() -> None:
    interface = os.getenv("DESTINATION_INTERFACE")
    ip        = os.getenv("DESTINATION_IP")
    port      = int(os.getenv("DESTINATION_PORT"))
    report_destination_listen(interface)
    sniff(
        iface  =interface,
        prn    =destination_sniff,
        store  =0,
        lfilter=(lambda packet: (
            packet.haslayer(IP)  and packet[IP].dst    == ip and
            packet.haslayer(TCP) and packet[TCP].dport == port
        ))
    )

def destination_sniff(packet: Packet) -> None:
    if packet.haslayer(UplinkRecord):
        report_destination_sniff(packet)

if __name__ == "__main__":
    destination_main()
