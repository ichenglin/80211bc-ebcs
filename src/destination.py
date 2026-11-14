import os

from dotenv import load_dotenv
from scapy.all import IP, TCP, sniff
from scapy.packet import Packet

from modules.report import report_destination_listen, report_destination_sniff
from packets.record import UplinkRecord

load_dotenv()

def destination_main() -> None:
    report_destination_listen()
    sniff(
        iface  =os.getenv("DESTINATION_INTERFACE"),
        prn    =destination_sniff,
        store  =0,
        lfilter=(lambda packet: (
            packet.haslayer(IP)  and packet[IP].dst    ==     os.getenv("DESTINATION_IP") and
            packet.haslayer(TCP) and packet[TCP].dport == int(os.getenv("DESTINATION_PORT"))
        ))
    )

def destination_sniff(packet: Packet) -> None:
    if packet.haslayer(UplinkRecord):
        report_destination_sniff(packet)

if __name__ == "__main__":
    destination_main()