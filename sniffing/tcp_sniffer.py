# File : tcp_sniffer.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from datetime import datetime
from utils.logger import logger
from reports.report_generator import save_as_json

packet_log = []


# Basic packet callback


def process_packet(packet):
    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logger.info(f"TCP Packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")


def start_sniffing(interface='eth0', packet_count=0, timeout=None):
    logger.info(f"[*] Starting TCP sniffing on {interface}... "
                f"(count={packet_count}, timeout={timeout})")
    sniff(iface=interface, prn=process_packet, filter="tcp",
          store=False, count=packet_count, timeout=timeout)
    return []


if __name__ == "__main__":
    import argparse
    from utils.runner import run_sniffer

    parser = argparse.ArgumentParser(description="Simple TCP Packet Sniffer")
    parser.add_argument("-i", "--interface",
                        help="Network interface to sniff on", required=True)
    parser.add_argument("-c", "--count",
                        help="Number of packets to capture (0 for infinite)",
                        type=int, default=0)
    parser.add_argument("-t", "--timeout",
                        help="Capture timeout in seconds (optional)",
                        type=int, default=None)
    args = parser.parse_args()

    run_sniffer(start_sniffing, "tcp", args)
