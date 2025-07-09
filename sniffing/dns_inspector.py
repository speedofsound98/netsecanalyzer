# File : dns_inspector.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :


# sudo -E python3 dns_inspector.py -i en0 -c 20

from scapy.all import sniff
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime
import re
from utils.logger import logger


def is_suspicious(domain):
    return len(domain) > 50 or re.search(r"[0-9]{8,}|[a-z]{20,}", domain, re.IGNORECASE)


def start_sniffing(interface='eth0', count=0, timeout=None):
    alerts = []
    logger.info(f"[*] Starting DNS inspection on {interface} (count={count}, "
                f"timeout={timeout})")

    def process_dns_packet(packet):
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode(errors="ignore")
            src_ip = packet[IP].src
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logger.info(f"DNS Query from {src_ip}: {query}")

            if is_suspicious(query):
                logger.warning(f"Suspicious DNS domain detected: {query}")
                alerts.append({
                    "Timestamp": timestamp,
                    "Event": "Suspicious DNS Query",
                    "Query": query,
                    "Source IP": src_ip
                })

    sniff(iface=interface, filter="udp port 53", prn=process_dns_packet,
          store=False, count=count, timeout=timeout)
    return alerts


if __name__ == "__main__":
    import argparse
    from utils.runner import run_sniffer

    parser = argparse.ArgumentParser(description="DNS Packet Inspector")
    parser.add_argument("-i", "--interface",
                        help="Network interface to sniff on", required=True)
    parser.add_argument("-c", "--count",
                        help="Number of packets to capture (0 for infinite)",
                        type=int, default=0)
    parser.add_argument("-t", "--timeout",
                        help="Capture timeout in seconds (optional)",
                        type=int, default=None)
    args = parser.parse_args()

    run_sniffer(start_sniffing, "dns", args)
