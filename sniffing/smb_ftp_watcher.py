# File : smb_ftp_watcher.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :
# sudo -E python3 smb_ftp_watcher.py -i en0 -c 50


from scapy.layers.inet import IP, TCP
# Detect FTP logins (port 21) and SMB packets (port 445)
# Monitors FTP/SMB activity and flags suspicious traffic
# sudo -E python3 sniffing/smb_ftp_watcher.py -i en0 -c 50

from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP
from datetime import datetime
from utils.logger import logger
import argparse
from reports.report_generator import save_as_json

FTP_PORT = 21
SMB_PORT = 445

suspicious_keywords = [b"login", b"pass", b"user", b"admin"]


def start_sniffing(interface='eth0', count=0, timeout=None):
    alerts = []
    logger.info(f"[*] Monitoring FTP/SMB on {interface} (count={count}, timeout={timeout})")

    def process_packet(packet):
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            ip = packet[IP]
            sport, dport = tcp.sport, tcp.dport
            payload = bytes(tcp.payload)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            if dport in (FTP_PORT, SMB_PORT) or sport in (FTP_PORT, SMB_PORT):
                proto = "FTP" if FTP_PORT in (sport, dport) else "SMB"
                logger.info(f"{proto} Packet from {ip.src}:{sport} to {ip.dst}:{dport}")

                if any(k in payload.lower() for k in suspicious_keywords):
                    logger.warning(f"Suspicious content detected in {proto} traffic: {payload[:50]}")
                    alerts.append({
                        "Timestamp": timestamp,
                        "Event": f"Suspicious {proto} Traffic",
                        "Payload": str(payload[:100]),
                        "Source IP": ip.src,
                        "Destination IP": ip.dst
                    })

    sniff(iface=interface, filter="tcp port 21 or tcp port 445", prn=process_packet, store=False, count=count, timeout=timeout)
    return alerts


if __name__ == "__main__":
    import argparse
    from utils.runner import run_sniffer

    parser = argparse.ArgumentParser(description="SMB/FTP Packet Monitor")
    parser.add_argument("-i", "--interface",
                        help="Network interface to sniff on", required=True)
    parser.add_argument("-c", "--count",
                        help="Number of packets to capture (0 for infinite)",
                        type=int, default=0)
    parser.add_argument("-t", "--timeout",
                        help="Capture timeout in seconds (optional)",
                        type=int, default=None)
    args = parser.parse_args()

    run_sniffer(start_sniffing, "smb_ftp", args)