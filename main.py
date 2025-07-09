# NetSecAnalyzer
# File : main.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :

import argparse
from reports.report_generator import save_as_json
from reports.mitre_mapper import map_event_to_mitre
from sniffing.dns_inspector import start_sniffing as run_dns

MODULES = {
    "dns": run_dns
}


def run_module(name, interface, count, timeout):
    if name not in MODULES:
        print(f"[!] Unknown module: {name}")
        return

    print(f"[+] Running {name} module...")
    alerts = MODULES[name](interface=interface, count=count, timeout=timeout)

    for alert in alerts:
        alert["MITRE"] = map_event_to_mitre(alert["Event"])

    save_as_json(alerts, f"{name}_alerts")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetSecAnalyzer CLI")
    parser.add_argument("-m", "--module", required=True, choices=MODULES.keys(), help="Module to run")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-c", "--count", type=int, default=20, help="Packet count")
    parser.add_argument("-t", "--timeout", type=int, help="Timeout in seconds")
    args = parser.parse_args()

    run_module(args.module, args.interface, args.count, args.timeout)