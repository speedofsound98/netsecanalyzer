# File : report_generator.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :

import json
import csv
from datetime import datetime


def save_as_json(data, filename_prefix="report"):
    filename = f"{filename_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Report saved to {filename}")


def save_as_csv(data, filename_prefix="report"):
    if not data:
        print("[!] No data to save.")
        return

    filename = f"{filename_prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    keys = data[0].keys()
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)
    print(f"[+] Report saved to {filename}")


# Example usage:
if __name__ == "__main__":
    sample_data = [
        {"Timestamp": "2025-07-01 10:00:00", "Event": "Possible SQL Injection", "Source IP": "192.168.1.10"},
        {"Timestamp": "2025-07-01 10:01:00", "Event": "Suspicious DNS Query", "Source IP": "192.168.1.12"}
    ]
    save_as_json(sample_data, "test_report")
    save_as_csv(sample_data, "test_report")