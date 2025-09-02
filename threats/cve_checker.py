# File : cve_checker.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :

import requests
import argparse
import json
import csv

CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(vendor, product, limit=5, severity=None, output_format=None):
    """
    This Function Queries NVD for CVEs by vendor and product
    """
    params = {
        "keywordSearch": f"{vendor} {product}",
        "resultsPerPage": limit
    }
    print(f"[*] Searching CVEs for: {vendor} {product} ...")
    response = requests.get(CVE_API_URL, params=params)

    if response.status_code != 200:
        print("[!] Failed to fetch CVE data.")
        return

    results = []
    data = response.json()
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve")
        if not cve:
            continue

        desc = cve['descriptions'][0]['value']
        sev = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'N/A')
        published = cve.get('published')

        if severity and sev.upper() != severity.upper():
            continue

        entry = {
            "CVE ID": cve.get('id'),
            "Description": desc,
            "Severity": sev,
            "Published": published
        }
        results.append(entry)
        print("---")
        print(f"CVE ID: {entry['CVE ID']}")
        print(f"Description: {entry['Description']}")
        print(f"Severity: {entry['Severity']}")
        print(f"Published: {entry['Published']}")

    if output_format == "json":
        with open("cve_output.json", "w") as f:
            json.dump(results, f, indent=2)
        print("[+] Results saved to cve_output.json")
    elif output_format == "csv":
        with open("cve_output.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["CVE ID", "Description", "Severity", "Published"])
            writer.writeheader()
            writer.writerows(results)
        print("[+] Results saved to cve_output.csv")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Query recent CVEs from NVD")
    parser.add_argument("--vendor", required=True,
                        help="Vendor name (e.g. apache)")
    parser.add_argument("--product", required=True,
                        help="Product name (e.g. httpd)")
    parser.add_argument("--limit", type=int, default=5,
                        help="Number of CVEs to return")
    parser.add_argument("--severity", help="Filter by severity "
                                           "(e.g. CRITICAL, HIGH, MEDIUM, LOW)")
    parser.add_argument("--format", help="Output format (json or csv)")

    args = parser.parse_args()
    search_cves(args.vendor, args.product, args.limit, args.severity, args.format)