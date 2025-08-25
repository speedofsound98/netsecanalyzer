# NetSecAnalyzer 
# File : cve_parser.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :
import pandas as pd
import argparse
import os


def process_csv(file, min_cvss=8.0, export_json=False):
    df = pd.read_csv(file)
    df = df[df["cvss_score"] >= min_cvss]
    df = df[["cve_id", "description", "vendor", "cvss_score", "published_date"]]

    output_dir = "reports/output"
    os.makedirs(output_dir, exist_ok=True)

    csv_path = os.path.join(output_dir, "filtered_cves.csv")
    df.to_csv(csv_path, index=False)

    if export_json:
        json_path = os.path.join(output_dir, "filtered_cves.json")
        df.to_json(json_path, orient="records", indent=2)

    print(f"[✓] Exported {len(df)} rows to {csv_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, help="CSV input file")
    parser.add_argument("--min_cvss", type=float, default=8.0)
    parser.add_argument("--export_json", action="store_true")
    args = parser.parse_args()

    process_csv(args.file, args.min_cvss, args.export_json)
