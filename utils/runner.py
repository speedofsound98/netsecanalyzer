# NetSecAnalyzer 
# File : runner.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :
from reports.report_generator import save_as_json
from reports.mitre_mapper import map_event_to_mitre
from utils.logger import logger


def run_sniffer(start_fn, module_name, args):
    """
    Runs a sniffer module, enriches alerts with MITRE data, and saves them as JSON.

    Parameters:
        start_fn (function): The sniffing function to execute.
        module_name (str): A short identifier for the module (e.g., 'dns', 'tcp').
        args (argparse.Namespace): Parsed CLI arguments with interface, count, timeout.
    """
    try:
        alerts = start_fn(interface=args.interface, count=args.count, timeout=args.timeout)
        for alert in alerts:
            alert["MITRE"] = map_event_to_mitre(alert["Event"])
        save_as_json(alerts, f"{module_name}_alerts")
        logger.info(f"Saved {len(alerts)} alerts to report.")
    except Exception as e:
        logger.error(f"[!] Failed to run {module_name} sniffer: {e}")