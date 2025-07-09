# File : heuristic_rules.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :


import re


# Example rule: suspicious HTTP payload content
def detect_sql_injection(payload):
    # Looks for SQL keywords or common injection patterns
    return bool(re.search(r"('|\"|--|;|\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\b)", payload, re.IGNORECASE))


# Example rule: directory traversal attempts
def detect_dir_traversal(payload):
    return "../" in payload or "..\\" in payload


# Example rule: long encoded URLs or Base64-like payloads
def detect_encoded_payload(payload):
    return bool(re.search(r"[A-Za-z0-9+/=]{40,}", payload))


# Apply all rules and return list of hits
def run_heuristics(payload):
    alerts = []
    if detect_sql_injection(payload):
        alerts.append("Possible SQL Injection")
    if detect_dir_traversal(payload):
        alerts.append("Possible Directory Traversal")
    if detect_encoded_payload(payload):
        alerts.append("Suspicious Encoded Payload")
    return alerts


# Example usage:
if __name__ == "__main__":
    test_payload = "GET /page.php?id=1 UNION SELECT password FROM users -- " \
                   "HTTP/1.1"
    print(run_heuristics(test_payload))
