# NetSecAnalyzer 
# File : mitre_mapper.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :

MITRE_MAP = {
    "Suspicious DNS Query": {
        "Tactic": "Command and Control",
        "Technique": "Domain Generation Algorithms",
        "ID": "T1568.002"
    },
    "Anonymous FTP Login": {
        "Tactic": "Initial Access",
        "Technique": "Valid Accounts",
        "ID": "T1078"
    },
    "SMB NTLM Authentication": {
        "Tactic": "Credential Access",
        "Technique": "Pass the Hash",
        "ID": "T1550.002"
    },
    "Possible SQL Injection": {
        "Tactic": "Initial Access",
        "Technique": "Exploitation for Web Access",
        "ID": "T1190"
    },
    "Directory Traversal": {
        "Tactic": "Defense Evasion",
        "Technique": "Exploitation for Defense Evasion",
        "ID": "T1211"
    }
}


def map_event_to_mitre(event_type):
    return MITRE_MAP.get(event_type, {
        "Tactic": "Unknown",
        "Technique": "Unknown",
        "ID": "N/A"
    })