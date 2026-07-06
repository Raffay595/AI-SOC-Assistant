"""
SOC AI Assistant — Threat Intelligence Service

Provides strict database/blacklist lookup-based reputation assessments for IPs, domains, and hashes.
NO AI fabrication. Returns 'Unknown' if the indicator is not in the malicious database.
Includes extension placeholders for VirusTotal, AbuseIPDB, and AlienVault OTX.
"""

from backend.schemas import ThreatIntelResponse
from typing import Optional

# Curated database of simulated known malicious and suspicious indicators
THREAT_INTEL_DB = {
    "ip": {
        "185.220.101.42": {
            "reputation": "Known Malicious",
            "malware_family": "Tor Exit Node / SSH Brute Force Botnet",
            "source": "AbuseIPDB, Emerging Threats",
            "recommended_actions": [
                "Block inbound traffic at perimeter firewall.",
                "Terminate any active sessions originating from this IP.",
                "Investigate host authentication logs for successful logons."
            ]
        },
        "198.51.100.23": {
            "reputation": "Known Malicious",
            "malware_family": "Cobalt Strike C2 / Phishing Redirector",
            "source": "AlienVault OTX, Feodo Tracker",
            "recommended_actions": [
                "Block all outbound traffic to this IP at perimeter firewall.",
                "Isolate any internal host communicating with this IP.",
                "Conduct full memory and process forensics on communicating hosts."
            ]
        },
        "91.108.56.200": {
            "reputation": "Suspicious",
            "malware_family": "VPN Anomaly / Proxy Network",
            "source": "Spamhaus DROP",
            "recommended_actions": [
                "Require Multi-Factor Authentication (MFA) step-up for sessions.",
                "Verify login legitimacy with user (Sarah Chen).",
                "Monitor for subsequent privilege escalation or discovery actions."
            ]
        },
        "45.33.32.156": {
            "reputation": "Known Malicious",
            "malware_family": "Mirai Variant SSH Scanner",
            "source": "ThreatFeeds.io",
            "recommended_actions": [
                "Block inbound SSH/TCP 22 attempts from this IP.",
                "Verify that local servers do not use default SSH credentials."
            ]
        }
    },
    "domain": {
        "cdn-update-service.com": {
            "reputation": "Known Malicious",
            "malware_family": "SystemBC C2 Proxy Domain",
            "source": "ThreatConnect, DNSBL",
            "recommended_actions": [
                "Sinkhole domain DNS resolution on internal DNS servers.",
                "Inspect proxy/DNS logs for all hosts querying this domain.",
                "Isolate querying systems."
            ]
        },
        "xk3j8f9a2b.com": {
            "reputation": "Suspicious",
            "malware_family": "Domain Generation Algorithm (DGA) / Beaconing",
            "source": "DNS Query Anomaly Detector",
            "recommended_actions": [
                "Block outbound DNS queries to this domain.",
                "Check system for running powershell or script interpreters spawning external network calls."
            ]
        },
        "malware.evil.com": {
            "reputation": "Known Malicious",
            "malware_family": "Phishing Payload Host",
            "source": "URLhaus",
            "recommended_actions": [
                "Block domain and host URL at email gateway and proxy.",
                "Inspect email inbox logs for emails containing this link."
            ]
        }
    },
    "hash": {
        "d41d8cd98f00b204e9800998ecf8427e": {
            "reputation": "Suspicious",
            "malware_family": "Empty/Corrupt Web Shell template",
            "source": "Local Hash Baseline",
            "recommended_actions": [
                "Delete file from web root directory (/var/www/html/uploads/cmd.php).",
                "Audit file upload controller permissions."
            ]
        },
        # WannaCry Ransomware SHA256 (simulated)
        "24d6f71cd95788d5aa2da0d7d295c256722d5aa2da0d7d295c256722d5aa2da0d": {
            "reputation": "Known Malicious",
            "malware_family": "WannaCry Ransomware",
            "source": "VirusTotal, ThreatIntel Shared",
            "recommended_actions": [
                "Isolate system immediately to prevent lateral encryption.",
                "Deploy local endpoint blocking rule for WannaCry file hash.",
                "Verify backup restoration status."
            ]
        }
    }
}


def lookup_indicator(indicator: str, indicator_type: str) -> ThreatIntelResponse:
    """
    Lookup an indicator in the threat intelligence DB.
    Guarantees 'Unknown' classification if not found, preventing AI hallucination.
    """
    indicator = indicator.strip()
    indicator_type = indicator_type.lower()
    
    # Select sub-db
    sub_db = THREAT_INTEL_DB.get(indicator_type, {})
    
    # Perform match
    match = sub_db.get(indicator)
    
    if match:
        return ThreatIntelResponse(
            indicator=indicator,
            type=indicator_type,
            reputation=match["reputation"],
            malware_family=match["malware_family"],
            source=match["source"],
            recommended_actions=match["recommended_actions"],
            last_seen="2026-07-05T12:00:00Z"
        )
    
    # Fallback to Unknown (no fabrication)
    return ThreatIntelResponse(
        indicator=indicator,
        type=indicator_type,
        reputation="Unknown",
        malware_family=None,
        source="System DB Lookup",
        recommended_actions=[
            "No known malicious matching indicators found in local dataset.",
            "Submit indicator to VirusTotal or AbuseIPDB for broader search.",
            "Monitor network traffic for anomalies associated with this indicator."
        ],
        last_seen=None
    )
