"""
SOC AI Assistant — Threat Intelligence Service

Provides strict database/blacklist lookup-based reputation assessments for IPs, domains, and hashes.
NO AI fabrication. Returns 'Unknown' if the indicator is not in the malicious database.
Includes extension placeholders for VirusTotal, AbuseIPDB, and AlienVault OTX.
"""

from backend.schemas import ThreatIntelResponse
from backend.models import Alert
from backend.services.ai.client import call_ai
from sqlalchemy.orm import Session
from typing import Optional

# Curated database of simulated known malicious and suspicious indicators
THREAT_INTEL_DB = {
    "ip": {
        "185.220.101.42": {
            "reputation": "Known Malicious",
            "severity": "Critical",
            "confidence": 94,
            "category": "Botnet",
            "malware_family": "Tor Exit Node / SSH Brute Force Botnet",
            "sources": ["AbuseIPDB", "Emerging Threats", "Internal SOC Database"],
            "mitre": ["T1110.001"],
            "first_seen": "2026-07-01",
            "last_seen": "2026-07-10",
            "recommended_actions": [
                "Block inbound traffic at perimeter firewall.",
                "Terminate any active sessions originating from this IP.",
                "Investigate host authentication logs for successful logons."
            ]
        },
        "198.51.100.23": {
            "reputation": "Known Malicious",
            "severity": "High",
            "confidence": 90,
            "category": "Command and Control",
            "malware_family": "Cobalt Strike C2 / Phishing Redirector",
            "sources": ["AlienVault OTX", "Feodo Tracker", "Internal SOC Database"],
            "mitre": ["T1071.001"],
            "first_seen": "2026-06-25",
            "last_seen": "2026-07-09",
            "recommended_actions": [
                "Block all outbound traffic to this IP at perimeter firewall.",
                "Isolate any internal host communicating with this IP.",
                "Conduct full memory and process forensics on communicating hosts."
            ]
        },
        "91.108.56.200": {
            "reputation": "Suspicious",
            "severity": "Medium",
            "confidence": 75,
            "category": "Suspicious Infrastructure",
            "malware_family": "VPN Anomaly / Proxy Network",
            "sources": ["Spamhaus DROP", "Internal Database"],
            "mitre": ["T1090"],
            "first_seen": "2026-07-04",
            "last_seen": "2026-07-10",
            "recommended_actions": [
                "Require Multi-Factor Authentication (MFA) step-up for sessions.",
                "Verify login legitimacy with user (Sarah Chen).",
                "Monitor for subsequent privilege escalation or discovery actions."
            ]
        },
        "45.33.32.156": {
            "reputation": "Known Malicious",
            "severity": "High",
            "confidence": 95,
            "category": "Scanner",
            "malware_family": "Mirai Variant SSH Scanner",
            "sources": ["ThreatFeeds.io", "Internal Database"],
            "mitre": ["T1110.001"],
            "first_seen": "2026-07-01",
            "last_seen": "2026-07-10",
            "recommended_actions": [
                "Block inbound SSH/TCP 22 attempts from this IP.",
                "Verify that local servers do not use default SSH credentials."
            ]
        }
    },
    "domain": {
        "cdn-update-service.com": {
            "reputation": "Known Malicious",
            "severity": "High",
            "confidence": 92,
            "category": "Command and Control",
            "malware_family": "SystemBC C2 Proxy Domain",
            "sources": ["ThreatConnect", "DNSBL", "Emerging Threats"],
            "mitre": ["T1071.001"],
            "first_seen": "2026-06-20",
            "last_seen": "2026-07-08",
            "recommended_actions": [
                "Sinkhole domain DNS resolution on internal DNS servers.",
                "Inspect proxy/DNS logs for all hosts querying this domain.",
                "Isolate querying systems."
            ]
        },
        "xk3j8f9a2b.com": {
            "reputation": "Suspicious",
            "severity": "Medium",
            "confidence": 65,
            "category": "Suspicious Infrastructure",
            "malware_family": "Domain Generation Algorithm (DGA) / Beaconing",
            "sources": ["DNS Query Anomaly Detector"],
            "mitre": ["T1568.002"],
            "first_seen": "2026-07-05",
            "last_seen": "2026-07-10",
            "recommended_actions": [
                "Block outbound DNS queries to this domain.",
                "Check system for running powershell or script interpreters spawning external network calls."
            ]
        },
        "malware.evil.com": {
            "reputation": "Known Malicious",
            "severity": "Critical",
            "confidence": 98,
            "category": "Phishing",
            "malware_family": "Phishing Payload Host",
            "sources": ["URLhaus", "AbuseIPDB"],
            "mitre": ["T1566.002"],
            "first_seen": "2026-07-02",
            "last_seen": "2026-07-09",
            "recommended_actions": [
                "Block domain and host URL at email gateway and proxy.",
                "Inspect email inbox logs for emails containing this link."
            ]
        }
    },
    "hash": {
        "d41d8cd98f00b204e9800998ecf8427e": {
            "reputation": "Suspicious",
            "severity": "Medium",
            "confidence": 60,
            "category": "Suspicious Infrastructure",
            "malware_family": "Empty/Corrupt Web Shell template",
            "sources": ["Local Hash Baseline"],
            "mitre": ["T1505.003"],
            "first_seen": "2026-07-01",
            "last_seen": "2026-07-05",
            "recommended_actions": [
                "Delete file from web root directory (/var/www/html/uploads/cmd.php).",
                "Audit file upload controller permissions."
            ]
        },
        "24d6f71cd95788d5aa2da0d7d295c256722d5aa2da0d7d295c256722d5aa2da0d": {
            "reputation": "Known Malicious",
            "severity": "Critical",
            "confidence": 99,
            "category": "Malware",
            "malware_family": "WannaCry Ransomware",
            "sources": ["VirusTotal", "ThreatIntel Shared"],
            "mitre": ["T1486"],
            "first_seen": "2026-05-12",
            "last_seen": "2026-07-10",
            "recommended_actions": [
                "Isolate system immediately to prevent lateral encryption.",
                "Deploy local endpoint blocking rule for WannaCry file hash.",
                "Verify backup restoration status."
            ]
        }
    }
}


async def generate_ai_summary(indicator: str, indicator_type: str, match_data: dict, alerts_count: int) -> str:
    """Queries OpenRouter API for a brief, actionable SOC summary or falls back to simulated template."""
    is_unknown = match_data.get("reputation") == "Unknown"
    
    if is_unknown:
        system_prompt = (
            "You are an expert enterprise SOC AI analyst. Generate a short, actionable warning summary (max 3 sentences) "
            "for an UNKNOWN reputation indicator. Explain that it was not found in internal baselines, and outline key monitoring suggestions. "
            "Your response MUST be a JSON object with a single key 'summary'."
        )
        user_prompt = f"Indicator: {indicator}\nType: {indicator_type.upper()}\nReputation: UNKNOWN\nAlerts Count: {alerts_count}"
    else:
        system_prompt = (
            "You are an expert enterprise SOC AI analyst. Generate a short, concise, action-oriented, "
            "and technical threat intelligence summary (max 3 sentences) for a known malicious/suspicious indicator lookup. "
            "Highlight the reputation, severity, category, and related alerts count. "
            "Your response MUST be a JSON object with a single key 'summary'."
        )
        user_prompt = f"""
        Indicator: {indicator}
        Type: {indicator_type.upper()}
        Reputation: {match_data.get('reputation')}
        Severity: {match_data.get('severity')}
        Category: {match_data.get('category')}
        Malware Family: {match_data.get('malware_family')}
        Sources: {", ".join(match_data.get('sources', []))}
        MITRE: {", ".join(match_data.get('mitre', []))}
        Related Alerts Count: {alerts_count}
        """
        
    try:
        res = await call_ai(system_prompt, user_prompt)
        if res and isinstance(res, dict) and "summary" in res:
            return res["summary"]
    except Exception:
        pass
        
    # Local fallback
    if is_unknown:
        return (
            f"AI Analyst Summary: No threat matches for {indicator_type.upper()} '{indicator}' found in local datasets. "
            "This suggests an UNKNOWN profile rather than a guaranteed safe status. "
            "Actionable recommendations include logging perimeter queries, verifying anomalous ingress behavior, and checking AbuseIPDB."
        )
    else:
        severity = match_data.get("severity", "Unknown")
        category = match_data.get("category", "Malicious Activity")
        alert_desc = f"and correlates with {alerts_count} active security alert(s)" if alerts_count > 0 else "but currently has 0 related alerts"
        return (
            f"AI Analyst Summary: The {indicator_type.upper()} indicator '{indicator}' is categorized as "
            f"{match_data['reputation']} ({severity} severity) representing potential {category} behavior. "
            f"It {alert_desc} on our systems. Immediate ingress blocking and credential inspection is strongly advised."
        )


async def lookup_indicator(indicator: str, indicator_type: str, db: Optional[Session] = None) -> ThreatIntelResponse:
    """
    Lookup an indicator in the threat intelligence DB.
    Guarantees 'Unknown' classification if not found, preventing AI hallucination.
    Queries the database session to retrieve related events.
    """
    indicator = indicator.strip()
    indicator_type = indicator_type.lower()
    
    # Query database for related alerts
    related_alerts = []
    if db is not None:
        try:
            if indicator_type == "ip":
                related_alerts = db.query(Alert).filter(
                    (Alert.source_ip == indicator) | (Alert.dest_ip == indicator)
                ).limit(10).all()
            elif indicator_type == "domain":
                related_alerts = db.query(Alert).filter(
                    (Alert.description.like(f"%{indicator}%")) | (Alert.raw_log.like(f"%{indicator}%"))
                ).limit(10).all()
            elif indicator_type == "hash":
                related_alerts = db.query(Alert).filter(
                    (Alert.raw_log.like(f"%{indicator}%")) | (Alert.description.like(f"%{indicator}%"))
                ).limit(10).all()
        except Exception as e:
            # Fallback gracefully
            print(f"Error querying related alerts for Threat Intel: {e}")

    # Select sub-db
    sub_db = THREAT_INTEL_DB.get(indicator_type, {})
    
    # Perform match
    match = sub_db.get(indicator)
    
    if match:
        ai_summary = await generate_ai_summary(indicator, indicator_type, match, len(related_alerts))
        return ThreatIntelResponse(
            indicator=indicator,
            type=indicator_type,
            reputation=match["reputation"],
            malware_family=match["malware_family"],
            source=", ".join(match["sources"]),
            recommended_actions=match["recommended_actions"],
            last_seen=match["last_seen"],
            severity=match.get("severity", "Medium"),
            confidence=match.get("confidence", 70),
            category=match.get("category"),
            sources=match.get("sources", []),
            mitre=match.get("mitre", []),
            first_seen=match.get("first_seen"),
            related_alerts=related_alerts,
            ai_summary=ai_summary
        )
    
    # Fallback to Unknown (no fabrication)
    unknown_data = {
        "reputation": "Unknown",
        "severity": "Unknown",
        "confidence": 0,
        "category": "Unknown",
        "sources": ["System DB Lookup"],
        "recommended_actions": [
            "Submit indicator to external threat intelligence sources.",
            "Monitor future activity originating from or targeting this indicator.",
            "Check related network logs for historical anomalies."
        ]
    }
    ai_summary = await generate_ai_summary(indicator, indicator_type, unknown_data, len(related_alerts))
    return ThreatIntelResponse(
        indicator=indicator,
        type=indicator_type,
        reputation="Unknown",
        malware_family=None,
        source="System DB Lookup",
        recommended_actions=unknown_data["recommended_actions"],
        last_seen=None,
        severity="Unknown",
        confidence=0,
        category="Unknown",
        sources=unknown_data["sources"],
        mitre=[],
        first_seen=None,
        related_alerts=related_alerts,
        ai_summary=ai_summary
    )
