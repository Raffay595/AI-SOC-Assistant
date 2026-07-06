"""
SOC AI Assistant — Correlation & Attack Chain Engine

Detects attack patterns (e.g. Brute Force -> Successful Logon -> Priv Escalation)
by correlating multiple alerts within time windows.
"""

from datetime import datetime, timedelta
from backend.models import Alert
from sqlalchemy.orm import Session
from sqlalchemy import desc
import uuid


# Correlation Rules defining attack chains
CORRELATION_RULES = [
    {
        "id": "RULE_001",
        "name": "Brute Force to Privilege Escalation",
        "description": "Observed multiple login failures followed by successful access and privilege assignment/persistence within 20 minutes.",
        "severity": "Critical",
        "chain": [
            {"mitre_technique_id": "T1110.001", "role": "brute_force"}, # Brute force
            {"mitre_technique_id": "T1078", "role": "initial_access"},      # Valid Accounts logon
            {"mitre_tactic": "Privilege Escalation", "role": "priv_escalation"} # Privilege escalation or persistence
        ],
        "window_minutes": 20
    },
    {
        "id": "RULE_002",
        "name": "Phishing to Outbound C2",
        "description": "Office application execution followed by encoded scripting shell execution and outbound connection to external IP.",
        "severity": "Critical",
        "chain": [
            {"mitre_technique_id": "T1204.002", "role": "phishing_click"}, # User execution
            {"mitre_technique_id": "T1059.001", "role": "execution"},      # PowerShell
            {"mitre_technique_id": "T1071.001", "role": "c2_beacon"}       # Web C2
        ],
        "window_minutes": 15
    },
    {
        "id": "RULE_003",
        "name": "Lateral Movement to Persistence",
        "description": "Network discovery scan followed by remote admin shares lateral transfer and service installation/persistence.",
        "severity": "Critical",
        "chain": [
            {"mitre_technique_id": "T1046", "role": "discovery"},         # Scan
            {"mitre_technique_id": "T1570", "role": "lateral_transfer"},   # Lateral transfer
            {"mitre_technique_id": "T1543.003", "role": "persistence"}     # Create system process service
        ],
        "window_minutes": 30
    }
]


def detect_attack_chains(db: Session) -> list[dict]:
    """
    Scans recent alerts and groups them into attack chains based on correlation rules.
    Returns a list of dicts representing detected chains, timestamps, and alerts in the chain.
    """
    # Fetch alerts from database (chronological order)
    alerts = db.query(Alert).order_by(Alert.timestamp).all()
    if not alerts:
        return []

    detected_chains = []

    # Simple correlation engine matching rules
    for rule in CORRELATION_RULES:
        # Group alerts by host or IP to find correlation per entity
        entities = {}
        for alert in alerts:
            # Correlate either by host or source IP (if available)
            key = alert.host or alert.source_ip or "unknown"
            if key not in entities:
                entities[key] = []
            entities[key].append(alert)

        for entity_key, entity_alerts in entities.items():
            # Try to match the rule's sequence of techniques in chronological order
            chain_steps = rule["chain"]
            matched_instances = []
            
            # Simple state machine to look for sequential alerts matching rule criteria within window
            i = 0
            while i < len(entity_alerts):
                # Search for the first step
                first_alert = entity_alerts[i]
                if _matches_criteria(first_alert, chain_steps[0]):
                    current_chain = [first_alert]
                    window_start = first_alert.timestamp
                    window_end = window_start + timedelta(minutes=rule["window_minutes"])
                    
                    # Look for subsequent steps within the time window
                    step_idx = 1
                    j = i + 1
                    while j < len(entity_alerts) and step_idx < len(chain_steps):
                        next_alert = entity_alerts[j]
                        # Must be within window
                        if next_alert.timestamp > window_end:
                            break
                        
                        # Must match criteria for the current step
                        if _matches_criteria(next_alert, chain_steps[step_idx]):
                            current_chain.append(next_alert)
                            step_idx += 1
                        j += 1

                    if step_idx == len(chain_steps):
                        # Full chain matched!
                        chain_id = str(uuid.uuid4())[:8]
                        matched_instances.append({
                            "chain_id": f"CHAIN-{chain_id.upper()}",
                            "name": rule["name"],
                            "description": rule["description"],
                            "severity": rule["severity"],
                            "host": first_alert.host or "Multiple",
                            "attacker": first_alert.source_ip or "Multiple",
                            "start_time": window_start,
                            "end_time": current_chain[-1].timestamp,
                            "alerts": current_chain,
                            "timeline": [
                                {
                                    "time": a.timestamp,
                                    "event": a.description,
                                    "severity": a.severity,
                                    "id": a.id,
                                    "mitre": f"{a.mitre_technique_id or 'N/A'} ({a.mitre_technique_name or 'N/A'})"
                                } for a in current_chain
                            ]
                        })
                        # Skip past matches to avoid duplicates
                        i = j - 1
                i += 1
                
            detected_chains.extend(matched_instances)

    # Sort chains newest first (by end_time)
    detected_chains.sort(key=lambda x: x["end_time"], reverse=True)
    return detected_chains


def _matches_criteria(alert: Alert, criteria: dict) -> bool:
    """Helper to check if an alert matches correlation criteria."""
    if "mitre_technique_id" in criteria:
        # Match technique ID (or main technique if checking parent)
        alert_tech = alert.mitre_technique_id or ""
        target_tech = criteria["mitre_technique_id"]
        # Allow checking parent technique (e.g. T1078 matches T1078.002)
        if alert_tech == target_tech or alert_tech.startswith(target_tech + "."):
            return True

    if "mitre_tactic" in criteria:
        if alert.mitre_tactic == criteria["mitre_tactic"]:
            return True

    return False
