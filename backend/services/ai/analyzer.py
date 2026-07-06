"""
SOC AI Assistant — AI Analyzer

Core analysis functions: alert analysis, log summarization, report generation.
Uses OpenRouter via the AI client. Falls back to mock responses when no API key.
"""

from backend.services.ai.client import call_ai, get_model
from backend.services.ai.prompts import (
    ALERT_ANALYSIS_SYSTEM, ALERT_ANALYSIS_USER,
    LOG_SUMMARY_SYSTEM, LOG_SUMMARY_USER,
    INCIDENT_REPORT_SYSTEM, INCIDENT_REPORT_USER,
    CORRELATION_ANALYSIS_SYSTEM, CORRELATION_ANALYSIS_USER,
)
from backend.schemas import AIAnalysisResult, LogSummaryResult
from backend.models import Alert
from typing import Optional
import json


async def analyze_alert(alert: Alert) -> dict:
    """
    Analyze a security alert using AI.
    Returns a dict matching AIAnalysisResult schema.
    Falls back to mock analysis if no API key.
    """
    user_prompt = ALERT_ANALYSIS_USER.format(
        alert_id=alert.id,
        timestamp=alert.timestamp,
        source_ip=alert.source_ip or "N/A",
        dest_ip=alert.dest_ip or "N/A",
        event_id=alert.event_id or "N/A",
        rule_id=alert.rule_id or "N/A",
        severity=alert.severity or "Unknown",
        description=alert.description or "N/A",
        host=alert.host or "N/A",
        agent=alert.agent or "N/A",
        username=alert.username or "N/A",
        mitre_tactic=alert.mitre_tactic or "N/A",
        mitre_technique_id=alert.mitre_technique_id or "N/A",
        mitre_technique_name=alert.mitre_technique_name or "N/A",
        raw_log=alert.raw_log or "No raw log available",
    )

    result = await call_ai(ALERT_ANALYSIS_SYSTEM, user_prompt)

    if result is None:
        # No API key — return mock analysis
        return _mock_alert_analysis(alert)

    return result


async def summarize_logs(raw_logs: str) -> dict:
    """Summarize raw logs using AI."""
    user_prompt = LOG_SUMMARY_USER.format(raw_logs=raw_logs)
    result = await call_ai(LOG_SUMMARY_SYSTEM, user_prompt)

    if result is None:
        return _mock_log_summary(raw_logs)

    return result


async def generate_report_section(
    section: str, section_key: str, title: str, severity: str,
    description: str, alerts_data: str
) -> dict:
    """Generate a single section of an incident report."""
    user_prompt = INCIDENT_REPORT_USER.format(
        section=section,
        section_key=section_key,
        title=title,
        severity=severity,
        description=description or "",
        alerts_data=alerts_data,
    )

    result = await call_ai(INCIDENT_REPORT_SYSTEM, user_prompt)

    if result is None:
        return {section_key: f"[Mock] {section} for incident: {title}"}

    return result


async def analyze_correlation(chain_name: str, rule_description: str, alerts_data: str) -> dict:
    """Analyze a detected attack chain."""
    user_prompt = CORRELATION_ANALYSIS_USER.format(
        chain_name=chain_name,
        rule_description=rule_description,
        alerts_data=alerts_data,
    )

    result = await call_ai(CORRELATION_ANALYSIS_SYSTEM, user_prompt)

    if result is None:
        return _mock_correlation_analysis(chain_name)

    return result


# ─── Mock Responses (when no API key) ──────────────────────

def _mock_alert_analysis(alert: Alert) -> dict:
    """Generate a realistic mock analysis for demo purposes."""
    severity_map = {"Critical": 0.95, "High": 0.82, "Medium": 0.65, "Low": 0.45, "Informational": 0.3}
    confidence = severity_map.get(alert.severity, 0.5)

    iocs = []
    if alert.source_ip and alert.source_ip != "N/A":
        iocs.append({"type": "IP", "value": alert.source_ip})
    if alert.dest_ip and alert.dest_ip != "N/A" and "/" not in alert.dest_ip:
        iocs.append({"type": "IP", "value": alert.dest_ip})

    return {
        "summary": f"Alert detected: {alert.description}. "
                   f"This event was triggered on host {alert.host} "
                   f"{'by user ' + alert.username if alert.username else ''} "
                   f"and involves {alert.mitre_tactic or 'suspicious'} activity. "
                   f"Source IP {alert.source_ip} initiated the activity targeting {alert.dest_ip}.",
        "severity": alert.severity,
        "confidence": confidence,
        "confidence_reason": f"Confidence based on alert severity ({alert.severity}), "
                            f"MITRE mapping ({alert.mitre_technique_id or 'N/A'}), "
                            f"and event characteristics. This is a mock analysis — configure your OpenRouter API key for real AI analysis.",
        "attack_stage": alert.mitre_tactic or "Unknown",
        "mitre": {
            "tactic": alert.mitre_tactic or "Unknown",
            "technique": alert.mitre_technique_name or "Unknown",
            "technique_id": alert.mitre_technique_id or "Unknown",
            "description": f"This alert maps to {alert.mitre_technique_name} based on the observed behavior pattern."
        } if alert.mitre_tactic else None,
        "iocs": iocs,
        "evidence": [
            f"Event ID {alert.event_id} was observed on {alert.host}",
            f"Source IP: {alert.source_ip}",
            f"Rule {alert.rule_id} was triggered",
            f"Raw log contains indicators matching this alert type",
        ],
        "recommendations": [
            f"Investigate host {alert.host} for additional indicators of compromise",
            f"Check for related alerts from the same source IP ({alert.source_ip})",
            f"Review authentication logs for the affected timeframe",
            f"Consider isolating the affected host if severity warrants it",
        ],
        "investigation_steps": [
            f"1. Review all events from {alert.source_ip} in the last 24 hours",
            f"2. Check if user '{alert.username or 'N/A'}' has legitimate access to {alert.host}",
            f"3. Look for lateral movement from {alert.host} to other hosts",
            f"4. Search for the MITRE technique {alert.mitre_technique_id} across all hosts",
            f"5. Check threat intelligence for {alert.source_ip}",
        ],
        "facts_vs_assumptions": {
            "facts": [
                f"Event ID {alert.event_id} was logged at {alert.timestamp}",
                f"Source: {alert.source_ip}, Destination: {alert.dest_ip}",
                f"Host: {alert.host}, Agent: {alert.agent}",
            ],
            "assumptions": [
                "The activity may be part of a larger attack campaign",
                f"The source IP {alert.source_ip} may be compromised or malicious",
                "Additional investigation is needed to confirm intent",
            ],
        },
    }


def _mock_log_summary(raw_logs: str) -> dict:
    """Generate mock log summary."""
    from backend.services.ioc.service import extract_iocs
    iocs_result = extract_iocs(raw_logs)

    return {
        "summary": f"Log analysis of {len(raw_logs.splitlines())} lines. "
                   "Found potential indicators requiring investigation. "
                   "This is a mock summary — configure your OpenRouter API key for real AI analysis.",
        "suspicious_events": [
            "Multiple authentication-related events detected",
            "Network connections to external IPs observed",
        ],
        "timeline": [
            {"time": "Start of logs", "event": "First event recorded", "severity": "Low"},
            {"time": "End of logs", "event": "Last event recorded", "severity": "Low"},
        ],
        "recommendations": [
            "Review flagged IOCs against threat intelligence",
            "Correlate with other log sources",
            "Investigate any high-severity events in detail",
        ],
        "iocs": [{"type": ioc["type"], "value": ioc["value"]} for ioc in iocs_result],
    }


def _mock_correlation_analysis(chain_name: str) -> dict:
    """Generate mock correlation analysis."""
    return {
        "chain_summary": f"Attack chain '{chain_name}' detected. Multiple related alerts suggest a coordinated attack. "
                         "This is a mock analysis — configure your OpenRouter API key for real AI analysis.",
        "severity": "Critical",
        "confidence": 0.75,
        "confidence_reason": "Multiple correlated alerts from the same source suggest coordinated activity.",
        "attack_narrative": "The attacker appears to have followed a common attack pattern progressing through multiple MITRE ATT&CK tactics.",
        "mitre_tactics_flow": ["Initial Access", "Execution", "Persistence", "Lateral Movement"],
        "recommendations": [
            "Immediately isolate affected hosts",
            "Reset credentials for compromised accounts",
            "Review firewall rules for the involved IPs",
            "Conduct a full forensic analysis",
        ],
        "immediate_actions": [
            "Isolate affected systems from the network",
            "Block malicious IPs at the firewall",
            "Force password reset for affected accounts",
        ],
    }
