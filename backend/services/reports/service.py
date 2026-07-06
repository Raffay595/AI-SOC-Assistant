"""
SOC AI Assistant — Incident Report Generator Service

Fills out structured 8-section Incident Reports using sequential AI calls per section.
"""

from sqlalchemy.orm import Session
from backend.models import Incident, Alert
from backend.schemas import IncidentCreate, IncidentReport, MITREMapping, IOCItem
from backend.services.ai.analyzer import generate_report_section
from backend.services.ioc.service import extract_iocs
import json


def create_incident(db: Session, incident_create: IncidentCreate) -> Incident:
    """Create a new incident case linking alerts."""
    db_incident = Incident(
        title=incident_create.title,
        severity=incident_create.severity,
        status="Open",
        description=incident_create.description,
        alert_ids=incident_create.alert_ids,
        report_json=None
    )
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident


def get_incident_by_id(db: Session, incident_id: int) -> Incident:
    """Retrieve an incident by ID."""
    return db.query(Incident).filter(Incident.id == incident_id).first()


def list_incidents(db: Session) -> list[Incident]:
    """List all incidents."""
    return db.query(Incident).order_by(Incident.created_at.desc()).all()


def update_incident(db: Session, incident_id: int, title: str, severity: str, status: str, description: str, alert_ids: list[int]) -> Incident:
    """Update details of an incident."""
    incident = get_incident_by_id(db, incident_id)
    if incident:
        incident.title = title
        incident.severity = severity
        incident.status = status
        incident.description = description
        incident.alert_ids = alert_ids
        db.commit()
        db.refresh(incident)
    return incident


async def generate_incident_report(db: Session, incident_id: int) -> Incident:
    """
    Generates a full 8-section incident report by querying AI for individual sections,
    extracting dynamic parameters (timeline, IOCs, affected hosts) directly from linked alert structures.
    """
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        return None

    # Load linked alerts
    alerts = db.query(Alert).filter(Alert.id.in_(incident.alert_ids)).order_by(Alert.timestamp).all()
    
    # 1. Executive Summary (AI-generated)
    # 2. Timeline (Direct extraction from alert timestamps)
    timeline = [
        {
            "time": alert.timestamp.isoformat(),
            "event": alert.description,
            "source": f"{alert.host} ({alert.source})"
        } for alert in alerts
    ]

    # 3. Affected Hosts (Direct extraction from alerts)
    affected_hosts = list(set([alert.host for alert in alerts if alert.host]))

    # 4. IOCs (Direct extraction using IOC regex extractor)
    all_raw_logs = "\n".join([alert.raw_log or "" for alert in alerts])
    extracted = extract_iocs(all_raw_logs)
    iocs = [IOCItem(type=ioc["type"], value=ioc["value"]) for ioc in extracted]

    # 5. MITRE Mapping (Direct extraction from alerts)
    mitre_mappings = []
    seen_techniques = set()
    for alert in alerts:
        if alert.mitre_technique_id and alert.mitre_technique_id not in seen_techniques:
            mitre_mappings.append(MITREMapping(
                tactic=alert.mitre_tactic or "Unknown",
                technique=alert.mitre_technique_name or "Unknown",
                technique_id=alert.mitre_technique_id,
                description=f"Observed on host {alert.host} during alert trigger."
            ))
            seen_techniques.add(alert.mitre_technique_id)

    # Format alert details as text context for the AI
    alerts_context = ""
    for idx, alert in enumerate(alerts):
        alerts_context += (
            f"Alert #{idx+1}: {alert.timestamp} | Host: {alert.host} | "
            f"Event ID: {alert.event_id} | Tactic: {alert.mitre_tactic} | "
            f"Description: {alert.description}\n"
            f"Raw Log: {alert.raw_log}\n\n"
        )

    # 6. Executive Summary (AI-generated)
    exec_sec = await generate_report_section(
        "Executive Summary", "executive_summary",
        incident.title, incident.severity, incident.description, alerts_context
    )
    executive_summary = exec_sec.get("executive_summary", "Failed to generate summary.")

    # 7. Root Cause (AI-generated)
    rc_sec = await generate_report_section(
        "Root Cause Analysis", "root_cause",
        incident.title, incident.severity, incident.description, alerts_context
    )
    root_cause = rc_sec.get("root_cause", "Failed to analyze root cause.")

    # 8. Recommendations & Next Actions (AI-generated)
    rec_sec = await generate_report_section(
        "Actionable Recommendations", "recommendations",
        incident.title, incident.severity, incident.description, alerts_context
    )
    recommendations = rec_sec.get("recommendations", ["Review logs.", "Investigate endpoints."])

    act_sec = await generate_report_section(
        "Next Investigation Actions", "next_actions",
        incident.title, incident.severity, incident.description, alerts_context
    )
    next_actions = act_sec.get("next_actions", ["Isolate host.", "Reset passwords."])

    # Assemble report schema
    report = IncidentReport(
        executive_summary=executive_summary,
        timeline=timeline,
        affected_hosts=affected_hosts,
        iocs=iocs,
        mitre_mapping=mitre_mappings,
        root_cause=root_cause,
        recommendations=recommendations,
        next_actions=next_actions
    )

    # Save to database
    incident.report_json = report.model_dump()
    db.commit()
    db.refresh(incident)

    return incident
