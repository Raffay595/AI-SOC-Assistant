"""
SOC AI Assistant — Alert Service

Handles CRUD, filtering, searching, and exports of alerts.
Provides 9-dimension search parameters: IP, host, rule ID, MITRE, severity, time range, status, username, event ID.
"""

from sqlalchemy import or_, and_, desc
from sqlalchemy.orm import Session
from backend.models import Alert
from backend.schemas import AlertFilter, AlertCreate
from datetime import datetime, timedelta
import csv
import io


def get_alert_by_id(db: Session, alert_id: int) -> Alert:
    """Retrieve a single alert by ID."""
    return db.query(Alert).filter(Alert.id == alert_id).first()


def list_alerts(db: Session, filters: AlertFilter) -> list[Alert]:
    """
    List alerts with advanced 9-dimension filtering and pagination.
    """
    query = db.query(Alert)

    # 1. Source IP
    if filters.source_ip:
        query = query.filter(Alert.source_ip == filters.source_ip)

    # 2. Destination IP
    if filters.dest_ip:
        query = query.filter(Alert.dest_ip == filters.dest_ip)

    # 3. Hostname
    if filters.host:
        query = query.filter(Alert.host.like(f"%{filters.host}%"))

    # 4. Severity
    if filters.severity:
        query = query.filter(Alert.severity == filters.severity)

    # 5. Status
    if filters.status:
        query = query.filter(Alert.status == filters.status)

    # 6. Event ID
    if filters.event_id:
        query = query.filter(Alert.event_id == filters.event_id)

    # 7. Rule ID
    if filters.rule_id:
        query = query.filter(Alert.rule_id == filters.rule_id)

    # 8. Username
    if filters.username:
        query = query.filter(Alert.username.like(f"%{filters.username}%"))

    # 9. MITRE Technique ID
    if filters.mitre_technique_id:
        query = query.filter(Alert.mitre_technique_id == filters.mitre_technique_id)

    # Time range filtering
    if filters.start_date:
        query = query.filter(Alert.timestamp >= filters.start_date)
    if filters.end_date:
        query = query.filter(Alert.timestamp <= filters.end_date)

    # Keyword search (combines multiple fields)
    if filters.keyword:
        kw = f"%{filters.keyword}%"
        query = query.filter(
            or_(
                Alert.description.like(kw),
                Alert.raw_log.like(kw),
                Alert.host.like(kw),
                Alert.username.like(kw),
                Alert.source_ip.like(kw),
                Alert.dest_ip.like(kw),
                Alert.mitre_technique_name.like(kw)
            )
        )

    # Order by timestamp descending (newest first)
    query = query.order_by(desc(Alert.timestamp))

    return query.offset(filters.offset).limit(filters.limit).all()


def count_alerts(db: Session, filters: AlertFilter) -> int:
    """Count total alerts matching filters."""
    query = db.query(Alert)
    
    if filters.source_ip:
        query = query.filter(Alert.source_ip == filters.source_ip)
    if filters.dest_ip:
        query = query.filter(Alert.dest_ip == filters.dest_ip)
    if filters.host:
        query = query.filter(Alert.host.like(f"%{filters.host}%"))
    if filters.severity:
        query = query.filter(Alert.severity == filters.severity)
    if filters.status:
        query = query.filter(Alert.status == filters.status)
    if filters.event_id:
        query = query.filter(Alert.event_id == filters.event_id)
    if filters.rule_id:
        query = query.filter(Alert.rule_id == filters.rule_id)
    if filters.username:
        query = query.filter(Alert.username.like(f"%{filters.username}%"))
    if filters.mitre_technique_id:
        query = query.filter(Alert.mitre_technique_id == filters.mitre_technique_id)
    if filters.start_date:
        query = query.filter(Alert.timestamp >= filters.start_date)
    if filters.end_date:
        query = query.filter(Alert.timestamp <= filters.end_date)
    if filters.keyword:
        kw = f"%{filters.keyword}%"
        query = query.filter(
            or_(
                Alert.description.like(kw),
                Alert.raw_log.like(kw),
                Alert.host.like(kw),
                Alert.username.like(kw),
                Alert.source_ip.like(kw),
                Alert.dest_ip.like(kw)
            )
        )

    return query.count()


def update_alert_status(db: Session, alert_id: int, status: str) -> Alert:
    """Update alert lifecycle status."""
    alert = get_alert_by_id(db, alert_id)
    if alert:
        alert.status = status
        db.commit()
        db.refresh(alert)
    return alert


def assign_alert(db: Session, alert_id: int, analyst: str) -> Alert:
    """Assign alert to an analyst."""
    alert = get_alert_by_id(db, alert_id)
    if alert:
        alert.assigned_to = analyst
        alert.status = "Investigating"
        db.commit()
        db.refresh(alert)
    return alert


def create_alert(db: Session, alert_create: AlertCreate) -> Alert:
    """Create a new security alert manually (or from Wazuh webhook)."""
    db_alert = Alert(**alert_create.model_dump())
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert


def export_alerts_to_csv(alerts: list[Alert]) -> str:
    """Export a list of alerts to CSV format."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Headers
    writer.writerow([
        "ID", "Timestamp", "Severity", "Status", "Host", "Agent", 
        "Source IP", "Dest IP", "Event ID", "Rule ID", "Username",
        "MITRE Tactic", "MITRE Technique ID", "Description"
    ])
    
    # Rows
    for alert in alerts:
        writer.writerow([
            alert.id,
            alert.timestamp.isoformat() if alert.timestamp else "",
            alert.severity,
            alert.status,
            alert.host or "",
            alert.agent or "",
            alert.source_ip or "",
            alert.dest_ip or "",
            alert.event_id or "",
            alert.rule_id or "",
            alert.username or "",
            alert.mitre_tactic or "",
            alert.mitre_technique_id or "",
            alert.description or ""
        ])
        
    return output.getvalue()
