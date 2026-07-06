"""
SOC AI Assistant — Alert Router
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.schemas import AlertResponse, AlertFilter, AlertCreate
from backend.services.alerts import service as alert_service
from backend.services.alerts.correlation import detect_attack_chains
from typing import Optional
from datetime import datetime

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("", response_model=list[AlertResponse])
def get_alerts(
    source_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    host: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    event_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    mitre_technique_id: Optional[str] = None,
    username: Optional[str] = None,
    keyword: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Retrieve filtered, paginated lists of security alerts."""
    filters = AlertFilter(
        source_ip=source_ip,
        dest_ip=dest_ip,
        host=host,
        severity=severity,
        status=status,
        event_id=event_id,
        rule_id=rule_id,
        mitre_technique_id=mitre_technique_id,
        username=username,
        keyword=keyword,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset
    )
    return alert_service.list_alerts(db, filters)


@router.post("", response_model=AlertResponse)
def create_new_alert(alert_in: AlertCreate, db: Session = Depends(get_db)):
    """Ingest a new alert manually or via Wazuh script webhook."""
    return alert_service.create_alert(db, alert_in)


@router.get("/correlated")
def get_correlated_chains(db: Session = Depends(get_db)):
    """Runs correlation engine scanning and returning active attack chains."""
    chains = detect_attack_chains(db)
    # Serialize for output
    serializable = []
    for chain in chains:
        serializable.append({
            "chain_id": chain["chain_id"],
            "name": chain["name"],
            "description": chain["description"],
            "severity": chain["severity"],
            "host": chain["host"],
            "attacker": chain["attacker"],
            "start_time": chain["start_time"].isoformat(),
            "end_time": chain["end_time"].isoformat(),
            "timeline": chain["timeline"],
            "alert_count": len(chain["alerts"])
        })
    return serializable


@router.get("/export")
def export_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Exports filtered alerts to a downloadable CSV format."""
    filters = AlertFilter(severity=severity, status=status, limit=1000)
    alerts = alert_service.list_alerts(db, filters)
    csv_content = alert_service.export_alerts_to_csv(alerts)
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_export.csv"}
    )


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get single alert details."""
    alert = alert_service.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.put("/{alert_id}/status", response_model=AlertResponse)
def update_status(alert_id: int, status: str, db: Session = Depends(get_db)):
    """Update lifecycle status of an alert."""
    alert = alert_service.update_alert_status(db, alert_id, status)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.put("/{alert_id}/assign", response_model=AlertResponse)
def assign_analyst(alert_id: int, analyst: str, db: Session = Depends(get_db)):
    """Assign alert case to a named SOC analyst."""
    alert = alert_service.assign_alert(db, alert_id, analyst)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
