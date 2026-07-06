"""
SOC AI Assistant — Incident Case Router
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.schemas import IncidentResponse, IncidentCreate
from backend.services.reports import service as report_service

router = APIRouter(prefix="/api/incidents", tags=["Incidents & Cases"])


@router.get("", response_model=list[IncidentResponse])
def get_incidents(db: Session = Depends(get_db)):
    """Retrieve list of all logged incident cases."""
    return report_service.list_incidents(db)


@router.post("", response_model=IncidentResponse)
def create_incident(req: IncidentCreate, db: Session = Depends(get_db)):
    """Create a new incident case linking a set of alerts."""
    return report_service.create_incident(db, req)


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    """Retrieve specific incident details by ID."""
    inc = report_service.get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident case not found")
    return inc


@router.put("/{incident_id}", response_model=IncidentResponse)
def update_incident_details(
    incident_id: int, 
    title: str, 
    severity: str, 
    status: str, 
    description: str, 
    alert_ids: list[int],
    db: Session = Depends(get_db)
):
    """Modify details of an incident case."""
    inc = report_service.update_incident(db, incident_id, title, severity, status, description, alert_ids)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@router.post("/{incident_id}/generate-report", response_model=IncidentResponse)
async def generate_ai_report(incident_id: int, db: Session = Depends(get_db)):
    """
    Triggers structured 8-section Incident Report generation via AI completions.
    Updates the incident entity with generated results inside SQL databases.
    """
    inc = await report_service.generate_incident_report(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident case not found")
    return inc
