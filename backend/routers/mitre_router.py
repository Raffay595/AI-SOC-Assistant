"""
SOC AI Assistant — MITRE Router
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import Alert
from backend.schemas import MITRETactic, MITRETechnique
from backend.services.mitre import service as mitre_service
from sqlalchemy import func

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])


@router.get("/tactics", response_model=list[MITRETactic])
def get_mitre_tactics():
    """Retrieve full lists of tactics and their nested techniques."""
    return mitre_service.get_all_tactics()


@router.get("/techniques", response_model=list[MITRETechnique])
def get_mitre_techniques():
    """Retrieve flat lists of all techniques in dataset."""
    return mitre_service.get_all_techniques()


@router.get("/techniques/{technique_id}", response_model=MITRETechnique)
def get_technique_details(technique_id: str):
    """Retrieve technique details by ID (e.g. T1059.001)."""
    tech = mitre_service.get_technique_by_id(technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail="MITRE Technique not found")
    return tech


@router.get("/stats")
def get_mitre_frequency_stats(db: Session = Depends(get_db)):
    """
    Returns statistics showing frequency distribution of MITRE technique IDs
    across all active alerts. Used to render matrix highlights.
    """
    counts = db.query(
        Alert.mitre_technique_id, func.count(Alert.id)
    ).filter(Alert.mitre_technique_id.isnot(None))\
     .group_by(Alert.mitre_technique_id).all()
     
    return {row[0]: row[1] for row in counts}
