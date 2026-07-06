"""
SOC AI Assistant — Threat Intelligence Router
"""

from fastapi import APIRouter, Depends, HTTPException
from backend.schemas import ThreatIntelRequest, ThreatIntelResponse
from backend.services.threatintel import service as threat_intel_service

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])


@router.post("/lookup", response_model=ThreatIntelResponse)
def lookup_ioc(req: ThreatIntelRequest):
    """Looks up IP, domain or file hash in local threat intelligence lists."""
    try:
        return threat_intel_service.lookup_indicator(req.indicator, req.type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat intelligence lookup failed: {str(e)}")
