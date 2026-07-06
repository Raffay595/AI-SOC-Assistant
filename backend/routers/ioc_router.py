"""
SOC AI Assistant — IOC Router
"""

from fastapi import APIRouter, HTTPException
from backend.schemas import IOCExtractRequest, IOCExtractResponse
from backend.services.ioc.service import extract_iocs

router = APIRouter(prefix="/api/extract-ioc", tags=["IOC Extraction"])


@router.post("", response_model=IOCExtractResponse)
def extract_indicators(req: IOCExtractRequest):
    """Parses text blocks via regex filters returning sorted list of extracted IOC items."""
    try:
        iocs = extract_iocs(req.text)
        return IOCExtractResponse(
            iocs=iocs,
            total=len(iocs)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IOC extraction failed: {str(e)}")
