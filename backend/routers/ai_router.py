"""
SOC AI Assistant — AI Analysis Router

Handles security analysis endpoints, using FastAPI BackgroundTasks for async execution.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import Alert, Analysis
from backend.schemas import AnalysisResponse, AnalyzeRequest, LogSummarizeRequest, LogSummaryResult
from backend.services.ai import analyzer as ai_analyzer
from backend.services.ai.client import get_model
from datetime import datetime
import json

router = APIRouter(prefix="/api/analyze", tags=["AI Analysis"])


async def run_async_analysis(analysis_id: int, alert_id: int):
    """
    Asynchronous background job worker.
    Runs AI call and saves output JSON object back to database.
    """
    db = next(get_db())
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not analysis or not alert:
        db.close()
        return

    try:
        # Update state to running
        analysis.status = "running"
        db.commit()

        # Execute analysis
        result = await ai_analyzer.analyze_alert(alert)

        # Update analysis model attributes
        analysis.status = "completed"
        analysis.result_json = result
        analysis.confidence = result.get("confidence", 0.0)
        analysis.completed_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        # Capture error and write failures
        analysis.status = "failed"
        analysis.error_message = str(e)
        analysis.completed_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()


@router.post("", response_model=AnalysisResponse)
def trigger_analysis(
    req: AnalyzeRequest, 
    background_tasks: BackgroundTasks, 
    db: Session = Depends(get_db)
):
    """
    Triggers analysis for a security alert.
    Launches as BackgroundTask immediately. Returns queued state representation.
    """
    alert = db.query(Alert).filter(Alert.id == req.alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Check for existing analysis to avoid duplicates
    existing = db.query(Analysis).filter(
        Analysis.alert_id == req.alert_id,
        Analysis.status.in_(["queued", "running", "completed"])
    ).order_by(Analysis.created_at.desc()).first()

    if existing:
        return existing

    # Create new analysis instance
    analysis = Analysis(
        alert_id=req.alert_id,
        status="queued",
        model_used=get_model()
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    # Queue background task execution
    background_tasks.add_task(run_async_analysis, analysis.id, alert.id)

    return analysis


@router.get("/alert/{alert_id}", response_model=AnalysisResponse)
def get_analysis_by_alert(alert_id: int, db: Session = Depends(get_db)):
    """Retrieve current analysis result or status for an alert ID."""
    analysis = db.query(Analysis).filter(Analysis.alert_id == alert_id).order_by(Analysis.created_at.desc()).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not triggered yet for this alert")
    
    # Format output for serialization (mapping json object inside column)
    return AnalysisResponse(
        id=analysis.id,
        alert_id=analysis.alert_id,
        status=analysis.status,
        result=analysis.result_json,
        confidence=analysis.confidence,
        model_used=analysis.model_used,
        error_message=analysis.error_message,
        created_at=analysis.created_at,
        completed_at=analysis.completed_at
    )


@router.post("/logs", response_model=LogSummaryResult)
async def summarize_raw_logs(req: LogSummarizeRequest):
    """Summarizes raw logs and returns timeline, IOC list, and suggestions."""
    try:
        result = await ai_analyzer.summarize_logs(req.raw_logs)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log summarization failed: {str(e)}")
