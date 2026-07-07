"""
SOC AI Assistant — Dashboard Router
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from backend.database import get_db
from backend.models import Alert, Incident, Analysis
from backend.schemas import DashboardMetrics
from backend.services.alerts.correlation import detect_attack_chains
from datetime import datetime, timedelta

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("", response_model=DashboardMetrics)
def get_dashboard_metrics(db: Session = Depends(get_db)):
    """Retrieve all metrics needed for the main SOC dashboard."""
    # Counts
    total_alerts = db.query(Alert).count()
    critical_alerts = db.query(Alert).filter(Alert.severity == "Critical").count()
    open_incidents = db.query(Incident).filter(Incident.status != "Closed").count()
    closed_incidents = db.query(Incident).filter(Incident.status == "Closed").count()

    # Alerts by severity
    severity_counts = db.query(
        Alert.severity, func.count(Alert.id)
    ).group_by(Alert.severity).all()
    alerts_by_severity = {sev: count for sev, count in severity_counts}

    # Alerts by source
    source_counts = db.query(
        Alert.source, func.count(Alert.id)
    ).group_by(Alert.source).all()
    alerts_by_source = {src: count for src, count in source_counts}

    # Top MITRE Techniques
    mitre_tech_counts = db.query(
        Alert.mitre_technique_id, Alert.mitre_technique_name, func.count(Alert.id)
    ).filter(Alert.mitre_technique_id.isnot(None))\
     .group_by(Alert.mitre_technique_id, Alert.mitre_technique_name)\
     .order_by(func.count(Alert.id).desc())\
     .limit(5).all()
    top_mitre_techniques = [
        {"id": row[0], "name": row[1], "count": row[2]} for row in mitre_tech_counts
    ]

    # Top Attacked Hosts
    host_counts = db.query(
        Alert.host, func.count(Alert.id)
    ).group_by(Alert.host)\
     .order_by(func.count(Alert.id).desc())\
     .limit(5).all()
    top_attacked_hosts = [
        {"host": row[0], "count": row[1]} for row in host_counts
    ]

    # Most Targeted Users
    user_counts = db.query(
        Alert.username, func.count(Alert.id)
    ).filter(Alert.username.isnot(None))\
     .group_by(Alert.username)\
     .order_by(func.count(Alert.id).desc())\
     .limit(5).all()
    most_targeted_users = [
        {"username": row[0], "count": row[1]} for row in user_counts
    ]

    # Alert Trend 24h
    now = datetime.utcnow()
    one_day_ago = now - timedelta(hours=24)
    # Simple bucket by hour for SQLite compatibility
    trend_data = db.query(
        func.strftime("%Y-%m-%d %H:00:00", Alert.timestamp).label("hour"),
        func.count(Alert.id)
    ).filter(Alert.timestamp >= one_day_ago)\
     .group_by("hour")\
     .order_by("hour").all()
    
    alert_trend_24h = [
        {"hour": row[0], "count": row[1]} for row in trend_data
    ]

    # AI Success Rate
    total_analyses = db.query(Analysis).count()
    completed_analyses = db.query(Analysis).filter(Analysis.status == "completed").count()
    ai_success_rate = (completed_analyses / total_analyses) if total_analyses > 0 else 0.0

    # Recent Analyses
    recent_an = db.query(Analysis).order_by(Analysis.created_at.desc()).limit(5).all()
    recent_analyses_list = []
    for an in recent_an:
        alert = db.query(Alert).filter(Alert.id == an.alert_id).first()
        recent_analyses_list.append({
            "id": an.id,
            "alert_id": an.alert_id,
            "description": alert.description if alert else "Unknown Alert",
            "status": an.status,
            "confidence": an.confidence,
            "created_at": an.created_at.isoformat()
        })

    # Detect attack chains
    attack_chains = detect_attack_chains(db)
    # Format for JSON serialization (remove datetime objects)
    serializable_chains = []
    for chain in attack_chains:
        serializable_chains.append({
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

    return DashboardMetrics(
        total_alerts=total_alerts,
        critical_alerts=critical_alerts,
        open_incidents=open_incidents,
        closed_incidents=closed_incidents,
        alerts_by_severity=alerts_by_severity,
        alerts_by_source=alerts_by_source,
        top_mitre_techniques=top_mitre_techniques,
        top_attacked_hosts=top_attacked_hosts,
        alert_trend_24h=alert_trend_24h,
        most_targeted_users=most_targeted_users,
        ai_success_rate=ai_success_rate,
        recent_analyses=recent_analyses_list,
        attack_chains=serializable_chains
    )


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Health check endpoint checking DB responsiveness."""
    try:
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception:
        db_status = "unhealthy"
        
    return {
        "status": "online",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat()
    }
