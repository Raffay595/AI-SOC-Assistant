"""
SOC AI Assistant — Pydantic Schemas

Request/response validation schemas.
Includes strict AI response schemas that enforce structured JSON output.
"""

from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime


# ─── Alert Schemas ──────────────────────────────────────────

class AlertBase(BaseModel):
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    event_id: Optional[str] = None
    rule_id: Optional[str] = None
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"] = "Medium"
    description: Optional[str] = None
    host: Optional[str] = None
    agent: Optional[str] = None
    raw_log: Optional[str] = None
    username: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    source: str = "Wazuh"


class AlertCreate(AlertBase):
    pass


class AlertResponse(AlertBase):
    id: int
    status: str = "New"
    assigned_to: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AlertFilter(BaseModel):
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    host: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    event_id: Optional[str] = None
    rule_id: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    username: Optional[str] = None
    keyword: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = 50
    offset: int = 0


# ─── AI Analysis Schemas ────────────────────────────────────

class MITREMapping(BaseModel):
    tactic: str = "Unknown"
    technique: str = "Unknown"
    technique_id: str = "Unknown"
    description: Optional[str] = None


class IOCItem(BaseModel):
    type: str  # IP, Domain, URL, Email, Hash, Registry, FilePath, CVE
    value: str


class AIAnalysisResult(BaseModel):
    """Strict schema for AI analysis output. All AI responses must conform."""
    summary: str
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_reason: str
    attack_stage: str
    mitre: Optional[MITREMapping] = None
    iocs: list[IOCItem] = []
    evidence: list[str] = []  # Why the AI reached its conclusion
    recommendations: list[str] = []
    investigation_steps: list[str] = []
    facts_vs_assumptions: dict = Field(default_factory=lambda: {"facts": [], "assumptions": []})


class AnalysisResponse(BaseModel):
    id: int
    alert_id: int
    status: str
    result: Optional[AIAnalysisResult] = None
    confidence: Optional[float] = None
    model_used: Optional[str] = None
    error_message: Optional[str] = None
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AnalyzeRequest(BaseModel):
    alert_id: int


class LogSummarizeRequest(BaseModel):
    raw_logs: str


class LogSummaryResult(BaseModel):
    summary: str
    suspicious_events: list[str] = []
    timeline: list[dict] = []
    recommendations: list[str] = []
    iocs: list[IOCItem] = []


# ─── Incident Schemas ───────────────────────────────────────

class IncidentCreate(BaseModel):
    title: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    description: Optional[str] = None
    alert_ids: list[int] = []


class IncidentReport(BaseModel):
    executive_summary: str = ""
    timeline: list[dict] = []
    affected_hosts: list[str] = []
    iocs: list[IOCItem] = []
    mitre_mapping: list[MITREMapping] = []
    root_cause: str = ""
    recommendations: list[str] = []
    next_actions: list[str] = []


class IncidentResponse(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    description: Optional[str] = None
    alert_ids: list[int] = []
    report: Optional[IncidentReport] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ─── Chat Schemas ───────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"
    alert_id: Optional[int] = None  # Optional context


class ChatResponse(BaseModel):
    response: str
    session_id: str


class ChatHistoryItem(BaseModel):
    role: str
    content: str
    timestamp: Optional[datetime] = None


# ─── IOC Schemas ────────────────────────────────────────────

class IOCExtractRequest(BaseModel):
    text: str


class IOCExtractResponse(BaseModel):
    iocs: list[IOCItem] = []
    total: int = 0


# ─── Threat Intel Schemas ───────────────────────────────────

class ThreatIntelRequest(BaseModel):
    indicator: str
    type: Literal["ip", "domain", "hash"] = "ip"


class ThreatIntelResponse(BaseModel):
    indicator: str
    type: str
    reputation: Literal["Known Malicious", "Suspicious", "Unknown"]
    malware_family: Optional[str] = None
    source: Optional[str] = None
    recommended_actions: list[str] = []
    last_seen: Optional[str] = None
    severity: Optional[str] = "Unknown"
    confidence: Optional[int] = 0
    category: Optional[str] = None
    sources: list[str] = []
    mitre: list[str] = []
    first_seen: Optional[str] = None
    related_alerts: list[AlertResponse] = []
    ai_summary: Optional[str] = None


# ─── Dashboard Schemas ──────────────────────────────────────

class DashboardMetrics(BaseModel):
    total_alerts: int = 0
    critical_alerts: int = 0
    open_incidents: int = 0
    closed_incidents: int = 0
    alerts_by_severity: dict = {}
    alerts_by_source: dict = {}
    top_mitre_techniques: list[dict] = []
    top_attacked_hosts: list[dict] = []
    alert_trend_24h: list[dict] = []
    most_targeted_users: list[dict] = []
    ai_success_rate: float = 0.0
    recent_analyses: list[dict] = []
    attack_chains: list[dict] = []


# ─── Settings Schemas ───────────────────────────────────────

class SettingUpdate(BaseModel):
    key: str
    value: str


class SettingResponse(BaseModel):
    key: str
    value: str


# ─── MITRE Schemas ──────────────────────────────────────────

class MITRETechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    description: str = ""
    detection: str = ""
    url: str = ""


class MITRETactic(BaseModel):
    tactic_id: str
    name: str
    description: str = ""
    techniques: list[MITRETechnique] = []


# ─── Correlation Schemas ────────────────────────────────────

class AttackChain(BaseModel):
    chain_id: str
    name: str
    severity: str
    description: str
    alerts: list[AlertResponse] = []
    timeline: list[dict] = []
