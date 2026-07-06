"""
SOC AI Assistant — ORM Models

All database tables for the SOC platform.
No auth tables in MVP (single analyst mode).
"""

from sqlalchemy import Column, Integer, String, Float, Text, DateTime, Boolean, JSON
from sqlalchemy.sql import func
from backend.database import Base


class Alert(Base):
    """Security alert ingested from Wazuh or mock data."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=func.now(), index=True)
    source_ip = Column(String(45), index=True)
    dest_ip = Column(String(45), index=True)
    event_id = Column(String(20), index=True)
    rule_id = Column(String(20), index=True)
    severity = Column(String(20), index=True)  # Critical, High, Medium, Low, Informational
    description = Column(Text)
    host = Column(String(255), index=True)
    agent = Column(String(255))
    status = Column(String(20), default="New", index=True)  # New, Investigating, Resolved, Closed
    assigned_to = Column(String(255), nullable=True)
    raw_log = Column(Text)
    username = Column(String(255), nullable=True, index=True)

    # MITRE ATT&CK mapping
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique_id = Column(String(20), nullable=True, index=True)
    mitre_technique_name = Column(String(255), nullable=True)

    # Metadata
    source = Column(String(100), default="Wazuh")  # Wazuh, Firewall, IDS, etc.
    created_at = Column(DateTime, default=func.now())


class Analysis(Base):
    """AI analysis result for an alert."""
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, index=True)
    status = Column(String(20), default="queued")  # queued, running, completed, failed
    result_json = Column(JSON, nullable=True)
    confidence = Column(Float, nullable=True)
    model_used = Column(String(100), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime, nullable=True)


class Incident(Base):
    """Security incident linking multiple alerts."""
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(500))
    severity = Column(String(20))  # Critical, High, Medium, Low
    status = Column(String(20), default="Open")  # Open, Investigating, Resolved, Closed
    description = Column(Text, nullable=True)
    alert_ids = Column(JSON, default=list)  # List of linked alert IDs
    report_json = Column(JSON, nullable=True)  # AI-generated 8-section report
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class ChatMessage(Base):
    """Chat conversation history."""
    __tablename__ = "chat_history"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(100), index=True)
    role = Column(String(20))  # user, assistant
    content = Column(Text)
    context_json = Column(JSON, nullable=True)  # Alert context, MITRE context, etc.
    timestamp = Column(DateTime, default=func.now())


class AppSetting(Base):
    """Application settings (key-value store)."""
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True)
    value = Column(Text)
