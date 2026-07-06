"""
SOC AI Assistant — Database Initialization

Creates all tables and seeds with mock alert data.
"""

from backend.database import engine, SessionLocal, Base
from backend.models import Alert, AppSetting
from backend.utils.mock_alerts import generate_mock_alerts


def init_database():
    """Create all tables."""
    Base.metadata.create_all(bind=engine)


def seed_alerts():
    """Seed the database with mock Wazuh alerts if empty."""
    db = SessionLocal()
    try:
        count = db.query(Alert).count()
        if count > 0:
            return  # Already seeded

        alerts = generate_mock_alerts()
        for alert_data in alerts:
            alert = Alert(**alert_data)
            db.add(alert)
        db.commit()
        print(f"[SEED] Inserted {len(alerts)} mock alerts")
    finally:
        db.close()


def seed_settings():
    """Seed default application settings."""
    db = SessionLocal()
    try:
        count = db.query(AppSetting).count()
        if count > 0:
            return

        defaults = [
            ("ai_model", "anthropic/claude-sonnet-4"),
            ("ai_temperature", "0.3"),
            ("ai_max_tokens", "4096"),
            ("ai_timeout", "60"),
            ("openrouter_api_key", ""),
            ("auto_refresh_interval", "30"),
            ("severity_critical_threshold", "12"),
            ("severity_high_threshold", "8"),
        ]

        for key, value in defaults:
            setting = AppSetting(key=key, value=value)
            db.add(setting)
        db.commit()
        print(f"[SEED] Inserted {len(defaults)} default settings")
    finally:
        db.close()


def initialize():
    """Full initialization: create tables + seed data."""
    init_database()
    seed_alerts()
    seed_settings()
    print("[INIT] Database initialized successfully")


if __name__ == "__main__":
    initialize()
