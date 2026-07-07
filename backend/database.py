"""
SOC AI Assistant — Database Setup

SQLAlchemy engine and session factory for SQLite.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

if os.getenv("VERCEL"):
    DATABASE_DIR = "/tmp"
    DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(DATABASE_DIR, 'soc.db')}")
else:
    DATABASE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database")
    os.makedirs(DATABASE_DIR, exist_ok=True)
    DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.join(DATABASE_DIR, 'soc.db')}")

# SQLite needs check_same_thread=False for FastAPI
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
