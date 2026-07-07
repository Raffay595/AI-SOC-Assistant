"""
SOC AI Assistant — FastAPI Main Application Entrypoint

Wires up database initialization, startup event listeners, routers, and CORS.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.database import engine, Base
from backend.init_db import initialize
from backend.routers import (
    dashboard_router,
    alert_router,
    ai_router,
    mitre_router,
    ioc_router,
    incident_router,
    chat_router,
    threat_intel_router,
    setting_router,
)
import os


# Ensure DB directories exist (skip if on Vercel — uses /tmp via database.py)
if not os.getenv("VERCEL"):
    os.makedirs(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "database"),
        exist_ok=True
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan handler: initializes DB on startup."""
    try:
        initialize()
    except Exception as e:
        print(f"[WARN] Database initialization error (non-fatal): {e}")
    yield
    # Shutdown cleanup (none needed)


app = FastAPI(
    title="SOC AI Assistant API",
    description="Backend API for the AI-Powered Security Operations Center Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow all origins so the frontend SPA (served from /frontend) can call /api
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers
app.include_router(dashboard_router.router)
app.include_router(alert_router.router)
app.include_router(ai_router.router)
app.include_router(mitre_router.router)
app.include_router(ioc_router.router)
app.include_router(incident_router.router)
app.include_router(chat_router.router)
app.include_router(threat_intel_router.router)
app.include_router(setting_router.router)


@app.get("/")
def read_root():
    return {
        "message": "AI SOC Assistant API is running.",
        "documentation": "/docs"
    }
