"""
SOC AI Assistant — FastAPI Main Application Entrypoint

Wires up database initialization, startup event listeners, routers, and CORS.
"""

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

# Ensure DB directories exist (skip if on Vercel to avoid read-only FS error)
if not os.getenv("VERCEL"):
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "database"), exist_ok=True)

app = FastAPI(
    title="SOC AI Assistant API",
    description="Backend API for the AI-Powered Security Operations Center Platform",
    version="1.0.0",
)

# CORS Config (explicitly allows Streamlit frontend port)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Streamlit runs client-side inside the analyst's browser
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup DB Event
@app.on_event("startup")
def on_startup():
    """Initializes tables and seeds alerts + settings database on start."""
    initialize()

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
