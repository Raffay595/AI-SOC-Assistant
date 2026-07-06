"""
SOC AI Assistant — HTTP Backend API Client

Provides interface functions wrapping httpx calls to local FastAPI backend.
"""

import httpx
from typing import Optional, Any
import os

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")


def get(endpoint: str, params: Optional[dict] = None) -> Optional[Any]:
    """Helper to run HTTP GET requests."""
    try:
        response = httpx.get(f"{BACKEND_URL}{endpoint}", params=params, timeout=30.0)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"[API Error GET] {endpoint}: {str(e)}")
        return None


def post(endpoint: str, data: Optional[dict] = None) -> Optional[Any]:
    """Helper to run HTTP POST requests."""
    try:
        response = httpx.post(f"{BACKEND_URL}{endpoint}", json=data, timeout=60.0)
        if response.status_code in (200, 201):
            return response.json()
        return None
    except Exception as e:
        print(f"[API Error POST] {endpoint}: {str(e)}")
        return None


def put(endpoint: str, data: Optional[dict] = None, params: Optional[dict] = None) -> Optional[Any]:
    """Helper to run HTTP PUT requests."""
    try:
        response = httpx.put(f"{BACKEND_URL}{endpoint}", json=data, params=params, timeout=30.0)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"[API Error PUT] {endpoint}: {str(e)}")
        return None


def delete(endpoint: str) -> bool:
    """Helper to run HTTP DELETE requests."""
    try:
        response = httpx.delete(f"{BACKEND_URL}{endpoint}", timeout=30.0)
        return response.status_code == 200
    except Exception as e:
        print(f"[API Error DELETE] {endpoint}: {str(e)}")
        return False
