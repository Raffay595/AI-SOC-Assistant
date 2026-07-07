"""
SOC AI Assistant — Settings Router

Provides GET (all settings), PUT (single key upsert), and POST /batch (multi-key upsert).
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import AppSetting
from backend.schemas import SettingResponse, SettingUpdate
from typing import List
import os

router = APIRouter(prefix="/api/settings", tags=["Settings"])


@router.get("", response_model=List[SettingResponse])
def get_all_settings(db: Session = Depends(get_db)):
    """Retrieve all configuration keys and values."""
    try:
        settings_list = db.query(AppSetting).all()
        result = [SettingResponse(key=s.key, value=s.value) for s in settings_list]

        # Overlay env vars for Vercel (env vars take precedence over DB for API key)
        env_key = os.getenv("OPENROUTER_API_KEY", "")
        if env_key and env_key != "sk-or-v1-your-key-here":
            # Return the env-var key masked, so frontend knows a key is set
            for item in result:
                if item.key == "openrouter_api_key" and not item.value:
                    item.value = env_key

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load settings: {str(e)}")


@router.put("", response_model=SettingResponse)
def update_setting(update: SettingUpdate, db: Session = Depends(get_db)):
    """Update or create a single setting key-value pair."""
    try:
        setting = db.query(AppSetting).filter(AppSetting.key == update.key).first()
        if not setting:
            setting = AppSetting(key=update.key, value=update.value)
            db.add(setting)
        else:
            setting.value = update.value
        db.commit()
        db.refresh(setting)
        return SettingResponse(key=setting.key, value=setting.value)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save setting '{update.key}': {str(e)}")


@router.post("/batch", response_model=List[SettingResponse])
def batch_update_settings(updates: List[SettingUpdate], db: Session = Depends(get_db)):
    """
    Atomically upsert multiple settings keys in a single transaction.
    The frontend uses this to save all settings at once.
    """
    try:
        saved = []
        for update in updates:
            setting = db.query(AppSetting).filter(AppSetting.key == update.key).first()
            if not setting:
                setting = AppSetting(key=update.key, value=update.value)
                db.add(setting)
            else:
                setting.value = update.value
            saved.append(setting)

        db.commit()

        # Refresh all
        for s in saved:
            db.refresh(s)

        return [SettingResponse(key=s.key, value=s.value) for s in saved]
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Batch settings save failed: {str(e)}")
