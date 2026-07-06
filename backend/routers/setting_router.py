"""
SOC AI Assistant — Settings Router
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import AppSetting
from backend.schemas import SettingResponse, SettingUpdate

router = APIRouter(prefix="/api/settings", tags=["Settings"])


@router.get("", response_model=list[SettingResponse])
def get_all_settings(db: Session = Depends(get_db)):
    """Retrieve all configuration keys and values."""
    settings_list = db.query(AppSetting).all()
    return [SettingResponse(key=s.key, value=s.value) for s in settings_list]


@router.put("", response_model=SettingResponse)
def update_setting(update: SettingUpdate, db: Session = Depends(get_db)):
    """Update or create a setting key-value pair."""
    setting = db.query(AppSetting).filter(AppSetting.key == update.key).first()
    if not setting:
        setting = AppSetting(key=update.key, value=update.value)
        db.add(setting)
    else:
        setting.value = update.value
    db.commit()
    db.refresh(setting)
    return SettingResponse(key=setting.key, value=setting.value)
