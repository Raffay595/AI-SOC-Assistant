"""
SOC AI Assistant — OpenRouter AI Client

Direct OpenAI SDK integration with OpenRouter.
No LangChain — just clean, simple API calls.
"""

from openai import AsyncOpenAI
from backend.config import settings
from backend.models import AppSetting
from backend.database import SessionLocal
from typing import Optional
import json


def get_ai_settings() -> dict:
    """Get AI settings from database, fallback to config."""
    db = SessionLocal()
    try:
        result = {}
        for setting in db.query(AppSetting).all():
            result[setting.key] = setting.value
        return result
    except Exception:
        return {}
    finally:
        db.close()


def get_client() -> Optional[AsyncOpenAI]:
    """Get an AsyncOpenAI client configured for OpenRouter."""
    db_settings = get_ai_settings()
    api_key = db_settings.get("openrouter_api_key", "") or settings.OPENROUTER_API_KEY

    if not api_key or api_key == "sk-or-v1-your-key-here":
        return None

    return AsyncOpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
        default_headers={
            "HTTP-Referer": "http://localhost:8501",
            "X-Title": "SOC AI Assistant",
        },
    )


def get_model() -> str:
    """Get the configured AI model."""
    db_settings = get_ai_settings()
    return db_settings.get("ai_model", settings.AI_MODEL)


def get_temperature() -> float:
    """Get the configured temperature."""
    db_settings = get_ai_settings()
    try:
        return float(db_settings.get("ai_temperature", settings.AI_TEMPERATURE))
    except (ValueError, TypeError):
        return settings.AI_TEMPERATURE


def get_max_tokens() -> int:
    """Get the configured max tokens."""
    db_settings = get_ai_settings()
    try:
        return int(db_settings.get("ai_max_tokens", settings.AI_MAX_TOKENS))
    except (ValueError, TypeError):
        return settings.AI_MAX_TOKENS


async def call_ai(system_prompt: str, user_prompt: str) -> Optional[dict]:
    """
    Call OpenRouter API and return parsed JSON response.
    
    Returns None if no API key is configured (will trigger mock fallback).
    Raises Exception on API errors.
    """
    client = get_client()
    if client is None:
        return None  # Signal to use mock response

    response = await client.chat.completions.create(
        model=get_model(),
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=get_temperature(),
        max_tokens=get_max_tokens(),
    )

    content = response.choices[0].message.content
    return json.loads(content)
