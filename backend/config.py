"""
SOC AI Assistant — Application Configuration

Loads settings from .env file using Pydantic BaseSettings.
All AI, database, and server parameters are configurable.
"""

from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # OpenRouter
    OPENROUTER_API_KEY: str = ""
    AI_MODEL: str = "anthropic/claude-sonnet-4"
    AI_TEMPERATURE: float = 0.3
    AI_MAX_TOKENS: int = 4096
    AI_TIMEOUT: int = 60

    # Database
    DATABASE_URL: str = "sqlite:///./database/soc.db"

    # Server
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    BACKEND_URL: str = "http://localhost:8000"
    FRONTEND_PORT: int = 8501

    # Available models for the settings UI
    AVAILABLE_MODELS: list[str] = [
        "anthropic/claude-sonnet-4",
        "openai/gpt-4o",
        "google/gemini-2.5-flash",
        "deepseek/deepseek-chat",
        "qwen/qwen-2.5-72b-instruct",
    ]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()

settings = get_settings()
