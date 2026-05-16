"""
Configuration module for Shadow IT Discovery Bot.
Loads environment variables and provides app-wide settings.
"""

import os
from functools import lru_cache
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Shodan API configuration
    shodan_api_key: str = ""
    shodan_rate_limit: float = 1.0  # requests per second (free tier limit)
    
    # Demo mode flag - when True, always use mock data
    demo_mode: bool = False
    
    # Network scanning options
    enable_network_scan: bool = False  # Must be explicitly enabled
    scan_timeout: float = 1.0  # Timeout per port in seconds
    max_concurrent_scans: int = 50  # Max concurrent port checks
    
    # Server configuration
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Scan retention
    scan_retention_days: int = 30  # Auto-delete scans older than this
    
    # Storage paths
    data_dir: str = "data"
    scans_dir: str = "data/scans"
    mock_dir: str = "data/mock"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    Uses lru_cache to avoid re-reading env vars on every call.
    """
    return Settings()


def is_shodan_available() -> bool:
    """Check if Shodan API is configured and available."""
    settings = get_settings()
    return bool(settings.shodan_api_key) and not settings.demo_mode
