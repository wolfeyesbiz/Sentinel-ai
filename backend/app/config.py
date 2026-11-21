import os
from pydantic import BaseModel
from typing import List, Optional

class Settings(BaseModel):
    PROJECT_NAME: str = "Sentinel AI"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "production"
    API_PREFIX: str = "/api"
    
    # Anomaly Detection Settings
    ANOMALY_THRESHOLD: float = 0.70  # Default configurable threshold (0.0 to 1.0)
    CRITICAL_RISK_THRESHOLD: float = 0.85
    BASELINE_TRAINING_SAMPLES: int = 2000
    
    # Rate Limiting & DoS Settings
    RATE_LIMIT_LOGIN_PER_MIN: int = 5
    RATE_LIMIT_GLOBAL_PER_SEC: int = 100
    RATE_LIMIT_BURST_THRESHOLD: int = 40
    
    # Auto-blocking Settings
    AUTO_BLOCK_CRITICAL: bool = True
    AUTO_BLOCK_DURATION_HOURS: int = 24
    
    # Notification Settings
    SLACK_WEBHOOK_URL: Optional[str] = None
    DISCORD_WEBHOOK_URL: Optional[str] = None
    ADMIN_EMAIL: str = "security-admin@sentinel-ai.store"
    ADMIN_PHONE: str = "+1-555-019-9876"
    ENABLE_AUDIO_CHIMES: bool = True

settings = Settings()
