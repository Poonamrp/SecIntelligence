import os
import json
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from dotenv import load_dotenv

# Load .env file automatically
load_dotenv(override=False)

@dataclass
class AppConfig:
    nvd_api_key: Optional[str] = None
    github_token: Optional[str] = None
    
    # SMTP Settings
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    alert_from: str = ""
    alert_to: str = ""
    
    # Notification policies: IMMEDIATE_CRITICAL_KEV, ALL_IMMEDIATE, DISABLED
    email_notification_policy: str = "IMMEDIATE_CRITICAL_KEV"
    
    # Schedule & Runtime
    check_interval_minutes: int = 60
    app_timezone: str = "UTC"
    database_url: str = "sqlite:///data/security_monitor.db"
    log_level: str = "INFO"
    baseline_mode: bool = True

    @classmethod
    def from_env(cls) -> "AppConfig":
        load_dotenv(override=True)
        return cls(
            nvd_api_key=os.getenv("NVD_API_KEY", "").strip() or None,
            github_token=os.getenv("GITHUB_TOKEN", "").strip() or None,
            smtp_host=os.getenv("SMTP_HOST", "smtp.gmail.com").strip(),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            smtp_username=os.getenv("SMTP_USERNAME", "").strip(),
            smtp_password=os.getenv("SMTP_PASSWORD", "").strip(),
            alert_from=os.getenv("ALERT_FROM", "").strip(),
            alert_to=os.getenv("ALERT_TO", "").strip(),
            email_notification_policy=os.getenv("EMAIL_NOTIFICATION_POLICY", "IMMEDIATE_CRITICAL_KEV").strip(),
            check_interval_minutes=int(os.getenv("CHECK_INTERVAL_MINUTES", "60")),
            app_timezone=os.getenv("APP_TIMEZONE", "UTC").strip(),
            database_url=os.getenv("DATABASE_URL", "sqlite:///data/security_monitor.db").strip(),
            log_level=os.getenv("LOG_LEVEL", "INFO").strip(),
            baseline_mode=os.getenv("BASELINE_MODE", "true").lower() in ("true", "1", "yes"),
        )

# Global configuration instance
config = AppConfig.from_env()

def get_config() -> AppConfig:
    global config
    config = AppConfig.from_env()
    return config
