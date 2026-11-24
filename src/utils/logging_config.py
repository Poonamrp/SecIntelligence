import logging
import os
import re
from logging.handlers import RotatingFileHandler
from typing import Optional

class SecretRedactingFormatter(logging.Formatter):
    """Formatter that redacts potential secrets, passwords, and tokens."""
    
    SECRET_PATTERNS = [
        re.compile(r'(password[:=]\s*)([^\s&]+)', re.IGNORECASE),
        re.compile(r'(token[:=]\s*)([^\s&]+)', re.IGNORECASE),
        re.compile(r'(api[_-]?key[:=]\s*)([^\s&]+)', re.IGNORECASE),
        re.compile(r'(bearer\s+)([a-zA-Z0-9_\-\.]+)', re.IGNORECASE),
    ]

    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None):
        super().__init__(fmt, datefmt)
        self.exact_secrets = set()
        for env_var in ["SMTP_PASSWORD", "NVD_API_KEY", "GITHUB_TOKEN"]:
            val = os.getenv(env_var)
            if val and len(val.strip()) > 3:
                self.exact_secrets.add(val.strip())

    def format(self, record: logging.LogRecord) -> str:
        orig = super().format(record)
        redacted = orig
        for pattern in self.SECRET_PATTERNS:
            redacted = pattern.sub(r'\1[REDACTED]', redacted)
        for secret in self.exact_secrets:
            redacted = redacted.replace(secret, "[REDACTED]")
        return redacted

def setup_logging(log_level: str = "INFO", log_dir: str = "logs") -> logging.Logger:
    """Configures root logger with file rotation and console output."""
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "security_monitor.log")
    
    level = getattr(logging, log_level.upper(), logging.INFO)
    logger = logging.getLogger("sec_monitor")
    logger.setLevel(level)
    
    # Avoid duplicate handlers on re-init
    if not logger.handlers:
        fmt_str = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        formatter = SecretRedactingFormatter(fmt_str, datefmt="%Y-%m-%d %H:%M:%S")
        
        # Rotating File Handler (5 MB max, 5 backups)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Console Stream Handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
    return logger

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"sec_monitor.{name}")
