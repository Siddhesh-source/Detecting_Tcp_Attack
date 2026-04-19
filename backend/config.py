"""
Configuration settings for the application.
"""

import os
from alerting import AlertConfig


# SMTP Configuration
SMTP_CONFIG = AlertConfig(
    smtp_host=os.getenv("SMTP_HOST", "smtp.gmail.com"),
    smtp_port=int(os.getenv("SMTP_PORT", "587")),
    smtp_user=os.getenv("SMTP_USER", ""),
    smtp_password=os.getenv("SMTP_PASSWORD", ""),
    from_email=os.getenv("SMTP_FROM_EMAIL", ""),
    to_emails=os.getenv("SMTP_TO_EMAILS", "").split(",") if os.getenv("SMTP_TO_EMAILS") else [],
    min_severity=os.getenv("ALERT_MIN_SEVERITY", "medium"),
    dedup_window=int(os.getenv("ALERT_DEDUP_WINDOW", "300")),
    enabled=os.getenv("ALERT_ENABLED", "false").lower() == "true"
)
