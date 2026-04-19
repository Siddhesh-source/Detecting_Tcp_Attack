"""
Real-time alerting system with SMTP email notifications.
Supports configurable severity levels, deduplication, and alert grouping.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import aiosmtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


@dataclass
class AlertConfig:
    """Alert configuration."""
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    from_email: str = ""
    to_emails: List[str] = None
    min_severity: str = "medium"  # low, medium, high, critical
    dedup_window: int = 300  # seconds
    enabled: bool = False

    def __post_init__(self):
        if self.to_emails is None:
            self.to_emails = []


class AlertManager:
    """Manages alert notifications with deduplication and severity filtering."""

    SEVERITY_LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self, config: AlertConfig):
        self.config = config
        self.alert_cache: Dict[str, float] = {}  # hash -> timestamp
        self.pending_alerts: List[Dict] = []
        self._cleanup_task: Optional[asyncio.Task] = None

    def start(self):
        """Start background cleanup task."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def _cleanup_loop(self):
        """Periodically clean expired alerts from cache."""
        while True:
            await asyncio.sleep(60)
            now = time.time()
            expired = [k for k, v in self.alert_cache.items() if now - v > self.config.dedup_window]
            for k in expired:
                del self.alert_cache[k]

    def _get_alert_hash(self, flow: Dict) -> str:
        """Generate hash for alert deduplication."""
        key = f"{flow['src_ip']}:{flow['dst_ip']}:{flow['protocol']}"
        return hashlib.md5(key.encode()).hexdigest()

    def _get_severity(self, score: float) -> str:
        """Map suspicion score to severity level."""
        if score >= 90:
            return "critical"
        elif score >= 70:
            return "high"
        elif score >= 50:
            return "medium"
        else:
            return "low"

    def should_alert(self, flow: Dict) -> bool:
        """Check if alert should be sent based on severity and deduplication."""
        if not self.config.enabled:
            return False

        score = flow.get("suspicion_score", 0)
        severity = self._get_severity(score)

        # Check severity threshold
        if self.SEVERITY_LEVELS[severity] < self.SEVERITY_LEVELS[self.config.min_severity]:
            return False

        # Check deduplication
        alert_hash = self._get_alert_hash(flow)
        now = time.time()
        
        if alert_hash in self.alert_cache:
            last_sent = self.alert_cache[alert_hash]
            if now - last_sent < self.config.dedup_window:
                return False

        self.alert_cache[alert_hash] = now
        return True

    async def send_alert(self, flow: Dict):
        """Send email alert for suspicious flow."""
        if not self.config.enabled or not self.config.to_emails:
            return

        severity = self._get_severity(flow.get("suspicion_score", 0))
        
        # Build email
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{severity.upper()}] Covert Channel Detected: {flow['src_ip']} → {flow['dst_ip']}"
        msg["From"] = self.config.from_email
        msg["To"] = ", ".join(self.config.to_emails)

        # Plain text version
        text_body = self._build_text_alert(flow, severity)
        
        # HTML version
        html_body = self._build_html_alert(flow, severity)

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        # Send via SMTP
        try:
            await aiosmtplib.send(
                msg,
                hostname=self.config.smtp_host,
                port=self.config.smtp_port,
                username=self.config.smtp_user,
                password=self.config.smtp_password,
                start_tls=True,
            )
            print(f"[Alert] Email sent for {flow['flow_id']} (severity: {severity})")
        except Exception as e:
            print(f"[Alert] Failed to send email: {e}")

    def _build_text_alert(self, flow: Dict, severity: str) -> str:
        """Build plain text alert body."""
        return f"""
COVERT CHANNEL ALERT - {severity.upper()}

Flow Details:
  Source:      {flow['src_ip']}:{flow['src_port']}
  Destination: {flow['dst_ip']}:{flow['dst_port']}
  Protocol:    {flow['protocol']}
  
Suspicion Score: {flow['suspicion_score']}/100

Alert Reasons:
{flow.get('alert_reasons', 'N/A')}

Flow Statistics:
  Duration:     {flow.get('duration', 0):.2f}s
  Packets:      {flow.get('total_packets', 0)}
  Bytes:        {flow.get('total_bytes', 0)}
  Mean IAT:     {flow.get('mean_iat', 0):.6f}s
  Std IAT:      {flow.get('std_iat', 0):.6f}s

Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(flow.get('created_at', time.time())))}

---
TCP Covert Channel Detector
"""

    def _build_html_alert(self, flow: Dict, severity: str) -> str:
        """Build HTML alert body."""
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8"
        }
        color = severity_colors.get(severity, "#6c757d")

        return f"""
<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: {color}; color: white; padding: 15px; border-radius: 5px;">
            <h2 style="margin: 0;">🚨 Covert Channel Detected</h2>
            <p style="margin: 5px 0 0 0; font-size: 14px;">Severity: {severity.upper()}</p>
        </div>
        
        <div style="background: #f8f9fa; padding: 15px; margin-top: 20px; border-radius: 5px;">
            <h3 style="margin-top: 0;">Flow Details</h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 5px; font-weight: bold;">Source:</td>
                    <td style="padding: 5px;">{flow['src_ip']}:{flow['src_port']}</td>
                </tr>
                <tr>
                    <td style="padding: 5px; font-weight: bold;">Destination:</td>
                    <td style="padding: 5px;">{flow['dst_ip']}:{flow['dst_port']}</td>
                </tr>
                <tr>
                    <td style="padding: 5px; font-weight: bold;">Protocol:</td>
                    <td style="padding: 5px;">{flow['protocol']}</td>
                </tr>
            </table>
        </div>

        <div style="background: #fff3cd; padding: 15px; margin-top: 20px; border-radius: 5px; border-left: 4px solid {color};">
            <h3 style="margin-top: 0;">Suspicion Score: {flow['suspicion_score']}/100</h3>
            <p><strong>Alert Reasons:</strong></p>
            <p style="margin: 5px 0;">{flow.get('alert_reasons', 'N/A').replace('; ', '<br>')}</p>
        </div>

        <div style="background: #f8f9fa; padding: 15px; margin-top: 20px; border-radius: 5px;">
            <h3 style="margin-top: 0;">Flow Statistics</h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 5px;">Duration:</td>
                    <td style="padding: 5px;">{flow.get('duration', 0):.2f}s</td>
                </tr>
                <tr>
                    <td style="padding: 5px;">Packets:</td>
                    <td style="padding: 5px;">{flow.get('total_packets', 0)}</td>
                </tr>
                <tr>
                    <td style="padding: 5px;">Bytes:</td>
                    <td style="padding: 5px;">{flow.get('total_bytes', 0)}</td>
                </tr>
                <tr>
                    <td style="padding: 5px;">Mean IAT:</td>
                    <td style="padding: 5px;">{flow.get('mean_iat', 0):.6f}s</td>
                </tr>
            </table>
        </div>

        <p style="margin-top: 20px; font-size: 12px; color: #6c757d;">
            Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(flow.get('created_at', time.time())))}
        </p>
    </div>
</body>
</html>
"""
