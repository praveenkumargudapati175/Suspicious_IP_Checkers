"""
alert_engine.py - Alert generation and dispatch for Suspicious IP Checker.

Supports:
  - In-app dashboard alerts (stored in session state)
  - Email alerts via SMTP (Gmail App Password recommended)
"""

import smtplib
import threading
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

from config import load_config, has_email_config


@dataclass
class Alert:
    """Represents a single security alert."""
    alert_id: str
    timestamp: str
    ip: str
    severity: str  # "low", "medium", "high", "critical"
    title: str
    message: str
    source: str  # "monitoring", "reputation_check", "manual"
    reputation_score: Optional[int] = None
    email_sent: bool = False
    acknowledged: bool = False


# In-memory alert store (thread-safe)
_alerts: List[Alert] = []
_alert_lock = threading.Lock()
_alert_counter = 0


def create_alert(
    ip: str,
    severity: str,
    title: str,
    message: str,
    source: str = "monitoring",
    reputation_score: Optional[int] = None,
    send_email: bool = True,
) -> Alert:
    """Create a new alert and optionally send email notification."""
    global _alert_counter
    with _alert_lock:
        _alert_counter += 1
        alert = Alert(
            alert_id=f"ALT-{_alert_counter:05d}",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip=ip,
            severity=severity,
            title=title,
            message=message,
            source=source,
            reputation_score=reputation_score,
        )
        _alerts.append(alert)

    # Send email outside lock to avoid blocking
    if send_email and severity in ("high", "critical"):
        threading.Thread(target=_try_send_email, args=(alert,), daemon=True).start()

    return alert


def get_alerts(limit: int = 100, unacknowledged_only: bool = False) -> List[Alert]:
    """Get recent alerts, newest first."""
    with _alert_lock:
        alerts = _alerts[-limit:]
        if unacknowledged_only:
            alerts = [a for a in alerts if not a.acknowledged]
        return list(reversed(alerts))


def acknowledge_alert(alert_id: str) -> bool:
    """Mark an alert as acknowledged."""
    with _alert_lock:
        for alert in _alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
    return False


def get_alert_count(unacknowledged_only: bool = False) -> int:
    """Get total count of alerts."""
    with _alert_lock:
        if unacknowledged_only:
            return sum(1 for a in _alerts if not a.acknowledged)
        return len(_alerts)


def clear_alerts():
    """Clear all alerts."""
    global _alerts, _alert_counter
    with _alert_lock:
        _alerts = []
        _alert_counter = 0


def _try_send_email(alert: Alert):
    """Attempt to send email alert using configured SMTP settings."""
    config = load_config()
    email_cfg = config.get("alert_email", {})
    if not email_cfg.get("enabled", False):
        return
    if not email_cfg.get("sender_email") or not email_cfg.get("sender_password"):
        return
    if not email_cfg.get("recipient_email"):
        return
    try:
        subject = f"[ALERT:{alert.severity.upper()}] Suspicious IP Detected - {alert.ip}"
        body_html = f"""
        <div style="font-family:Arial,sans-serif;padding:20px;">
            <h2 style="color:#d32f2f;">🛡️ Suspicious IP Alert</h2>
            <table style="border-collapse:collapse;width:100%;max-width:600px;">
                <tr><td style="padding:8px;font-weight:bold;">Alert ID</td><td style="padding:8px;">{alert.alert_id}</td></tr>
                <tr style="background:#f5f5f5;"><td style="padding:8px;font-weight:bold;">Time</td><td style="padding:8px;">{alert.timestamp}</td></tr>
                <tr><td style="padding:8px;font-weight:bold;">IP Address</td><td style="padding:8px;font-family:monospace;font-size:16px;">{alert.ip}</td></tr>
                <tr style="background:#f5f5f5;"><td style="padding:8px;font-weight:bold;">Severity</td><td style="padding:8px;color:#d32f2f;font-weight:bold;">{alert.severity.upper()}</td></tr>
                <tr><td style="padding:8px;font-weight:bold;">Title</td><td style="padding:8px;">{alert.title}</td></tr>
                <tr style="background:#f5f5f5;"><td style="padding:8px;font-weight:bold;">Source</td><td style="padding:8px;">{alert.source}</td></tr>
            </table>
            <div style="margin-top:15px;padding:12px;background:#fff3e0;border-left:4px solid #ff9800;">
                <p>{alert.message}</p>
            </div>
            {"<p><b>Reputation Score:</b> " + str(alert.reputation_score) + "%</p>" if alert.reputation_score else ""}
            <hr>
            <p style="color:#666;font-size:12px;">Sent by Suspicious IP Checker | Monitor: {alert.source}</p>
        </div>
        """
        msg = MIMEMultipart("alternative")
        msg["From"] = email_cfg["sender_email"]
        msg["To"] = email_cfg["recipient_email"]
        msg["Subject"] = subject
        msg.attach(MIMEText(body_html, "html"))

        smtp_host = email_cfg.get("smtp_host", "smtp.gmail.com")
        smtp_port = email_cfg.get("smtp_port", 587)
        use_tls = email_cfg.get("use_tls", True)

        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            if use_tls:
                server.starttls()
            server.login(email_cfg["sender_email"], email_cfg["sender_password"])
            server.sendmail(
                email_cfg["sender_email"],
                email_cfg["recipient_email"],
                msg.as_string()
            )
        alert.email_sent = True
    except Exception as e:
        # Store error but don't crash
        print(f"Email alert failed: {e}")


def test_email_connection() -> tuple:
    """Test email configuration. Returns (success: bool, message: str)."""
    config = load_config()
    email_cfg = config.get("alert_email", {})
    if not email_cfg.get("sender_email") or not email_cfg.get("sender_password"):
        return False, "Email sender or password not configured in Settings."
    try:
        smtp_host = email_cfg.get("smtp_host", "smtp.gmail.com")
        smtp_port = email_cfg.get("smtp_port", 587)
        use_tls = email_cfg.get("use_tls", True)

        msg = MIMEMultipart()
        msg["From"] = email_cfg["sender_email"]
        msg["To"] = email_cfg.get("recipient_email", email_cfg["sender_email"])
        msg["Subject"] = "[TEST] Suspicious IP Checker - Email Test"
        msg.attach(MIMEText(
            "<p>This is a test email from Suspicious IP Checker. "
            "If you received this, email alerts are configured correctly.</p>",
            "html"
        ))

        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            if use_tls:
                server.starttls()
            server.login(email_cfg["sender_email"], email_cfg["sender_password"])
            server.sendmail(
                email_cfg["sender_email"],
                email_cfg.get("recipient_email", email_cfg["sender_email"]),
                msg.as_string()
            )
        return True, "Test email sent successfully! Check your inbox."
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed. Check sender email and App Password."
    except smtplib.SMTPConnectError:
        return False, f"Cannot connect to SMTP server. Verify host/port settings."
    except Exception as e:
        return False, f"Email test failed: {str(e)}"


def get_severity_counts() -> dict:
    """Get count of alerts by severity level."""
    with _alert_lock:
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for a in _alerts:
            if a.severity in counts:
                counts[a.severity] += 1
        return counts
