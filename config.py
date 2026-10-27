"""
config.py - Configuration management for Suspicious IP Checker.

API Key Requirements:
=====================
1. AbuseIPDB (Free tier):
   - Sign up: https://www.abuseipdb.com/register
   - Free: 100 requests/day, 1000 requests/month
   - Returns: abuse confidence score, total reports, country, ISP
   - Get key: Account Settings -> API -> Generate New Key

2. VirusTotal (Free tier):
   - Sign up: https://www.virustotal.com/gui/join-us
   - Free: 4 requests/min, 500 requests/day
   - Returns: detection ratio, malicious verdicts from 90+ engines
   - Get key: Your Profile -> API Key

3. AlienVault OTX (Free):
   - Sign up: https://otx.alienvault.com/signup
   - Free: 10,000 requests/day (soft limit)
   - Returns: pulses, malware associations, reputation score
   - Get key: My Settings -> OTX API Key

Email Alert Setup (Gmail):
==========================
1. Enable 2-Factor Auth on your Google Account
2. Go to: https://myaccount.google.com/apppasswords
3. Generate an App Password (select Mail -> Other -> Suspicious IP Checker)
4. Use the 16-character password as EMAIL_PASSWORD

All keys stored in config.json (NOT committed to git).
"""

import json
import os
from pathlib import Path
from typing import Optional

CONFIG_FILE = Path(__file__).parent / "config.json"

DEFAULT_CONFIG = {
    "abuseipdb_api_key": "",
    "virustotal_api_key": "",
    "alienvault_otx_api_key": "",
    "alert_email": {
        "enabled": False,
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 587,
        "use_tls": True,
        "sender_email": "",
        "sender_password": "",
        "recipient_email": ""
    },
    "monitoring": {
        "log_file_path": "",
        "check_interval_seconds": 5,
        "flag_threshold_requests": 5,
        "flag_threshold_failures": 3,
        "reputation_score_threshold": 80
    },
    "alert_rules": {
        "high_request_rate": True,
        "multiple_auth_failures": True,
        "bad_reputation_score": True,
        "blacklisted_by_any_source": True
    }
}


def load_config() -> dict:
    """Load configuration from file or return defaults."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            # Merge with defaults for any new keys
            merged = {**DEFAULT_CONFIG, **user_cfg}
            for key in DEFAULT_CONFIG:
                if isinstance(DEFAULT_CONFIG[key], dict):
                    if key not in merged:
                        merged[key] = DEFAULT_CONFIG[key]
                    else:
                        merged[key] = {**DEFAULT_CONFIG[key], **merged[key]}
            return merged
        except (json.JSONDecodeError, IOError):
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()


def save_config(config: dict) -> bool:
    """Save configuration to file. Returns True on success."""
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except IOError as e:
        print(f"Error saving config: {e}")
        return False


def get_api_key(provider: str) -> Optional[str]:
    """Get a specific API key. Returns None if not configured."""
    config = load_config()
    key = config.get(f"{provider}_api_key", "").strip()
    return key if key else None


def has_email_config() -> bool:
    """Check if email alerting is fully configured."""
    config = load_config()
    email = config.get("alert_email", {})
    return (
        email.get("enabled", False)
        and email.get("sender_email", "").strip() != ""
        and email.get("sender_password", "").strip() != ""
        and email.get("recipient_email", "").strip() != ""
    )


def get_monitoring_config() -> dict:
    """Get monitoring settings."""
    config = load_config()
    return config.get("monitoring", DEFAULT_CONFIG["monitoring"])


def get_alert_rules() -> dict:
    """Get alert rules configuration."""
    config = load_config()
    return config.get("alert_rules", DEFAULT_CONFIG["alert_rules"])
