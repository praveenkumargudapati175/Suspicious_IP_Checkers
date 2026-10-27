"""
ip_reputation.py - IP Reputation checking via threat intelligence APIs.

Supported providers:
  - AbuseIPDB (https://www.abuseipdb.com)
  - VirusTotal (https://www.virustotal.com)
  - AlienVault OTX (https://otx.alienvault.com)
  - ip-api.com (Free, no API key required for basic lookups)
"""

import requests
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Dict, List

from config import get_api_key


@dataclass
class ReputationResult:
    """Stores reputation lookup results from all sources."""
    ip: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    # AbuseIPDB
    abuse_score: Optional[int] = None
    abuse_total_reports: Optional[int] = None
    abuse_country: Optional[str] = None
    abuse_isp: Optional[str] = None
    abuse_categories: List[str] = field(default_factory=list)
    # VirusTotal
    vt_detection_ratio: Optional[str] = None
    vt_malicious_count: Optional[int] = None
    vt_total_engines: Optional[int] = None
    vt_verdicts: Dict[str, str] = field(default_factory=dict)
    # AlienVault OTX
    otx_reputation_score: Optional[float] = None
    otx_pulse_count: Optional[int] = None
    otx_pulses: List[str] = field(default_factory=list)
    # ip-api (free, no key needed)
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    geo_isp: Optional[str] = None
    geo_asn: Optional[str] = None
    geo_proxy: bool = False
    geo_hosting: bool = False
    # Overall
    is_suspicious: bool = False
    sources_checked: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = []
        if self.abuse_score is not None:
            parts.append(f"Abuse Confidence: {self.abuse_score}%")
        if self.vt_malicious_count is not None:
            parts.append(f"VT Detections: {self.vt_malicious_count}/{self.vt_total_engines}")
        if self.otx_reputation_score is not None:
            parts.append(f"OTX Reputation: {self.otx_reputation_score}")
        if self.geo_proxy:
            parts.append("Known Proxy")
        if self.geo_hosting:
            parts.append("Hosting Provider")
        return " | ".join(parts) if parts else "No reputation data available"


def check_ipapi(ip: str) -> dict:
    """Free IP geolocation via ip-api.com (max 45 requests/min, no key needed)."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,isp,as,proxy,hosting,message"},
            timeout=10
        )
        data = resp.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "asn": data.get("as", ""),
                "proxy": data.get("proxy", False),
                "hosting": data.get("hosting", False),
            }
        return {"error": data.get("message", "Lookup failed")}
    except requests.RequestException as e:
        return {"error": str(e)}


def check_abuseipdb(ip: str, api_key: Optional[str] = None) -> dict:
    """Query AbuseIPDB for abuse confidence score. Requires free API key.
    Free tier: 100 requests/day, 1000/month.
    """
    if api_key is None:
        api_key = get_api_key("abuseipdb")
    if not api_key:
        return {"error": "AbuseIPDB API key not configured"}
    try:
        resp = requests.get(
            f"https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={
                "Key": api_key,
                "Accept": "application/json"
            },
            timeout=15
        )
        if resp.status_code == 429:
            return {"error": "AbuseIPDB rate limit exceeded (free: 100/day)"}
        data = resp.json()
        if "errors" in data and "data" not in data:
            return {"error": data["errors"][0].get("detail", "Unknown error")}
        d = data.get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
            "usage_type": d.get("usageType", ""),
            "domain": d.get("domain", ""),
            "is_tor": d.get("isTor", False),
            "blacklisted": d.get("isPublic", False) and d.get("totalReports", 0) > 5,
        }
    except requests.RequestException as e:
        return {"error": str(e)}
    except (KeyError, ValueError):
        return {"error": "Failed to parse AbuseIPDB response"}


def check_virustotal(ip: str, api_key: Optional[str] = None) -> dict:
    """Query VirusTotal for IP detection ratio. Requires free API key.
    Free tier: 4 requests/min, 500 requests/day.
    """
    if api_key is None:
        api_key = get_api_key("virustotal")
    if not api_key:
        return {"error": "VirusTotal API key not configured"}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=15
        )
        if resp.status_code == 429:
            return {"error": "VirusTotal rate limit exceeded (free: 4/min, 500/day)"}
        if resp.status_code == 404:
            return {"error": "IP not found in VirusTotal database"}
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        # Get verdicts from engines that flagged it
        analysis = attrs.get("last_analysis_results", {})
        flagged_verdicts = {}
        for engine, result in analysis.items():
            if result.get("category") in ("malicious", "suspicious"):
                flagged_verdicts[engine] = result.get("result", "flagged")
        return {
            "detection_ratio": f"{malicious}/{total}",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total,
            "verdicts": flagged_verdicts,
            "country": attrs.get("country", ""),
            "asn": attrs.get("asn", ""),
            "as_owner": attrs.get("as_owner", ""),
        }
    except requests.RequestException as e:
        return {"error": str(e)}
    except (KeyError, ValueError):
        return {"error": "Failed to parse VirusTotal response"}


def check_alienvault_otx(ip: str, api_key: Optional[str] = None) -> dict:
    """Query AlienVault OTX for IP reputation and pulse associations.
    Free tier: ~10,000 requests/day (soft limit).
    """
    if api_key is None:
        api_key = get_api_key("alienvault_otx")
    if not api_key:
        return {"error": "AlienVault OTX API key not configured"}
    try:
        headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers=headers,
            timeout=15
        )
        if resp.status_code == 429:
            return {"error": "AlienVault OTX rate limit exceeded"}
        if resp.status_code == 404:
            return {"error": "IP not found in OTX database"}
        data = resp.json()
        # Extract reputation
        base_reputation = data.get("base_reputation_score", 0)
        # Pulses
        pulses_data = data.get("pulses", {})
        pulse_count = pulses_data.get("count", 0)
        pulse_names = [p.get("name", "") for p in pulses_data.get("pulses", [])][:10]
        # Whois info
        whois = data.get("whois", {})
        return {
            "reputation_score": base_reputation,
            "pulse_count": pulse_count,
            "pulses": pulse_names,
            "country": whois.get("country", {}).get("name", ""),
            "asn": whois.get("asn", ""),
        }
    except requests.RequestException as e:
        return {"error": str(e)}
    except (KeyError, ValueError):
        return {"error": "Failed to parse AlienVault OTX response"}


def full_reputation_check(ip: str) -> ReputationResult:
    """Run all available reputation checks for an IP address.
    ip-api is always free. Other providers used if API keys configured.
    """
    result = ReputationResult(ip=ip)

    # 1. Always check ip-api (free, no key)
    geo = check_ipapi(ip)
    if "error" not in geo:
        result.geo_country = geo.get("country")
        result.geo_city = geo.get("city")
        result.geo_isp = geo.get("isp")
        result.geo_asn = geo.get("asn")
        result.geo_proxy = geo.get("proxy", False)
        result.geo_hosting = geo.get("hosting", False)
        result.sources_checked.append("ip-api")
    else:
        result.errors.append(f"ip-api: {geo['error']}")

    # Scoring system instead of binary flag — require multiple signals
    suspicious_signals = 0

    # 2. AbuseIPDB
    abuse = check_abuseipdb(ip)
    if "error" not in abuse:
        result.abuse_score = abuse.get("abuse_score")
        result.abuse_total_reports = abuse.get("total_reports")
        result.abuse_country = abuse.get("country")
        result.abuse_isp = abuse.get("isp")
        result.sources_checked.append("abuseipdb")
        # High abuse score: >= 70 = strong signal, 40-69 = weak signal
        if result.abuse_score and result.abuse_score >= 70:
            suspicious_signals += 2
        elif result.abuse_score and result.abuse_score >= 40:
            suspicious_signals += 1
        if result.abuse_total_reports and result.abuse_total_reports >= 20:
            suspicious_signals += 1
    elif "not configured" not in abuse.get("error", ""):
        result.errors.append(f"AbuseIPDB: {abuse['error']}")

    # 3. VirusTotal
    vt = check_virustotal(ip)
    if "error" not in vt:
        result.vt_detection_ratio = vt.get("detection_ratio")
        result.vt_malicious_count = vt.get("malicious_count")
        result.vt_total_engines = vt.get("total_engines")
        result.vt_verdicts = vt.get("verdicts", {})
        result.sources_checked.append("virustotal")
        # Require at least 3+ engines to flag it as malicious
        if result.vt_malicious_count and result.vt_malicious_count >= 3:
            suspicious_signals += 2
        elif result.vt_malicious_count and result.vt_malicious_count >= 1:
            suspicious_signals += 1
    elif "not configured" not in vt.get("error", ""):
        result.errors.append(f"VirusTotal: {vt['error']}")

    # 4. AlienVault OTX
    otx = check_alienvault_otx(ip)
    if "error" not in otx:
        result.otx_reputation_score = otx.get("reputation_score")
        result.otx_pulse_count = otx.get("pulse_count")
        result.otx_pulses = otx.get("pulses", [])
        result.sources_checked.append("alienvault_otx")
        # Require multiple pulse associations
        if result.otx_pulse_count and result.otx_pulse_count >= 5:
            suspicious_signals += 2
        elif result.otx_pulse_count and result.otx_pulse_count >= 2:
            suspicious_signals += 1
    elif "not configured" not in otx.get("error", ""):
        result.errors.append(f"AlienVault: {otx['error']}")

    # ip-api signals: proxy is moderate, hosting alone is NOT suspicious
    # (Google 8.8.8.8, Cloudflare 1.1.1.1 are all "hosting" — they're legit)
    if result.geo_proxy:
        suspicious_signals += 1
    # hosting alone does NOT add signals (too many legit hosting providers)

    # Verdict: need cumulative signal score >= 2 to be suspicious
    # 1 signal = "Notable" (shown as warning but NOT flagged)
    # >= 2 signals = SUSPICIOUS
    result.is_suspicious = suspicious_signals >= 2
    if suspicious_signals == 1:
        result.errors.append("Single weak indicator — not enough evidence to flag as malicious")

    return result
