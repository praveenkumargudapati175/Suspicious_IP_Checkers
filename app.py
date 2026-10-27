"""
app.py - Suspicious IP Checker: Full Dashboard
Features: IP Reputation, Live Log Monitoring, Alerts (Dashboard + Email)
Platform: Windows laptop | Stack: Python + Streamlit
"""

import ipaddress
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt

from config import load_config, save_config, DEFAULT_CONFIG
from ip_reputation import full_reputation_check, check_ipapi, ReputationResult
from log_monitor import LogMonitor, load_csv_log
from alert_engine import (
    create_alert, get_alerts, get_alert_count, acknowledge_alert,
    clear_alerts, get_severity_counts, Alert
)

# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Suspicious IP Checker",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
.block-container {padding-top: 1.4rem; padding-bottom: 1.5rem;}
div[data-testid="stMetric"] {border: 1px solid rgba(128,128,128,.25); padding: 14px; border-radius: 12px;}
.alert-card {padding:12px 16px; border-radius:8px; margin:4px 0; border-left:5px solid #ccc;}
.alert-critical {border-left-color:#d32f2f; background:#ffebee;}
.alert-high {border-left-color:#f57c00; background:#fff3e0;}
.alert-medium {border-left-color:#fbc02d; background:#fffde7;}
.alert-low {border-left-color:#388e3c; background:#e8f5e9;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Suspicious IP Checker")
st.caption("IP Reputation • Live Log Monitoring • Dashboard & Email Alerts | Educational Mini Project")

# ─── Session State Init ───────────────────────────────────────────────────────
if "monitor" not in st.session_state:
    st.session_state.monitor = None
if "reputation_cache" not in st.session_state:
    st.session_state.reputation_cache = {}
if "alert_history" not in st.session_state:
    st.session_state.alert_history = []


# ─── Helper: classify a single IP ────────────────────────────────────────────
def classify_ip(value):
    try:
        ip = ipaddress.ip_address(str(value).strip())
        if ip.is_loopback:
            kind = "Loopback"
        elif ip.is_private:
            kind = "Private"
        elif ip.is_global:
            kind = "Public"
        elif ip.is_multicast:
            kind = "Multicast"
        elif ip.is_link_local:
            kind = "Link-local"
        else:
            kind = "Reserved"
        return {"valid": True, "normalized": str(ip), "version": f"IPv{ip.version}",
                "classification": kind, "is_private": ip.is_private, "is_global": ip.is_global}
    except ValueError:
        return {"valid": False, "normalized": str(value), "classification": "Invalid"}


# ─── Sidebar: Settings & Navigation ──────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")
    config = load_config()

    # Monitoring section
    with st.expander("📂 Log File Monitor", expanded=True):
        mon_cfg = config.get("monitoring", {})
        st.session_state["log_path"] = st.text_input(
            "Log file path", value=mon_cfg.get("log_file_path", ""),
            placeholder="C:\\server\\logs\\access.log", key="sid_logpath"
        )
        st.session_state["check_interval"] = st.slider(
            "Check interval (sec)", 2, 30, mon_cfg.get("check_interval_seconds", 5), key="sid_interval"
        )
        st.session_state["req_threshold"] = st.number_input(
            "Request threshold", 3, 50, mon_cfg.get("flag_threshold_requests", 5), key="sid_reqth"
        )
        st.session_state["fail_threshold"] = st.number_input(
            "Failure threshold", 2, 20, mon_cfg.get("flag_threshold_failures", 3), key="sid_failth"
        )
        if st.button("💾 Save Monitor Config"):
            config["monitoring"]["log_file_path"] = st.session_state.get("log_path", "")
            config["monitoring"]["check_interval_seconds"] = st.session_state.get("check_interval", 5)
            config["monitoring"]["flag_threshold_requests"] = st.session_state.get("req_threshold", 5)
            config["monitoring"]["flag_threshold_failures"] = st.session_state.get("fail_threshold", 3)
            save_config(config)
            st.success("Monitoring config saved!")

    st.divider()
    st.caption("⚠️ Use only logs/systems you are authorized to inspect.")
    st.caption("📌 Sample IPs use TEST-NET ranges (203.0.113.x, 198.51.100.x)")

# ─── Main Tabs ────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔍 IP Reputation",
    "📡 Live Monitor",
    "🚨 Alerts",
    "📊 Log Dashboard",
    "ℹ️ About & Help"
])

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 1: IP REPUTATION CHECKER
# ═══════════════════════════════════════════════════════════════════════════════
with tab1:
    st.subheader("🔍 Check IP Reputation Against Threat Intelligence")
    st.markdown("Queries AbuseIPDB, VirusTotal, AlienVault OTX, and ip-api.com to build a reputation profile.")

    col1, col2 = st.columns([2, 1])
    with col1:
        ip_input = st.text_input("Enter IP Address", value="8.8.8.8", placeholder="e.g. 203.0.113.25", key="rep_ip")
    with col2:
        st.write("")
        st.write("")
        check_btn = st.button("🔎 Check Reputation", type="primary", use_container_width=True)

    if check_btn and ip_input:
        validation = classify_ip(ip_input)
        if not validation["valid"]:
            st.error(f"'{ip_input}' is not a valid IP address.")
        elif validation["is_private"]:
            st.warning(f"⚠️ {ip_input} is a **private/local** address. Reputation checks are designed for public IPs.")
            st.info("Private IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x) are not listed in threat intel databases.")
        else:
            with st.spinner("Querying threat intelligence sources..."):
                result: ReputationResult = full_reputation_check(validation["normalized"])

            # Display results
            st.markdown(f"### Results for {result.ip}")

            # Alert banner
            if result.is_suspicious:
                st.error(f"🚨 **SUSPICIOUS** — This IP has been flagged by threat intelligence sources.")
                create_alert(
                    ip=result.ip, severity="high",
                    title="Suspicious IP found via Reputation Check",
                    message=f"IP {result.ip} flagged: {result.summary()}",
                    source="reputation_check",
                    reputation_score=result.abuse_score,
                )
            else:
                st.success("✅ **CLEAN** — No major threat intelligence sources flagged this IP.")

            # Score metrics
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Abuse Score", f"{result.abuse_score or 0}%")
            m2.metric("VT Detections", result.vt_detection_ratio or "N/A")
            m3.metric("OTX Pulses", str(result.otx_pulse_count or 0))
            m4.metric("Reports", str(result.abuse_total_reports or 0))

            # Details
            det1, det2 = st.columns(2)
            with det1:
                st.markdown("**📍 Geolocation (ip-api)**")
                if result.geo_country:
                    st.write(f"- Country: {result.geo_country}")
                    st.write(f"- City: {result.geo_city or 'N/A'}")
                    st.write(f"- ISP: {result.geo_isp or 'N/A'}")
                    st.write(f"- ASN: {result.geo_asn or 'N/A'}")
                    st.write(f"- Proxy: {'⚠️ Yes' if result.geo_proxy else 'No'}")
                    st.write(f"- Hosting: {'⚠️ Yes' if result.geo_hosting else 'No'}")
                else:
                    st.write("No geolocation data available.")

            with det2:
                st.markdown("**🛡️ Threat Sources Checked**")
                for src in result.sources_checked:
                    st.write(f"- ✅ {src.replace('_', ' ').title()}")
                if result.errors:
                    st.markdown("**⚠️ Warnings/Errors:**")
                    for err in result.errors:
                        st.write(f"- {err}")

            # VirusTotal verdicts table
            if result.vt_verdicts:
                st.markdown("**🦠 VirusTotal Engine Verdicts (Malicious/Suspicious)**")
                vt_df = pd.DataFrame(
                    [{"Engine": k, "Verdict": v} for k, v in result.vt_verdicts.items()]
                )
                st.dataframe(vt_df, use_container_width=True)

            # OTX Pulses
            if result.otx_pulses:
                st.markdown("**📡 AlienVault OTX Pulse Associations**")
                for pulse in result.otx_pulses[:8]:
                    st.write(f"- 🔸 {pulse}")

            st.caption(f"Checked at {result.timestamp} • Sources queried: {len(result.sources_checked)}")

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 2: LIVE LOG MONITOR
# ═══════════════════════════════════════════════════════════════════════════════
with tab2:
    st.subheader("📡 Live Log File Monitoring")
    st.markdown("Tail your server access log in real-time. New entries are analyzed automatically against thresholds.")

    mon_cfg = load_config().get("monitoring", {})
    log_path = mon_cfg.get("log_file_path", "") or st.session_state.get("log_path", "")

    status_col, action_col = st.columns([2, 1])
    with status_col:
        st.markdown(f"**Watching:** `{log_path or 'No path configured'}`")
    with action_col:
        if st.session_state.monitor and st.session_state.monitor.is_running:
            if st.button("⏹️ Stop Monitor", type="secondary"):
                st.session_state.monitor.stop()
                st.session_state.monitor = None
                st.rerun()
        else:
            if st.button("▶️ Start Monitor", type="primary"):
                if not log_path or not Path(log_path).exists():
                    st.error(f"Log file not found: `{log_path}`. Set path in sidebar → Log File Monitor.")
                else:
                    def alert_callback(activity):
                        create_alert(
                            ip=activity.ip, severity="medium",
                            title=f"Threshold exceeded: {activity.ip}",
                            message=activity.flag_reason,
                            source="live_monitor"
                        )

                    monitor = LogMonitor(
                        log_path=log_path,
                        check_interval=mon_cfg.get("check_interval_seconds", 5),
                        request_threshold=mon_cfg.get("flag_threshold_requests", 5),
                        failure_threshold=mon_cfg.get("flag_threshold_failures", 3),
                    )
                    monitor.on_alert(alert_callback)
                    if monitor.start(load_existing=True):
                        st.session_state.monitor = monitor
                        st.success(f"✅ Monitoring started on `{log_path}`")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error(f"Failed to start: {monitor.error}")

    # Live status
    if st.session_state.monitor and st.session_state.monitor.is_running:
        st.info("🟢 Monitor is running. New log entries are processed every few seconds.")
        # Auto-refresh every 3s using Streamlit's rerun
        st.caption("Refresh this tab to see the latest data (or press R).")

        # IP Activity Table
        st.markdown("#### 📊 IP Activity Summary")
        summary_df = st.session_state.monitor.get_summary_df()
        if not summary_df.empty:
            flagged = (summary_df["Flagged"] == "YES").sum()
            total_entries = len(st.session_state.monitor.entries)
            m1, m2, m3 = st.columns(3)
            m1.metric("Total Entries Seen", total_entries)
            m2.metric("Unique IPs", len(summary_df))
            m3.metric("Flagged IPs", flagged, delta=f"-{flagged}" if flagged else "0")
            # Color the flagged rows
            def highlight_flagged(row):
                color = "background-color:#ffcdd2" if row["Flagged"] == "YES" else ""
                return [color] * len(row)
            st.dataframe(summary_df.style.apply(highlight_flagged, axis=1), use_container_width=True)

        # Recent Entries
        st.markdown("#### 📝 Recent Log Entries")
        entries_df = st.session_state.monitor.get_recent_entries_df(30)
        st.dataframe(entries_df, use_container_width=True, hide_index=True)

    elif not log_path:
        st.warning("⚠️ No log file path set. Go to **Sidebar → Log File Monitor** to configure.")
        st.markdown("**Sample usage:**")
        st.code("""
# Example: Watch IIS logs on Windows
C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log

# Example: Watch Apache/Nginx logs
C:\\Apache24\\logs\\access.log
C:\\nginx\\logs\\access.log
        """, language="text")
        st.markdown("Your log must follow Apache Combined, Nginx, or CSV format: `timestamp,ip,path,status`")
    else:
        st.info("Monitor is stopped. Click **Start Monitor** to begin watching.")

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 3: ALERTS DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
with tab3:
    st.subheader("🚨 Alert Dashboard")
    st.markdown("All alerts from reputation checks and live monitoring appear here.")

    alerts = get_alerts(limit=50)
    sev_counts = get_severity_counts()
    total_unack = get_alert_count(unacknowledged_only=True)

    # Metrics row
    mc1, mc2, mc3, mc4 = st.columns(4)
    mc1.metric("Critical", sev_counts["critical"], delta=None)
    mc2.metric("High", sev_counts["high"], delta=None)
    mc3.metric("Medium", sev_counts["medium"], delta=None)
    mc4.metric("Low", sev_counts["low"], delta=None)

    st.write(f"**Unacknowledged:** {total_unack}")

    if alerts:
        # Filter controls
        filter_col, action_col2 = st.columns([2, 1])
        with filter_col:
            show_only_unack = st.checkbox("Show only unacknowledged", value=False)
        with action_col2:
            if st.button("🗑️ Clear All Alerts"):
                clear_alerts()
                st.rerun()

        display_alerts = [a for a in alerts if not a.acknowledged] if show_only_unack else alerts

        st.markdown("#### Recent Alerts")
        for alert in display_alerts[:30]:
            severity_class = f"alert-{alert.severity}"
            email_icon = " 📧" if alert.email_sent else ""
            ack_icon = " ✅" if alert.acknowledged else ""
            st.markdown(
                f"""<div class="alert-card {severity_class}">
                <b>{alert.severity.upper()}</b> {alert.alert_id} | {alert.timestamp}{email_icon}{ack_icon}<br>
                <b>IP:</b> <code>{alert.ip}</code> | <b>Source:</b> {alert.source}<br>
                <b>{alert.title}</b><br>
                <span>{alert.message}</span>
                </div>""",
                unsafe_allow_html=True
            )
            if not alert.acknowledged:
                if st.button(f"Acknowledge {alert.alert_id}", key=f"ack_{alert.alert_id}"):
                    acknowledge_alert(alert.alert_id)
                    st.rerun()

        # Download alerts CSV
        alerts_df = pd.DataFrame([vars(a) for a in display_alerts])
        st.download_button(
            "⬇️ Download Alerts CSV",
            alerts_df.to_csv(index=False).encode("utf-8"),
            file_name=f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No alerts yet. Run a reputation check or start the live monitor to generate alerts.")


# ═══════════════════════════════════════════════════════════════════════════════
# TAB 4: LOG ANALYSIS DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
with tab4:
    st.subheader("📊 Log Analysis Dashboard")
    st.markdown("Upload a CSV log or use built-in sample data for batch analysis.")

    def analyze_logs(df, threshold, failure_threshold):
        required = {"ip", "timestamp", "path", "status"}
        if not required.issubset(set(df.columns)):
            missing = sorted(required - set(df.columns))
            raise ValueError(f"Missing required columns: {', '.join(missing)}")
        work = df.copy()
        work["ip"] = work["ip"].astype(str).str.strip()
        work["status"] = pd.to_numeric(work["status"], errors="coerce")
        work["timestamp"] = work["timestamp"].astype(str)
        work["path"] = work["path"].astype(str)
        work = work[work["ip"].map(lambda x: classify_ip(x)["valid"])].copy()
        if work.empty:
            return work, pd.DataFrame(columns=["ip", "request_count", "failed_requests", "flag"])
        counts = work.groupby("ip").size().rename("request_count")
        failures = work.assign(is_fail=work["status"].ge(400)).groupby("ip")["is_fail"].sum().rename("failed_requests")
        summary = pd.concat([counts, failures], axis=1).fillna(0).reset_index()
        summary["failed_requests"] = summary["failed_requests"].astype(int)
        summary["flag"] = summary.apply(
            lambda r: "Review" if (r["request_count"] >= threshold or r["failed_requests"] >= failure_threshold) else "Normal", axis=1
        )
        work = work.merge(summary[["ip", "request_count", "failed_requests", "flag"]], on="ip", how="left")
        return work, summary.sort_values(["request_count", "failed_requests"], ascending=False)

    SAMPLE = pd.DataFrame([
        {"timestamp": "2026-10-20 09:00:00", "ip": "192.168.1.10", "path": "/", "status": 200},
        {"timestamp": "2026-10-20 09:01:00", "ip": "192.168.1.10", "path": "/login", "status": 200},
        {"timestamp": "2026-10-20 09:02:00", "ip": "203.0.113.25", "path": "/login", "status": 401},
        {"timestamp": "2026-10-20 09:02:20", "ip": "203.0.113.25", "path": "/login", "status": 401},
        {"timestamp": "2026-10-20 09:02:40", "ip": "203.0.113.25", "path": "/login", "status": 403},
        {"timestamp": "2026-10-20 09:03:00", "ip": "203.0.113.25", "path": "/admin", "status": 404},
        {"timestamp": "2026-10-20 09:04:00", "ip": "198.51.100.7", "path": "/products", "status": 200},
        {"timestamp": "2026-10-20 09:04:30", "ip": "198.51.100.7", "path": "/cart", "status": 200},
        {"timestamp": "2026-10-20 09:05:00", "ip": "198.51.100.7", "path": "/checkout", "status": 200},
        {"timestamp": "2026-10-20 09:06:00", "ip": "198.51.100.7", "path": "/profile", "status": 200},
        {"timestamp": "2026-10-20 09:07:00", "ip": "198.51.100.7", "path": "/help", "status": 200},
        {"timestamp": "2026-10-20 09:08:00", "ip": "192.168.1.22", "path": "/", "status": 200},
        {"timestamp": "2026-10-20 09:09:00", "ip": "192.168.1.22", "path": "/about", "status": 200},
        {"timestamp": "2026-10-20 09:10:00", "ip": "192.168.1.10", "path": "/logout", "status": 200},
        {"timestamp": "2026-10-20 09:11:00", "ip": "203.0.113.25", "path": "/login", "status": 401},
        {"timestamp": "2026-10-20 09:12:00", "ip": "203.0.113.99", "path": "/admin", "status": 403},
        {"timestamp": "2026-10-20 09:12:15", "ip": "203.0.113.99", "path": "/wp-login.php", "status": 404},
        {"timestamp": "2026-10-20 09:12:30", "ip": "203.0.113.99", "path": "/phpmyadmin", "status": 404},
        {"timestamp": "2026-10-20 09:12:45", "ip": "203.0.113.99", "path": "/.env", "status": 403},
        {"timestamp": "2026-10-20 09:13:00", "ip": "203.0.113.99", "path": "/config.php", "status": 404},
    ])

    uploaded = st.file_uploader("Upload CSV log file", type=["csv"], key="upload_log")
    use_sample = st.checkbox("Use built-in sample data", value=uploaded is None)

    threshold = st.slider("Requests per IP to flag", min_value=3, max_value=50, value=5, key="log_thresh")
    fail_thresh = st.slider("Failure count to flag", min_value=2, max_value=20, value=3, key="log_fail_thresh")

    try:
        if uploaded is not None and not use_sample:
            raw = pd.read_csv(uploaded)
            source_label = f"Uploaded: {uploaded.name}"
        else:
            raw = SAMPLE.copy()
            source_label = "Built-in sample data"

        st.caption(f"Source: {source_label} • {len(raw)} rows")

        if st.button("🚀 Run Analysis", type="primary"):
            events, summary = analyze_logs(raw, threshold, fail_thresh)
            if summary.empty:
                st.warning("No valid IP addresses found in data.")
            else:
                total = len(events)
                unique = events["ip"].nunique()
                flagged = int((summary["flag"] == "Review").sum())
                failures = int(events["status"].ge(400).sum())
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Valid requests", total)
                m2.metric("Unique IPs", unique)
                m3.metric("Flagged IPs", flagged)
                m4.metric("Error responses", failures)

                # Charts
                left, right = st.columns(2)
                with left:
                    st.markdown("**Requests by IP**")
                    fig, ax = plt.subplots(figsize=(6, 3.5))
                    plot_data = summary.head(10).sort_values("request_count")
                    ax.barh(plot_data["ip"], plot_data["request_count"], color=["#d32f2f" if f == "Review" else "#1976d2" for f in plot_data["flag"]])
                    ax.set_xlabel("Requests")
                    fig.tight_layout()
                    st.pyplot(fig)
                    plt.close(fig)
                with right:
                    st.markdown("**Normal vs Flagged**")
                    status_counts = summary["flag"].value_counts()
                    fig2, ax2 = plt.subplots(figsize=(4, 3.5))
                    ax2.bar(status_counts.index, status_counts.values, color=["#1976d2", "#d32f2f"][:len(status_counts)])
                    ax2.set_ylabel("IP count")
                    fig2.tight_layout()
                    st.pyplot(fig2)
                    plt.close(fig2)

                st.markdown("**IP Summary**")
                st.dataframe(summary, use_container_width=True)
                st.markdown("**Request Details**")
                st.dataframe(events.tail(30), use_container_width=True)

                # Download
                dl1, dl2 = st.columns(2)
                dl1.download_button("⬇️ Summary CSV", summary.to_csv(index=False).encode("utf-8"), "ip_summary.csv", "text/csv")
                dl2.download_button("⬇️ Events CSV", events.to_csv(index=False).encode("utf-8"), "analyzed_events.csv", "text/csv")

                # Auto-generate alerts from flagged IPs
                flagged_ips = summary[summary["flag"] == "Review"]
                for _, row in flagged_ips.iterrows():
                    create_alert(
                        ip=row["ip"], severity="medium",
                        title=f"Batch analysis flagged {row['ip']}",
                        message=f"Requests: {row['request_count']}, Failures: {row['failed_requests']}",
                        source="batch_analysis",
                        send_email=False,
                    )
                if not flagged_ips.empty:
                    st.info(f"{len(flagged_ips)} IP(s) flagged. See **Alerts** tab for details.")

    except Exception as exc:
        st.error(f"Analysis error: {exc}")
        st.info("Required CSV columns: `timestamp`, `ip`, `path`, `status`")

# ═══════════════════════════════════════════════════════════════════════════════
# TAB 5: ABOUT & HELP
# ═══════════════════════════════════════════════════════════════════════════════
with tab5:
    st.subheader("ℹ️ About Suspicious IP Checker")
    st.markdown("""
    This **educational cybersecurity mini project** demonstrates how to check IP reputation,
    monitor server logs in real-time, and generate alerts for potentially suspicious activity.
    
    **It does NOT exploit, block, scan other networks, or attribute activity to individuals.**
    """)

    st.markdown("### 🔑 API Key Requirements & Limitations")
    api_info = pd.DataFrame([
        {"Provider": "AbuseIPDB", "Free Tier": "100 req/day", "Signup": "https://www.abuseipdb.com/register", "Data": "Abuse confidence, reports, country"},
        {"Provider": "VirusTotal", "Free Tier": "4/min, 500/day", "Signup": "https://www.virustotal.com", "Data": "90+ engine detections, verdicts"},
        {"Provider": "AlienVault OTX", "Free Tier": "~10K/day", "Signup": "https://otx.alienvault.com", "Data": "Reputation score, threat pulses"},
        {"Provider": "ip-api.com", "Free Tier": "45 req/min (no key!)", "Signup": "Not required", "Data": "Geo, ISP, proxy/hosting flags"},
    ])
    st.dataframe(api_info, use_container_width=True)

    st.markdown("""
    **Limitations:**
    - Free tiers have daily rate limits; heavy scanning will fail gracefully.
    - Private IP addresses (192.168.x.x, 10.x.x.x) cannot be checked externally.
    - A high reputation score does not prove guilt; it indicates community reports.
    - No single source is authoritative. Always cross-reference before action.
    """)

    st.markdown("### 📧 Email Alert Setup (Gmail)")
    st.markdown("""
    1. Enable **2-Factor Authentication** on your Google Account
    2. Visit [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
    3. Generate an App Password → select "Mail" → name it "IP Checker"
    4. Enter the 16-character password in **Sidebar → Email Alerts → App Password**
    5. Click **Test Email** to verify configuration
    """)

    st.markdown("### 🚀 Quick Start Steps")
    st.markdown("""
    1. `pip install -r requirements.txt`
    2. `streamlit run app.py`
    3. (Optional) Add API keys in Sidebar → API Keys
    4. (Optional) Configure email in Sidebar → Email Alerts
    5. (Optional) Set log file path in Sidebar → Log File Monitor
    6. Use **IP Reputation** tab to check any public IP
    7. Use **Live Monitor** tab to watch your server log file
    8. Check **Alerts** tab for flagged activity
    9. Use **Log Dashboard** for batch analysis of CSV logs
    """)

    st.markdown("### ⚠️ Important Disclaimers")
    st.warning("""
    - **Authorized use only.** Analyze only logs and systems you own or have written permission to inspect.
    - **False positives.** Rule-based flagging is heuristic; flagged IPs may not be malicious.
    - **No attribution.** This tool does not identify persons or prove intent.
    - **Rate limits.** Free API tiers are limited. Do not abuse endpoints.
    """)

    st.markdown("**Project Structure:**")
    st.code("""
IP_Analysis_Mini_Project/
├── app.py              # Main Streamlit dashboard
├── config.py           # Configuration (API keys, email)
├── ip_reputation.py    # Threat intelligence integrations
├── log_monitor.py      # Real-time log file monitor
├── alert_engine.py     # Alert creation & email dispatch
├── requirements.txt    # Python dependencies
├── generate_reports.py # Report/PPT/flowchart generator
├── data/
│   └── sample_logs.csv # Sample log data
└── reports/
    ├── Project_Report.docx
    ├── Project_Presentation.pptx
    └── flowchart.png
""", language="text")
