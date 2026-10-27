# Suspicious IP Checker - Full Project

## Overview
A Python + Streamlit cybersecurity dashboard that checks IP reputation against threat intelligence APIs, monitors server logs in real-time, and generates alerts (in-dashboard + email) when suspicious activity is detected.

**⚠️ IMPORTANT:** Use only on systems and logs you are authorized to inspect. This is an educational tool. Flagged IPs are not proof of malicious activity.

## Features
| Feature | Description |
|---------|-------------|
| **IP Reputation** | Query AbuseIPDB, VirusTotal, AlienVault OTX, ip-api.com |
| **Live Log Monitor** | Tail Apache/Nginx/CSV logs in real-time with threshold alerts |
| **Alert Dashboard** | In-app alerts with severity levels (low/medium/high/critical) |
| **Email Alerts** | SMTP-based email notifications for high/critical severity alerts |
| **Batch Log Analysis** | Upload CSV logs, analyze patterns, download results |

## Requirements
- **Python 3.10+** (Windows laptop)
- **Internet** (for API lookups)
- **API keys** (optional but recommended for full reputation features)

---

## Setup Steps (Windows)

### Step 1: Install Python
1. Download from [python.org](https://www.python.org/downloads/)
2. Check **"Add Python to PATH"** during installation
3. Verify: Open Command Prompt → `python --version`

### Step 2: Extract & Open Project
1. Extract the project ZIP to `C:\Users\YourName\Suspicious_IP_Checker\`
2. Open the folder in File Explorer
3. Click address bar → type `cmd` → press Enter

### Step 3: Create Virtual Environment & Install Dependencies
```powershell
py -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Run the Application
```powershell
streamlit run app.py
```
The browser opens at `http://localhost:8501`.

---

## API Key Requirements

### ip-api.com (Free, NO key needed)
- Always available without any setup
- Rate limit: 45 requests/min
- Provides: geolocation, ISP, proxy/hosting detection

### AbuseIPDB (Free Tier - Key Required)
- **Sign up:** https://www.abuseipdb.com/register
- **Get key:** Account Settings → API → Generate New Key
- **Free limit:** 100 requests/day, 1,000/month
- **Returns:** Abuse confidence score (0-100%), total reports, country, ISP
- **Without key:** Reputation score unavailable, app works fine without it

### VirusTotal (Free Tier - Key Required)
- **Sign up:** https://www.virustotal.com/gui/join-us
- **Get key:** Your Profile (top right) → API Key
- **Free limit:** 4 requests/min, 500 requests/day
- **Returns:** Detection ratio (X/90 engines), verdicts from each engine
- **Without key:** Engine detection data unavailable

### AlienVault OTX (Free - Key Required)
- **Sign up:** https://otx.alienvault.com/signup
- **Get key:** My Settings (user icon) → API Key
- **Free limit:** ~10,000 requests/day (soft limit)
- **Returns:** Reputation score, threat pulse associations, related malware
- **Without key:** Pulse/threat group data unavailable

### Adding API Keys
1. In the app, go to **Sidebar → ⚙️ Configuration → 🔑 API Keys**
2. Paste each key in its field
3. Click **💾 Save API Keys**
4. Keys are stored in `config.json` (local file, never uploaded)

---

## Email Alert Setup (Gmail)

### Prerequisites
1. A Gmail account with **2-Factor Authentication enabled**
2. An **App Password** (not your regular password)

### Steps
1. Go to https://myaccount.google.com/security → Enable 2-Step Verification
2. Go to https://myaccount.google.com/apppasswords
3. Create app password → App: "Mail", Device: "Other" → Name: "IP Checker"
4. Copy the 16-character password (e.g., `abcd efgh ijkl mnop`)
5. In the app sidebar → **📧 Email Alerts**:
   - Check "Enable Email Alerts"
   - Sender Email: your@gmail.com
   - App Password: the 16-char code (no spaces)
   - Recipient Email: where to send alerts
6. Click **📨 Test Email** to verify

### Other Email Providers
- **Outlook/Hotmail:** smtp.office365.com, port 587, TLS
- **Yahoo:** smtp.mail.yahoo.com, port 465 or 587
- **Custom:** Edit smtp_host/smtp_port in config.json

---

## Live Log Monitoring Setup

### Supported Formats
- Apache Combined Log Format
- Nginx Access Log Format
- CSV with columns: `timestamp, ip, path, status`

### Configuration
1. Go to **Sidebar → 📂 Log File Monitor**
2. Enter your log file path, e.g.:
   ```
   C:\Apache24\logs\access.log
   C:\nginx\logs\access.log
   C:\inetpub\logs\LogFiles\W3SVC1\u_ex261020.log
   ```
3. Set thresholds:
   - Request threshold (flag after N requests)
   - Failure threshold (flag after N HTTP 4xx/5xx)
   - Check interval (poll frequency)
4. Click **Save Monitor Config**
5. Go to **📡 Live Monitor** tab → Click **▶️ Start Monitor**

### Testing with Sample Log
1. Use `data/sample_logs.csv` as test input
2. Append lines to it in a separate terminal:
   ```powershell
   Add-Content -Path "data\sample_logs.csv" -Value "2026-10-20 10:00:00,45.155.205.233,/login,401"
   ```

---

## Detection Rules
An IP is flagged when:
- Total requests from that IP >= configured threshold, OR
- HTTP failures (status >= 400) >= failure threshold, OR
- Reputation score from any API exceeds configured level, OR
- Listed by any threat intel source

---

## Project Files
```
IP_Analysis_Mini_Project/
├── app.py              # Main Streamlit dashboard
├── config.py           # Configuration management
├── ip_reputation.py    # Threat intelligence API modules
├── log_monitor.py      # Real-time log file monitor
├── alert_engine.py     # Alert system + email dispatch
├── requirements.txt    # Python dependencies
├── generate_reports.py # Generates report, PPT, flowchart
├── config.json         # User settings (auto-created, NOT in git)
├── data/
│   └── sample_logs.csv # Sample log data (TEST-NET addresses)
└── reports/
    ├── Project_Report.docx
    ├── Project_Presentation.pptx
    └── flowchart.png
```

---

## Generate Reports & Presentation
```powershell
python generate_reports.py
```
This creates/updates:
- `reports/Project_Report.docx` — Full project report
- `reports/Project_Presentation.pptx` — Presentation slides
- `reports/flowchart.png` — System architecture flowchart

---

## Troubleshooting
| Problem | Solution |
|---------|----------|
| `py` not recognized | Reinstall Python with "Add to PATH" checked |
| `streamlit` not found | Activate venv first: `.venv\Scripts\activate` |
| API returns errors | Verify keys in Sidebar; check rate limits |
| Email fails | Use App Password, NOT your regular Gmail password |
| Log file not found | Use full absolute path with drive letter |
| Private IP shows no results | Expected — threat intel only works for public IPs |
