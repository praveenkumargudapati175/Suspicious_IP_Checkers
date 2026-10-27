# Testing Guide - Suspicious IP Checker

## 1. Environment Setup Verification

```powershell
# Open terminal in project folder
cd c:\Users\teja\Desktop\Suspicious_IP_Checker_Project\IP_Analysis_Mini_Project

# Create and activate venv
py -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Verify Streamlit launches
streamlit run app.py
```
**Expected:** Browser opens at `http://localhost:8501` showing the dashboard with 5 tabs.

---

## 2. IP Reputation Tab Tests

### Test 2.1: Valid Public IP (no API keys)
- Enter: `8.8.8.8`
- Click "Check Reputation"
- **Expected:** ✅ Geolocation data from ip-api.com, "CLEAN" verdict, sources shows "ip-api"

### Test 2.2: Known bad IP (requires AbuseIPDB key)
- Enter: `45.155.205.233`
- Click "Check Reputation"
- **Expected:** High abuse score, flagged SUSPICIOUS, alert created

### Test 2.3: Private IP
- Enter: `192.168.1.10`
- **Expected:** Warning shown, no API calls made

### Test 2.4: Invalid IP
- Enter: `999.999.999.999`
- **Expected:** Error message "not a valid IP address"

### Test 2.5: IPv6 address
- Enter: `2001:4860:4860::8888`
- **Expected:** Valid, reputation check proceeds

### Test 2.6: With ALL API keys configured
- Enter any public IP (e.g., `1.1.1.1`)
- **Expected:** Shows results from ip-api, AbuseIPDB, VirusTotal, OTX all populated

---

## 3. Live Monitor Tab Tests

### Test 3.1: Start without path
- Ensure no log path set
- Click "Start Monitor"
- **Expected:** Error "Log file not found"

### Test 3.2: Monitor sample CSV
1. Set log path in sidebar to: `c:\Users\teja\Desktop\Suspicious_IP_Checker_Project\IP_Analysis_Mini_Project\data\sample_logs.csv`
2. Set interval: 5s, thresholds: requests=5, failures=3
3. Save config, go to Live Monitor tab
4. Click "Start Monitor"
5. In PowerShell (separate window), append lines:
   ```powershell
   Add-Content "data\sample_logs.csv" "2026-10-20 10:00:00,10.0.0.1,/test,200"
   Add-Content "data\sample_logs.csv" "2026-10-20 10:00:01,10.0.0.1,/test,401"
   Add-Content "data\sample_logs.csv" "2026-10-20 10:00:02,10.0.0.1,/test,401"
   Add-Content "data\sample_logs.csv" "2026-10-20 10:00:03,10.0.0.1,/test,401"
   ```
6. Switch back to browser, press R to refresh
- **Expected:** New entries appear in "Recent Log Entries", IP Activity table updates

### Test 3.3: Threshold flagging
- Continue adding requests from same IP until count > threshold
- **Expected:** IP gets flagged "YES" in activity table, alert appears in Alerts tab

### Test 3.4: Stop monitor
- Click "Stop Monitor"
- Append lines to log
- Refresh
- **Expected:** No new entries processed

---

## 4. Alerts Dashboard Tests

### Test 4.1: View alerts
- After running reputation checks and/or monitoring
- Go to Alerts tab
- **Expected:** Alert cards show severity, IP, source, message

### Test 4.2: Acknowledge alert
- Click "Acknowledge ALT-00001"
- **Expected:** Alert shows ✅ icon, disappears from "unacknowledged only" view

### Test 4.3: Filter unacknowledged
- Check "Show only unacknowledged"
- **Expected:** Only unacknowledged alerts visible

### Test 4.4: Clear all alerts
- Click "🗑️ Clear All Alerts"
- **Expected:** Counters reset to 0, "No alerts yet" message

### Test 4.5: Download alerts CSV
- Generate some alerts, click "Download Alerts CSV"
- **Expected:** CSV file downloads with all alert fields

---

## 5. Email Alert Tests

### Test 5.1: Email not configured
- Go to Alerts tab
- **Expected:** Warning banner: "Email alerts not configured"

### Test 5.2: Test email connection
1. Sidebar → Email Alerts
2. Enter Gmail address + App Password + Recipient
3. Check "Enable Email Alerts"
4. Save
5. Click "📨 Test Email"
- **Expected:** "Test email sent successfully" toast; email arrives in inbox

### Test 5.3: Critical alert triggers email
1. Ensure email configured and enabled
2. Check a suspicious IP via IP Reputation (e.g., `45.155.205.233`)
- **Expected:** Alert marked HIGH → email sent automatically within seconds

### Test 5.4: Invalid credentials
- Enter wrong App Password → Click Test Email
- **Expected:** "SMTP authentication failed" error message

---

## 6. Log Dashboard (Batch Analysis) Tests

### Test 6.1: Sample data analysis
1. Go to Log Dashboard tab
2. Keep "Use built-in sample data" checked
3. Set threshold to 5
4. Click "Run Analysis"
- **Expected:** Metrics (Valid requests, Unique IPs, Flagged IPs, Error responses), charts, summary table

### Test 6.2: Upload CSV file
1. Uncheck "Use built-in sample data"
2. Upload `data/sample_logs.csv`
3. Click "Run Analysis"
- **Expected:** Same as above with uploaded data

### Test 6.3: Invalid CSV (missing columns)
1. Create a test CSV with only columns `time, address, status` (wrong names)
2. Upload and run
- **Expected:** Error message listing missing required columns

### Test 6.4: Download outputs
- After running analysis, click both download buttons
- **Expected:** Two CSV files download (summary + events)

### Test 6.5: Auto-generate alerts from analysis
- After analysis with flagged IPs
- **Expected:** New alerts appear in Alerts tab from "batch_analysis" source

---

## 7. Configuration Persistence Tests

### Test 7.1: API keys survive restart
1. Enter API keys → Save
2. Stop Streamlit (Ctrl+C) → Restart
3. Check sidebar → API Keys
- **Expected:** Keys are still present (loaded from config.json)

### Test 7.2: Monitoring settings persist
1. Set log path and thresholds → Save
2. Restart app
- **Expected:** Settings still visible in sidebar

---

## 8. Edge Cases

### Test 8.1: Empty CSV file
- Upload a CSV with only headers, no data rows
- **Expected:** "No valid IP addresses found" warning

### Test 8.2: Very large log file
- Monitor a log file > 100MB
- **Expected:** Monitor skips to end, processes only new lines (no hang)

### Test 8.3: Network offline
- Disable internet → Try reputation check
- **Expected:** Graceful error messages, app doesn't crash

### Test 8.4: Multiple IPs flagged simultaneously
- Monitor a log with many rapid requests from same IP
- **Expected:** Single flag/alert per IP (not repeated once flagged)
