"""
generate_reports.py - Generates Project Report (DOCX), Presentation (PPTX), and Flowchart (PNG).
Run: python generate_reports.py
"""

import os
from pathlib import Path

# Ensure reports directory exists
REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. FLOWCHART (matplotlib)
# ═══════════════════════════════════════════════════════════════════════════════
def generate_flowchart():
    """Create system architecture flowchart as PNG."""
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.patches import FancyBboxPatch

    fig, ax = plt.subplots(1, 1, figsize=(14, 10))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 10)
    ax.axis("off")
    ax.set_title("Suspicious IP Checker - System Architecture", fontsize=16, fontweight="bold", pad=20)

    def draw_box(x, y, w, h, text, color, fontsize=9):
        box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.1",
                             facecolor=color, edgecolor="black", linewidth=1.5)
        ax.add_patch(box)
        ax.text(x + w/2, y + h/2, text, ha="center", va="center",
                fontsize=fontsize, fontweight="bold", wrap=True)

    def draw_arrow(x1, y1, x2, y2, text=""):
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="->", color="black", lw=1.5))
        if text:
            mid_x, mid_y = (x1 + x2) / 2, (y1 + y2) / 2
            ax.text(mid_x + 0.1, mid_y + 0.15, text, fontsize=7, style="italic")

    # User Input
    draw_box(0.5, 8.5, 2.5, 1.0, "User Input\n(IP / CSV / Log File)", "#E3F2FD")

    # Streamlit Dashboard
    draw_box(4.5, 8.5, 3.5, 1.0, "Streamlit Dashboard\n(app.py)", "#FFF9C4")

    # Config
    draw_box(9.5, 8.5, 2.5, 1.0, "Config\n(API Keys, Email)", "#F3E5F5")

    # IP Reputation Module
    draw_box(0.5, 5.5, 3.0, 1.2, "IP Reputation\nModule\n(ip_reputation.py)", "#FFEBEE")

    # Log Monitor Module
    draw_box(4.5, 5.5, 3.0, 1.2, "Log Monitor\nModule\n(log_monitor.py)", "#E8F5E9")

    # Alert Engine
    draw_box(8.5, 5.5, 3.0, 1.2, "Alert Engine\n(alert_engine.py)", "#FFF3E0")

    # External APIs
    draw_box(0.5, 3.0, 3.0, 1.2, "Threat Intel APIs\nAbuseIPDB | VirusTotal\nAlienVault | ip-api", "#E0F7FA")

    # Log File
    draw_box(4.5, 3.0, 3.0, 1.2, "Server Log File\nApache / Nginx / CSV", "#F1F8E9")

    # SMTP Email
    draw_box(8.5, 3.0, 3.0, 1.2, "SMTP Email\n(Gmail App Password)", "#FCE4EC")

    # Output
    draw_box(3.5, 0.5, 3.5, 1.2, "Alert Dashboard\n(Severity Cards + CSV)", "#F9A825")

    # Reports
    draw_box(8.0, 0.5, 3.0, 1.2, "Reports\nDOCX | PPTX | PNG", "#78909C")

    # Arrows
    draw_arrow(3.0, 9.0, 4.5, 9.0)
    draw_arrow(8.0, 9.0, 9.5, 9.0)
    draw_arrow(5.5, 8.5, 2.0, 6.7)
    draw_arrow(6.25, 8.5, 6.0, 6.7)
    draw_arrow(7.0, 8.5, 10.0, 6.7)
    draw_arrow(2.0, 5.5, 2.0, 4.2)
    draw_arrow(6.0, 5.5, 6.0, 4.2)
    draw_arrow(10.0, 5.5, 10.0, 4.2)
    draw_arrow(2.0, 5.5, 9.0, 5.5, "reputation data")
    draw_arrow(6.0, 5.5, 9.0, 6.1, "alerts")
    draw_arrow(5.25, 5.5, 5.25, 1.7)
    draw_arrow(10.0, 5.5, 10.0, 1.7)

    plt.tight_layout()
    output_path = str(REPORTS_DIR / "flowchart.png")
    plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"[OK] Flowchart saved: {output_path}")


# ═══════════════════════════════════════════════════════════════════════════════
# 2. PROJECT REPORT (DOCX)
# ═══════════════════════════════════════════════════════════════════════════════
def generate_report():
    """Generate project report as DOCX."""
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    doc = Document()

    # Title
    title = doc.add_heading("Suspicious IP Checker", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle = doc.add_paragraph("Project Report - Mini Project")
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph()

    # Abstract
    doc.add_heading("1. Abstract", level=1)
    doc.add_paragraph(
        "The Suspicious IP Checker is an educational cybersecurity tool that checks IP "
        "reputation against multiple threat intelligence sources, monitors server log files "
        "in real-time, and generates alerts via dashboard and email when suspicious activity "
        "is detected. Built with Python and Streamlit, it demonstrates practical application "
        "of network security concepts, API integration, and event-driven alerting."
    )

    # Problem Statement
    doc.add_heading("2. Problem Statement", level=1)
    doc.add_paragraph(
        "System administrators need tools to quickly identify potentially malicious IP "
        "addresses accessing their servers. Existing enterprise solutions are complex and "
        "costly. This project provides a lightweight, open-source approach to: "
    )
    doc.add_paragraph("Check an IP against threat-intelligence sources", style="List Bullet")
    doc.add_paragraph("Display available reputation information", style="List Bullet")
    doc.add_paragraph("Flag IPs listed as suspicious", style="List Bullet")
    doc.add_paragraph("Alert via dashboard and email", style="List Bullet")
    doc.add_paragraph("Monitor server logs in real-time", style="List Bullet")

    # Technology Stack
    doc.add_heading("3. Technology Stack", level=1)
    table = doc.add_table(rows=7, cols=2)
    table.style = "Light Grid Accent 1"
    tech_data = [
        ("Component", "Technology"),
        ("Web Framework", "Streamlit (Python)"),
        ("Language", "Python 3.10+"),
        ("Data Analysis", "Pandas, Matplotlib"),
        ("HTTP Client", "requests"),
        ("Email", "smtplib (SMTP)"),
        ("Threat Intel APIs", "AbuseIPDB, VirusTotal, AlienVault OTX, ip-api.com"),
    ]
    for i, (col1, col2) in enumerate(tech_data):
        table.rows[i].cells[0].text = col1
        table.rows[i].cells[1].text = col2

    doc.add_paragraph()

    # System Architecture
    doc.add_heading("4. System Architecture", level=1)
    doc.add_paragraph(
        "The system consists of 5 modules:"
    )
    doc.add_paragraph("app.py - Main Streamlit dashboard (5 tabs)", style="List Bullet")
    doc.add_paragraph("config.py - Configuration management (API keys, email, thresholds)", style="List Bullet")
    doc.add_paragraph("ip_reputation.py - Threat intelligence API integration layer", style="List Bullet")
    doc.add_paragraph("log_monitor.py - Real-time log file tailing and threshold detection", style="List Bullet")
    doc.add_paragraph("alert_engine.py - Alert creation, severity routing, SMTP email dispatch", style="List Bullet")

    try:
        doc.add_picture(str(REPORTS_DIR / "flowchart.png"), width=Inches(5.5))
    except Exception:
        doc.add_paragraph("[See flowchart.png in reports folder]")

    # Implementation Details
    doc.add_heading("5. Implementation Details", level=1)

    doc.add_heading("5.1 IP Reputation Checking", level=2)
    doc.add_paragraph(
        "The ip_reputation module queries 4 providers: AbuseIPDB (abuse confidence score), "
        "VirusTotal (90+ engine detection ratio), AlienVault OTX (threat pulse associations), "
        "and ip-api.com (free geolocation + proxy/hosting detection). Results are combined "
        "into a ReputationResult dataclass. An IP is flagged if any source indicates risk."
    )

    doc.add_heading("5.2 Live Log Monitoring", level=2)
    doc.add_paragraph(
        "The log_monitor module runs a background thread that polls a log file for new "
        "lines. It parses Apache Combined, Nginx, or CSV formats. For each IP, it tracks "
        "request count and failure count against configurable thresholds. When exceeded, "
        "an IP is flagged and a callback fires the alert engine."
    )

    doc.add_heading("5.3 Alert System", level=2)
    doc.add_paragraph(
        "The alert_engine creates Alert objects with severity levels (low/medium/high/critical). "
        "High/critical alerts automatically trigger email notifications via SMTP. All alerts "
        "appear in the dashboard's Alerts tab with acknowledge/clear functionality."
    )

    # Limitations
    doc.add_heading("6. Limitations", level=1)
    doc.add_paragraph("Free API tiers have daily rate limits (AbuseIPDB: 100/day, VirusTotal: 500/day)", style="List Bullet")
    doc.add_paragraph("Private IPs cannot be checked against external threat intelligence", style="List Bullet")
    doc.add_paragraph("Rule-based flagging produces false positives; not proof of malice", style="List Bullet")
    doc.add_paragraph("Does not identify persons or exact physical locations", style="List Bullet")
    doc.add_paragraph("No active blocking/defense - detection only", style="List Bullet")

    # Conclusion
    doc.add_heading("7. Conclusion", level=1)
    doc.add_paragraph(
        "The Suspicious IP Checker successfully demonstrates how to build a multi-source "
        "threat intelligence lookup tool with real-time log monitoring and tiered alerting. "
        "The modular architecture makes it easy to add new IP reputation providers, different "
        "alert channels (Slack, Teams), or more complex detection rules. As an educational "
        "project, it highlights practical cybersecurity concepts without requiring expensive "
        "enterprise tools."
    )

    output_path = str(REPORTS_DIR / "Project_Report.docx")
    doc.save(output_path)
    print(f"[OK] Report saved: {output_path}")


# ═══════════════════════════════════════════════════════════════════════════════
# 3. PRESENTATION (PPTX)
# ═══════════════════════════════════════════════════════════════════════════════
def generate_presentation():
    """Generate presentation slides as PPTX."""
    from pptx import Presentation
    from pptx.util import Inches, Pt, Emu
    from pptx.dml.color import RGBColor
    from pptx.enum.text import PP_ALIGN

    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    def add_title_slide(title_text, subtitle_text=""):
        slide = prs.slides.add_slide(prs.slide_layouts[0])
        slide.shapes.title.text = title_text
        slide.placeholders[1].text = subtitle_text
        return slide

    def add_content_slide(title_text, bullet_points):
        slide = prs.slides.add_slide(prs.slide_layouts[1])
        slide.shapes.title.text = title_text
        body = slide.placeholders[1].text_frame
        body.clear()
        for point in bullet_points:
            p = body.add_paragraph()
            p.text = point
            p.level = 0
            p.font.size = Pt(18)
        return slide

    # Slide 1: Title
    add_title_slide(
        "Suspicious IP Checker",
        "IP Reputation | Live Monitoring | Alerts\nEducational Cybersecurity Mini Project\nBuilt with Python + Streamlit"
    )

    # Slide 2: Problem Statement
    add_content_slide("Problem Statement", [
        "System admins need to identify malicious IPs on their servers",
        "Enterprise SIEM tools are expensive and complex",
        "Goal: Lightweight tool for IP reputation + log monitoring + alerts",
        "Must be educational, transparent, and ethically responsible",
    ])

    # Slide 3: Solution Overview
    add_content_slide("Solution Overview", [
        "Multi-source IP Reputation Checking (4 threat intel providers)",
        "Real-time log file monitoring with configurable thresholds",
        "Tiered alert system (Dashboard + Email)",
        "Batch CSV analysis with visualization",
        "5-tab Streamlit web dashboard",
    ])

    # Slide 4: Tech Stack
    add_content_slide("Technology Stack", [
        "Python 3.10+ | Streamlit (web UI framework)",
        "Pandas + Matplotlib (data analysis, charts)",
        "requests (HTTP API calls to threat intel)",
        "smtplib (email alerts via Gmail SMTP)",
        "threading (background log monitoring)",
        "python-docx, python-pptx (report generation)",
    ])

    # Slide 5: System Architecture
    slide = prs.slides.add_slide(prs.slide_layouts[5])
    slide.shapes.title.text = "System Architecture"
    try:
        slide.shapes.add_picture(
            str(REPORTS_DIR / "flowchart.png"),
            Inches(2.5), Inches(1.5), Inches(8), Inches(5.5)
        )
    except Exception:
        pass

    # Slide 6: Modules
    add_content_slide("Project Modules", [
        "app.py - Main dashboard (5 tabs: Reputation, Monitor, Alerts, Analysis, Help)",
        "config.py - Settings management (API keys, email, thresholds)",
        "ip_reputation.py - Threat intel API integrations",
        "log_monitor.py - Real-time file tailing + threshold detection",
        "alert_engine.py - Alert creation + SMTP email dispatch",
    ])

    # Slide 7: IP Reputation
    add_content_slide("IP Reputation Checking", [
        "AbuseIPDB: Abuse confidence score (0-100%), reports, ISP",
        "VirusTotal: Detection ratio from 90+ security engines",
        "AlienVault OTX: Reputation score + threat pulse associations",
        "ip-api.com: Geolocation, proxy/hosting flags (FREE, no key!)",
        "Combined verdict: Flag if ANY source indicates risk",
    ])

    # Slide 8: Live Monitoring
    add_content_slide("Live Log Monitoring", [
        "Polls a log file (Apache/Nginx/CSV) every N seconds",
        "Background thread processes new lines",
        "Per-IP activity tracking (requests, failures, paths)",
        "Configurable thresholds trigger automatic alerts",
        "Works with any file you append new lines to",
    ])

    # Slide 9: Alerts
    add_content_slide("Alert System", [
        "4 severity levels: Low, Medium, High, Critical",
        "Dashboard: Visual alert cards with acknowledge/clear",
        "Email: Auto-sent for High + Critical severity",
        "Gmail SMTP with App Password authentication",
        "Sources: Live monitor, reputation check, batch analysis",
    ])

    # Slide 10: API Keys & Limitations
    add_content_slide("API Keys & Limitations", [
        "ip-api.com: Free, no key needed (45 req/min limit)",
        "AbuseIPDB: Free tier = 100 req/day",
        "VirusTotal: Free tier = 4 req/min, 500 req/day",
        "AlienVault OTX: Free = ~10,000 req/day (soft)",
        "Limitations: Rate limits, false positives, private IPs, no attribution",
    ])

    # Slide 11: Demo Results
    add_content_slide("Demo / Sample Testing", [
        "Test IP 8.8.8.8: CLEAN, geolocation shows Google DNS",
        "Sample logs: Brute-force pattern from 203.0.113.25 flagged",
        "Path scanning from 203.0.113.99: /admin, /.env, /phpmyadmin",
        "Alert appears in dashboard with Medium severity",
        "Email sent for high-severity reputation matches",
    ])

    # Slide 12: Conclusion
    add_content_slide("Conclusion", [
        "Successfully demonstrated multi-source IP reputation",
        "Real-time monitoring with threshold-based detection",
        "Tiered alerting via dashboard + email",
        "Modular design allows easy extension (new providers, channels)",
        "Ethical: Analyze only authorized systems, no blocking/scanning",
        "Future: Add more APIs, ML-based anomaly detection, Slack/Teams alerts",
    ])

    # Slide 13: Thank you
    add_title_slide("Thank You!", "Questions?\n\nGitHub / Report / Demo available")

    output_path = str(REPORTS_DIR / "Project_Presentation.pptx")
    prs.save(output_path)
    print(f"[OK] Presentation saved: {output_path}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("  Suspicious IP Checker - Report Generator")
    print("=" * 60)
    print()

    print("[1/3] Generating Flowchart...")
    generate_flowchart()

    print("[2/3] Generating Project Report (DOCX)...")
    generate_report()

    print("[3/3] Generating Presentation (PPTX)...")
    generate_presentation()

    print()
    print("All reports generated in:", str(REPORTS_DIR))
    print("Done!")
