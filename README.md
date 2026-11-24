# 🛡️ Security Intelligence Monitor

> **Continuous Defensive Vulnerability Intelligence, CISA KEV Tracking, and Alert Automation**  
> *Built with Python 3.10+, Streamlit, SQLite, SQLAlchemy, Public Security APIs, and APScheduler.*

---

## 📋 Table of Contents
1. [Overview & Capabilities](#overview--capabilities)
2. [Prerequisites](#prerequisites)
3. [Quickstart Setup (Windows PowerShell)](#quickstart-setup-windows-powershell)
4. [Configuration (.env & Sources Registry)](#configuration-env--sources-registry)
5. [How to Run the Application](#how-to-run-the-application)
6. [Baseline Mode & First-Run Workflow](#baseline-mode--first-run-workflow)
7. [Email Notifications & SMTP Setup](#email-notifications--smtp-setup)
8. [Threat Classification & Zero-Day Evidence Model](#threat-classification--zero-day-evidence-model)
9. [Running Tests](#running-tests)
10. [Database Management & CSV Export](#database-management--csv-export)
11. [Troubleshooting Guide](#troubleshooting-guide)
12. [Server Deployment & 24/7 Operations](#server-deployment--247-operations)
13. [Official Reference Links](#official-reference-links)

---

## 1. Overview & Capabilities

The **Security Intelligence Monitor** is a defensive cybersecurity automation platform designed for security engineers, analysts, and learners. It continuously collects, normalizes, deduplicates, and alerts on newly disclosed or materially updated security vulnerabilities across 10 to 50 public threat intelligence sources.

- **Zero Software Cost:** Engineered for $0 starting cost using free, public APIs (NVD API 2.0, CISA KEV, GitHub Global Advisories, and official CERT/vendor RSS feeds).
- **Multi-Flag Alerting:** Discloses Critical/High severities, CISA Known Exploited Vulnerabilities (KEV), and zero-day reports without hiding overlapping risk flags.
- **Change Detection & Deduplication:** Calculates deterministic content fingerprints (excluding fetch timestamps). Detects when a score is updated or a CVE is newly added to CISA KEV.
- **First-Run Baseline Mode:** Ingests historical intelligence on first launch without flooding your inbox. Notifications can be enabled with one click once the baseline is complete.
- **Durable Email Outbox:** Outbound alert emails are persisted in a database outbox with exponential backoff retries. Never marks an email sent unless verified by the SMTP server.
- **Interactive Multi-Page Dashboard:** Built with Streamlit featuring KPI cards, vulnerability explorer, source health diagnostics, outbox retry controls, and CSV export.

---

## 2. Prerequisites

Before starting, ensure you have the following installed on your machine:
- **Python 3.10 or newer:** [Download Python for Windows](https://www.python.org/downloads/)  
  *(Make sure to check "Add Python to PATH" during installation).*
- **Visual Studio Code (Optional):** [Download VS Code](https://code.visualstudio.com/)
- **Git (Optional):** [Download Git](https://git-scm.com/)

---

## 3. Quickstart Setup (Windows PowerShell)

Open PowerShell and navigate to your project directory (`d:\Poonam\Automation`):

```powershell
# 1. Create a Python virtual environment
python -m venv .venv

# 2. Activate the virtual environment
.venv\Scripts\Activate.ps1
# (If script execution is disabled on your system, run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass)

# 3. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Copy example environment configuration
Copy-Item .env.example .env
```

---

## 4. Configuration (.env & Sources Registry)

Open `.env` in any text editor (such as VS Code or Notepad) and configure your settings:

```ini
# --- Optional API Keys (Increases rate limits) ---
NVD_API_KEY=               # Free key from https://nvd.nist.gov/developers/request-an-api-key
GITHUB_TOKEN=              # Free public read-only token from https://github.com/settings/tokens

# --- SMTP Email Notifications ---
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_FROM=your-email@gmail.com
ALERT_TO=your-alerts-recipient@example.com

# --- Policy & Intervals ---
# Options: IMMEDIATE_CRITICAL_KEV, ALL_IMMEDIATE, DISABLED
EMAIL_NOTIFICATION_POLICY=IMMEDIATE_CRITICAL_KEV
CHECK_INTERVAL_MINUTES=60
APP_TIMEZONE=UTC
DATABASE_URL=sqlite:///data/security_monitor.db
LOG_LEVEL=INFO
BASELINE_MODE=true
```

### Configuring Threat Advisory Sources
The initial registry of 20 public threat feeds is located at `config/sources.yaml`.
- **Verified active sources** include:
  - CISA Known Exploited Vulnerabilities (JSON feed)
  - NVD API 2.0 (NIST REST endpoint)
  - GitHub Global Security Advisories (REST API)
  - CISA Cybersecurity Alerts & US-CERT Current Activity (RSS)
  - Canadian Centre for Cyber Security (CCCS) (RSS)
  - CERT-EU Security Advisories (RSS)
  - JPCERT/CC Technical Advisories (RSS)
  - Microsoft Security Response Center (MSRC) (RSS)
  - Google Project Zero Research (Atom)
  - Ubuntu & Red Hat Security Notices (RSS)
  - Cisco Security Advisories & AWS Bulletins (RSS)
- **Unverified/Example feeds** (such as CERT-In HTML bulletin, Debian, Apple) are preserved with `enabled: false` so you can verify their endpoints before enabling.

---

## 5. How to Run the Application

Launch the Streamlit dashboard in your active virtual environment:

```powershell
streamlit run app.py
```

Streamlit will launch local web server at:
👉 **`http://localhost:8501`**

> **Note on Scheduling:** When `app.py` runs, it automatically initializes the persistent background **APScheduler** in a background worker thread. The scheduler runs hourly collection cycles automatically as long as the Streamlit app process is running. You can also trigger immediate polling anytime using the **Run Collection Now** button.

---

## 6. Baseline Mode & First-Run Workflow

1. **Start the app:** By default, `BASELINE_MODE=true`.
2. **Collect the initial intelligence:** Click **"Run Collection Now"** on the dashboard. The application will connect to the active sources, collect the latest vulnerabilities, normalize them, and store them in SQLite.
3. **No email spam:** Because baseline mode is active, historical records are imported silently without sending hundreds of emails.
4. **Enable notifications:** Once your initial catalog is populated, click the **"Enable Notifications"** button on the Overview page or in Settings.
5. **Continuous monitoring:** From that moment forward, any newly disclosed advisory, CVSS score update, or CISA KEV addition will generate an alert.

---

## 7. Email Notifications & SMTP Setup

### For Gmail Users (Using an App Password):
1. Go to your [Google Account Security Settings](https://myaccount.google.com/security).
2. Ensure **2-Step Verification** is turned ON.
3. In the search bar, type **"App passwords"**.
4. Generate a 16-character app password for app name "Security Monitor".
5. Paste this 16-character string into `SMTP_PASSWORD` in your `.env`.

### Verifying Email Delivery:
Navigate to the **Settings** page in the dashboard and click **"Send Test Email"**. The monitor will execute an actual TLS handshake with your SMTP provider and display the verified delivery result.

---

## 8. Threat Classification & Zero-Day Evidence Model

The application classifies every advisory using defensive rules:

| Category | Qualification Criteria | Alert Handling |
| :--- | :--- | :--- |
| **Critical** | CVSS base score $\ge 9.0$, or explicit source label `Critical`. | High-priority immediate alert |
| **High** | CVSS base score $7.0 - 8.9$, or source label `High`. | Included in alerts / digest |
| **Medium** | CVSS base score $4.0 - 6.9$. | Stored, included in digest |
| **Low** | CVSS base score $0.1 - 3.9$. | Stored, included in digest |
| **Unknown** | No valid CVSS score or label provided. Never guessed. | Labeled `Unknown` |
| **CISA KEV** | Listed in CISA Known Exploited Vulnerabilities catalog. | Independent `is_kev=True` flag |
| **Confirmed 0-Day** | Authoritative primary source evidence URL verified. | Independent `CONFIRMED_ZERO_DAY` flag |
| **0-Day Signal** | Text contains keyword like "zero-day" or "in the wild" without verification. | Labeled `UNVERIFIED_SIGNAL` (Needs review) |

---

## 9. Running Tests

The application includes 14 unit and integration tests covering classification, deduplication, change detection, NVD parser, CISA KEV parser, GitHub parser, RSS parser, and email outbox backoff retries.

Run the test suite with pytest:

```powershell
python -m pytest -v
```

All 14 tests run in an isolated in-memory database environment and complete in ~1 second.

---

## 10. Database Management & CSV Export

- **Database Location:** `data/security_monitor.db` (SQLite)
- **Backup:** Simply copy the `data/security_monitor.db` file to a backup folder or external drive while the app is idle.
- **Exporting CSV:**
  1. Open the **Export Data** page in the dashboard.
  2. Filter by desired severity or CISA KEV status.
  3. Click **"Download Advisories CSV"** or **"Download Events CSV"** for analysis in Excel or SIEM tools.

---

## 11. Troubleshooting Guide

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **HTTP 429 (Rate Limited)** | NVD or GitHub public endpoint reached threshold. | The built-in client automatically backs off with exponential jitter. To increase limits, add a free `NVD_API_KEY` or `GITHUB_TOKEN` in `.env`. |
| **SMTP Authentication Error** | Incorrect username or normal Google password used. | For Gmail, you **must** use a 16-character **App Password**, not your regular account password. Verify TLS on port 587. |
| **No Advisories in Dashboard** | Baseline collection has not been run yet. | Click **"Run Collection Now"** on the Overview page or wait for the scheduled hourly run. |
| **Missing feed or parse error** | Publisher changed their RSS endpoint. | Go to the **Sources Registry** page, click **"Test"** to inspect the HTTP status code, and update the URL if necessary. |
| **Scheduler Stopped** | Computer went to sleep or terminal was closed. | Local scheduling requires the host machine to stay powered on. See Section 12 for server deployment. |

---

## 12. Server Deployment & 24/7 Operations

For uninterrupted 24/7 monitoring, host the application on a dedicated Linux VPS (such as a free-tier or low-cost cloud instance) using `systemd`:

```ini
# /etc/systemd/system/sec-monitor.service
[Unit]
Description=Security Intelligence Monitor Streamlit Service
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/opt/security-intelligence-monitor
ExecStart=/opt/security-intelligence-monitor/.venv/bin/streamlit run app.py --server.port 8501 --server.headless true
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## 13. Official Reference Links
- [NIST NVD API 2.0 Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [Request Free NVD API Key](https://nvd.nist.gov/developers/request-an-api-key)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA KEV JSON Feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- [GitHub Security Advisories REST API](https://docs.github.com/en/rest/security-advisories/global-advisories)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [APScheduler Documentation](https://apscheduler.readthedocs.io/)
- [SQLite Documentation](https://www.sqlite.org/docs.html)

---

### Disclaimer
*This tool is created strictly for defensive cybersecurity awareness and vulnerability management. Ingesting public advisories does not confirm whether a specific organization or system is affected.*
