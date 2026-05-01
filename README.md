# 🛡️ Copilot Data Exposure Firewall

**See exactly what Microsoft 365 Copilot can read in your tenant — in 15 minutes.**

A lightweight SaaS audit tool for IT admins at 100–500 person organizations on M365. Connects via read-only Graph API, maps Copilot's blast radius across SharePoint and OneDrive, and scores your AI data governance posture.

---

## The Problem

When you enable Microsoft 365 Copilot, it inherits every permission every user already has. Files that were over-shared in 2019 — salary folders, legal contracts, client NDAs — are now one Copilot query away from any employee who shouldn't see them. Enterprise DLP tools cost $30k+/year. This fills the gap.

---

## What It Does

- **Connects** via Microsoft Graph API (read-only, delegated permissions)
- **Scans** all SharePoint sites and OneDrive drives in your tenant
- **Flags** anonymous links, org-wide sharing links, sensitive folders with stale permissions
- **Scores** your tenant 0–100 (AI Readiness Score)
- **Exports** a 3-section PDF: Summary, Findings, PowerShell Remediation Playbook

---

## Setup

### 1. Azure App Registration

1. Go to [portal.azure.com](https://portal.azure.com) > **App registrations** > **New registration**
2. Name: `Copilot Firewall`
3. Supported account types: **Multitenant** (for SaaS)
4. Redirect URI: `http://localhost:8501/callback` (Web platform)
5. Under **API permissions** → Add delegated permissions:
   - `Files.Read.All`, `Sites.Read.All`, `User.Read.All`, `Directory.Read.All`, `Group.Read.All`
6. **Grant admin consent** for your tenant
7. Create a client secret and copy the value.

### 2. Environment

```bash
cp .env.example .env
# Fill in AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
```

### 3. Install & Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501)

---

## Architecture

```
app.py                  Streamlit UI + OAuth router
src/
  auth.py               MSAL OAuth2 (delegated, web flow)
  graph_client.py       Read-only Graph API client with pagination
  scanner.py            Exposure detection engine + AI Readiness Score
  report_generator.py   ReportLab PDF generator (preview + full)
```

---

## Risk Classification

| Level | Trigger |
|-------|---------|
| Critical | Anonymous sharing link, or org-wide link on sensitive folder |
| High | Org-wide link, or sensitive folder with stale permissions (>180 days) |
| Medium | Sensitive folder pattern match, or stale guest permissions |

---

## Pricing

| Plan | Price | Included |
|------|-------|----------|
| Audit | $999 one-time | Full scan + PDF + PowerShell remediation playbook |
| Monitor | $499/mo | Weekly scans + Slack/email alerts |

---

## License

MIT
