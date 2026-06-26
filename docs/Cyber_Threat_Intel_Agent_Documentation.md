# Cyber Threat Intel Agent — Application Documentation

**Version:** 1.0  
**Author:** Narendra Karki  
**Date:** June 2026  
**License:** MIT  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Application Overview](#2-application-overview)
3. [Architecture](#3-architecture)
4. [AI Agent Pipeline](#4-ai-agent-pipeline)
5. [Intelligence Sources](#5-intelligence-sources)
6. [Sector Classification](#6-sector-classification)
7. [Technology Stack](#7-technology-stack)
8. [Installation and Setup](#8-installation-and-setup)
9. [Running the Application](#9-running-the-application)
10. [Running on GitHub Codespaces](#10-running-on-github-codespaces)
11. [Configuration Reference](#11-configuration-reference)
12. [Dashboard Interface](#12-dashboard-interface)
13. [Security Considerations](#13-security-considerations)
14. [File Structure and Module Reference](#14-file-structure-and-module-reference)
15. [Troubleshooting](#15-troubleshooting)
16. [Future Enhancements](#16-future-enhancements)

---

## 1. Executive Summary

Cyber Threat Intel Agent is an AI-powered cyber threat intelligence application that fetches, classifies, enriches, and presents live threat data across three critical sectors: **Financial**, **Healthcare**, and **Government**. 

The application follows an **agentic AI pipeline** architecture — a multi-step, autonomous reasoning workflow where the AI agent collects raw intelligence, classifies threats by sector relevance, enriches each finding with analyst-grade summaries, and produces executive briefings — all running on a **local AI model** (Ollama) with **zero cloud dependencies**.

The entire system runs on-demand with no persistent infrastructure, no API keys required for core functionality, and no data leaving the user's machine.

---

## 2. Application Overview

### Purpose

Security teams, analysts, and decision-makers need timely, sector-relevant threat intelligence without the cost and complexity of enterprise platforms. This application delivers that by:

- Pulling live intelligence from reputable, authoritative sources (CISA, NIST NVD)
- Automatically mapping each threat to the business sector(s) it endangers
- Providing AI-generated analyst summaries and recommended defensive actions
- Presenting everything in a clean, sector-organised web dashboard

### Key Differentiators

| Feature | This Application | Typical CTI Tools |
|---------|-----------------|-------------------|
| AI Processing | Local Ollama model — fully offline | Cloud APIs (OpenAI, etc.) |
| Data Privacy | Nothing leaves your machine | Data sent to third-party servers |
| Dependencies | Python stdlib + certifi | Heavy frameworks (Flask, Django, React) |
| Cost | Free (open-source, no API keys) | Subscription-based |
| Deployment | One command, or GitHub Codespaces | Complex infrastructure |
| Graceful Degradation | Works without AI (keyword heuristics) | Fails without API access |

---

## 3. Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Web Dashboard (Browser)                │
│          Financial  │  Healthcare  │  Government          │
└──────────────────────────┬──────────────────────────────┘
                           │ HTTP (port 8077)
┌──────────────────────────┴──────────────────────────────┐
│              stdlib HTTP Server (server.py)               │
│         GET /  │  POST /api/sweep  │  GET /api/report     │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────┐
│                  CTI Agent (agent.py)                     │
│                                                          │
│   ┌──────────┐  ┌──────────┐  ┌────────┐  ┌───────┐    │
│   │ COLLECT  │→ │ CLASSIFY │→ │ ENRICH │→ │ BRIEF │    │
│   └──────────┘  └──────────┘  └────────┘  └───────┘    │
│        │              │            │           │         │
│        ▼              ▼            ▼           ▼         │
│   sources.py    keywords +     per-item    executive     │
│                 LLM judge     analysis     briefing      │
└──────────────────────────┬──────────────────────────────┘
                           │
            ┌──────────────┴──────────────┐
            │     Local Ollama LLM        │
            │  (llama3 / phi3 / etc.)     │
            │  Degrades to heuristics     │
            │  if unavailable             │
            └─────────────────────────────┘
```

### Design Principles

1. **Zero cloud dependency** — All AI reasoning runs locally via Ollama. No data is sent to any cloud service.
2. **Graceful degradation** — Every AI step has a deterministic fallback. The application always produces useful output.
3. **Minimal dependencies** — Built on Python's standard library. Only `certifi` (TLS certificates) and `defusedxml` (secure XML parsing) are external.
4. **Defence in depth** — TLS verification stays on, external content is sanitised before LLM processing, prompt injection defences are layered.

---

## 4. AI Agent Pipeline

The application implements a four-stage agentic pipeline. Each stage operates autonomously, making decisions based on the data it receives.

### Stage 1: COLLECT

**Module:** `sources.py`

The agent pulls raw intelligence from all configured sources in parallel-safe sequential calls. Each source fetcher normalises its data into a common schema:

```
{
    "id":         "CVE-2026-XXXXX",
    "title":      "Human-readable title",
    "summary":    "Description of the vulnerability/threat",
    "source":     "CISA KEV | CISA Advisories | NVD | ThreatFox",
    "url":        "Link to authoritative reference",
    "published":  "ISO date string",
    "severity":   "Critical | High | Medium | Low | Advisory",
    "tags":       ["vendor", "product"],
    "ransomware": true/false,
    "exploited":  true/false,
    "active":     true/false,
    "status":     "Human-readable status text"
}
```

Error handling: if any single source fails (network timeout, API error), the sweep continues with the remaining sources. Errors are reported in the dashboard but never crash the application.

### Stage 2: CLASSIFY

**Module:** `agent.py` → `classify()`

Each raw item is mapped to one or more sectors using a two-tier classification:

1. **Keyword pre-pass (fast, deterministic):** Pre-compiled word-boundary regular expressions match sector-specific terms in the title, summary, and tags. Examples: "banking" → Financial, "hospital" → Healthcare, ".gov" → Government. CISA boilerplate text ("Critical Infrastructure Sectors:...") is stripped before matching to prevent false positives.

2. **LLM classification (semantic, for ambiguous items):** Items with no keyword match are sent to the local LLM in batches of 15. The LLM determines which sector(s) each threat endangers based on semantic understanding.

3. **Cross-sector fill:** Actively exploited threats (CISA KEV entries) and Critical-severity CVEs are surfaced across all sectors as "generic" fill, ensuring no panel is starved. CISA Advisories are excluded from this fill to prevent topic leakage.

### Stage 3: ENRICH

**Module:** `agent.py` → `_enrich()`

For each sector, the top threats (ranked by relevance tier, exploitation status, severity, ransomware linkage, and recency) are sent to the LLM for enrichment:

- **Analysis:** A one-sentence, sector-specific risk assessment
- **Action:** A concrete recommended defensive action

Fallback: If the LLM is unavailable, the source-provided description and CISA's required action text are used instead.

### Stage 4: BRIEF

**Module:** `agent.py` → `_brief()`

The LLM writes a 2-3 sentence executive briefing per sector, summarising the threat landscape for security leadership.

Fallback: A statistical summary (count of threats, critical count, ransomware count) is generated deterministically.

### Relevance Ranking

Within each sector panel, threats are ranked using a multi-factor scoring system:

| Priority | Factor | Description |
|----------|--------|-------------|
| 1 (highest) | Relevance Tier | keyword (2) > LLM-judged (1) > generic fill (0) |
| 2 | Exploitation | Actively exploited threats rank higher |
| 3 | Severity | Critical > High > Medium > Low |
| 4 | Ransomware | Known ransomware linkage ranks higher |
| 5 (lowest) | Recency | More recently published ranks higher |

---

## 5. Intelligence Sources

### CISA Known Exploited Vulnerabilities (KEV)

- **URL:** https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- **What it provides:** Vulnerabilities confirmed to be actively exploited in the wild
- **Authority:** U.S. Cybersecurity and Infrastructure Security Agency
- **Update frequency:** As new exploits are confirmed (typically several per week)
- **Key fields used:** CVE ID, vulnerability name, description, vendor/product, ransomware campaign use, required remediation action, date added
- **Special handling:** KEV entries are always marked as `exploited: true` and surface across all sectors

### CISA Cybersecurity Advisories (RSS/Atom)

- **URL:** https://www.cisa.gov/cybersecurity-advisories/all.xml
- **What it provides:** ICS/OT advisories, product security advisories, and alerts
- **Authority:** U.S. Cybersecurity and Infrastructure Security Agency
- **Update frequency:** Multiple times per week
- **Key fields used:** Title, description, publication date, CVSS scores (extracted from advisory text)
- **Special handling:** 
  - CVSS scores are extracted from advisory body text via regex
  - KEV catalog announcement posts are filtered out (they duplicate the KEV feed)
  - Items without a CVSS score are labelled "Advisory" rather than "Unknown"
  - CISA's standard boilerplate text is stripped before sector classification

### NIST National Vulnerability Database (NVD)

- **URL:** https://services.nvd.nist.gov/rest/json/cves/2.0
- **What it provides:** Recently published CVEs with CVSS severity scores
- **Authority:** U.S. National Institute of Standards and Technology
- **Update frequency:** Continuous
- **Key fields used:** CVE ID, description, CVSS v4.0/v3.1/v3.0/v2.0 scores, affected CPE configurations
- **Special handling:**
  - Keyless API is rate-limited and slow (30-90 seconds); dedicated 90-second timeout with 2 retries
  - Can be disabled entirely with `CTI_MAX_NVD=0` for fast sweeps
  - Rejected/placeholder CVEs are filtered out
  - Vendor/product tags extracted from CPE configurations

### abuse.ch ThreatFox (Optional)

- **URL:** https://threatfox-api.abuse.ch/api/v1/
- **What it provides:** In-the-wild malware indicators of compromise (IOCs)
- **Authority:** abuse.ch (Swiss non-profit)
- **Requires:** Free Auth-Key (set `ABUSE_CH_KEY` environment variable)
- **Special handling:** Skipped gracefully when no key is set — no error, no empty panel

---

## 6. Sector Classification

### Financial Sector Keywords

`bank`, `banking`, `financial`, `finance`, `payment`, `atm`, `point of sale`, `point-of-sale`, `fintech`, `trading`, `brokerage`, `credit card`, `debit card`, `card data`, `pci dss`, `insurance`, `insurer`, `fiserv`, `visa`, `mastercard`, `paypal`, `treasury`, `wire transfer`, `mortgage`, `stock exchange`, `interbank`, `swift payment`, `swift network`, `core banking`

### Healthcare Sector Keywords

`health`, `hospital`, `medical`, `patient`, `hipaa`, `pharma`, `clinic`, `clinical`, `ehr`, `emr`, `medtech`, `hl7`, `dicom`, `healthcare`, `medical device`, `diagnostic`, `laboratory`, `telehealth`, `epic systems`, `cerner`, `imaging`, `pacs`, `biomed`, `life sciences`

### Government Sector Keywords

`government`, `federal`, `agency`, `.gov`, `municipal`, `defense`, `department of defense`, `department of`, `election`, `public sector`, `state agency`, `military`, `fbi`, `nsa`, `homeland`, `national security`, `public safety`, `census`, `law enforcement`, `intelligence community`, `veterans affairs`

### Classification Notes

- Keywords are matched using **word-boundary** regular expressions to prevent partial matches (e.g., "swift" alone won't match Apple's SwiftNIO framework — only "swift payment" or "swift network" will)
- CISA's standard boilerplate listing "Critical Infrastructure Sectors:" is stripped before matching to prevent false sector assignment
- Items that don't match any keyword are classified semantically by the LLM
- Widely-deployed enterprise software (Microsoft, Cisco, Oracle, VPNs) typically affects all sectors — the LLM is instructed to recognise this

---

## 7. Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Language | Python 3.11+ | Universal availability, stdlib richness |
| Web Server | `http.server.ThreadingHTTPServer` | Zero-dependency, stdlib |
| HTTP Client | `urllib.request` + `curl` fallback | stdlib + CDN compatibility |
| XML Parsing | `defusedxml.ElementTree` | Secure XML parsing (prevents XXE attacks) |
| TLS | `ssl` + `certifi` CA bundle | Verified HTTPS without system dependency |
| AI Model | Ollama (llama3 / phi3) | Local, offline, no API keys |
| Frontend | Embedded HTML/CSS/JS | Single-file, no build step |
| Hosting | GitHub + GitHub Codespaces | On-demand, no infrastructure |

---

## 8. Installation and Setup

### Prerequisites

- Python 3.11 or later
- Ollama (optional — application degrades gracefully without it)
- Git

### Local Installation

```bash
# Clone the repository
git clone git@github.com:NarendraKarki/cyber_threat_intel.git
cd cyber_threat_intel

# Install dependencies
pip3 install -r requirements.txt

# (Optional) Install Ollama for AI-enhanced analysis
# Visit https://ollama.com and follow installation instructions
# Then pull a model:
ollama pull llama3:latest
```

### Dependencies

The application has only two external Python dependencies:

| Package | Version | Purpose |
|---------|---------|---------|
| `certifi` | >=2024.0.0 | Provides a curated CA certificate bundle for TLS verification |
| `defusedxml` | >=0.7.0 | Secure XML parsing that prevents XXE and other XML attacks |

---

## 9. Running the Application

### One-Command Launch

```bash
./run.sh
```

This script:
1. Checks if Ollama is installed and starts it if needed
2. Waits for Ollama to become responsive
3. Launches the dashboard server on port 8077
4. Falls back to heuristics mode if Ollama is unavailable

### Manual Launch

```bash
# With LLM (requires Ollama running)
python3 -m cti_agent.server

# Without LLM (fast heuristics mode)
CTI_LLM=0 python3 -m cti_agent.server

# Without NVD (faster, avoids slow keyless API)
CTI_MAX_NVD=0 python3 -m cti_agent.server

# Heuristics only, no NVD (fastest)
CTI_LLM=0 CTI_MAX_NVD=0 python3 -m cti_agent.server
```

### CLI / JSON Output

```bash
# Run a sweep and print JSON to stdout
python3 -m cti_agent.agent

# Heuristics only
CTI_LLM=0 python3 -m cti_agent.agent
```

### Using the Dashboard

1. Open `http://127.0.0.1:8077` in a browser
2. Click **Run Intelligence Sweep**
3. Wait for the sweep to complete (30-60 seconds without LLM, 2-5 minutes with LLM)
4. Review the three sector panels: Financial, Healthcare, Government
5. Each panel shows:
   - An executive briefing at the top
   - Ranked threat cards with severity badges, active status, and recommended actions

---

## 10. Running on GitHub Codespaces

GitHub Codespaces provides a cloud-based development environment that can run the full application without any local installation.

### First-Time Setup

1. Navigate to **github.com/NarendraKarki/cyber_threat_intel**
2. Click **Code → Codespaces → Create codespace on main**
3. Wait for the environment to build (the `.devcontainer` configuration automatically installs Python dependencies, Ollama, and pulls the lightweight `phi3` model)
4. The dashboard port (8077) auto-forwards

### Running a Sweep

1. In the Codespace terminal:
   ```bash
   git pull && python3 -m cti_agent.server
   ```
2. Click the forwarded **8077** URL (from the Ports tab) to open the dashboard
3. Click **Run Intelligence Sweep**
4. Wait 2-4 minutes for the AI-powered sweep to complete (the LLM generates executive briefings and per-threat analysis)

> **Note:** If the sweep fails with a `SyntaxError`, set port 8077 visibility to **Public** (Ports tab → right-click port 8077 → Port Visibility → Public) and retry.

### Returning to an Existing Codespace

1. Go to **github.com/codespaces**
2. Find your Codespace and click to open it
3. In the terminal:
   ```bash
   git pull && python3 -m cti_agent.server
   ```

### Cost and Resource Notes

- The **free tier** provides 120 core-hours/month — ample for on-demand use
- Codespaces are CPU-only, so LLM sweeps are slower; use `CTI_LLM=0` for fast testing
- Codespaces **auto-stop** when idle to conserve hours
- **Stop or delete** the Codespace when done to save quota

---

## 11. Configuration Reference

All configuration is via environment variables. Defaults are sensible for most use cases.

| Variable | Default | Description |
|----------|---------|-------------|
| `CTI_MODEL` | `llama3:latest` | Ollama model name for AI reasoning |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint |
| `CTI_LLM` | `1` | Set to `0` to disable LLM (uses heuristics only) |
| `CTI_LLM_TIMEOUT` | `60` | Timeout per LLM call in seconds |
| `CTI_HTTP_TIMEOUT` | `20` | General HTTP request timeout in seconds |
| `CTI_MAX_KEV` | `60` | Maximum CISA KEV items to ingest per sweep |
| `CTI_MAX_RSS` | `40` | Maximum CISA Advisory items to ingest per sweep |
| `CTI_MAX_NVD` | `50` | Maximum NVD CVEs to ingest (set `0` to disable) |
| `CTI_NVD_DAYS` | `7` | NVD look-back window in days |
| `CTI_NVD_TIMEOUT` | `90` | NVD-specific request timeout in seconds |
| `CTI_NVD_RETRIES` | `2` | Number of NVD request retry attempts |
| `CTI_NVD_PAGE` | `2000` | NVD results per page (API parameter) |
| `ABUSE_CH_KEY` | _(unset)_ | abuse.ch ThreatFox Auth-Key (enables ThreatFox source) |
| `CTI_MAX_TF` | `40` | Maximum ThreatFox IOCs to ingest |
| `CTI_TF_DAYS` | `2` | ThreatFox look-back window in days |
| `CTI_MAX_PER_SECTOR` | `8` | Maximum enriched threats shown per sector panel |

---

## 12. Dashboard Interface

### Layout

The dashboard is a single-page web application with:

- **Header:** Application name, subtitle, sweep button, and metadata (generation time, LLM status, source count)
- **Progress bar:** Visual indicator during sweep execution
- **Three sector columns:** Financial (green dot), Healthcare (blue dot), Government (purple dot)

### Threat Cards

Each threat card displays:

| Element | Description |
|---------|-------------|
| **Title** | CVE ID and vulnerability name or threat description |
| **Severity badge** | Color-coded: Critical (red), High (orange), Medium (yellow), Low (green), Advisory (slate) |
| **ACTIVE badge** | Green outline badge indicating the threat is currently active |
| **RANSOMWARE badge** | Red badge for threats linked to known ransomware campaigns |
| **Source badge** | Which intelligence source provided this item |
| **Tags** | Vendor/product identifiers |
| **Reported date** | Publication date with relative age (e.g., "Jun 20, 2026 · 6 days ago") |
| **Status** | Current status text (e.g., "Listed in current CISA KEV catalog") |
| **Analysis** | AI-generated or source-provided risk assessment |
| **Action** | Recommended defensive action |
| **URL** | Link to authoritative reference |

---

## 13. Security Considerations

### Data Handling

- **No data exfiltration:** All processing happens locally. No threat data is sent to any cloud service or third-party API (except the original source queries).
- **TLS verification:** All HTTPS connections verify server certificates using the `certifi` CA bundle. Certificate verification is never disabled.
- **Secure XML parsing:** Uses `defusedxml` library to parse CISA Advisory XML feeds, which prevents XML External Entity (XXE) attacks, XML bombs, and other XML-based attack vectors.

### LLM Security

- **Prompt injection defence:** External threat feed content is sanitised before being sent to the LLM. Known injection trigger phrases ("ignore previous instructions", "you are now a", etc.) are redacted.
- **System prompt hardening:** The LLM system prompt explicitly instructs the model to disregard any instructions embedded in threat data.
- **Content truncation:** All external content is truncated before LLM processing to limit attack surface.
- **Defence in depth:** Prompt injection cannot be fully prevented at the input layer alone. The sanitisation is a defence-in-depth measure alongside the system prompt instruction. Human-in-the-loop review of LLM outputs remains the primary control.

### Network Security

- **CDN compatibility:** CISA's Akamai CDN blocks non-browser HTTP clients at the TLS fingerprint level. The application transparently falls back to the system `curl` binary when `urllib` is blocked.
- **User-Agent:** A browser-like User-Agent string is used to prevent CDN rejection.
- **No authentication stored:** The only optional credential (abuse.ch Auth-Key) is read from an environment variable, never stored in code.

### Code Security

- **No web framework vulnerabilities:** The application uses Python's stdlib HTTP server, avoiding the attack surface of full web frameworks.
- **HTML escaping:** All dynamic content in the dashboard is escaped to prevent Cross-Site Scripting (XSS).
- **No database:** No SQL injection surface — all data is in-memory and ephemeral.
- **No file uploads:** No file upload surface.
- **No user input processing:** The dashboard accepts only a button click to trigger a sweep; there are no user-supplied text inputs.

---

## 14. File Structure and Module Reference

```
cyber_threat_intel/
├── cti_agent/                  # Main application package
│   ├── __init__.py
│   ├── __main__.py             # Package entry point
│   ├── config.py               # Central configuration (sectors, keywords, URLs, settings)
│   ├── net.py                  # TLS context, HTTP GET/POST with curl fallback
│   ├── sources.py              # Source fetchers (CISA KEV, Advisories, NVD, ThreatFox)
│   ├── llm.py                  # Ollama client with graceful degradation
│   ├── agent.py                # CTIAgent class — the agentic pipeline orchestrator
│   └── server.py               # Web dashboard and API server
├── .devcontainer/
│   ├── devcontainer.json       # GitHub Codespaces configuration
│   └── setup.sh                # Codespace setup script (deps + Ollama + model)
├── docs/
│   └── dashboard.png           # Dashboard screenshot (for README)
├── run.sh                      # One-command launcher script
├── requirements.txt            # Python dependencies (certifi, defusedxml)
├── README.md                   # Project overview and quick-start guide
└── LICENSE                     # MIT License
```

### Module Details

#### `config.py`
Central configuration hub. All tuneable parameters are environment-variable-driven with sensible defaults. Contains sector definitions, keyword maps, source URLs, LLM settings, and HTTP settings.

#### `net.py`
Shared networking layer. Creates a TLS context using the `certifi` CA bundle (necessary for Python 3.14 which ships without a system CA bundle). Implements `http_get()` with automatic fallback to the system `curl` binary when urllib is blocked by CDN TLS fingerprinting. Also provides `http_post_json()` for the ThreatFox API.

#### `sources.py`
Four independent fetcher functions, each returning normalised threat items. Handles RSS date parsing, CVSS score extraction from advisory text, CPE-based vendor/product tagging, and graceful error handling. Each source can fail independently without affecting others.

#### `llm.py`
Thin Ollama client providing `generate()` (free text), `generate_json()` (structured output with defensive JSON parsing), and `available()` (lazy cached health check). Every method returns `None` on any failure, enabling the graceful degradation pattern used throughout the agent.

#### `agent.py`
The core intelligence — implements the four-stage agentic pipeline. Contains the `CTIAgent` class with `run_sweep()` as the main orchestrator. Includes keyword matching with CISA boilerplate stripping, LLM batch classification, tiered relevance ranking, per-sector enrichment with dict cloning, and executive briefing generation.

#### `server.py`
Stdlib HTTP server with embedded HTML/CSS/JS dashboard. Routes: `GET /` (dashboard), `POST /api/sweep` (trigger sweep), `GET /api/report` (cached report), `GET /healthz` (liveness). The sweep runs synchronously on POST — the response contains the complete report.

---

## 15. Troubleshooting

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `ModuleNotFoundError: defusedxml` | Dependencies not installed | Run `pip3 install -r requirements.txt` |
| `Sweep failed: SyntaxError` (in Codespaces) | Port 8077 is Private | Set port visibility to **Public** in the Ports tab |
| `NVD: The read operation timed out` | NVD keyless API is slow | Wait and retry, or disable with `CTI_MAX_NVD=0` |
| `CISA Advisories: HTTP 403` | CDN blocking urllib | Should auto-fallback to curl; check curl is installed |
| `SSL: CERTIFICATE_VERIFY_FAILED` | No CA bundle | Install certifi: `pip3 install certifi` |
| Sweep takes 2-5 minutes | LLM processing on CPU | Normal for local models; use `CTI_LLM=0` for speed |
| Dashboard shows old data | Cached report | Click **Run Intelligence Sweep** for fresh data |
| DICOM in Government panel | Boilerplate classification | Fixed in current version — update with `git pull` |

### Performance Tips

- **Fastest sweep:** `CTI_LLM=0 CTI_MAX_NVD=0 python3 -m cti_agent.server` (15-30 seconds)
- **Balanced:** `CTI_MAX_NVD=0 python3 -m cti_agent.server` (2-4 minutes with LLM, skip slow NVD)
- **Full:** `python3 -m cti_agent.server` (3-6 minutes, all sources + LLM)

---

## 16. Future Enhancements

Potential areas for expansion:

- **Additional sectors:** Energy, Transportation, Education, Telecommunications
- **Additional sources:** MITRE ATT&CK, AlienVault OTX, VirusTotal, Shodan
- **Scheduled sweeps:** Automated periodic intelligence collection
- **Email/Slack alerts:** Notification when critical threats are detected
- **Historical trending:** Track threat landscape changes over time
- **IOC export:** STIX/TAXII format export for integration with SIEMs
- **Cyber brand monitoring:** Domain impersonation and phishing detection (planned)

---

*This document describes Cyber Threat Intel Agent v1.0. For the latest updates, refer to the GitHub repository.*
