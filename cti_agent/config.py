"""Central configuration for the Cyber Threat Intel Agent agent."""
import os

# ---------------------------------------------------------------------------
# Sectors the agent reports on
# ---------------------------------------------------------------------------
SECTORS = ["Financial", "Healthcare", "Government"]

# Keyword / vendor heuristics used for the fast pre-classification pass and as
# the fallback when no LLM is available. Lower-cased, matched as substrings.
# Matched with word boundaries (see agent._keyword_sectors), so broad tokens
# like "ics" won't hit "graphics". Ambiguous bare tokens (e.g. "swift", which
# matches Apple's SwiftNIO, or "broker" which matches message brokers) are
# qualified to avoid false positives.
SECTOR_KEYWORDS = {
    "Financial": [
        "bank", "banking", "financial", "finance", "payment", "atm",
        "point of sale", "point-of-sale", "fintech", "trading", "brokerage",
        "credit card", "debit card", "card data", "pci dss", "insurance",
        "insurer", "fiserv", "visa", "mastercard", "paypal", "treasury",
        "wire transfer", "mortgage", "stock exchange", "interbank",
        "swift payment", "swift network", "core banking",
    ],
    "Healthcare": [
        "health", "hospital", "medical", "patient", "hipaa", "pharma", "clinic",
        "clinical", "ehr", "emr", "medtech", "hl7", "dicom", "healthcare",
        "medical device", "diagnostic", "laboratory", "telehealth",
        "epic systems", "cerner", "imaging", "pacs", "biomed", "life sciences",
    ],
    "Government": [
        "government", "federal", "agency", ".gov", "municipal", "defense",
        "department of defense", "department of", "election", "public sector",
        "state agency", "military", "fbi", "nsa", "homeland",
        "national security", "public safety", "census", "law enforcement",
        "intelligence community", "veterans affairs",
        # NOTE: "critical infrastructure" / "scada" / "industrial control" were
        # removed — they appear in CISA's standard "Critical Infrastructure
        # Sectors:" advisory boilerplate and wrongly pulled medical/industrial
        # advisories (e.g. DICOM) into Government. The LLM classifies these
        # semantically instead.
    ],
}

# ---------------------------------------------------------------------------
# Intelligence sources (reputable, free, no API key required)
# ---------------------------------------------------------------------------
SOURCES = {
    "CISA KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "NVD": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "ThreatFox": "https://threatfox-api.abuse.ch/api/v1/",
}

# How many of the most-recent raw items to consider from each source.
MAX_KEV_ITEMS = int(os.getenv("CTI_MAX_KEV", "60"))
MAX_RSS_ITEMS = int(os.getenv("CTI_MAX_RSS", "40"))
MAX_NVD_ITEMS = int(os.getenv("CTI_MAX_NVD", "50"))
MAX_THREATFOX_ITEMS = int(os.getenv("CTI_MAX_TF", "40"))

# NVD: look back this many days for newly-published CVEs.
NVD_LOOKBACK_DAYS = int(os.getenv("CTI_NVD_DAYS", "7"))
# NVD's keyless API can be slow with a large result set, so give it more time
# and a few retries (separate from the general HTTP timeout).
NVD_TIMEOUT = int(os.getenv("CTI_NVD_TIMEOUT", "90"))
NVD_RETRIES = int(os.getenv("CTI_NVD_RETRIES", "2"))
# Fetch the whole look-back window (so client-side sorting yields the newest
# CVEs); lower this on very slow links to shrink the payload.
NVD_PAGE_SIZE = int(os.getenv("CTI_NVD_PAGE", "2000"))

# abuse.ch ThreatFox now requires a free Auth-Key. When unset, the source is
# skipped gracefully (no error). Get one at https://auth.abuse.ch/.
ABUSE_CH_KEY = os.getenv("ABUSE_CH_KEY", "").strip()
THREATFOX_LOOKBACK_DAYS = int(os.getenv("CTI_TF_DAYS", "2"))

# Max enriched items to keep per sector in the final briefing.
MAX_ITEMS_PER_SECTOR = int(os.getenv("CTI_MAX_PER_SECTOR", "8"))

# ---------------------------------------------------------------------------
# LLM (local Ollama) settings
# ---------------------------------------------------------------------------
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("CTI_MODEL", "llama3:latest")
LLM_ENABLED = os.getenv("CTI_LLM", "1") != "0"
LLM_TIMEOUT = int(os.getenv("CTI_LLM_TIMEOUT", "60"))

HTTP_TIMEOUT = int(os.getenv("CTI_HTTP_TIMEOUT", "20"))
# A browser-like UA: some CDNs (CISA fronted by Akamai) 403 unknown agents.
USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/124.0 Safari/537.36 CTI-Agent/1.0")
