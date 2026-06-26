"""Threat-intelligence source fetchers (stdlib only).

Each fetcher returns a list of normalized threat items:
    {
        "id":        str,          # stable id (CVE or guid)
        "title":     str,
        "summary":   str,
        "source":    str,          # human-readable source name
        "url":       str,
        "published": str,          # ISO-ish date
        "severity":  str,          # Critical|High|Medium|Low|Unknown
        "tags":      [str],        # vendor / product / misc
        "ransomware": bool,        # known ransomware use (KEV only)
    }
"""
import json
import re
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree as ET

from . import config
from .net import http_get, http_post_json


def _get(url, timeout=None):
    return http_get(url, config.USER_AGENT, timeout or config.HTTP_TIMEOUT, extra_headers={
        "Accept": "application/json, application/xml, text/xml, */*",
        "Accept-Language": "en-US,en;q=0.9",
    })


def _to_iso(s):
    """Normalize an RFC-822 RSS date (e.g. 'Thu, 25 Jun 26 12:00:00 +0000')
    to an ISO date string the frontend can parse; pass through on failure."""
    s = (s or "").strip()
    if not s:
        return ""
    try:
        return parsedate_to_datetime(s).date().isoformat()
    except Exception:
        return s


_CVSS_RE = re.compile(r"\bv[34](?:\.\d)?\s+(\d{1,2}(?:\.\d+)?)", re.I)


def _severity_from_text(text):
    """Derive a severity from CVSS scores embedded in advisory text
    (e.g. 'CVSS ... v3 8.2'); returns the highest found, or None."""
    best = None
    for m in _CVSS_RE.findall(text or ""):
        try:
            s = float(m)
        except ValueError:
            continue
        if 0.0 <= s <= 10.0 and (best is None or s > best):
            best = s
    if best is None:
        return None
    if best >= 9.0:
        return "Critical"
    if best >= 7.0:
        return "High"
    if best >= 4.0:
        return "Medium"
    return "Low"


def _strip_html(text):
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def fetch_cisa_kev():
    """CISA Known Exploited Vulnerabilities catalog."""
    data = json.loads(_get(config.SOURCES["CISA KEV"]))
    vulns = data.get("vulnerabilities", [])
    # Most-recently-added first.
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    items = []
    for v in vulns[: config.MAX_KEV_ITEMS]:
        ransomware = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        items.append({
            "id": v.get("cveID", ""),
            "title": f"{v.get('cveID', '')}: {v.get('vulnerabilityName', '')}".strip(": "),
            "summary": v.get("shortDescription", ""),
            "source": "CISA KEV",
            "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID', '')}",
            "published": v.get("dateAdded", ""),
            # KEV entries are actively exploited -> treat as High baseline,
            # Critical if tied to ransomware campaigns.
            "severity": "Critical" if ransomware else "High",
            "tags": [t for t in (v.get("vendorProject"), v.get("product")) if t],
            "ransomware": ransomware,
            "exploited": True,  # KEV = confirmed actively exploited
            # Re-fetched live each sweep, so its presence == still listed.
            "active": True,
            "status": "Listed in current CISA KEV catalog — actively exploited",
            "required_action": v.get("requiredAction", ""),
        })
    return items


def fetch_cisa_advisories():
    """CISA Cybersecurity Advisories (RSS/Atom)."""
    raw = _get(config.SOURCES["CISA Advisories"])
    root = ET.fromstring(raw)
    # Handle both RSS <item> and Atom <entry>; strip namespaces for simplicity.
    def tag(el):
        return el.tag.split("}")[-1]

    entries = [el for el in root.iter() if tag(el) in ("item", "entry")]
    items = []
    for e in entries[: config.MAX_RSS_ITEMS]:
        children = {tag(c): c for c in e}
        # NOTE: ElementTree elements are falsy when they have no child elements,
        # so use explicit `is not None` lookups — never `a or b` on elements.
        def pick(*names):
            for n in names:
                el = children.get(n)
                if el is not None:
                    return el
            return None
        title_el = pick("title")
        title = (title_el.text if title_el is not None else "") or ""
        # Skip redundant KEV-catalog announcement posts — those exploited CVEs
        # already arrive (with detail) via the CISA KEV source.
        if re.search(r"\badd(?:s|ed)?\b.*known exploited vulnerabilit", title, re.I):
            continue
        # link can be element text (RSS) or href attribute (Atom)
        link_el = pick("link")
        link = ""
        if link_el is not None:
            link = link_el.text or link_el.get("href") or ""
        desc_el = pick("description", "summary", "content")
        summary = _strip_html(desc_el.text if desc_el is not None else "")
        pub_el = pick("pubDate", "updated", "published", "date")
        published = _to_iso((pub_el.text if pub_el is not None else "") or "")
        guid_el = pick("guid", "id")
        gid = (guid_el.text if guid_el is not None else "") or link or title
        items.append({
            "id": gid.strip(),
            "title": title.strip(),
            "summary": summary[:600],
            "source": "CISA Advisories",
            "url": link.strip(),
            "published": published.strip(),
            # Use the CVSS score embedded in the advisory text when present;
            # otherwise label it "Advisory" rather than a bare "Unknown".
            "severity": _severity_from_text(summary) or "Advisory",
            "tags": [],
            "ransomware": False,
            "exploited": False,
            "active": True,
            "status": "Current CISA advisory",
        })
    return items


_NVD_SEV = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}


def _nvd_severity(cve):
    """Best available CVSS base severity, newest metric version first."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            m = entries[0]
            sev = m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity")
            if sev:
                return _NVD_SEV.get(sev.upper(), "Unknown")
            score = m.get("cvssData", {}).get("baseScore")
            if score is not None:
                if score >= 9.0: return "Critical"
                if score >= 7.0: return "High"
                if score >= 4.0: return "Medium"
                return "Low"
    return "Unknown"


def fetch_nvd_recent():
    """Recently-published CVEs from the NIST National Vulnerability Database.

    NVD's keyless API is slow and rate-limited; set CTI_MAX_NVD=0 to skip it
    entirely (CISA KEV + Advisories remain the fast, reliable core).
    """
    if config.MAX_NVD_ITEMS <= 0:
        return []
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=config.NVD_LOOKBACK_DAYS)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    url = (f"{config.SOURCES['NVD']}?pubStartDate={start.strftime(fmt)}"
           f"&pubEndDate={end.strftime(fmt)}&resultsPerPage={config.NVD_PAGE_SIZE}")
    # NVD's keyless API is occasionally slow; retry with a longer timeout
    # before giving up (the sweep still succeeds on other sources if it fails).
    data = None
    last_err = None
    for attempt in range(config.NVD_RETRIES):
        try:
            data = json.loads(_get(url, timeout=config.NVD_TIMEOUT))
            break
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            if attempt < config.NVD_RETRIES - 1:
                time.sleep(6)  # respect NVD's recommended keyless request spacing
    if data is None:
        raise last_err
    rows = []
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        # Skip rejected / placeholder CVEs.
        if cve.get("vulnStatus", "").lower() == "rejected" or desc.startswith("** REJECT"):
            continue
        # Vendor/product hints from the affected CPE configurations.
        tags = sorted({
            cm.get("criteria", "").split(":")[3].replace("_", " ")
            for cfg in cve.get("configurations", [])
            for node in cfg.get("nodes", [])
            for cm in node.get("cpeMatch", [])
            if len(cm.get("criteria", "").split(":")) > 4
        } - {""})[:3]
        rows.append({
            "id": cve.get("id", ""),
            "title": f"{cve.get('id', '')}: {desc[:90]}".strip(": "),
            "summary": desc,
            "source": "NVD",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
            "published": cve.get("published", ""),
            "severity": _nvd_severity(cve),
            "tags": tags,
            "ransomware": False,
            "exploited": False,
            # Rejected CVEs are filtered out above, so what remains is live.
            "active": True,
            "status": f"NVD status: {cve.get('vulnStatus', 'Published')}",
        })
    rows.sort(key=lambda r: r["published"], reverse=True)
    return rows[: config.MAX_NVD_ITEMS]


def fetch_threatfox():
    """abuse.ch ThreatFox IOCs. Requires a free Auth-Key; skipped if unset."""
    if not config.ABUSE_CH_KEY:
        return []
    raw = http_post_json(
        config.SOURCES["ThreatFox"],
        {"query": "get_iocs", "days": config.THREATFOX_LOOKBACK_DAYS},
        config.USER_AGENT, config.HTTP_TIMEOUT,
        extra_headers={"Auth-Key": config.ABUSE_CH_KEY},
    )
    data = json.loads(raw)
    if data.get("query_status") != "ok":
        return []
    items = []
    for ioc in data.get("data", [])[: config.MAX_THREATFOX_ITEMS]:
        malware = ioc.get("malware_printable") or "Unknown malware"
        items.append({
            "id": str(ioc.get("id", "")),
            "title": f"{malware}: {ioc.get('ioc_type_desc', 'IOC')} indicator",
            "summary": (f"{ioc.get('threat_type_desc', '')}. IOC "
                        f"{ioc.get('ioc', '')} associated with {malware}. "
                        f"Confidence {ioc.get('confidence_level', '?')}%."),
            "source": "ThreatFox",
            "url": ioc.get("reference") or "https://threatfox.abuse.ch/",
            "published": ioc.get("first_seen", ""),
            "severity": "High",
            "tags": [t for t in (malware, ioc.get("threat_type")) if t][:3],
            "ransomware": "ransom" in (ioc.get("malware") or "").lower(),
            "exploited": True,  # IOCs reflect in-the-wild activity
            "active": True,
            "status": f"ThreatFox IOC (first seen {(ioc.get('first_seen') or '')[:10]})",
        })
    return items


def fetch_all():
    """Fetch every source; never let one bad source kill the sweep."""
    results, errors = [], []
    for name, fn in (("CISA KEV", fetch_cisa_kev),
                     ("CISA Advisories", fetch_cisa_advisories),
                     ("NVD", fetch_nvd_recent),
                     ("ThreatFox", fetch_threatfox)):
        try:
            results.extend(fn())
        except Exception as exc:  # noqa: BLE001 - report, don't crash
            errors.append(f"{name}: {exc}")
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return {"items": results, "errors": errors, "fetched_at": fetched_at}
