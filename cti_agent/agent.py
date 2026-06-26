"""Sentinel CTI — the AI agent.

Pipeline (agentic, multi-step):
    1. COLLECT   pull raw intel from every configured source
    2. CLASSIFY  map each item to Financial / Healthcare / Government
                 (keyword pre-pass, refined by the LLM)
    3. ENRICH    LLM writes an analyst summary + recommended action per item
    4. BRIEF     LLM writes a per-sector executive briefing

Every LLM step degrades gracefully to deterministic logic if the local
model is unavailable, so a sweep always returns something useful.
"""
import json
import re
from datetime import datetime, timezone

from . import config, sources
from .llm import LLM

_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

# Pre-compiled word-boundary matchers per sector keyword. `(?<!\w)...(?!\w)`
# works for tokens with punctuation (".gov", "hl7") where plain \b would not.
_KEYWORD_RE = {
    sector: [(kw, re.compile(r"(?<!\w)" + re.escape(kw) + r"(?!\w)"))
             for kw in kws]
    for sector, kws in config.SECTOR_KEYWORDS.items()
}

SYSTEM_PROMPT = (
    "You are a senior cyber threat intelligence analyst. You map active "
    "threats and vulnerabilities to the business sectors they most endanger "
    "(Financial, Healthcare, Government) and write concise, factual, "
    "decision-useful briefings. Never invent CVE numbers or facts."
)


class CTIAgent:
    def __init__(self, llm=None):
        self.llm = llm or LLM()
        self.log = []

    def _note(self, msg):
        self.log.append(msg)

    # -- step 2: classification ------------------------------------------
    def _keyword_sectors(self, item):
        """Return {sector: score} from keyword/vendor heuristics."""
        text = " ".join([
            item.get("title", ""), item.get("summary", ""),
            " ".join(item.get("tags", [])),
        ]).lower()
        scores = {}
        for sector, matchers in _KEYWORD_RE.items():
            hits = sum(1 for _, rx in matchers if rx.search(text))
            if hits:
                scores[sector] = hits
        return scores

    def _llm_classify(self, items, chunk_size=15):
        """Ask the LLM which sector(s) each ambiguous item threatens.

        Items are classified in small chunks — large 8B-class local models
        lose accuracy (and drop items) on long lists, so we trade a few extra
        calls for reliable coverage.
        """
        mapping = {}
        for start in range(0, len(items), chunk_size):
            chunk = items[start:start + chunk_size]
            catalog = [
                {"i": start + j, "title": it["title"][:140],
                 "summary": it["summary"][:240]}
                for j, it in enumerate(chunk)
            ]
            prompt = (
                "For each item below, decide which of these sectors it most "
                "threatens: Financial, Healthcare, Government. An item may map "
                "to several sectors if widely used across them, or to none if "
                "clearly irrelevant. Widely-deployed enterprise software "
                "(Microsoft, Cisco, Oracle, VPNs, ERP, databases) typically "
                "threatens all three sectors.\n"
                "Return JSON: {\"results\":[{\"i\":<index>,\"sectors\":[...]}]}\n\n"
                f"ITEMS:\n{json.dumps(catalog, ensure_ascii=False)}"
            )
            data = self.llm.generate_json(prompt, system=SYSTEM_PROMPT)
            if data and isinstance(data.get("results"), list):
                for r in data["results"]:
                    try:
                        idx = int(r["i"])
                    except (KeyError, ValueError, TypeError):
                        continue
                    secs = [s for s in r.get("sectors", []) if s in config.SECTORS]
                    mapping[idx] = secs
        return mapping

    def classify(self, items):
        buckets = {s: [] for s in config.SECTORS}
        ambiguous = []
        for it in items:
            scores = self._keyword_sectors(it)
            if scores:
                it["_sectors"] = list(scores.keys())
                it["_match"] = "keyword"
            else:
                ambiguous.append(it)
                it["_sectors"] = []
                it["_match"] = "pending"

        # Let the LLM resolve items with no clear keyword signal.
        if ambiguous and self.llm.available():
            self._note(f"LLM classifying {len(ambiguous)} ambiguous items")
            mapping = self._llm_classify(ambiguous)
            for idx, it in enumerate(ambiguous):
                secs = mapping.get(idx)
                if secs:
                    it["_sectors"] = secs
                    it["_match"] = "llm"
        # (Items with no clear sector are handled by the cross-sector
        # top-up below, so no per-item fallback assignment is needed here.)

        # Each bucket gets its OWN copy of every item: the same threat can map
        # to several sectors, and per-sector enrichment writes a sector-specific
        # analysis — sharing one dict would let the last sector clobber it.
        seen = {s: set() for s in config.SECTORS}
        for it in items:
            for s in it.get("_sectors", []):
                buckets[s].append(dict(it))
                seen[s].add(id(it))

        # Top-up: actively-exploited threats (every CISA KEV entry) and any
        # critical vulnerability endanger all organisations. Surface them as
        # cross-sector intel so no sector panel is starved. Tagged "generic",
        # they always rank below sector-specific findings.
        generic = [it for it in items
                   if it.get("exploited") or it.get("severity") == "Critical"]
        for sector in config.SECTORS:
            for it in generic:
                if id(it) not in seen[sector]:
                    clone = dict(it)
                    clone["_match"] = "generic"
                    clone["_sectors"] = sorted(set(it.get("_sectors", []) + [sector]))
                    buckets[sector].append(clone)
                    seen[sector].add(id(it))
        return buckets

    # Relevance tiers — higher surfaces first within a sector panel:
    #   keyword (2): a sector domain term is explicitly present (strongest)
    #   llm     (1): the model judged the threat relevant to the sector
    #   generic (0): broadly-critical / exploited cross-sector fill
    _TIER = {"keyword": 2, "llm": 1, "generic": 0}

    @classmethod
    def _score(cls, it):
        tier = cls._TIER.get(it.get("_match"), 0)
        exploited = 1 if it.get("exploited") else 0
        sev = _SEVERITY_RANK.get(it.get("severity", "Unknown"), 0)
        ransom = 1 if it.get("ransomware") else 0
        # Order: sector-specificity > actively-exploited > severity > ransomware > recency.
        return (tier, exploited, sev, ransom, it.get("published", ""))

    # -- step 3: enrichment ----------------------------------------------
    def _enrich(self, sector, items):
        items = sorted(items, key=self._score, reverse=True)[: config.MAX_ITEMS_PER_SECTOR]
        if self.llm.available() and items:
            catalog = [
                {"i": i, "title": it["title"][:140], "summary": it["summary"][:300],
                 "severity": it["severity"], "ransomware": it["ransomware"]}
                for i, it in enumerate(items)
            ]
            prompt = (
                f"Sector: {sector}. For each threat below, write a one-sentence "
                f"analyst summary of the risk to the {sector} sector, and a "
                "short concrete recommended action for defenders.\n"
                "Return JSON: {\"results\":[{\"i\":<index>,"
                "\"analysis\":\"...\",\"action\":\"...\"}]}\n\n"
                f"THREATS:\n{json.dumps(catalog, ensure_ascii=False)}"
            )
            data = self.llm.generate_json(prompt, system=SYSTEM_PROMPT)
            if data and isinstance(data.get("results"), list):
                for r in data["results"]:
                    try:
                        it = items[int(r["i"])]
                    except (KeyError, ValueError, TypeError, IndexError):
                        continue
                    it["analysis"] = (r.get("analysis") or "").strip()
                    it["action"] = (r.get("action") or "").strip()
        # Fallbacks for anything the LLM didn't fill.
        for it in items:
            it.setdefault("analysis", it.get("summary", "") or it["title"])
            it.setdefault("action", it.get("required_action")
                          or "Review exposure, prioritise patching, and monitor for exploitation.")
        return items

    # -- step 4: executive briefing --------------------------------------
    def _brief(self, sector, items):
        if not items:
            return f"No active threats currently mapped to the {sector} sector in this sweep."
        if self.llm.available():
            titles = "\n".join(f"- {it['title']} [{it['severity']}]" for it in items[:8])
            prompt = (
                f"Write a 2-3 sentence executive threat briefing for {sector}-sector "
                f"security leadership, based only on these active threats:\n{titles}\n"
                "Be specific and factual. No preamble, no markdown."
            )
            txt = self.llm.generate(prompt, system=SYSTEM_PROMPT, temperature=0.3)
            if txt:
                return txt
        crit = sum(1 for it in items if it["severity"] == "Critical")
        ransom = sum(1 for it in items if it["ransomware"])
        return (f"{len(items)} active threat(s) mapped to the {sector} sector "
                f"({crit} critical, {ransom} linked to ransomware). "
                "Prioritise patching of actively exploited vulnerabilities below.")

    # -- orchestration ----------------------------------------------------
    def run_sweep(self):
        self.log = []
        self._note("Collecting intel from sources")
        raw = sources.fetch_all()
        items = raw["items"]
        self._note(f"Collected {len(items)} raw items "
                   f"({len(raw['errors'])} source error(s))")

        buckets = self.classify(items)

        report_sectors = {}
        for sector in config.SECTORS:
            enriched = self._enrich(sector, buckets[sector])
            report_sectors[sector] = {
                "briefing": self._brief(sector, enriched),
                "count": len(enriched),
                "items": enriched,
            }
            self._note(f"{sector}: {len(enriched)} threats briefed")

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "fetched_at": raw["fetched_at"],
            "llm": {"enabled": self.llm.available(), "model": self.llm.model},
            "sources": list(config.SOURCES.keys()),
            "source_errors": raw["errors"],
            "total_raw": len(items),
            "sectors": report_sectors,
            "agent_log": self.log,
        }


if __name__ == "__main__":
    report = CTIAgent().run_sweep()
    print(json.dumps(report, indent=2)[:4000])
