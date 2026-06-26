"""Thin Ollama client (stdlib only) with graceful degradation.

The CTI agent uses a local LLM for reasoning. If Ollama is unreachable or
disabled, callers fall back to deterministic heuristics, so the app keeps
working without a model.
"""
import json
import urllib.request
import urllib.error

from . import config


class LLM:
    def __init__(self, host=None, model=None, timeout=None):
        self.host = (host or config.OLLAMA_HOST).rstrip("/")
        self.model = model or config.OLLAMA_MODEL
        self.timeout = timeout or config.LLM_TIMEOUT
        self._available = None  # lazy health check, cached

    def available(self):
        if not config.LLM_ENABLED:
            self._available = False
        if self._available is None:
            try:
                req = urllib.request.Request(f"{self.host}/api/tags")
                with urllib.request.urlopen(req, timeout=5) as r:
                    self._available = r.status == 200
            except Exception:
                self._available = False
        return self._available

    def generate(self, prompt, system=None, temperature=0.2, fmt=None):
        """Return the model's text response, or None on any failure."""
        if not self.available():
            return None
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system
        if fmt:
            payload["format"] = fmt  # e.g. "json"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate", data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = json.loads(r.read().decode("utf-8"))
                return body.get("response", "").strip()
        except Exception:
            return None

    def generate_json(self, prompt, system=None, temperature=0.1):
        """Ask the model for JSON and parse it defensively."""
        raw = self.generate(prompt, system=system, temperature=temperature, fmt="json")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            # Best-effort: extract the first {...} block.
            start, end = raw.find("{"), raw.rfind("}")
            if 0 <= start < end:
                try:
                    return json.loads(raw[start:end + 1])
                except ValueError:
                    return None
            return None
