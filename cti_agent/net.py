"""Networking helpers: a verified-TLS context and a resilient HTTP GET.

python.org builds on macOS often ship without a usable CA store, so we prefer
the `certifi` bundle when present and fall back to the system default. TLS
verification stays ON — important for a tool that ingests threat data.

Some sources (CISA is fronted by a CDN with bot management) reject stdlib
urllib at the TLS-fingerprint level regardless of headers. When urllib is
blocked we transparently fall back to the system `curl`, which ships on
macOS/Linux — keeping the app dependency-free while still getting the data.
"""
import json
import shutil
import ssl
import subprocess
import urllib.request

_CTX = None


def ssl_context():
    global _CTX
    if _CTX is None:
        try:
            import certifi
            _CTX = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            _CTX = ssl.create_default_context()
    return _CTX


def _curl_get(url, user_agent, timeout):
    curl = shutil.which("curl")
    if not curl:
        raise RuntimeError("urllib blocked and curl not available")
    out = subprocess.run(
        [curl, "-sSL", "--fail", "--max-time", str(timeout),
         "-A", user_agent, url],
        capture_output=True, timeout=timeout + 5,
    )
    if out.returncode != 0:
        raise RuntimeError(f"curl failed ({out.returncode}): "
                           f"{out.stderr.decode('utf-8', 'replace')[:200]}")
    return out.stdout


def http_get(url, user_agent, timeout, extra_headers=None):
    """GET bytes via urllib; on 403/blocking, retry via curl."""
    headers = {"User-Agent": user_agent}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code in (403, 406, 429, 503):
            return _curl_get(url, user_agent, timeout)
        raise
    except (urllib.error.URLError, ssl.SSLError, TimeoutError):
        # Includes read timeouts — curl often fares better on slow/large responses.
        return _curl_get(url, user_agent, timeout)


def http_post_json(url, payload, user_agent, timeout, extra_headers=None):
    """POST a JSON body and return raw response bytes."""
    headers = {"User-Agent": user_agent, "Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_context()) as r:
        return r.read()
