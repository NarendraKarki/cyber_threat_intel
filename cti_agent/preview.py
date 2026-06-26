"""Dev-preview launcher: serves the dashboard with a cached report preloaded
(from /tmp/cti_report.json if present) so the UI renders without waiting for a
live sweep. For normal use run `python3 -m cti_agent.server` instead.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cti_agent import server  # noqa: E402

import tempfile, os
_cache = os.path.join(tempfile.gettempdir(), "cti_report.json")
if os.path.exists(_cache):
    server._STATE["report"] = json.load(open(_cache))
    print(f"Preloaded cached report from {_cache}")

if __name__ == "__main__":
    server.main()
