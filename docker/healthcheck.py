#!/usr/bin/env python3
"""Container healthcheck: both brokers answer /health, the UI serves a page."""
import os
import sys
import urllib.request

vuln = os.environ.get("VULN_PORT", "8765")
clean = os.environ.get("CLEAN_PORT", "8766")
ui = os.environ.get("UI_PORT", "8080")

for url in (f"http://127.0.0.1:{vuln}/health",
            f"http://127.0.0.1:{clean}/health",
            f"http://127.0.0.1:{ui}/"):
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            if r.status != 200:
                sys.exit(1)
    except Exception:
        sys.exit(1)

sys.exit(0)
