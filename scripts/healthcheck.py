#!/usr/bin/env python3
"""Docker HEALTHCHECK: LocalMCP (:8001) or streamable HTTP (:8000)."""
from __future__ import annotations

import sys
import urllib.request


def main() -> int:
    for port in (8001, 8000):
        try:
            urllib.request.urlopen(f"http://localhost:{port}/health", timeout=5)
            return 0
        except Exception:
            continue
    return 1


if __name__ == "__main__":
    sys.exit(main())
