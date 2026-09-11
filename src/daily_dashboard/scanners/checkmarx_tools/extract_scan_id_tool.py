from __future__ import annotations

import json
import re
from typing import Optional

_SCAN_ID_RE = re.compile(
    r"(?:scans\?id=|scan-id=)([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)


def extract_scan_id_from_logs(log_text: str) -> str:
    """Tool 1: parse pipeline logs and extract the Checkmarx scan id."""
    match = _SCAN_ID_RE.search(log_text or "")
    if not match:
        return json.dumps({"scanId": None, "found": False})
    return json.dumps({"scanId": match.group(1), "found": True})


def extract_scan_id(log_text: str) -> Optional[str]:
    """Library helper for non-tool callers."""
    match = _SCAN_ID_RE.search(log_text or "")
    return match.group(1) if match else None
