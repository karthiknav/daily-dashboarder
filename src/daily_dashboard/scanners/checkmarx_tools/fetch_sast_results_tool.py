from __future__ import annotations

import json
from pathlib import Path
import os
from typing import Any, Dict, List

import requests


_MOCK_FILE_PATH = Path(__file__).with_name("mock_sast_results.json")
with _MOCK_FILE_PATH.open("r", encoding="utf-8") as mock_file:
    _MOCKED_RESPONSE: Dict[str, Any] = json.load(mock_file)


def _extract_primary_location(result: Dict[str, Any]) -> Dict[str, Any]:
    data = result.get("data") or {}
    nodes = result.get("nodes") or data.get("nodes") or []
    if not nodes:
        return {"file": None, "line": None}
    primary = nodes[0]
    return {"file": primary.get("fileName"), "line": primary.get("line")}


def _sanitize_result(result: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
    loc = _extract_primary_location(result)
    data = result.get("data") or {}
    vulnerability = result.get("vulnerabilityDetails") or {}
    return {
        "scanId": scan_id,
        "queryName": result.get("queryName") or data.get("queryName") or "",
        "severity": result.get("severity"),
        "cwe": result.get("cweID") if result.get("cweID") is not None else vulnerability.get("cweId"),
        "cvss": result.get("cvssScore"),
        "status": result.get("status"),
        "state": result.get("state"),
        "language": result.get("languageName") or data.get("languageName"),
        "description": result.get("description"),
        "file": loc["file"],
        "line": loc["line"],
        "foundAt": result.get("foundAt"),
    }


def _call_checkmarx_sast_results(scan_id: str) -> Dict[str, Any]:
    base_url = (os.environ.get("CHECKMARX_BASE_URL") or "https://eu-2.ast.checkmarx.net").rstrip("/")
    token = os.environ.get("CHECKMARX_API_TOKEN", "").strip()
    if not token:
        raise RuntimeError("CHECKMARX_API_TOKEN is not set")

    url = f"{base_url}/api/sast-results/"
    params = {
        "scan-id": scan_id,
        "severity": "MEDIUM",
        "include-nodes": "true",
        "apply-predicates": "true",
        "offset": 0,
        "limit": 20,
        "sort": "+status,+severity,-queryname",
    }
    headers = {"accept": "application/json", "Authorization": f"Bearer {token}"}
    response = requests.get(url, params=params, headers=headers, timeout=45)
    if response.status_code >= 400:
        raise requests.HTTPError(f"{response.status_code}: {response.text}", response=response)
    return response.json() or {}


def fetch_checkmarx_sast_results(scan_id: str) -> str:
    """Tool 2: call Checkmarx API by scan id and return a cleaned summary.

    If the API fails for any reason, return a cleaned summary based on mocked data.
    """
    used_mock = False
    api_error = None
    try:
        payload = _call_checkmarx_sast_results(scan_id)
    except Exception as exc:
        used_mock = True
        api_error = str(exc)
        payload = _MOCKED_RESPONSE

    results: List[Dict[str, Any]] = payload.get("results") or []
    clean = [_sanitize_result(item, scan_id) for item in results]
    return json.dumps(
        {
            "scanId": scan_id,
            "totalCount": payload.get("totalCount", len(results)),
            "usedMockResponse": used_mock,
            "apiError": api_error,
            "findings": clean,
        }
    )
