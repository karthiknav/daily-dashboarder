from __future__ import annotations

import json
import os
from typing import Any, Dict, List

import requests


_MOCKED_RESPONSE: Dict[str, Any] = {
    "results": [
        {
            "queryName": "Open*Redirect",
            "severity": "MEDIUM",
            "cvssScore": 6.6667,
            "cweID": 601,
            "state": "PROPOSED*NOT_EXPLOITABLE",
            "status": "RECURRENT",
            "languageName": "java",
            "nodes": [
                {
                    "fileName": "/src/main/java/nl/rabobank/gict/bl/forward/forward*integrations/features/generate*document/services/GenerateDocumentServiceImpl.java",
                    "line": 81,
                    "name": "requestContentStr",
                    "domType": "UnknownReference",
                },
                {
                    "fileName": "/src/main/java/nl/rabobank/gict/bl/forward/forward*integrations/features/generate*document/controller/GenerateDocumentControllerImpl.java",
                    "line": 32,
                    "name": "requestContentStr",
                    "domType": "UnknownReference",
                },
            ],
            "foundAt": "2026-09-11T13:08:16Z",
        }
    ],
    "totalCount": 1,
}


def _extract_primary_location(result: Dict[str, Any]) -> Dict[str, Any]:
    nodes = result.get("nodes") or []
    if not nodes:
        return {"file": None, "line": None}
    primary = nodes[0]
    return {"file": primary.get("fileName"), "line": primary.get("line")}


def _sanitize_result(result: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
    loc = _extract_primary_location(result)
    return {
        "scanId": scan_id,
        "queryName": result.get("queryName") or "",
        "severity": result.get("severity"),
        "cwe": result.get("cweID"),
        "cvss": result.get("cvssScore"),
        "status": result.get("status"),
        "state": result.get("state"),
        "language": result.get("languageName"),
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
