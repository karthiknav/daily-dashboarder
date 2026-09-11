"""LLM-driven Checkmarx pipeline-log investigation.

Flow:
1) Parse pipeline task logs to extract scan id.
2) Fetch Checkmarx SAST results by scan id.
3) Return normalized findings for remediation.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..core.llm_agent import ToolCallingAgent, extract_last_json
from .checkmarx_scanner import CheckmarxFinding
from .checkmarx_tools.extract_scan_id_tool import extract_scan_id, extract_scan_id_from_logs
from .checkmarx_tools.fetch_sast_results_tool import fetch_checkmarx_sast_results

INSTRUCTIONS = (
    "You are a Checkmarx investigation assistant.\\n"
    "You receive pipeline task logs from Azure DevOps.\\n"
    "Your process is mandatory:\\n"
    "1. Call extract_scan_id_from_logs once to get scanId.\\n"
    "2. If scanId exists, call fetch_checkmarx_sast_results once with that scanId.\\n"
    "3. Return strict JSON with keys: scanId, findings.\\n"
    "4. findings must be a list of objects with keys: rule, file, line, severity, description.\\n"
    "5. rule should come from queryName. description should include CWE/CVSS/status/state when available.\\n"
    "Respond with JSON only."
)


def _tool_schemas() -> List[Dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "extract_scan_id_from_logs",
                "description": "Extract Checkmarx scan id from pipeline logs.",
                "parameters": {
                    "type": "object",
                    "properties": {"log_text": {"type": "string"}},
                    "required": ["log_text"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "fetch_checkmarx_sast_results",
                "description": "Fetch and clean Checkmarx SAST results by scan id.",
                "parameters": {
                    "type": "object",
                    "properties": {"scan_id": {"type": "string"}},
                    "required": ["scan_id"],
                },
            },
        },
    ]


def _available_functions() -> Dict[str, Any]:
    return {
        "extract_scan_id_from_logs": extract_scan_id_from_logs,
        "fetch_checkmarx_sast_results": fetch_checkmarx_sast_results,
    }


def _to_findings(clean_findings: List[Dict[str, Any]]) -> List[CheckmarxFinding]:
    findings: List[CheckmarxFinding] = []
    for item in clean_findings:
        rule = item.get("rule") or item.get("queryName") or ""
        file_path = item.get("file") or ""
        if not rule or not file_path:
            continue
        notes = []
        if item.get("cwe") is not None:
            notes.append(f"CWE-{item['cwe']}")
        if item.get("cvss") is not None:
            notes.append(f"CVSS {item['cvss']}")
        if item.get("status"):
            notes.append(f"status={item['status']}")
        if item.get("state"):
            notes.append(f"state={item['state']}")
        description = "; ".join(notes) if notes else None

        findings.append(
            CheckmarxFinding(
                rule=rule,
                file=file_path,
                line=item.get("line"),
                severity=item.get("severity"),
                description=description,
                source="checkmarx_api",
                raw=item,
            )
        )
    return findings


def _fallback_without_llm(task_logs: str) -> Dict[str, Any]:
    scan_id = extract_scan_id(task_logs)
    if not scan_id:
        return {"scanId": None, "findings": []}
    fetched = json.loads(fetch_checkmarx_sast_results(scan_id))
    return {"scanId": scan_id, "findings": fetched.get("findings") or []}


def investigate_checkmarx_task_logs(task_logs: str, *, max_steps: int = 12) -> Dict[str, Any]:
    """Use tool-calling LLM to resolve Checkmarx findings from pipeline logs."""
    agent = ToolCallingAgent(
        name="checkmarx-scan-investigator",
        instructions=INSTRUCTIONS,
        tools=_tool_schemas(),
        available_functions=_available_functions(),
    )

    user_input = json.dumps({"taskLogs": task_logs})
    try:
        session = agent.run(user_input, max_steps=max_steps)
        payload = extract_last_json(session.get("messages") or []) or {}
    except Exception:
        payload = {}

    if not isinstance(payload, dict) or "findings" not in payload:
        payload = _fallback_without_llm(task_logs)

    normalized = _to_findings(payload.get("findings") or [])
    return {"scanId": payload.get("scanId"), "findings": normalized}
