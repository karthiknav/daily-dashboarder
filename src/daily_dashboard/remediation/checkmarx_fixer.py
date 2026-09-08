"""LLM-driven remediation for a single Checkmarx violation.

Same ToolCallingAgent + file-tools + report_result pattern as
dependency_fixer.py. Kept as a separate module (rather than parameterizing
one generic fixer) because the instructions and risk posture differ:
Checkmarx fixes are source-code edits and are explicitly scoped to
high/critical severity findings only (see scanners/checkmarx_scanner.py's
filter_by_min_severity) - the PR is the safety gate, not auto-merge.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from ..core.llm_agent import ToolCallingAgent, extract_last_json
from ..scanners.checkmarx_scanner import CheckmarxFinding
from ._file_tools import RepoFileTools

INSTRUCTIONS = (
    "You are a secure-code-remediation assistant working inside a checked-out git repository.\n"
    "You will be given one Checkmarx violation (rule/query name, file, line, severity, "
    "description). Your job:\n"
    "1. Use read_file to read the affected file (and any directly related file if the fix "
    "requires it, e.g. a shared utility).\n"
    "2. Apply the smallest possible source change that resolves the specific violation "
    "described (e.g. parameterize a SQL query, sanitize an input, remove a hardcoded secret). "
    "Do not perform unrelated refactoring.\n"
    "3. Write the change with write_file, passing the full updated file content.\n"
    "4. Call report_result exactly once when done, with filesChanged (list of relative paths "
    "actually written), notes (explain the fix in terms a security reviewer can verify), and "
    "success. If you are not confident a safe fix is possible without deeper context, set "
    "success=false and explain why in notes instead of guessing at a security fix.\n"
    "Respond with ONLY the JSON returned by report_result, no extra prose."
)


def _report_result_tool_schema() -> Dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": "report_result",
            "description": "Finalize the Checkmarx fix attempt (does not modify files).",
            "parameters": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "filesChanged": {"type": "array", "items": {"type": "string"}},
                    "notes": {"type": "string"},
                },
                "required": ["success", "filesChanged", "notes"],
            },
        },
    }


def _report_result(**kwargs) -> str:
    return json.dumps(kwargs)


def fix_checkmarx_violation(repo_dir: Path, finding: CheckmarxFinding, *, max_steps: int = 30) -> Dict[str, Any]:
    """Run one remediation session for a single Checkmarx finding. Returns the
    parsed report_result payload."""
    file_tools = RepoFileTools(repo_dir)
    tools = file_tools.tool_schemas() + [_report_result_tool_schema()]
    available_functions = {**file_tools.available_functions(), "report_result": _report_result}

    agent = ToolCallingAgent(
        name="checkmarx-fix-assistant",
        instructions=INSTRUCTIONS,
        tools=tools,
        available_functions=available_functions,
    )
    user_input = json.dumps({"finding": finding.to_dict()})
    session = agent.run(user_input, max_steps=max_steps)
    result = extract_last_json(session["messages"]) or {}
    result.setdefault("success", False)
    result.setdefault("filesChanged", file_tools.changed_files)
    return result
