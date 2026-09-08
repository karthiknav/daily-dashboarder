"""LLM-driven remediation for a single dependency/vulnerability finding.

Uses ToolCallingAgent (core/llm_agent.py) with file read/write/list tools
scoped to a repo checkout, plus a "report_result" finishing tool - the same
"finalize" pattern rewrite_runner.py uses for run_upgrade_tool.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from ..core.llm_agent import ToolCallingAgent, extract_last_json
from ..scanners.dependency_scanner import DependencyFinding
from ._file_tools import RepoFileTools

INSTRUCTIONS = (
    "You are a dependency-remediation assistant working inside a checked-out git repository.\n"
    "You will be given one vulnerable dependency finding (package, current version, manifest "
    "file hint, CVE, severity). Your job:\n"
    "1. Use list_files/read_file to locate the manifest file that declares this dependency "
    "(pom.xml, package.json, requirements.txt, build.gradle, etc). Prefer the manifestFile hint "
    "if given, but verify by reading it.\n"
    "2. Determine the minimum version that resolves the CVE. If a fixedVersion is given in the "
    "finding, use it. Otherwise pick the lowest version you are confident patches the CVE, and "
    "say so in your report.\n"
    "3. Edit ONLY the version string for that dependency using write_file with the full updated "
    "file content. Do not change anything else in the file.\n"
    "4. Call report_result exactly once when done, with filesChanged (list of relative paths "
    "actually written), newVersion (string), and notes (string explaining the fix and any "
    "uncertainty). If you cannot safely make the change, set success=false and explain why in "
    "notes instead of guessing.\n"
    "Respond with ONLY the JSON returned by report_result, no extra prose."
)


def _report_result_tool_schema() -> Dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": "report_result",
            "description": "Finalize the dependency fix attempt (does not modify files).",
            "parameters": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "filesChanged": {"type": "array", "items": {"type": "string"}},
                    "newVersion": {"type": "string"},
                    "notes": {"type": "string"},
                },
                "required": ["success", "filesChanged", "notes"],
            },
        },
    }


def _report_result(**kwargs) -> str:
    return json.dumps(kwargs)


def fix_dependency(repo_dir: Path, finding: DependencyFinding, *, max_steps: int = 30) -> Dict[str, Any]:
    """Run one remediation session for a single finding. Returns the parsed
    report_result payload, e.g. {"success": True, "filesChanged": [...], ...}."""
    file_tools = RepoFileTools(repo_dir)
    tools = file_tools.tool_schemas() + [_report_result_tool_schema()]
    available_functions = {**file_tools.available_functions(), "report_result": _report_result}

    agent = ToolCallingAgent(
        name="dependency-fix-assistant",
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
