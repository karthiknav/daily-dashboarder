"""Shared file-access tools bound to a repo checkout, used by both
dependency_fixer and checkmarx_fixer to build their `available_functions`
dispatch tables for ToolCallingAgent.

Kept file-scoped to the repo_dir (no path escaping) since these are invoked
by LLM tool calls against a real checkout that will be committed and pushed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


class RepoFileTools:
    def __init__(self, repo_dir: Path):
        self.repo_dir = Path(repo_dir).resolve()
        self.changed_files: List[str] = []

    def _resolve(self, rel_path: str) -> Path:
        candidate = (self.repo_dir / rel_path).resolve()
        if self.repo_dir not in candidate.parents and candidate != self.repo_dir:
            raise ValueError(f"path escapes repo checkout: {rel_path}")
        return candidate

    def list_files(self, pattern: str = "**/*") -> str:
        matches = sorted(
            p.relative_to(self.repo_dir).as_posix()
            for p in self.repo_dir.glob(pattern)
            if p.is_file() and ".git" not in p.parts
        )
        return json.dumps({"files": matches[:500]})

    def read_file(self, path: str) -> str:
        try:
            text = self._resolve(path).read_text(encoding="utf-8")
        except Exception as e:
            return json.dumps({"error": str(e)})
        return json.dumps({"path": path, "content": text})

    def write_file(self, path: str, content: str) -> str:
        try:
            target = self._resolve(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        except Exception as e:
            return json.dumps({"error": str(e)})
        if path not in self.changed_files:
            self.changed_files.append(path)
        return json.dumps({"path": path, "success": True})

    def tool_schemas(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "list_files",
                    "description": "List files in the repo checkout matching a glob pattern (default all files).",
                    "parameters": {
                        "type": "object",
                        "properties": {"pattern": {"type": "string", "description": "glob pattern, e.g. '**/pom.xml'"}},
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a text file's full content, given a path relative to the repo root.",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "write_file",
                    "description": "Overwrite a text file with new full content, given a path relative to the repo root.",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                        "required": ["path", "content"],
                    },
                },
            },
        ]

    def available_functions(self) -> Dict[str, Any]:
        return {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "write_file": self.write_file,
        }
