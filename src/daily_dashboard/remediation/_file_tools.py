"""Shared file-access tools bound to a repo checkout, used by both
dependency_fixer and checkmarx_fixer to build their `available_functions`
dispatch tables for ToolCallingAgent.

Kept file-scoped to the repo_dir (no path escaping) since these are invoked
by LLM tool calls against a real checkout that will be committed and pushed.
"""
from __future__ import annotations

import json
import re
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

    def read_file_lines(self, path: str, start_line: int, end_line: int) -> str:
        try:
            target = self._resolve(path)
            lines = target.read_text(encoding="utf-8").splitlines()
            start = max(1, int(start_line))
            end = min(len(lines), int(end_line))
            if end < start:
                return json.dumps({"error": "end_line must be >= start_line"})
            snippet = lines[start - 1:end]
        except Exception as e:
            return json.dumps({"error": str(e)})
        return json.dumps(
            {
                "path": path,
                "startLine": start,
                "endLine": end,
                "content": "\n".join(snippet),
            }
        )

    def list_related_files(self, path: str, max_results: int = 200) -> str:
        try:
            target = self._resolve(path)
            base_dir = target.parent if target.exists() else (self.repo_dir / path).parent
            if self.repo_dir not in base_dir.parents and base_dir != self.repo_dir:
                raise ValueError(f"path escapes repo checkout: {path}")
            files = [
                p.relative_to(self.repo_dir).as_posix()
                for p in base_dir.rglob("*")
                if p.is_file() and ".git" not in p.parts
            ]
            files.sort()
            limit = max(1, min(int(max_results), 1000))
        except Exception as e:
            return json.dumps({"error": str(e)})
        return json.dumps({"baseDir": base_dir.relative_to(self.repo_dir).as_posix(), "files": files[:limit]})

    def search_in_files(self, pattern: str, glob: str = "**/*", max_matches: int = 200) -> str:
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            limit = max(1, min(int(max_matches), 1000))
            matches: List[Dict[str, Any]] = []

            for file_path in self.repo_dir.glob(glob):
                if not file_path.is_file() or ".git" in file_path.parts:
                    continue
                rel = file_path.relative_to(self.repo_dir).as_posix()
                try:
                    text = file_path.read_text(encoding="utf-8")
                except Exception:
                    continue
                for idx, line in enumerate(text.splitlines(), start=1):
                    if regex.search(line):
                        matches.append({"path": rel, "line": idx, "text": line.strip()})
                        if len(matches) >= limit:
                            return json.dumps({"pattern": pattern, "matches": matches, "truncated": True})
        except Exception as e:
            return json.dumps({"error": str(e)})

        return json.dumps({"pattern": pattern, "matches": matches, "truncated": False})

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
            {
                "type": "function",
                "function": {
                    "name": "read_file_lines",
                    "description": "Read only a line range from a text file, using a path relative to the repo root.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "start_line": {"type": "integer"},
                            "end_line": {"type": "integer"},
                        },
                        "required": ["path", "start_line", "end_line"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "list_related_files",
                    "description": "List files in the same directory/subtree as the given relative path.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "max_results": {"type": "integer"},
                        },
                        "required": ["path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_in_files",
                    "description": "Regex search (case-insensitive) across repo files and return matching file/line snippets.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string"},
                            "glob": {"type": "string", "description": "glob pattern for files, default '**/*'"},
                            "max_matches": {"type": "integer"},
                        },
                        "required": ["pattern"],
                    },
                },
            },
        ]

    def available_functions(self) -> Dict[str, Any]:
        return {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "write_file": self.write_file,
            "read_file_lines": self.read_file_lines,
            "list_related_files": self.list_related_files,
            "search_in_files": self.search_in_files,
        }
