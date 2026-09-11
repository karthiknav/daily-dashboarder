"""Azure DevOps Build/Pipelines REST wrapper.

Covers the `_apis/build/*` surface, which nothing in yapl-upgrader touches
(that project only calls `_apis/git/*` via AdoGit). Uses the same PAT
Basic-auth convention as core/ado_git.py.

Reference: https://learn.microsoft.com/en-us/rest/api/azure/devops/build/
"""
from __future__ import annotations

import base64
import html
import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote, unquote

import requests

API_VERSION = "7.1"


def _basic_header(pat: str) -> str:
    raw = f":{pat}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("utf-8")


def _sanitize(s: str) -> str:
    s = html.unescape(s or "")
    s = re.sub(r"<[^>]+>", "", s)
    return s.strip()


class AdoPipelines:
    """Read-only helper for listing pipelines/builds and fetching logs/timelines."""

    def __init__(self, org_url: str, project: str, pat: str):
        self.org_url = _sanitize(org_url).rstrip("/")
        self.project = _sanitize(project)
        self.pat = pat
        self._headers = {
            "Authorization": _basic_header(pat),
            "Content-Type": "application/json",
        }

    def _project_api_base(self) -> str:
        proj = quote(unquote(self.project), safe="")
        return f"{self.org_url}/{proj}/_apis"

    @staticmethod
    def _normalize_branch_ref(branch: str) -> str:
        ref = (branch or "").strip()
        if ref and not ref.startswith("refs/"):
            ref = f"refs/heads/{ref}"
        return ref

    @classmethod
    def _build_matches_branch(cls, build: Dict[str, Any], branch_name: str) -> bool:
        expected = cls._normalize_branch_ref(branch_name)
        if not expected:
            return True
        source_branch = (build.get("sourceBranch") or "").strip()
        return source_branch == expected

    def _get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = dict(params or {})
        params.setdefault("api-version", API_VERSION)
        r = requests.get(url, headers=self._headers, params=params, timeout=30)
        if r.status_code >= 400:
            raise requests.HTTPError(
                f"{r.status_code} Error calling {url}\nParams={params}\nResponse={r.text}",
                response=r,
            )
        return r.json() or {}

    def list_pipeline_definitions(self, *, name_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """List build/pipeline definitions in the project."""
        url = f"{self._project_api_base()}/build/definitions"
        params: Dict[str, Any] = {}
        if name_filter:
            params["name"] = name_filter
        data = self._get(url, params=params)
        return data.get("value") or []

    def list_recent_builds(
        self,
        *,
        definition_id: Optional[int] = None,
        status_filter: Optional[str] = None,
        result_filter: Optional[str] = None,
        branch_name: Optional[str] = None,
        top: int = 5,
    ) -> List[Dict[str, Any]]:
        """List recent builds, most-recent first.

        status_filter: e.g. "completed". result_filter: e.g. "failed", "succeeded".
        """
        url = f"{self._project_api_base()}/build/builds"
        params: Dict[str, Any] = {"$top": top, "queryOrder": "finishTimeDescending"}
        if definition_id is not None:
            params["definitions"] = definition_id
        if status_filter:
            params["statusFilter"] = status_filter
        if result_filter:
            params["resultFilter"] = result_filter
        if branch_name:
            params["branchName"] = self._normalize_branch_ref(branch_name)
        data = self._get(url, params=params)
        return data.get("value") or []

    def get_latest_build(
        self,
        *,
        definition_id: int,
        result_filter: Optional[str] = None,
        branch_name: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        builds = self.list_recent_builds(
            definition_id=definition_id,
            status_filter="completed",
            result_filter=result_filter,
            branch_name=branch_name,
            top=1,
        )
        if builds:
            return builds[0]

        # Fallback: some pipeline configurations do not honor branchName reliably.
        # In that case, fetch a wider recent set and filter by sourceBranch locally.
        if branch_name:
            recent = self.list_recent_builds(
                definition_id=definition_id,
                status_filter="completed",
                result_filter=result_filter,
                top=50,
            )
            for build in recent:
                if self._build_matches_branch(build, branch_name):
                    return build
        return None

    def get_build_timeline(self, build_id: int) -> Dict[str, Any]:
        """Return the build timeline: per-task/stage records (name, result, log ref)."""
        url = f"{self._project_api_base()}/build/builds/{build_id}/timeline"
        return self._get(url)

    def find_timeline_records(
        self,
        build_id: int,
        *,
        name_contains: str,
    ) -> List[Dict[str, Any]]:
        """Find timeline records (tasks) whose name contains `name_contains` (case-insensitive)."""
        timeline = self.get_build_timeline(build_id)
        records = timeline.get("records") or []
        needle = name_contains.lower()
        return [r for r in records if needle in (r.get("name") or "").lower()]

    def get_build_log_text(self, build_id: int, log_id: int) -> str:
        """Return the raw text content of a single build log."""
        url = f"{self._project_api_base()}/build/builds/{build_id}/logs/{log_id}"
        params = {"api-version": API_VERSION}
        r = requests.get(url, headers={**self._headers, "Accept": "text/plain"}, params=params, timeout=60)
        if r.status_code >= 400:
            raise requests.HTTPError(
                f"{r.status_code} Error fetching log {log_id} for build {build_id}\nResponse={r.text}",
                response=r,
            )
        return r.text

    def get_task_log_text(self, build_id: int, timeline_record: Dict[str, Any]) -> str:
        """Convenience: fetch the log text for a single timeline record (task)."""
        log_ref = timeline_record.get("log") or {}
        log_id = log_ref.get("id")
        if log_id is None:
            return ""
        return self.get_build_log_text(build_id, log_id)

    def list_build_artifacts(self, build_id: int) -> List[Dict[str, Any]]:
        """List published artifacts for a build (e.g. a dependency-check or Checkmarx report)."""
        url = f"{self._project_api_base()}/build/builds/{build_id}/artifacts"
        data = self._get(url)
        return data.get("value") or []

    def download_artifact_content(self, artifact: Dict[str, Any]) -> bytes:
        """Download an artifact's content given the dict returned by list_build_artifacts.

        Artifacts are normally zip files; the caller is responsible for extraction.
        """
        download_url = ((artifact.get("resource") or {}).get("downloadUrl") or "").strip()
        if not download_url:
            raise ValueError(f"Artifact {artifact.get('name')} has no downloadUrl")
        r = requests.get(download_url, headers=self._headers, timeout=120)
        if r.status_code >= 400:
            raise requests.HTTPError(
                f"{r.status_code} Error downloading artifact {artifact.get('name')}\nResponse={r.text}",
                response=r,
            )
        return r.content
