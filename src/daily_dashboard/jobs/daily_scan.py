"""Orchestrator: for each configured target, fetch its latest pipeline run,
scan it for dependency/Checkmarx findings, and (unless --dry-run) remediate
each finding via branch -> fix -> commit -> PR, reusing AdoGit exactly the
way migrate_pipeline.py does today in yapl-upgrader.

Produces a dashboard-ready report: pipelines broken down into individual
findings (uniform shape across scanner types), with violation counts per
pipeline and a ready-PR link per remediated finding.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Union

from ..config import AdoConfig, CheckmarxConfig, ScanTarget, load_ado_config, load_checkmarx_config, load_targets
from ..core.ado_git import AdoGit
from ..core.ado_pipelines import AdoPipelines
from ..remediation.checkmarx_fixer import fix_checkmarx_violation
from ..remediation.dependency_fixer import fix_dependency
from ..scanners import dependency_scanner
from ..scanners.checkmarx_investigator import investigate_checkmarx_task_logs
from ..scanners.checkmarx_scanner import filter_by_min_severity
from ..scanners.checkmarx_scanner import CheckmarxFinding
from ..scanners.dependency_scanner import DependencyFinding

Finding = Union[DependencyFinding, CheckmarxFinding]

try:
    from databricks.sdk.runtime import dbutils  # type: ignore
except Exception:
    dbutils = None

def _try_parse_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def _scan_dependency_findings(pipelines: AdoPipelines, build_id: int) -> List[DependencyFinding]:
    records = pipelines.find_timeline_records(build_id, name_contains="depend")
    findings: List[DependencyFinding] = []
    for record in records:
        log_text = pipelines.get_task_log_text(build_id, record)
        parsed = _try_parse_json(log_text)
        if isinstance(parsed, dict) and "dependencies" in parsed:
            findings.extend(dependency_scanner.parse_owasp_dependency_check(parsed))
        elif isinstance(parsed, list):
            findings.extend(dependency_scanner.parse_generic_findings(parsed))
        # else: unrecognized log format for this task - skip (see scanners/dependency_scanner.py note).
    return findings


def _scan_checkmarx_findings(
    pipelines: AdoPipelines,
    build_id: int,
    *,
    cx_cfg: CheckmarxConfig,
) -> List[CheckmarxFinding]:
    records = pipelines.find_timeline_records(build_id, name_contains=cx_cfg.task_name)
    if not records:
        return []

    findings: List[CheckmarxFinding] = []
    for record in records:
        log_text = pipelines.get_task_log_text(build_id, record)
        if not log_text.strip():
            continue
        investigation = investigate_checkmarx_task_logs(log_text)
        findings.extend(investigation.get("findings") or [])

    return filter_by_min_severity(findings, min_severity=cx_cfg.min_severity)


def _finding_summary(category: str, finding: Finding) -> str:
    if category == "dependency_scanner":
        return f"{finding.package} {finding.current_version} ({finding.cve or 'no CVE'})"
    return f"{finding.rule} in {finding.file}" + (f":{finding.line}" if finding.line else "")


def _finding_entry(
    category: str,
    finding: Finding,
    *,
    attempted: bool,
    success: bool | None = None,
    pr_url: str | None = None,
    notes: str | None = None,
) -> Dict[str, Any]:
    return {
        "category": category,
        "severity": finding.severity,
        "summary": _finding_summary(category, finding),
        "finding": finding.to_dict(),
        "remediation": {
            "attempted": attempted,
            "success": success,
            "prUrl": pr_url,
            "notes": notes,
        },
    }


def _dedupe_paths(paths: List[Path]) -> List[Path]:
    unique: List[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _remediate_all_findings_single_branch(
    *,
    ado: AdoGit,
    target: ScanTarget,
    build_id: int,
    dep_findings: List[DependencyFinding],
    cx_findings: List[CheckmarxFinding],
    dry_run: bool,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    def _no_pr_reason_for_entry(entry: Dict[str, Any], default_reason: str) -> None:
        remediation = entry.get("remediation", {})
        if remediation.get("prUrl"):
            return
        notes = remediation.get("notes")
        if notes:
            return
        remediation["notes"] = default_reason
        entry["remediation"] = remediation

    if dry_run:
        findings.extend(
            _finding_entry("dependency_scanner", finding, attempted=False)
            for finding in dep_findings
        )
        findings.extend(
            _finding_entry("checkmarx", finding, attempted=False)
            for finding in cx_findings
        )
        return findings

    if not dep_findings and not cx_findings:
        return findings

    with tempfile.TemporaryDirectory(prefix="daily-dashboard-") as tmp:
        repo_dir = Path(tmp) / target.repo
        branch = f"daily-dashboard/remediation-{build_id}-{date.today().isoformat()}"
        changed_paths: List[Path] = []

        try:
            ado.clone_or_pull(target.checkout_url, repo_dir)
            ado.checkout_branch(repo_dir, target.target_branch)
            ado.create_branch(repo_dir, branch)
        except Exception as exc:
            reason = f"Repository setup failed; no automated fix applied: {exc}"
            for finding in dep_findings:
                findings.append(
                    _finding_entry(
                        "dependency_scanner",
                        finding,
                        attempted=True,
                        success=False,
                        pr_url=None,
                        notes=reason,
                    )
                )
            for finding in cx_findings:
                findings.append(
                    _finding_entry(
                        "checkmarx",
                        finding,
                        attempted=True,
                        success=False,
                        pr_url=None,
                        notes=reason,
                    )
                )
            return findings

        for finding in dep_findings:
            try:
                fix_result = fix_dependency(repo_dir, finding)
                changed_paths.extend(repo_dir / p for p in (fix_result.get("filesChanged") or []))
                findings.append(
                    _finding_entry(
                        "dependency_scanner",
                        finding,
                        attempted=True,
                        success=fix_result.get("success"),
                        pr_url=None,
                        notes=fix_result.get("notes"),
                    )
                )
            except Exception as exc:
                findings.append(
                    _finding_entry(
                        "dependency_scanner",
                        finding,
                        attempted=True,
                        success=False,
                        pr_url=None,
                        notes=f"LLM fixer failed: {exc}",
                    )
                )

        for finding in cx_findings:
            try:
                fix_result = fix_checkmarx_violation(repo_dir, finding)
                changed_paths.extend(repo_dir / p for p in (fix_result.get("filesChanged") or []))
                findings.append(
                    _finding_entry(
                        "checkmarx",
                        finding,
                        attempted=True,
                        success=fix_result.get("success"),
                        pr_url=None,
                        notes=fix_result.get("notes"),
                    )
                )
            except Exception as exc:
                findings.append(
                    _finding_entry(
                        "checkmarx",
                        finding,
                        attempted=True,
                        success=False,
                        pr_url=None,
                        notes=f"LLM fixer failed: {exc}",
                    )
                )

        changed_paths = _dedupe_paths(changed_paths)
        pr_url = None
        pr_failure_reason = "No fixable code changes were produced by the LLM fixers."
        if changed_paths:
            try:
                pushed = ado.commit_paths(repo_dir, changed_paths, "fix: automated remediation for scan findings")
                if pushed:
                    pr_url = ado.create_pr(
                        branch,
                        target.target_branch,
                        title=f"Automated security/dependency remediation for build {build_id}",
                        description=(
                            "Automated fixes by daily-dashboard for dependency and/or Checkmarx findings. "
                            "Please review before merge."
                        ),
                        repo_url=target.checkout_url,
                        repo_dir=repo_dir,
                    )
                else:
                    pr_failure_reason = "Fixes were generated, but nothing was committed/pushed."
            except Exception as exc:
                pr_failure_reason = f"Fixes were generated, but PR creation failed: {exc}"

        if pr_url:
            for entry in findings:
                if entry["remediation"].get("success"):
                    entry["remediation"]["prUrl"] = pr_url

        for entry in findings:
            if entry["remediation"].get("success") and not entry["remediation"].get("prUrl"):
                _no_pr_reason_for_entry(entry, pr_failure_reason)
            if entry["remediation"].get("success") is False:
                _no_pr_reason_for_entry(entry, "LLM could not generate an automated fix for this finding.")

    return findings


def _violation_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for entry in findings:
        category = entry["category"]
        counts[category] = counts.get(category, 0) + 1
    counts["total"] = len(findings)
    return counts


def _build_summary(pipelines: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_violations = 0
    by_category: Dict[str, int] = {}
    ready_pr_count = 0
    total_pipelines = 0
    for entry in pipelines:
        if "error" in entry:
            continue
        total_pipelines += 1
        for finding in entry.get("findings", []):
            total_violations += 1
            by_category[finding["category"]] = by_category.get(finding["category"], 0) + 1
            if finding["remediation"].get("prUrl"):
                ready_pr_count += 1
    return {
        "totalPipelines": total_pipelines,
        "totalViolations": total_violations,
        "violationsByCategory": by_category,
        "readyPrCount": ready_pr_count,
    }


def _openai_url_from_lab(lab_variant: str, environment: str) -> str:
    """Return OpenAI URL by lab variant using lazy branch-specific evaluation."""
    if lab_variant == "OpenLab":
        dbutils = globals().get("dbutils")
        if dbutils is None:
            raise Exception("dbutils is required for OpenLab")
        secret_scope = f"{lab_variant}-SecretScope"
        hostname = dbutils.secrets.get(scope=secret_scope, key="OpenAiHostname")
        return f"https://{hostname}openoaisdc-completions-apis/"
    elif lab_variant == "OneLab":
        return f"https://apim-1labgen-ap-apizone-{environment}01.azure-api.net/openaisdc-completions-apis/"
    elif lab_variant == "APAI":
        return f"https://apim-apai-ap-apizone-{environment}01.azure-api.net/openpaisdc-completions-apis/"
    else:
        raise Exception("Invalid lab_variant")


def _bootstrap_openai_token_from_dbutils() -> None:
    """Populate Azure OpenAI env vars from Databricks secrets when available."""
    lab_variant = os.getenv("OPENAI_LAB_VARIANT") or os.getenv("LAB_VARIANT") or "OpenLab"
    environment = os.getenv("OPENAI_ENVIRONMENT") or os.getenv("ENVIRONMENT") or "prd"
    tenant_id = os.getenv("AZURE_TENANT_ID", "6e93a626-8aca-4dc1-9191-ce291b4b75a1")
    secret_scope = f"{lab_variant}-SecretScope"

    base_url = _openai_url_from_lab(lab_variant, environment)
    os.environ["AZURE_OPENAI_BASE_URL"] = base_url
    os.environ.setdefault("AZURE_OPENAI_ENDPOINT", base_url)

    try:
        from azure.identity import ClientSecretCredential

        client_id = dbutils.secrets.get(scope=secret_scope, key="DataServicePrincipalClientId")
        client_secret = dbutils.secrets.get(scope=secret_scope, key="DataServicePrincipalClientSecret")
        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        token = credential.get_token("https://cognitiveservices.azure.com/.default").token
        os.environ["AZURE_OPENAI_TOKEN"] = token
        os.environ["AZURE_OPENAI_API_KEY"] = token
        os.environ["AZURE_OPENAI_VERSION"] = "2024-10-21"
        os.environ.setdefault("AZURE_OPENAI_DEPLOYMENT", "gpt-5.1")
    except Exception:
        # Non-Databricks/local runs should continue without hard failure.
        return


def run_daily_scan(config_path: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    _bootstrap_openai_token_from_dbutils()
    ado_cfg = load_ado_config()
    cx_cfg = load_checkmarx_config()
    targets = load_targets(config_path)
    pipelines_report: List[Dict[str, Any]] = []

    for target in targets:
        project = target.project or ado_cfg.project
        pipelines = AdoPipelines(ado_cfg.org_url, project, ado_cfg.pat)
        ado = AdoGit(ado_cfg.org_url, project, target.repo, ado_cfg.pat)

        definitions = pipelines.list_pipeline_definitions(name_filter=target.pipeline)
        if not definitions:
            pipelines_report.append({"target": target.repo, "error": f"pipeline '{target.pipeline}' not found"})
            continue
        exact = next(
            (d for d in definitions if str(d.get("name", "")).strip().lower() == target.pipeline.strip().lower()),
            None,
        )
        definition_id = (exact or definitions[0])["id"]
        latest_build = pipelines.get_latest_build(
            definition_id=definition_id,
            branch_name=target.target_branch,
        )
        if not latest_build:
            recent_builds = pipelines.list_recent_builds(
                definition_id=definition_id,
                status_filter="completed",
                top=10,
            )
            recent_branch_hints = [
                {
                    "id": b.get("id"),
                    "sourceBranch": b.get("sourceBranch"),
                    "buildNumber": b.get("buildNumber"),
                }
                for b in recent_builds
            ]
            pipelines_report.append(
                {
                    "target": target.repo,
                    "error": f"no completed builds found for branch '{target.target_branch}'",
                    "branchDebug": recent_branch_hints,
                }
            )
            continue
        build_id = latest_build["id"]

        dep_findings: List[DependencyFinding] = []
        if "dependency_scanner" in target.features:
            dep_findings = _scan_dependency_findings(pipelines, build_id)

        cx_findings: List[CheckmarxFinding] = []
        if any(str(feature).strip().lower() in {"checkmarx", "rabobankcheckmarx"} for feature in target.features):
            cx_findings = _scan_checkmarx_findings(pipelines, build_id, cx_cfg=cx_cfg)

        findings = _remediate_all_findings_single_branch(
            ado=ado,
            target=target,
            build_id=build_id,
            dep_findings=dep_findings,
            cx_findings=cx_findings,
            dry_run=dry_run,
        )

        pipelines_report.append(
            {
                "target": target.repo,
                "pipeline": target.pipeline,
                "project": project,
                "buildId": build_id,
                "buildNumber": latest_build.get("buildNumber"),
                "buildUrl": (latest_build.get("_links") or {}).get("web", {}).get("href"),
                "violationCounts": _violation_counts(findings),
                "findings": findings,
            }
        )

    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "pipelines": pipelines_report,
        "summary": _build_summary(pipelines_report),
    }


def write_report(report: Dict[str, Any], output_path: Path) -> Path:
    """Write the dashboard report to output_path as JSON, creating parent dirs."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return output_path
