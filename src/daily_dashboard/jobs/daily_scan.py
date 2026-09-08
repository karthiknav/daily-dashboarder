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
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Union

from ..config import AdoConfig, ScanTarget, load_ado_config, load_targets
from ..core.ado_git import AdoGit
from ..core.ado_pipelines import AdoPipelines
from ..remediation.checkmarx_fixer import fix_checkmarx_violation
from ..remediation.dependency_fixer import fix_dependency
from ..scanners import checkmarx_scanner, dependency_scanner
from ..scanners.checkmarx_scanner import CheckmarxFinding
from ..scanners.dependency_scanner import DependencyFinding

Finding = Union[DependencyFinding, CheckmarxFinding]


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


def _scan_checkmarx_findings(pipelines: AdoPipelines, build_id: int) -> List[CheckmarxFinding]:
    records = pipelines.find_timeline_records(build_id, name_contains="checkmarx")
    findings: List[CheckmarxFinding] = []
    for record in records:
        log_text = pipelines.get_task_log_text(build_id, record)
        parsed = _try_parse_json(log_text)
        if isinstance(parsed, dict) and "runs" in parsed:
            findings.extend(checkmarx_scanner.parse_sarif(parsed))
        elif isinstance(parsed, list):
            findings.extend(checkmarx_scanner.parse_generic_findings(parsed))
        # else: unrecognized log format for this task - skip (see scanners/checkmarx_scanner.py note).
    return checkmarx_scanner.filter_by_min_severity(findings, min_severity="high")


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


def _remediate_dependency_findings(
    *,
    ado: AdoGit,
    ado_cfg: AdoConfig,
    target: ScanTarget,
    findings: List[DependencyFinding],
    dry_run: bool,
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for finding in findings:
        if dry_run:
            entries.append(_finding_entry("dependency_scanner", finding, attempted=False))
            continue
        with tempfile.TemporaryDirectory(prefix="daily-dashboard-") as tmp:
            repo_dir = Path(tmp) / target.repo
            ado.clone_or_pull(target.checkout_url, repo_dir)
            branch = f"daily-dashboard/dep-fix-{finding.package}-{date.today().isoformat()}"
            ado.create_branch(repo_dir, branch)
            fix_result = fix_dependency(repo_dir, finding)
            changed = [repo_dir / p for p in fix_result.get("filesChanged") or []]
            pr_url = None
            if fix_result.get("success") and changed:
                pushed = ado.commit_paths(
                    repo_dir, changed, f"fix: bump {finding.package} to resolve {finding.cve or 'vulnerability'}"
                )
                if pushed:
                    pr_url = ado.create_pr(
                        branch,
                        target.target_branch,
                        title=f"Fix: {finding.package} vulnerability ({finding.cve or 'unknown CVE'})",
                        description=(
                            f"Automated fix by daily-dashboard.\n\n{fix_result.get('notes', '')}"
                        ),
                        repo_url=target.checkout_url,
                        repo_dir=repo_dir,
                    )
            entries.append(
                _finding_entry(
                    "dependency_scanner",
                    finding,
                    attempted=True,
                    success=fix_result.get("success"),
                    pr_url=pr_url,
                    notes=fix_result.get("notes"),
                )
            )
    return entries


def _remediate_checkmarx_findings(
    *,
    ado: AdoGit,
    ado_cfg: AdoConfig,
    target: ScanTarget,
    findings: List[CheckmarxFinding],
    dry_run: bool,
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for finding in findings:
        if dry_run:
            entries.append(_finding_entry("checkmarx", finding, attempted=False))
            continue
        with tempfile.TemporaryDirectory(prefix="daily-dashboard-") as tmp:
            repo_dir = Path(tmp) / target.repo
            ado.clone_or_pull(target.checkout_url, repo_dir)
            safe_rule = "".join(c if c.isalnum() else "-" for c in finding.rule)[:40]
            branch = f"daily-dashboard/checkmarx-{safe_rule}-{date.today().isoformat()}"
            ado.create_branch(repo_dir, branch)
            fix_result = fix_checkmarx_violation(repo_dir, finding)
            changed = [repo_dir / p for p in fix_result.get("filesChanged") or []]
            pr_url = None
            if fix_result.get("success") and changed:
                pushed = ado.commit_paths(repo_dir, changed, f"fix: address Checkmarx finding {finding.rule}")
                if pushed:
                    pr_url = ado.create_pr(
                        branch,
                        target.target_branch,
                        title=f"Security fix: {finding.rule} in {finding.file}",
                        description=(
                            f"Automated fix by daily-dashboard. Requires security review before merge.\n\n"
                            f"{fix_result.get('notes', '')}"
                        ),
                        repo_url=target.checkout_url,
                        repo_dir=repo_dir,
                    )
            entries.append(
                _finding_entry(
                    "checkmarx",
                    finding,
                    attempted=True,
                    success=fix_result.get("success"),
                    pr_url=pr_url,
                    notes=fix_result.get("notes"),
                )
            )
    return entries


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


def run_daily_scan(config_path: Path, *, dry_run: bool = False) -> Dict[str, Any]:
    ado_cfg = load_ado_config()
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
        definition_id = definitions[0]["id"]
        latest_build = pipelines.get_latest_build(definition_id=definition_id)
        if not latest_build:
            pipelines_report.append({"target": target.repo, "error": "no completed builds found"})
            continue
        build_id = latest_build["id"]

        findings: List[Dict[str, Any]] = []

        if "dependency_scanner" in target.features:
            dep_findings = _scan_dependency_findings(pipelines, build_id)
            findings.extend(
                _remediate_dependency_findings(
                    ado=ado, ado_cfg=ado_cfg, target=target, findings=dep_findings, dry_run=dry_run
                )
            )

        if "checkmarx" in target.features:
            cx_findings = _scan_checkmarx_findings(pipelines, build_id)
            findings.extend(
                _remediate_checkmarx_findings(
                    ado=ado, ado_cfg=ado_cfg, target=target, findings=cx_findings, dry_run=dry_run
                )
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
