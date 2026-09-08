"""Parse dependency/vulnerability scan results into structured findings.

NOTE (open item, see plan): the exact format this org's dependency-scan ADO task
emits (raw log text vs. a published report artifact, and which tool - OWASP
Dependency-Check, Nexus IQ, Snyk, Mend, etc.) hasn't been confirmed against a
real pipeline run yet. This module supports:

  1. A pre-normalized generic JSON finding list (`parse_generic_findings`) -
     the safe fallback while the real report format is still unconfirmed.
  2. OWASP Dependency-Check's documented JSON report format
     (`parse_owasp_dependency_check`), since that's the most common
     open-source tool for this task and its schema is public/stable.

Extend with an org-specific parser once the real task output is inspected.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DependencyFinding:
    package: str
    current_version: str
    manifest_file: Optional[str] = None
    fixed_version: Optional[str] = None
    cve: Optional[str] = None
    severity: Optional[str] = None
    source: str = "unknown"
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": self.package,
            "currentVersion": self.current_version,
            "manifestFile": self.manifest_file,
            "fixedVersion": self.fixed_version,
            "cve": self.cve,
            "severity": self.severity,
            "source": self.source,
        }


def parse_generic_findings(report: List[Dict[str, Any]]) -> List[DependencyFinding]:
    """Parse a list of already-normalized finding dicts, e.g.:

    [{"package": "log4j-core", "currentVersion": "2.14.1", "fixedVersion": "2.17.1",
      "cve": "CVE-2021-44228", "severity": "critical", "manifestFile": "pom.xml"}]
    """
    findings: List[DependencyFinding] = []
    for item in report or []:
        findings.append(
            DependencyFinding(
                package=item.get("package") or item.get("name") or "",
                current_version=item.get("currentVersion") or item.get("version") or "",
                manifest_file=item.get("manifestFile"),
                fixed_version=item.get("fixedVersion"),
                cve=item.get("cve"),
                severity=item.get("severity"),
                source="generic",
                raw=item,
            )
        )
    return [f for f in findings if f.package]


def parse_owasp_dependency_check(report_json: Dict[str, Any]) -> List[DependencyFinding]:
    """Parse an OWASP Dependency-Check JSON report (`dependency-check-report.json`).

    Schema: https://jeremylong.github.io/DependencyCheck/general/internals.html
    Each entry under "dependencies" may have a "vulnerabilities" list; each
    vulnerability has "name" (CVE id) and "severity". Dependency-Check does not
    reliably report a "fixed version" - that's left None for the remediation
    step (LLM/tool) to resolve.
    """
    findings: List[DependencyFinding] = []
    for dep in report_json.get("dependencies") or []:
        vulns = dep.get("vulnerabilities") or []
        if not vulns:
            continue
        file_name = dep.get("fileName") or ""
        package_ids = dep.get("packages") or []
        package_name = (package_ids[0].get("id") if package_ids else None) or file_name
        version = dep.get("version") or ""
        for vuln in vulns:
            findings.append(
                DependencyFinding(
                    package=package_name,
                    current_version=version,
                    manifest_file=file_name,
                    fixed_version=None,
                    cve=vuln.get("name"),
                    severity=(vuln.get("severity") or "").lower() or None,
                    source="owasp-dependency-check",
                    raw=vuln,
                )
            )
    return findings
