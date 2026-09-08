"""Parse Checkmarx scan results into structured findings.

NOTE (open item, see plan): the exact export format this org's Checkmarx ADO
task produces hasn't been confirmed against a real pipeline run yet. This
module supports:

  1. A pre-normalized generic JSON finding list (`parse_generic_findings`).
  2. SARIF (`parse_sarif`), since Checkmarx (and CxFlow) can export results as
     SARIF, which is a standardized, publicly documented format
     (https://sarifweb.azurewebsites.net/), making it the safest structured
     format to support without confirming Checkmarx's proprietary XML/JSON.

Extend with an org-specific parser (e.g. CxSAST native XML/JSON) once the real
task output is inspected.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CheckmarxFinding:
    rule: str
    file: str
    line: Optional[int] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    source: str = "unknown"
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "description": self.description,
            "source": self.source,
        }


def parse_generic_findings(report: List[Dict[str, Any]]) -> List[CheckmarxFinding]:
    """Parse a list of already-normalized finding dicts, e.g.:

    [{"rule": "SQL_Injection", "file": "src/main/java/Foo.java", "line": 42,
      "severity": "high", "description": "..."}]
    """
    findings: List[CheckmarxFinding] = []
    for item in report or []:
        findings.append(
            CheckmarxFinding(
                rule=item.get("rule") or item.get("queryName") or "",
                file=item.get("file") or item.get("fileName") or "",
                line=item.get("line"),
                severity=item.get("severity"),
                description=item.get("description"),
                source="generic",
                raw=item,
            )
        )
    return [f for f in findings if f.rule and f.file]


_SARIF_LEVEL_TO_SEVERITY = {"error": "high", "warning": "medium", "note": "low"}


def parse_sarif(sarif_doc: Dict[str, Any]) -> List[CheckmarxFinding]:
    """Parse a SARIF v2.1.0 document into findings.

    Schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """
    findings: List[CheckmarxFinding] = []
    for run in sarif_doc.get("runs") or []:
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        driver = ((run.get("tool") or {}).get("driver") or {})
        for rule in driver.get("rules") or []:
            rid = rule.get("id")
            if rid:
                rules_by_id[rid] = rule

        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or ""
            rule_meta = rules_by_id.get(rule_id, {})
            message = ((result.get("message") or {}).get("text")) or ""
            level = result.get("level") or (rule_meta.get("defaultConfiguration") or {}).get("level") or "warning"

            locations = result.get("locations") or []
            file_path = ""
            line_no = None
            if locations:
                phys = (locations[0].get("physicalLocation") or {})
                file_path = ((phys.get("artifactLocation") or {}).get("uri")) or ""
                region = phys.get("region") or {}
                line_no = region.get("startLine")

            findings.append(
                CheckmarxFinding(
                    rule=rule_id or (rule_meta.get("name") or ""),
                    file=file_path,
                    line=line_no,
                    severity=_SARIF_LEVEL_TO_SEVERITY.get(level, level),
                    description=message,
                    source="sarif",
                    raw=result,
                )
            )
    return findings


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def filter_by_min_severity(
    findings: List[CheckmarxFinding], *, min_severity: str = "high"
) -> List[CheckmarxFinding]:
    """Cap remediation to high/critical severity by default (see plan: Checkmarx
    auto-fix is higher-risk, so v1 scopes down to the findings most worth a PR)."""
    threshold = _SEVERITY_ORDER.get(min_severity.lower(), 3)
    return [f for f in findings if _SEVERITY_ORDER.get((f.severity or "").lower(), 0) >= threshold]
