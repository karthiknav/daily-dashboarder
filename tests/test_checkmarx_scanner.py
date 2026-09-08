import unittest

from daily_dashboard.scanners.checkmarx_scanner import (
    CheckmarxFinding,
    filter_by_min_severity,
    parse_generic_findings,
    parse_sarif,
)


class TestCheckmarxScanner(unittest.TestCase):
    def test_parse_generic_findings(self) -> None:
        report = [
            {"rule": "SQL_Injection", "file": "src/main/java/Foo.java", "line": 42, "severity": "high"}
        ]
        findings = parse_generic_findings(report)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "SQL_Injection")
        self.assertEqual(findings[0].line, 42)

    def test_parse_sarif(self) -> None:
        sarif_doc = {
            "runs": [
                {
                    "tool": {"driver": {"rules": [{"id": "SQL_Injection", "name": "SQL Injection"}]}},
                    "results": [
                        {
                            "ruleId": "SQL_Injection",
                            "level": "error",
                            "message": {"text": "Unsanitized input reaches SQL query."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/main/java/Foo.java"},
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        findings = parse_sarif(sarif_doc)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule, "SQL_Injection")
        self.assertEqual(findings[0].file, "src/main/java/Foo.java")
        self.assertEqual(findings[0].line, 42)
        self.assertEqual(findings[0].severity, "high")  # SARIF "error" -> "high"

    def test_filter_by_min_severity(self) -> None:
        findings = [
            CheckmarxFinding(rule="A", file="a.java", severity="low"),
            CheckmarxFinding(rule="B", file="b.java", severity="high"),
            CheckmarxFinding(rule="C", file="c.java", severity="critical"),
        ]
        filtered = filter_by_min_severity(findings, min_severity="high")
        self.assertEqual({f.rule for f in filtered}, {"B", "C"})


if __name__ == "__main__":
    unittest.main()
