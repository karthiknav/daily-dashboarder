import unittest

from daily_dashboard.scanners.dependency_scanner import (
    parse_generic_findings,
    parse_owasp_dependency_check,
)


class TestDependencyScanner(unittest.TestCase):
    def test_parse_generic_findings(self) -> None:
        report = [
            {
                "package": "log4j-core",
                "currentVersion": "2.14.1",
                "fixedVersion": "2.17.1",
                "cve": "CVE-2021-44228",
                "severity": "critical",
                "manifestFile": "pom.xml",
            }
        ]
        findings = parse_generic_findings(report)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].package, "log4j-core")
        self.assertEqual(findings[0].fixed_version, "2.17.1")
        self.assertEqual(findings[0].source, "generic")

    def test_parse_generic_findings_skips_entries_without_package(self) -> None:
        findings = parse_generic_findings([{"currentVersion": "1.0"}])
        self.assertEqual(findings, [])

    def test_parse_owasp_dependency_check(self) -> None:
        report = {
            "dependencies": [
                {
                    "fileName": "log4j-core-2.14.1.jar",
                    "version": "2.14.1",
                    "packages": [{"id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
                    "vulnerabilities": [
                        {"name": "CVE-2021-44228", "severity": "CRITICAL"},
                        {"name": "CVE-2021-45046", "severity": "HIGH"},
                    ],
                },
                {"fileName": "safe-lib-1.0.jar", "version": "1.0", "vulnerabilities": []},
            ]
        }
        findings = parse_owasp_dependency_check(report)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].cve, "CVE-2021-44228")
        self.assertEqual(findings[0].severity, "critical")
        self.assertIsNone(findings[0].fixed_version)
        self.assertEqual(findings[0].source, "owasp-dependency-check")


if __name__ == "__main__":
    unittest.main()
