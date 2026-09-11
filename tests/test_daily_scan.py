import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from daily_dashboard.config import AdoConfig, ScanTarget
from daily_dashboard.jobs.daily_scan import run_daily_scan, write_report

MODULE = "daily_dashboard.jobs.daily_scan"


def _target(**overrides) -> ScanTarget:
    defaults = dict(
        project="MyProject",
        repo="my-repo",
        pipeline="my-repo-ci",
        checkout_url="https://dev.azure.com/org/MyProject/_git/my-repo",
        target_branch="main",
        features=["dependency_scanner"],
    )
    defaults.update(overrides)
    return ScanTarget(**defaults)


def _latest_build() -> dict:
    return {
        "id": 99,
        "buildNumber": "20260907.1",
        "_links": {"web": {"href": "https://dev.azure.com/org/MyProject/_build/results?buildId=99"}},
    }


class TestRunDailyScan(unittest.TestCase):
    def _patch_common(self, *, pipelines_mock, ado_gate_mock=None):
        patches = [
            patch(f"{MODULE}.load_ado_config", return_value=AdoConfig(org_url="https://dev.azure.com/org", project="MyProject", pat="pat")),
            patch(f"{MODULE}.AdoPipelines", return_value=pipelines_mock),
            patch(f"{MODULE}.AdoGit", return_value=ado_gate_mock or MagicMock()),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_dry_run_produces_uniform_finding_entry_and_counts(self) -> None:
        pipelines_mock = MagicMock()
        pipelines_mock.list_pipeline_definitions.return_value = [{"id": 1}]
        pipelines_mock.get_latest_build.return_value = _latest_build()
        pipelines_mock.find_timeline_records.return_value = [{"log": {"id": 1}}]
        pipelines_mock.get_task_log_text.return_value = json.dumps(
            [{"package": "log4j-core", "currentVersion": "2.14.1", "cve": "CVE-2021-44228", "severity": "critical"}]
        )
        self._patch_common(pipelines_mock=pipelines_mock)

        with patch(f"{MODULE}.load_targets", return_value=[_target()]):
            report = run_daily_scan(Path("pipelines.yml"), dry_run=True)

        pipelines_mock.get_latest_build.assert_called_once_with(definition_id=1, branch_name="main")

        self.assertIn("generatedAt", report)
        pipeline_entry = report["pipelines"][0]
        self.assertEqual(pipeline_entry["target"], "my-repo")
        self.assertEqual(pipeline_entry["buildNumber"], "20260907.1")
        self.assertEqual(pipeline_entry["violationCounts"], {"dependency_scanner": 1, "total": 1})

        finding = pipeline_entry["findings"][0]
        self.assertEqual(finding["category"], "dependency_scanner")
        self.assertEqual(finding["finding"]["package"], "log4j-core")
        self.assertEqual(
            finding["remediation"], {"attempted": False, "success": None, "prUrl": None, "notes": None}
        )

        self.assertEqual(
            report["summary"],
            {
                "totalPipelines": 1,
                "totalViolations": 1,
                "violationsByCategory": {"dependency_scanner": 1},
                "readyPrCount": 0,
            },
        )

    def test_live_run_surfaces_ready_pr_url(self) -> None:
        pipelines_mock = MagicMock()
        pipelines_mock.list_pipeline_definitions.return_value = [{"id": 1}]
        pipelines_mock.get_latest_build.return_value = _latest_build()
        pipelines_mock.find_timeline_records.return_value = [{"log": {"id": 1}}]
        pipelines_mock.get_task_log_text.return_value = json.dumps(
            [{"package": "log4j-core", "currentVersion": "2.14.1", "cve": "CVE-2021-44228", "severity": "critical"}]
        )
        ado_mock = MagicMock()
        ado_mock.commit_paths.return_value = True
        ado_mock.create_pr.return_value = "https://dev.azure.com/org/MyProject/_git/my-repo/pullrequest/42"
        self._patch_common(pipelines_mock=pipelines_mock, ado_gate_mock=ado_mock)

        fix_result = {"success": True, "filesChanged": ["pom.xml"], "notes": "Bumped to 2.17.1"}
        with patch(f"{MODULE}.load_targets", return_value=[_target()]), patch(
            f"{MODULE}.fix_dependency", return_value=fix_result
        ):
            report = run_daily_scan(Path("pipelines.yml"), dry_run=False)

        finding = report["pipelines"][0]["findings"][0]
        self.assertEqual(
            finding["remediation"],
            {
                "attempted": True,
                "success": True,
                "prUrl": "https://dev.azure.com/org/MyProject/_git/my-repo/pullrequest/42",
                "notes": "Bumped to 2.17.1",
            },
        )
        self.assertEqual(report["summary"]["readyPrCount"], 1)

    def test_error_target_is_excluded_from_summary_counts(self) -> None:
        pipelines_mock = MagicMock()
        pipelines_mock.list_pipeline_definitions.return_value = []
        self._patch_common(pipelines_mock=pipelines_mock)

        with patch(f"{MODULE}.load_targets", return_value=[_target()]):
            report = run_daily_scan(Path("pipelines.yml"), dry_run=True)

        self.assertEqual(report["pipelines"], [{"target": "my-repo", "error": "pipeline 'my-repo-ci' not found"}])
        self.assertEqual(report["summary"]["totalPipelines"], 0)
        self.assertEqual(report["summary"]["totalViolations"], 0)

    def test_checkmarx_feature_uses_task_logs_and_remediation(self) -> None:
        pipelines_mock = MagicMock()
        pipelines_mock.list_pipeline_definitions.return_value = [{"id": 7}]
        pipelines_mock.get_latest_build.return_value = _latest_build()
        pipelines_mock.find_timeline_records.return_value = [{"log": {"id": 12}}]
        pipelines_mock.get_task_log_text.return_value = "checkmarx task log"
        self._patch_common(pipelines_mock=pipelines_mock)

        target = _target(features=["RabobankCheckmarx"])
        with patch(f"{MODULE}.load_targets", return_value=[target]), patch(
            f"{MODULE}.investigate_checkmarx_task_logs",
            return_value={
                "scanId": "922f5390-5083-4b80-b6cf-6057622a3ac6",
                "findings": [
                    MagicMock(
                        severity="MEDIUM",
                        rule="Open*Redirect",
                        file="/src/main/java/Foo.java",
                        line=42,
                        to_dict=lambda: {
                            "rule": "Open*Redirect",
                            "file": "/src/main/java/Foo.java",
                            "line": 42,
                            "severity": "MEDIUM",
                            "description": "CWE-601",
                            "source": "checkmarx_api",
                        },
                    )
                ],
            },
        ), patch(f"{MODULE}.fix_checkmarx_violation", return_value={"success": False, "filesChanged": [], "notes": "manual fix required"}):
            report = run_daily_scan(Path("pipelines.yml"), dry_run=False)

        pipelines_mock.find_timeline_records.assert_called_once()
        args, kwargs = pipelines_mock.find_timeline_records.call_args
        self.assertEqual(args[0], 99)
        self.assertEqual(kwargs["name_contains"], "RabobankCheckmarx")
        finding = report["pipelines"][0]["findings"][0]
        self.assertEqual(finding["category"], "checkmarx")
        self.assertEqual(finding["finding"]["rule"], "Open*Redirect")

    def test_no_build_for_branch_includes_branch_debug_hints(self) -> None:
        pipelines_mock = MagicMock()
        pipelines_mock.list_pipeline_definitions.return_value = [{"id": 1}]
        pipelines_mock.get_latest_build.return_value = None
        pipelines_mock.list_recent_builds.return_value = [
            {"id": 301, "sourceBranch": "refs/heads/main", "buildNumber": "20260912.1"},
            {"id": 300, "sourceBranch": "refs/heads/checkmarx_v1", "buildNumber": "20260911.3"},
        ]
        self._patch_common(pipelines_mock=pipelines_mock)

        with patch(f"{MODULE}.load_targets", return_value=[_target(target_branch="checkmarx_v1")]):
            report = run_daily_scan(Path("pipelines.yml"), dry_run=True)

        entry = report["pipelines"][0]
        self.assertEqual(entry["target"], "my-repo")
        self.assertIn("no completed builds found for branch 'checkmarx_v1'", entry["error"])
        self.assertEqual(entry["branchDebug"][0]["sourceBranch"], "refs/heads/main")
        self.assertEqual(entry["branchDebug"][1]["sourceBranch"], "refs/heads/checkmarx_v1")


class TestWriteReport(unittest.TestCase):
    def test_round_trips_json(self) -> None:
        report = {"generatedAt": "2026-09-07T00:00:00+00:00", "pipelines": [], "summary": {}}
        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "nested" / "report.json"
            write_report(report, output_path)
            self.assertTrue(output_path.exists())
            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), report)


if __name__ == "__main__":
    unittest.main()
