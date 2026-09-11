import unittest
from unittest.mock import MagicMock, patch

from daily_dashboard.core.ado_pipelines import AdoPipelines


class TestAdoPipelines(unittest.TestCase):
    def setUp(self) -> None:
        self.pipelines = AdoPipelines(
            org_url="https://dev.azure.com/example-org",
            project="sample-project",
            pat="super-secret-token",
        )

    def _mock_response(self, json_data=None, text_data="", status_code=200):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = json_data or {}
        resp.text = text_data
        return resp

    def test_list_pipeline_definitions(self) -> None:
        resp = self._mock_response({"value": [{"id": 42, "name": "my-ci"}]})
        with patch("daily_dashboard.core.ado_pipelines.requests.get", return_value=resp) as mock_get:
            defs = self.pipelines.list_pipeline_definitions(name_filter="my-ci")

        self.assertEqual(defs, [{"id": 42, "name": "my-ci"}])
        called_url = mock_get.call_args.args[0]
        self.assertIn("/build/definitions", called_url)
        self.assertEqual(mock_get.call_args.kwargs["params"]["name"], "my-ci")

    def test_get_latest_build_uses_result_filter(self) -> None:
        resp = self._mock_response({"value": [{"id": 100, "result": "failed"}]})
        with patch("daily_dashboard.core.ado_pipelines.requests.get", return_value=resp) as mock_get:
            build = self.pipelines.get_latest_build(
                definition_id=42,
                result_filter="failed",
                branch_name="checkmarx_v1",
            )

        self.assertEqual(build["id"], 100)
        self.assertEqual(mock_get.call_args.kwargs["params"]["resultFilter"], "failed")
        self.assertEqual(mock_get.call_args.kwargs["params"]["definitions"], 42)
        self.assertEqual(mock_get.call_args.kwargs["params"]["branchName"], "checkmarx_v1")

    def test_get_latest_build_returns_none_when_empty(self) -> None:
        resp = self._mock_response({"value": []})
        with patch("daily_dashboard.core.ado_pipelines.requests.get", return_value=resp):
            build = self.pipelines.get_latest_build(definition_id=42)
        self.assertIsNone(build)

    def test_get_latest_build_branch_fallback_filters_locally(self) -> None:
        filtered_empty = self._mock_response({"value": []})
        filtered_empty_ref = self._mock_response({"value": []})
        recent_builds = self._mock_response(
            {
                "value": [
                    {"id": 201, "sourceBranch": "refs/heads/main"},
                    {"id": 202, "sourceBranch": "checkmarx_v1"},
                ]
            }
        )
        with patch(
            "daily_dashboard.core.ado_pipelines.requests.get",
            side_effect=[filtered_empty, filtered_empty_ref, recent_builds],
        ) as mock_get:
            build = self.pipelines.get_latest_build(definition_id=42, branch_name="checkmarx_v1")

        self.assertIsNotNone(build)
        self.assertEqual(build["id"], 202)
        self.assertEqual(mock_get.call_count, 3)
        first_params = mock_get.call_args_list[0].kwargs["params"]
        second_params = mock_get.call_args_list[1].kwargs["params"]
        third_params = mock_get.call_args_list[2].kwargs["params"]
        self.assertEqual(first_params["branchName"], "checkmarx_v1")
        self.assertEqual(second_params["branchName"], "refs/heads/checkmarx_v1")
        self.assertTrue("branchName" not in third_params)

    def test_find_timeline_records_filters_by_name(self) -> None:
        resp = self._mock_response(
            {"records": [{"name": "Dependency Check", "log": {"id": 5}}, {"name": "Build", "log": {"id": 1}}]}
        )
        with patch("daily_dashboard.core.ado_pipelines.requests.get", return_value=resp):
            records = self.pipelines.find_timeline_records(100, name_contains="depend")

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["name"], "Dependency Check")

    def test_get_build_log_text(self) -> None:
        resp = self._mock_response(text_data="raw log content")
        with patch("daily_dashboard.core.ado_pipelines.requests.get", return_value=resp) as mock_get:
            text = self.pipelines.get_build_log_text(100, 5)

        self.assertEqual(text, "raw log content")
        called_url = mock_get.call_args.args[0]
        self.assertIn("/build/builds/100/logs/5", called_url)

    def test_get_task_log_text_returns_empty_without_log_id(self) -> None:
        text = self.pipelines.get_task_log_text(100, {"name": "no-log-task"})
        self.assertEqual(text, "")


if __name__ == "__main__":
    unittest.main()
