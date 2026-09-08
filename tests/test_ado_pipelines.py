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
            build = self.pipelines.get_latest_build(definition_id=42, result_filter="failed")

        self.assertEqual(build["id"], 100)
        self.assertEqual(mock_get.call_args.kwargs["params"]["resultFilter"], "failed")
        self.assertEqual(mock_get.call_args.kwargs["params"]["definitions"], 42)

    def test_get_latest_build_returns_none_when_empty(self) -> None:
        resp = self._mock_response({"value": []})
        with patch("daily_dashboard.core.ado_pipelines.requests.get", return_value=resp):
            build = self.pipelines.get_latest_build(definition_id=42)
        self.assertIsNone(build)

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
