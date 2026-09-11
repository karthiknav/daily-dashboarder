import json
import unittest
from unittest.mock import patch

from daily_dashboard.scanners.checkmarx_tools.extract_scan_id_tool import extract_scan_id_from_logs
from daily_dashboard.scanners.checkmarx_tools.fetch_sast_results_tool import fetch_checkmarx_sast_results


class TestExtractScanIdTool(unittest.TestCase):
    def test_extract_scan_id_from_checkmarx_summary_url(self) -> None:
        log_text = (
            "Checkmarx One - Scan Summary & Details: "
            "https://eu-2.ast.checkmarx.net/projects/abc/scans?id="
            "922f5390-5083-4b80-b6cf-6057622a3ac6&branch=main"
        )
        payload = json.loads(extract_scan_id_from_logs(log_text))
        self.assertTrue(payload["found"])
        self.assertEqual(payload["scanId"], "922f5390-5083-4b80-b6cf-6057622a3ac6")

    def test_extract_scan_id_not_found(self) -> None:
        payload = json.loads(extract_scan_id_from_logs("no checkmarx url here"))
        self.assertFalse(payload["found"])
        self.assertIsNone(payload["scanId"])


class TestFetchSastResultsTool(unittest.TestCase):
    @patch("daily_dashboard.scanners.checkmarx_tools.fetch_sast_results_tool._call_checkmarx_sast_results")
    def test_uses_mock_when_api_errors(self, mock_call) -> None:
        mock_call.side_effect = RuntimeError("boom")
        payload = json.loads(fetch_checkmarx_sast_results("922f5390-5083-4b80-b6cf-6057622a3ac6"))
        self.assertTrue(payload["usedMockResponse"])
        self.assertIn("apiError", payload)
        self.assertEqual(payload["scanId"], "922f5390-5083-4b80-b6cf-6057622a3ac6")
        self.assertEqual(payload["totalCount"], 1)
        self.assertEqual(payload["findings"][0]["queryName"], "Open*Redirect")


if __name__ == "__main__":
    unittest.main()
