import unittest
from unittest.mock import patch

from daily_dashboard.scanners.checkmarx_investigator import investigate_checkmarx_task_logs


class TestCheckmarxInvestigator(unittest.TestCase):
    @patch("daily_dashboard.scanners.checkmarx_investigator.ToolCallingAgent.run")
    def test_returns_normalized_findings_from_llm_json(self, mock_run) -> None:
        mock_run.return_value = {
            "messages": [
                {
                    "role": "assistant",
                    "content": (
                        '{"scanId":"922f5390-5083-4b80-b6cf-6057622a3ac6",'
                        '"findings":[{"queryName":"Open*Redirect","severity":"MEDIUM",'
                        '"file":"/src/main/java/Foo.java","line":42,"cwe":601,"cvss":6.6}]}'
                    ),
                }
            ]
        }
        result = investigate_checkmarx_task_logs("log text")
        self.assertEqual(result["scanId"], "922f5390-5083-4b80-b6cf-6057622a3ac6")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0].rule, "Open*Redirect")
        self.assertEqual(result["findings"][0].line, 42)

    @patch("daily_dashboard.scanners.checkmarx_investigator.fetch_checkmarx_sast_results")
    @patch("daily_dashboard.scanners.checkmarx_investigator.ToolCallingAgent.run")
    def test_fallback_when_llm_output_invalid(self, mock_run, mock_fetch) -> None:
        mock_run.return_value = {"messages": [{"role": "assistant", "content": "not json"}]}
        mock_fetch.return_value = (
            '{"scanId":"922f5390-5083-4b80-b6cf-6057622a3ac6",'
            '"findings":[{"queryName":"Open*Redirect","severity":"MEDIUM",'
            '"file":"/src/main/java/Foo.java","line":42}],"totalCount":1}'
        )
        log_text = (
            "Checkmarx One - Scan Summary & Details: "
            "https://eu-2.ast.checkmarx.net/projects/abc/scans?id="
            "922f5390-5083-4b80-b6cf-6057622a3ac6&branch=main"
        )
        result = investigate_checkmarx_task_logs(log_text)
        self.assertEqual(result["scanId"], "922f5390-5083-4b80-b6cf-6057622a3ac6")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0].rule, "Open*Redirect")


if __name__ == "__main__":
    unittest.main()
