import json
import unittest
from unittest.mock import MagicMock

from daily_dashboard.scanners.announcement_scanner import parse_messages, summarize_announcements


def _graph_message(**overrides) -> dict:
    defaults = {
        "id": "msg-1",
        "subject": "Security Patch Deployment on Sep 25",
        "from": {"emailAddress": {"name": "Security Team", "address": "security@example.com"}},
        "receivedDateTime": "2026-09-13T06:00:00Z",
        "bodyPreview": "All services will receive the quarterly patch next Friday.",
        "body": {"contentType": "html", "content": "<p>All services will receive the <b>quarterly patch</b>.</p>"},
        "importance": "high",
        "isRead": False,
        "webLink": "https://outlook.office.com/mail/msg-1",
    }
    defaults.update(overrides)
    return defaults


class TestParseMessages(unittest.TestCase):
    def test_maps_graph_fields_and_strips_html_body(self) -> None:
        [announcement] = parse_messages([_graph_message()])
        self.assertEqual(announcement.id, "msg-1")
        self.assertEqual(announcement.subject, "Security Patch Deployment on Sep 25")
        self.assertEqual(announcement.sender, "Security Team")
        self.assertEqual(announcement.received_at, "2026-09-13T06:00:00Z")
        self.assertEqual(announcement.priority, "high")
        self.assertFalse(announcement.is_read)
        self.assertEqual(announcement.link, "https://outlook.office.com/mail/msg-1")
        self.assertIn("quarterly patch", announcement.body_text)
        self.assertNotIn("<b>", announcement.body_text)
        # Fallback summary (before LLM summarization) comes from bodyPreview.
        self.assertIn("quarterly patch", announcement.summary)

    def test_falls_back_to_sender_address_when_no_display_name(self) -> None:
        msg = _graph_message(**{"from": {"emailAddress": {"address": "ops@example.com"}}})
        [announcement] = parse_messages([msg])
        self.assertEqual(announcement.sender, "ops@example.com")

    def test_unknown_importance_defaults_to_normal_priority(self) -> None:
        [announcement] = parse_messages([_graph_message(importance="other")])
        self.assertEqual(announcement.priority, "normal")

    def test_skips_messages_without_id(self) -> None:
        self.assertEqual(parse_messages([_graph_message(id="")]), [])

    def test_empty_input(self) -> None:
        self.assertEqual(parse_messages([]), [])
        self.assertEqual(parse_messages(None), [])

    def test_to_dict_matches_dashboard_shape(self) -> None:
        [announcement] = parse_messages([_graph_message()])
        self.assertEqual(
            set(announcement.to_dict().keys()),
            {"id", "subject", "from", "receivedAt", "priority", "summary", "link"},
        )


class TestSummarizeAnnouncements(unittest.TestCase):
    def _client_returning(self, content: str) -> MagicMock:
        client = MagicMock()
        response = MagicMock()
        response.choices = [MagicMock(message=MagicMock(content=content))]
        client.chat.completions.create.return_value = response
        return client

    def test_applies_llm_summary_per_item_in_order(self) -> None:
        announcements = parse_messages(
            [_graph_message(id="a1"), _graph_message(id="a2", subject="Release Freeze this Friday")]
        )
        client = self._client_returning(json.dumps(["Patch rollout on all services Sep 25.", "No releases Friday."]))

        result = summarize_announcements(announcements, client=client, deployment="gpt-5")

        self.assertEqual(result[0].summary, "Patch rollout on all services Sep 25.")
        self.assertEqual(result[1].summary, "No releases Friday.")
        client.chat.completions.create.assert_called_once()

    def test_keeps_fallback_summary_when_llm_response_is_not_valid_json(self) -> None:
        [announcement] = parse_messages([_graph_message()])
        original_summary = announcement.summary
        client = self._client_returning("not json")

        [result] = summarize_announcements([announcement], client=client, deployment="gpt-5")

        self.assertEqual(result.summary, original_summary)

    def test_keeps_fallback_summary_when_item_count_mismatches(self) -> None:
        announcements = parse_messages([_graph_message(id="a1"), _graph_message(id="a2")])
        original_summaries = [a.summary for a in announcements]
        client = self._client_returning(json.dumps(["only one summary"]))

        result = summarize_announcements(announcements, client=client, deployment="gpt-5")

        self.assertEqual([a.summary for a in result], original_summaries)

    def test_keeps_fallback_summary_when_client_raises(self) -> None:
        [announcement] = parse_messages([_graph_message()])
        original_summary = announcement.summary
        client = MagicMock()
        client.chat.completions.create.side_effect = Exception("boom")

        [result] = summarize_announcements([announcement], client=client, deployment="gpt-5")

        self.assertEqual(result.summary, original_summary)

    def test_empty_input_returns_empty_without_building_client(self) -> None:
        self.assertEqual(summarize_announcements([]), [])


if __name__ == "__main__":
    unittest.main()
