import unittest
from unittest.mock import MagicMock, patch

from daily_dashboard.core.ms_graph import MsGraphMail

MODULE = "daily_dashboard.core.ms_graph"


def _response(status_code=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text
    return resp


class TestMsGraphMail(unittest.TestCase):
    def test_get_token_is_cached_across_calls(self) -> None:
        graph = MsGraphMail("tenant", "client", "secret")
        with patch(f"{MODULE}.requests.post", return_value=_response(json_data={"access_token": "tok-1"})) as post:
            self.assertEqual(graph._get_token(), "tok-1")
            self.assertEqual(graph._get_token(), "tok-1")
        post.assert_called_once()

    def test_get_token_raises_on_error_response(self) -> None:
        graph = MsGraphMail("tenant", "client", "secret")
        with patch(f"{MODULE}.requests.post", return_value=_response(status_code=401, text="invalid_client")):
            with self.assertRaises(Exception):
                graph._get_token()

    def test_list_recent_messages_single_page(self) -> None:
        graph = MsGraphMail("tenant", "client", "secret")
        graph._token = "tok"
        page = {"value": [{"id": "m1"}, {"id": "m2"}]}
        with patch(f"{MODULE}.requests.get", return_value=_response(json_data=page)) as get:
            messages = graph.list_recent_messages("mailbox@example.com", since_iso="2026-09-12T00:00:00Z")

        self.assertEqual([m["id"] for m in messages], ["m1", "m2"])
        args, kwargs = get.call_args
        self.assertIn("mailbox%40example.com", args[0])
        self.assertIn("inbox", args[0])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer tok")
        self.assertIn("receivedDateTime ge 2026-09-12T00:00:00Z", kwargs["params"]["$filter"])

    def test_list_recent_messages_follows_next_link(self) -> None:
        graph = MsGraphMail("tenant", "client", "secret")
        graph._token = "tok"
        page1 = {"value": [{"id": "m1"}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/next-page"}
        page2 = {"value": [{"id": "m2"}]}
        with patch(f"{MODULE}.requests.get", side_effect=[_response(json_data=page1), _response(json_data=page2)]) as get:
            messages = graph.list_recent_messages("mailbox@example.com", since_iso="2026-09-12T00:00:00Z")

        self.assertEqual([m["id"] for m in messages], ["m1", "m2"])
        self.assertEqual(get.call_count, 2)
        second_call_args, second_call_kwargs = get.call_args_list[1]
        self.assertEqual(second_call_args[0], "https://graph.microsoft.com/v1.0/next-page")
        self.assertIsNone(second_call_kwargs["params"])

    def test_list_recent_messages_respects_max_messages(self) -> None:
        graph = MsGraphMail("tenant", "client", "secret")
        graph._token = "tok"
        page = {"value": [{"id": f"m{i}"} for i in range(10)]}
        with patch(f"{MODULE}.requests.get", return_value=_response(json_data=page)):
            messages = graph.list_recent_messages(
                "mailbox@example.com", since_iso="2026-09-12T00:00:00Z", max_messages=3
            )
        self.assertEqual(len(messages), 3)

    def test_list_recent_messages_raises_on_error_response(self) -> None:
        graph = MsGraphMail("tenant", "client", "secret")
        graph._token = "tok"
        with patch(f"{MODULE}.requests.get", return_value=_response(status_code=403, text="Forbidden")):
            with self.assertRaises(Exception):
                graph.list_recent_messages("mailbox@example.com", since_iso="2026-09-12T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
