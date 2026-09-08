import json
import unittest
from unittest.mock import MagicMock

from daily_dashboard.core.llm_agent import ToolCallingAgent, extract_last_json


def _make_tool_call(call_id: str, name: str, arguments: dict):
    call = MagicMock()
    call.id = call_id
    call.function.name = name
    call.function.arguments = json.dumps(arguments)
    return call


def _make_completion(*, content=None, tool_calls=None):
    message = MagicMock()
    message.content = content
    message.tool_calls = tool_calls or []
    completion = MagicMock()
    completion.choices = [MagicMock(message=message)]
    return completion


class TestToolCallingAgent(unittest.TestCase):
    def test_run_dispatches_tool_call_and_returns_final_message(self) -> None:
        client = MagicMock()

        tool_call_completion = _make_completion(
            content=None,
            tool_calls=[_make_tool_call("call_1", "echo", {"value": "hi"})],
        )
        final_completion = _make_completion(content=json.dumps({"result": "ok"}))
        client.chat.completions.create.side_effect = [tool_call_completion, final_completion]

        echoed = {}

        def echo(value: str) -> str:
            echoed["value"] = value
            return json.dumps({"echoed": value})

        agent = ToolCallingAgent(
            client=client,
            deployment="gpt-5",
            name="test-assistant",
            instructions="test",
            tools=[{"type": "function", "function": {"name": "echo", "parameters": {}}}],
            available_functions={"echo": echo},
        )

        result = agent.run("do the thing", wait=0)

        self.assertEqual(echoed["value"], "hi")
        first_call_kwargs = client.chat.completions.create.call_args_list[0].kwargs
        self.assertEqual(first_call_kwargs["tool_choice"], "auto")

        second_call_kwargs = client.chat.completions.create.call_args_list[1].kwargs
        tool_messages = [m for m in second_call_kwargs["messages"] if m["role"] == "tool"]
        self.assertEqual(tool_messages[0]["tool_call_id"], "call_1")
        self.assertEqual(json.loads(tool_messages[0]["content"]), {"echoed": "hi"})

        self.assertEqual(result["run"], {"status": "completed"})
        self.assertEqual(result["messages"][-1]["content"], json.dumps({"result": "ok"}))

    def test_unknown_function_reports_error_without_raising(self) -> None:
        client = MagicMock()

        tool_call_completion = _make_completion(
            content=None,
            tool_calls=[_make_tool_call("call_1", "does_not_exist", {})],
        )
        final_completion = _make_completion(content="")
        client.chat.completions.create.side_effect = [tool_call_completion, final_completion]

        agent = ToolCallingAgent(
            client=client,
            deployment="gpt-5",
            name="test-assistant",
            instructions="test",
            tools=[],
            available_functions={},
        )

        agent.run("do the thing", wait=0)

        second_call_kwargs = client.chat.completions.create.call_args_list[1].kwargs
        tool_messages = [m for m in second_call_kwargs["messages"] if m["role"] == "tool"]
        self.assertIn("error", json.loads(tool_messages[0]["content"]))


class TestExtractLastJson(unittest.TestCase):
    def test_extracts_clean_json(self) -> None:
        messages = [{"role": "assistant", "content": '{"a": 1}'}]
        self.assertEqual(extract_last_json(messages), {"a": 1})

    def test_extracts_json_embedded_in_prose(self) -> None:
        messages = [{"role": "assistant", "content": 'Sure, here it is: {"a": 1} thanks'}]
        self.assertEqual(extract_last_json(messages), {"a": 1})

    def test_returns_none_when_no_assistant_message(self) -> None:
        messages = [{"role": "user", "content": "hello"}]
        self.assertIsNone(extract_last_json(messages))


if __name__ == "__main__":
    unittest.main()
