"""Generic Azure OpenAI Chat Completions tool-calling loop.

Generalized from the pattern in yapl-upgrader's core/rewrite_runner.py
(`create_upgrade_assistant` / `run_assistant_session` / `poll_run_till_completion`),
which hardcodes one assistant's instructions/tools/functions for a Spring Boot
upgrade. Here the instructions, tool schemas, and function dispatch table are
all parameters, so both the dependency-fix and Checkmarx-fix remediation flows
can reuse the same loop with their own tool sets.

Uses chat.completions with tool-calling rather than the Assistants API, which
Azure/OpenAI have retired.
"""
from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional

from openai import AzureOpenAI


def build_client() -> AzureOpenAI:
    """Build an AzureOpenAI client from the same env vars as core/llm.py."""
    return AzureOpenAI(
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
        api_key=os.getenv("AZURE_OPENAI_API_KEY"),
        api_version=os.environ.get("AZURE_OPENAI_VERSION", "2024-05-01-preview"),
    )


class ToolCallingAgent:
    """Runs one chat-completions tool-calling session: seeds a system/user
    message pair and drives the tool_calls -> dispatch -> tool-result loop
    until the model returns a plain text reply (or hits max_steps)."""

    def __init__(
        self,
        *,
        client: Optional[AzureOpenAI] = None,
        deployment: Optional[str] = None,
        name: str,
        instructions: str,
        tools: List[Dict[str, Any]],
        available_functions: Dict[str, Callable[..., str]],
    ):
        self.client = client or build_client()
        self.deployment = deployment or os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-5")
        self.name = name
        self.instructions = instructions
        self.tools = tools
        self.available_functions = available_functions

    def _dispatch_tool_call(self, tool_call: Any) -> str:
        fn_name = tool_call.function.name
        args_json = tool_call.function.arguments
        if fn_name not in self.available_functions:
            return json.dumps({"error": f"Unknown function {fn_name}"})
        try:
            parsed_args = json.loads(args_json) if args_json else {}
        except Exception:
            parsed_args = {}
        fn = self.available_functions[fn_name]
        try:
            return fn(**parsed_args) if parsed_args else fn()
        except Exception as e:
            return json.dumps({"error": str(e)})

    def run(self, user_input: str, *, max_steps: int = 50, wait: int = 2) -> Dict[str, Any]:
        """Run one session end-to-end. Returns {"run": <final status>, "messages": [...]}."""
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": self.instructions},
            {"role": "user", "content": user_input},
        ]

        steps = 0
        status = "completed"
        while steps < max_steps:
            response = self.client.chat.completions.create(
                model=self.deployment,
                messages=messages,
                tools=self.tools,
                tool_choice="auto" if self.tools else "none",
            )
            assistant_msg = response.choices[0].message
            tool_calls = assistant_msg.tool_calls or []

            if not tool_calls:
                messages.append({"role": "assistant", "content": assistant_msg.content or ""})
                break

            messages.append(
                {
                    "role": "assistant",
                    "content": assistant_msg.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments or "{}",
                            },
                        }
                        for tc in tool_calls
                    ],
                }
            )

            for tool_call in tool_calls:
                tool_result = self._dispatch_tool_call(tool_call)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": tool_result,
                    }
                )

            steps += 1
        else:
            status = "max_steps_exceeded"

        simple_messages = [
            {"role": m["role"], "content": m["content"]}
            for m in messages
            if m["role"] in ("user", "assistant") and m.get("content")
        ]
        return {"run": {"status": status}, "messages": simple_messages}


def extract_last_json(messages: List[Dict[str, str]]) -> Optional[Dict[str, Any]]:
    """Best-effort: find the last assistant message and parse it as JSON."""
    for msg in reversed(messages):
        if msg.get("role") != "assistant":
            continue
        text = (msg.get("content") or "").strip()
        try:
            return json.loads(text)
        except Exception:
            if "{" in text and "}" in text:
                candidate = text[text.find("{"): text.rfind("}") + 1]
                try:
                    return json.loads(candidate)
                except Exception:
                    continue
    return None
