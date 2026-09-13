"""Turn Microsoft Graph mail messages into dashboard "announcements" entries.

Raw messages come from core/ms_graph.py. Each one is first mapped to an
Announcement with a bodyPreview-based fallback summary, then (optionally)
condensed to a 1-2 line summary by the Azure OpenAI chat model, reusing the
client-building convention from core/llm_agent.py. The LLM step is best-effort:
if it fails, the fallback summary set in parse_messages is kept.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from openai import AzureOpenAI

from ..core.llm_agent import build_client

_IMPORTANCE_TO_PRIORITY = {"high": "high", "normal": "normal", "low": "low"}


@dataclass
class Announcement:
    id: str
    subject: str
    sender: str
    received_at: Optional[str]
    priority: str
    is_read: bool
    link: Optional[str] = None
    summary: str = ""
    body_text: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "subject": self.subject,
            "from": self.sender,
            "receivedAt": self.received_at,
            "priority": self.priority,
            "summary": self.summary,
            "link": self.link,
        }


def _strip_html(html_text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html_text or "")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def parse_messages(messages: List[Dict[str, Any]]) -> List[Announcement]:
    """Map raw Graph message dicts into Announcement entries with a fallback
    (bodyPreview-derived) summary, unsummarized by the LLM yet."""
    announcements: List[Announcement] = []
    for msg in messages or []:
        email_address = ((msg.get("from") or {}).get("emailAddress") or {})
        sender = email_address.get("name") or email_address.get("address") or "Unknown"

        body = msg.get("body") or {}
        body_text = body.get("content") or ""
        if (body.get("contentType") or "").lower() == "html":
            body_text = _strip_html(body_text)
        if not body_text:
            body_text = msg.get("bodyPreview") or ""

        announcements.append(
            Announcement(
                id=msg.get("id") or "",
                subject=msg.get("subject") or "(no subject)",
                sender=sender,
                received_at=msg.get("receivedDateTime"),
                priority=_IMPORTANCE_TO_PRIORITY.get((msg.get("importance") or "normal").lower(), "normal"),
                is_read=bool(msg.get("isRead", True)),
                link=msg.get("webLink"),
                summary=(msg.get("bodyPreview") or "").strip()[:200],
                body_text=body_text[:4000],
                raw=msg,
            )
        )
    return [a for a in announcements if a.id]


_SUMMARY_INSTRUCTIONS = (
    "You summarize internal team emails for an engineering daily dashboard. "
    "For each email, write a 1-2 sentence summary capturing only the actionable "
    "or noteworthy information - skip greetings/signatures. "
    'Reply with ONLY a JSON array of strings, one per input item, in the same order, e.g. ["...", "..."].'
)


def summarize_announcements(
    announcements: List[Announcement],
    *,
    client: Optional[AzureOpenAI] = None,
    deployment: Optional[str] = None,
) -> List[Announcement]:
    """Best-effort: condense each announcement's body into a 1-2 line summary via
    the LLM. On any failure (auth, parsing, mismatched item count), the
    bodyPreview-based fallback summary from parse_messages is kept as-is."""
    if not announcements:
        return announcements

    client = client or build_client()
    deployment = deployment or os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-5")

    items = [
        {"index": i, "subject": a.subject, "body": a.body_text or a.summary}
        for i, a in enumerate(announcements)
    ]

    try:
        response = client.chat.completions.create(
            model=deployment,
            messages=[
                {"role": "system", "content": _SUMMARY_INSTRUCTIONS},
                {"role": "user", "content": json.dumps(items)},
            ],
        )
        content = (response.choices[0].message.content or "").strip()
        if "[" in content and "]" in content:
            content = content[content.find("[") : content.rfind("]") + 1]
        summaries = json.loads(content)
        if isinstance(summaries, list) and len(summaries) == len(announcements):
            for announcement, summary in zip(announcements, summaries):
                if isinstance(summary, str) and summary.strip():
                    announcement.summary = summary.strip()
    except Exception:
        pass

    return announcements
