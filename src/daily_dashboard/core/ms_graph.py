"""Microsoft Graph mail reader for the dashboard's "announcements" section.

Uses the OAuth2 client-credentials flow (app-only Graph permission Mail.Read
for the target mailbox) - the same token-then-REST-call shape as
core/ado_pipelines.py, but with a bearer token instead of a PAT.

Reference: https://learn.microsoft.com/en-us/graph/api/user-list-messages
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

_MESSAGE_FIELDS = "id,subject,from,receivedDateTime,bodyPreview,body,importance,isRead,webLink"


class MsGraphMail:
    """Read-only helper for listing recent messages in a mailbox folder."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None

    def _get_token(self) -> str:
        if self._token:
            return self._token
        resp = requests.post(
            _TOKEN_URL.format(tenant_id=self.tenant_id),
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=30,
        )
        if resp.status_code >= 400:
            raise requests.HTTPError(f"{resp.status_code} Error acquiring Graph token\nResponse={resp.text}")
        self._token = resp.json()["access_token"]
        return self._token

    def list_recent_messages(
        self,
        mailbox: str,
        *,
        since_iso: str,
        folder: str = "inbox",
        top: int = 50,
        max_messages: int = 200,
    ) -> List[Dict[str, Any]]:
        """Return messages received at/after since_iso (UTC ISO 8601 datetime), newest first."""
        url = f"{GRAPH_BASE_URL}/users/{quote(mailbox)}/mailFolders/{quote(folder)}/messages"
        params: Optional[Dict[str, Any]] = {
            "$filter": f"receivedDateTime ge {since_iso}",
            "$orderby": "receivedDateTime desc",
            "$top": str(min(top, max_messages)),
            "$select": _MESSAGE_FIELDS,
        }
        headers = {"Authorization": f"Bearer {self._get_token()}"}

        messages: List[Dict[str, Any]] = []
        while url and len(messages) < max_messages:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code >= 400:
                raise requests.HTTPError(f"{resp.status_code} Error calling {url}\nResponse={resp.text}")
            data = resp.json()
            messages.extend(data.get("value") or [])
            url = data.get("@odata.nextLink")
            params = None  # nextLink already carries the query string
        return messages[:max_messages]
