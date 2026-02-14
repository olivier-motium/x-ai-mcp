"""Cookie-based HTTP client for X's internal API (v1.1 + GraphQL).

Uses session cookies (auth_token + ct0) with X's public bearer token
to access internal endpoints like DM inbox, conversations, and the
key registry for E2E encrypted messages.

Pattern adapted from oracular-spectacular's cookie_extractor.py + graphql_client.py.
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from . import config

# Public bearer token — same for ALL X web clients, embedded in x.com JS bundles.
# This is NOT a secret; it identifies requests as coming from the official web client.
PUBLIC_BEARER = (
    "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs"
    "%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
)

DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:142.0) "
    "Gecko/20100101 Firefox/142.0"
)


class CookieClientError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        super().__init__(f"X internal API {status}: {detail}")


class CookieClient:
    """Async HTTP client using session cookies for X's internal API.

    Requires X_AUTH_TOKEN and X_CT0 environment variables (extracted from
    a logged-in browser session on x.com).
    """

    def __init__(self) -> None:
        self._auth_token = config.X_AUTH_TOKEN
        self._ct0 = config.X_CT0
        self._client: httpx.AsyncClient | None = None

    @property
    def available(self) -> bool:
        return bool(self._auth_token and self._ct0)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        return self._client

    def _headers(self) -> dict[str, str]:
        return {
            "authorization": PUBLIC_BEARER,
            "x-csrf-token": self._ct0,
            "x-twitter-auth-type": "OAuth2Session",
            "x-twitter-active-user": "yes",
            "x-twitter-client-language": "en",
            "accept": "application/json",
            "accept-language": "en-US,en;q=0.5",
            "user-agent": DEFAULT_UA,
            "origin": "https://x.com",
            "referer": "https://x.com/messages",
            "cookie": f"auth_token={self._auth_token}; ct0={self._ct0}",
        }

    async def _request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        client = await self._get_client()
        resp = await client.request(
            method, url, params=params, json=json_body, headers=self._headers()
        )

        # Handle ct0 rotation from Set-Cookie headers
        for cookie_name, cookie_value in resp.cookies.items():
            if cookie_name == "ct0":
                self._ct0 = cookie_value

        if resp.status_code == 429:
            reset = resp.headers.get("x-rate-limit-reset")
            wait = max(int(reset) - int(time.time()), 1) if reset else 5
            import asyncio

            await asyncio.sleep(wait + 0.5)
            # Retry once
            resp = await client.request(
                method, url, params=params, json=json_body, headers=self._headers()
            )

        if resp.status_code >= 400:
            raise CookieClientError(resp.status_code, resp.text[:500])

        return resp.json()

    # ── DM REST API v1.1 ──

    async def inbox_initial_state(self, cursor: str | None = None) -> dict:
        """Fetch DM inbox initial state — all conversations with metadata."""
        url = "https://x.com/i/api/1.1/dm/inbox_initial_state.json"
        params: dict[str, Any] = {
            "nsfw_filtering_enabled": "false",
            "filter_low_quality": "false",
            "include_quality": "all",
            "include_profile_interstitial_type": "1",
            "include_blocking": "1",
            "include_blocked_by": "1",
            "include_followed_by": "1",
            "include_want_retweets": "1",
            "include_mute_edge": "1",
            "include_can_dm": "1",
            "include_ext_is_blue_verified": "1",
            "dm_secret_conversations_enabled": "true",
            "krs_registration_enabled": "true",
            "cards_platform": "Web-12",
            "include_cards": "1",
            "include_ext_media_color": "true",
            "include_ext_media_availability": "true",
            "include_ext_sensitive_media_warning": "true",
            "ext": "mediaColor,altText,mediaStats,highlightedLabel,voiceInfo",
        }
        if cursor:
            params["cursor"] = cursor
        return await self._request("GET", url, params=params)

    async def conversation(
        self, conversation_id: str, max_id: str | None = None
    ) -> dict:
        """Fetch messages from a specific DM conversation."""
        url = f"https://x.com/i/api/1.1/dm/conversation/{conversation_id}.json"
        params: dict[str, Any] = {
            "include_profile_interstitial_type": "1",
            "include_blocking": "1",
            "include_blocked_by": "1",
            "include_followed_by": "1",
            "include_want_retweets": "1",
            "include_mute_edge": "1",
            "include_can_dm": "1",
            "include_ext_is_blue_verified": "1",
            "dm_secret_conversations_enabled": "true",
            "krs_registration_enabled": "true",
            "cards_platform": "Web-12",
            "include_cards": "1",
            "ext": "mediaColor,altText,mediaStats,highlightedLabel,voiceInfo",
        }
        if max_id:
            params["max_id"] = max_id
        return await self._request("GET", url, params=params)

    async def send_message(
        self, conversation_id: str, text: str
    ) -> dict:
        """Send a DM via the v1.1 API."""
        url = "https://x.com/i/api/1.1/dm/new2.json"
        body = {
            "conversation_id": conversation_id,
            "recipient_ids": "false",
            "request_id": f"req_{int(time.time() * 1000)}",
            "text": text,
            "cards_platform": "Web-12",
            "include_cards": 1,
            "include_quote_count": True,
            "dm_users": "false",
        }
        return await self._request("POST", url, json_body=body)

    # ── Key Registry API (requires X Premium) ──

    async def extract_public_keys(self, user_id: str) -> dict:
        """Fetch registered E2E device public keys for a user.

        Endpoint: GET keyregistry/extract_public_keys/{userId}
        Returns: {public_keys: [{identity_key, device_id, ...}]}
        Requires X Premium (returns 403 without it).
        """
        url = f"https://x.com/i/api/1.1/keyregistry/extract_public_keys/{user_id}"
        return await self._request("GET", url)

    async def register_device_key(
        self, device_id: str, registration_body: dict
    ) -> dict:
        """Register a device public key with X's key registry.

        Endpoint: POST keyregistry/register
        Body: {registration_id: int, identity_key: base64_spki}
        Header: X-Client-UUID: device_id
        Requires X Premium (returns 403 without it).
        """
        url = "https://x.com/i/api/1.1/keyregistry/register"
        client = await self._get_client()
        headers = self._headers()
        headers["X-Client-UUID"] = device_id
        resp = await client.post(url, json=registration_body, headers=headers)

        # Handle ct0 rotation
        for cookie_name, cookie_value in resp.cookies.items():
            if cookie_name == "ct0":
                self._ct0 = cookie_value

        if resp.status_code == 403:
            raise CookieClientError(
                403,
                "Key registry requires X Premium (Blue Verified). "
                "Error 403: Not authorized to use this endpoint.",
            )
        if resp.status_code >= 400:
            raise CookieClientError(resp.status_code, resp.text[:500])

        return resp.json()

    # ── Conversation Helpers ──

    async def get_all_conversations(self) -> list[dict]:
        """Paginate through all DM conversations."""
        all_conversations = []
        cursor = None
        seen_cursors: set[str] = set()

        while True:
            data = await self.inbox_initial_state(cursor)
            inbox = data.get("inbox_initial_state", {})

            conversations = inbox.get("conversations", {})
            all_conversations.extend(conversations.values())

            # Check pagination
            trusted = inbox.get("inbox_timelines", {}).get("trusted", {})
            status = trusted.get("status")
            if status == "AT_END":
                break

            new_cursor = trusted.get("min_entry_id")
            if not new_cursor or new_cursor in seen_cursors:
                break

            seen_cursors.add(new_cursor)
            cursor = new_cursor

        return all_conversations

    async def get_conversation_messages(
        self, conversation_id: str, limit: int = 100
    ) -> tuple[list[dict], dict[str, dict]]:
        """Get all messages from a conversation, paginating as needed.

        Returns (messages, users_dict).
        """
        all_messages = []
        users: dict[str, dict] = {}
        max_id = None
        seen_ids: set[str] = set()

        while len(all_messages) < limit:
            data = await self.conversation(conversation_id, max_id)
            timeline = data.get("conversation_timeline", {})

            # Collect users
            for uid, udata in data.get("users", {}).items():
                users[uid] = udata

            entries = timeline.get("entries", [])
            for entry in entries:
                msg = entry.get("message")
                if msg:
                    msg_data = msg.get("message_data", {})
                    msg_id = msg.get("id") or msg_data.get("id")
                    if msg_id and msg_id not in seen_ids:
                        seen_ids.add(msg_id)
                        all_messages.append(msg)

            # Pagination
            status = timeline.get("status")
            if status == "AT_END":
                break
            new_min = timeline.get("min_entry_id")
            if not new_min or new_min == max_id:
                break
            max_id = new_min

        return all_messages, users

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
