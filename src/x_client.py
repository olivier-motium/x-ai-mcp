"""X API v2 REST client with bearer token auth and rate limit handling."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from . import config


class XAPIError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        super().__init__(f"X API {status}: {detail}")


class XClient:
    """Async X API v2 client with automatic rate limit handling."""

    def __init__(self) -> None:
        self._bearer = config.X_BEARER_TOKEN
        self._oauth_tokens: dict[str, str] | None = None
        self._client: httpx.AsyncClient | None = None
        self._load_oauth_tokens()

    def _load_oauth_tokens(self) -> None:
        """Load OAuth tokens from disk."""
        if config.X_TOKEN_PATH.exists():
            try:
                self._oauth_tokens = json.loads(config.X_TOKEN_PATH.read_text())
            except (json.JSONDecodeError, OSError):
                pass

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    def _headers(self, use_oauth: bool = False) -> dict[str, str]:
        if use_oauth:
            # Reload tokens from disk if not yet loaded (supports late token arrival)
            if not self._oauth_tokens:
                self._load_oauth_tokens()
            if self._oauth_tokens:
                token = self._oauth_tokens.get("access_token", "")
                return {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
        return {
            "Authorization": f"Bearer {self._bearer}",
            "Content-Type": "application/json",
        }

    async def _refresh_oauth(self) -> bool:
        """Refresh OAuth 2.0 token using refresh_token."""
        if not self._oauth_tokens or not config.X_CLIENT_ID:
            return False

        refresh_token = self._oauth_tokens.get("refresh_token")
        if not refresh_token:
            return False

        client = await self._get_client()
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": config.X_CLIENT_ID,
        }
        auth = None
        if config.X_CLIENT_SECRET:
            auth = (config.X_CLIENT_ID, config.X_CLIENT_SECRET)
        else:
            data["client_id"] = config.X_CLIENT_ID

        try:
            resp = await client.post(
                "https://api.x.com/2/oauth2/token",
                data=data,
                auth=auth,
            )
            if resp.status_code == 200:
                new_tokens = resp.json()
                self._oauth_tokens.update(new_tokens)
                config.X_TOKEN_PATH.write_text(json.dumps(self._oauth_tokens, indent=2))
                return True
        except httpx.HTTPError:
            pass
        return False

    async def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        use_oauth: bool = False,
    ) -> dict[str, Any]:
        """Make an X API request with rate limit retry."""
        client = await self._get_client()
        url = f"{config.X_API_BASE}{path}"

        for attempt in range(3):
            resp = await client.request(
                method,
                url,
                params=params,
                json=json_body,
                headers=self._headers(use_oauth),
            )

            # Rate limited
            if resp.status_code == 429:
                reset = resp.headers.get("x-rate-limit-reset")
                if reset:
                    wait = max(int(reset) - int(time.time()), 1)
                else:
                    wait = 2 ** attempt
                import sys
                print(f"Rate limited, waiting {wait}s...", file=sys.stderr)
                import asyncio
                await asyncio.sleep(wait + 0.5)
                continue

            # OAuth token expired — refresh and retry
            if resp.status_code == 401 and use_oauth and attempt == 0:
                refreshed = await self._refresh_oauth()
                if refreshed:
                    continue

            if resp.status_code >= 400:
                try:
                    detail = resp.json()
                except Exception:
                    detail = resp.text
                raise XAPIError(resp.status_code, str(detail))

            if resp.status_code == 204:
                return {}

            return resp.json()

        raise XAPIError(429, "Rate limited after 3 retries")

    # ── Convenience Methods ──

    async def get_me(self) -> dict:
        return await self.request(
            "GET", "/users/me",
            params={"user.fields": config.USER_FIELDS},
        )

    async def get_user(self, user_id: str) -> dict:
        return await self.request(
            "GET", f"/users/{user_id}",
            params={"user.fields": config.USER_FIELDS},
        )

    async def get_user_by_username(self, username: str) -> dict:
        return await self.request(
            "GET", f"/users/by/username/{username}",
            params={"user.fields": config.USER_FIELDS},
        )

    async def home_timeline(self, max_results: int = 20, pagination_token: str | None = None) -> dict:
        params: dict[str, Any] = {
            "max_results": max_results,
            "tweet.fields": config.TWEET_FIELDS,
            "user.fields": config.USER_FIELDS,
            "expansions": config.EXPANSIONS,
        }
        if pagination_token:
            params["pagination_token"] = pagination_token
        return await self.request(
            "GET",
            f"/users/{config.X_USER_ID}/timelines/reverse_chronological",
            params=params,
            use_oauth=True,
        )

    async def user_tweets(self, user_id: str, max_results: int = 20) -> dict:
        return await self.request(
            "GET", f"/users/{user_id}/tweets",
            params={
                "max_results": max_results,
                "tweet.fields": config.TWEET_FIELDS,
                "expansions": config.EXPANSIONS,
                "user.fields": config.USER_FIELDS,
            },
        )

    async def get_tweet(self, tweet_id: str) -> dict:
        return await self.request(
            "GET", f"/tweets/{tweet_id}",
            params={
                "tweet.fields": config.TWEET_FIELDS,
                "expansions": config.EXPANSIONS,
                "user.fields": config.USER_FIELDS,
            },
        )

    async def post_tweet(self, text: str, reply_to: str | None = None) -> dict:
        body: dict[str, Any] = {"text": text}
        if reply_to:
            body["reply"] = {"in_reply_to_tweet_id": reply_to}
        return await self.request("POST", "/tweets", json_body=body, use_oauth=True)

    async def delete_tweet(self, tweet_id: str) -> dict:
        return await self.request("DELETE", f"/tweets/{tweet_id}", use_oauth=True)

    async def search_recent(self, query: str, max_results: int = 20) -> dict:
        return await self.request(
            "GET", "/tweets/search/recent",
            params={
                "query": query,
                "max_results": max_results,
                "tweet.fields": config.TWEET_FIELDS,
                "expansions": config.EXPANSIONS,
                "user.fields": config.USER_FIELDS,
            },
        )

    async def get_bookmarks(self, max_results: int = 20) -> dict:
        return await self.request(
            "GET", f"/users/{config.X_USER_ID}/bookmarks",
            params={
                "max_results": max_results,
                "tweet.fields": config.TWEET_FIELDS,
                "expansions": config.EXPANSIONS,
                "user.fields": config.USER_FIELDS,
            },
            use_oauth=True,
        )

    async def get_liked_tweets(self, user_id: str | None = None, max_results: int = 20) -> dict:
        uid = user_id or config.X_USER_ID
        return await self.request(
            "GET", f"/users/{uid}/liked_tweets",
            params={
                "max_results": max_results,
                "tweet.fields": config.TWEET_FIELDS,
            },
        )

    async def like_tweet(self, tweet_id: str) -> dict:
        return await self.request(
            "POST", f"/users/{config.X_USER_ID}/likes",
            json_body={"tweet_id": tweet_id},
            use_oauth=True,
        )

    async def get_followers(self, user_id: str | None = None, max_results: int = 50) -> dict:
        uid = user_id or config.X_USER_ID
        return await self.request(
            "GET", f"/users/{uid}/followers",
            params={"max_results": max_results, "user.fields": config.USER_FIELDS},
        )

    async def get_following(self, user_id: str | None = None, max_results: int = 50) -> dict:
        uid = user_id or config.X_USER_ID
        return await self.request(
            "GET", f"/users/{uid}/following",
            params={"max_results": max_results, "user.fields": config.USER_FIELDS},
        )

    async def get_dm_events(self, max_results: int = 20) -> dict:
        return await self.request(
            "GET", "/dm_events",
            params={
                "max_results": max_results,
                "dm_event.fields": "id,text,created_at,sender_id,dm_conversation_id,attachments",
                "event_types": "MessageCreate",
                "expansions": "sender_id",
                "user.fields": config.USER_FIELDS,
            },
            use_oauth=True,
        )

    async def get_dm_conversation(self, conversation_id: str, max_results: int = 20) -> dict:
        return await self.request(
            "GET", f"/dm_conversations/{conversation_id}/dm_events",
            params={
                "max_results": max_results,
                "dm_event.fields": "id,text,created_at,sender_id,attachments",
                "event_types": "MessageCreate",
            },
            use_oauth=True,
        )

    async def send_dm(self, participant_id: str, text: str) -> dict:
        return await self.request(
            "POST", f"/dm_conversations/with/{participant_id}/messages",
            json_body={"text": text},
            use_oauth=True,
        )

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
