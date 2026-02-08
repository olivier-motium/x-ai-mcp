"""xAI Grok API client for intelligence tools."""

from __future__ import annotations

from typing import Any

import httpx

from . import config


class GrokClient:
    """Async xAI Grok API client — OpenAI-compatible + Responses API."""

    def __init__(self) -> None:
        self._api_key = config.XAI_API_KEY
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=120.0)
        return self._client

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    async def chat(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.3,
        max_tokens: int = 4096,
    ) -> str:
        """Standard chat completion (OpenAI-compatible)."""
        client = await self._get_client()
        resp = await client.post(
            f"{config.XAI_API_BASE}/chat/completions",
            headers=self._headers(),
            json={
                "model": model or config.XAI_MODEL,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    async def x_search(
        self,
        query: str,
        model: str | None = None,
        max_sources: int = 10,
    ) -> dict[str, Any]:
        """Grok Responses API with x_search tool — real-time X data access."""
        client = await self._get_client()
        resp = await client.post(
            f"{config.XAI_API_BASE}/responses",
            headers=self._headers(),
            json={
                "model": model or config.XAI_MODEL,
                "tools": [{"type": "x_search"}],
                "input": query,
                "temperature": 0.3,
            },
        )
        resp.raise_for_status()
        return resp.json()

    async def analyze_tweets(self, tweets_text: str, instruction: str) -> str:
        """Send tweet data to Grok for analysis."""
        return await self.chat([
            {
                "role": "system",
                "content": (
                    "You are an expert X/Twitter analyst. Analyze the provided tweets "
                    "and deliver concise, actionable insights. Be specific with data — "
                    "cite usernames, engagement numbers, and exact quotes when relevant. "
                    "Focus on what matters, skip noise."
                ),
            },
            {
                "role": "user",
                "content": f"{instruction}\n\n---\n\nTWEET DATA:\n{tweets_text}",
            },
        ])

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
