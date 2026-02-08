"""Format X API responses as clean text for MCP tool output."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _ts(iso: str) -> str:
    """Format ISO timestamp compactly."""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("[%Y-%m-%d %H:%M]")
    except (ValueError, AttributeError):
        return "[unknown]"


def _metrics(m: dict | None) -> str:
    """Format public metrics inline."""
    if not m:
        return ""
    parts = []
    if m.get("reply_count"):
        parts.append(f"{m['reply_count']} replies")
    if m.get("retweet_count"):
        parts.append(f"{m['retweet_count']} RTs")
    if m.get("like_count"):
        parts.append(f"{m['like_count']} likes")
    if m.get("quote_count"):
        parts.append(f"{m['quote_count']} quotes")
    if m.get("impression_count"):
        parts.append(f"{m['impression_count']} views")
    return f" ({', '.join(parts)})" if parts else ""


def _resolve_author(tweet: dict, includes: dict | None) -> str:
    """Resolve author_id to @username from includes."""
    author_id = tweet.get("author_id")
    if includes and "users" in includes:
        for u in includes["users"]:
            if u.get("id") == author_id:
                return f"@{u['username']}"
    return f"user:{author_id}" if author_id else "@unknown"


def format_tweet(tweet: dict, includes: dict | None = None) -> str:
    """Format a single tweet as one-line text."""
    ts = _ts(tweet.get("created_at", ""))
    author = _resolve_author(tweet, includes)
    text = tweet.get("text", "").replace("\n", " ").strip()
    if len(text) > 500:
        text = text[:500] + "..."
    metrics = _metrics(tweet.get("public_metrics"))
    tid = tweet.get("id", "?")

    # Detect retweet / quote
    refs = tweet.get("referenced_tweets", [])
    prefix = ""
    for ref in refs:
        if ref.get("type") == "retweeted":
            prefix = "RT "
        elif ref.get("type") == "quoted":
            prefix = "QT "
        elif ref.get("type") == "replied_to":
            prefix = f"reply to {ref.get('id', '?')} "

    return f"{ts} {author}: {prefix}{text}{metrics} (ID: {tid})"


def format_tweet_list(data: dict) -> str:
    """Format a list of tweets from X API response."""
    tweets = data.get("data", [])
    if not tweets:
        return "No tweets found."

    includes = data.get("includes")
    lines = [format_tweet(t, includes) for t in tweets]
    result = "\n".join(lines)

    meta = data.get("meta", {})
    count = meta.get("result_count", len(tweets))
    next_token = meta.get("next_token")

    footer = f"\n---\n{count} tweets shown."
    if next_token:
        footer += f" Next page: {next_token}"
    return result + footer


def format_user(user: dict) -> str:
    """Format user profile."""
    name = user.get("name", "Unknown")
    username = user.get("username", "?")
    desc = user.get("description", "").replace("\n", " ")
    if len(desc) > 200:
        desc = desc[:200] + "..."

    m = user.get("public_metrics", {})
    lines = [
        f"{name} (@{username})",
        f"ID: {user.get('id', '?')}",
    ]
    if desc:
        lines.append(f"Bio: {desc}")
    if m:
        lines.append(
            f"Followers: {m.get('followers_count', 0)} | "
            f"Following: {m.get('following_count', 0)} | "
            f"Tweets: {m.get('tweet_count', 0)}"
        )
    if user.get("created_at"):
        lines.append(f"Joined: {_ts(user['created_at'])}")
    if user.get("verified"):
        lines.append("Verified: Yes")
    return "\n".join(lines)


def format_user_list(data: dict) -> str:
    """Format a list of users."""
    users = data.get("data", [])
    if not users:
        return "No users found."

    lines = []
    for i, u in enumerate(users, 1):
        m = u.get("public_metrics", {})
        followers = m.get("followers_count", 0)
        lines.append(
            f"{i}. {u.get('name', '?')} (@{u.get('username', '?')}) "
            f"— {followers} followers (ID: {u.get('id', '?')})"
        )
    return "\n".join(lines)


def format_dm_events(data: dict) -> str:
    """Format DM events."""
    events = data.get("data", [])
    if not events:
        return "No DM messages found."

    lines = []
    for e in reversed(events):  # chronological
        ts = _ts(e.get("created_at", ""))
        sender = e.get("sender_id", "?")
        text = e.get("text", "").replace("\n", " ")
        conv = e.get("dm_conversation_id", "?")
        lines.append(f"{ts} user:{sender} [conv:{conv}]: {text}")

    return "\n".join(lines)


def format_grok_response(data: dict) -> str:
    """Format Grok Responses API output (x_search results)."""
    # The Responses API returns output items
    output_items = data.get("output", [])
    text_parts = []

    for item in output_items:
        if item.get("type") == "message":
            content = item.get("content", [])
            for block in content:
                if block.get("type") == "output_text":
                    text_parts.append(block.get("text", ""))
                elif block.get("type") == "refusal":
                    text_parts.append(f"[Refused: {block.get('refusal', '')}]")

    if not text_parts:
        # Fallback: try to find any text in the response
        return str(data)

    return "\n\n".join(text_parts)
