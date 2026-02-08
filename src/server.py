"""X AI MCP Server — X API tools + Grok intelligence."""

from __future__ import annotations

import sys

from mcp.server.fastmcp import FastMCP

from . import config
from .formatters import (
    format_dm_events,
    format_grok_response,
    format_tweet,
    format_tweet_list,
    format_user,
    format_user_list,
)
from .grok_client import GrokClient
from .x_client import XClient

mcp = FastMCP("x-ai")

# Clients initialized lazily on first tool call
_x: XClient | None = None
_grok: GrokClient | None = None


def _x_client() -> XClient:
    global _x
    if _x is None:
        _x = XClient()
    return _x


def _grok_client() -> GrokClient:
    global _grok
    if _grok is None:
        if not config.XAI_API_KEY:
            raise RuntimeError(
                "XAI_API_KEY not set. Intelligence tools require a Grok API key. "
                "Get one at https://console.x.ai"
            )
        _grok = GrokClient()
    return _grok


# ──────────────────────────────────────────────
# X API Tools — Timeline & Tweets
# ──────────────────────────────────────────────


@mcp.tool()
async def x_home_timeline(count: int = 20) -> str:
    """Get your home timeline — tweets from people you follow. Requires OAuth token.

    Args:
        count: Number of tweets to fetch (1-100, default 20)
    """
    data = await _x_client().home_timeline(max_results=min(count, 100))
    return format_tweet_list(data)


@mcp.tool()
async def x_user_tweets(username: str, count: int = 20) -> str:
    """Get recent tweets from a specific user.

    Args:
        username: X username (without @) or user ID
        count: Number of tweets (1-100, default 20)
    """
    client = _x_client()
    # Resolve username to ID if needed
    if not username.isdigit():
        user_data = await client.get_user_by_username(username.lstrip("@"))
        user_id = user_data["data"]["id"]
    else:
        user_id = username
    data = await client.user_tweets(user_id, max_results=min(count, 100))
    return format_tweet_list(data)


@mcp.tool()
async def x_get_tweet(tweet_id: str) -> str:
    """Get a specific tweet by ID with full details.

    Args:
        tweet_id: The tweet ID to fetch
    """
    data = await _x_client().get_tweet(tweet_id)
    tweet = data.get("data", {})
    includes = data.get("includes")
    return format_tweet(tweet, includes)


@mcp.tool()
async def x_post_tweet(text: str, reply_to: str | None = None) -> str:
    """Post a new tweet. Requires OAuth token with tweet.write scope.

    Args:
        text: Tweet text (max 280 characters)
        reply_to: Optional tweet ID to reply to
    """
    if len(text) > 280:
        return f"Error: Tweet is {len(text)} chars, max 280."
    data = await _x_client().post_tweet(text, reply_to)
    tweet_id = data.get("data", {}).get("id", "?")
    return f"Tweet posted (ID: {tweet_id}): {text}"


@mcp.tool()
async def x_delete_tweet(tweet_id: str) -> str:
    """Delete one of your tweets. Permanent action.

    Args:
        tweet_id: ID of the tweet to delete
    """
    await _x_client().delete_tweet(tweet_id)
    return f"Tweet {tweet_id} deleted."


@mcp.tool()
async def x_search_tweets(query: str, count: int = 20) -> str:
    """Search recent tweets (last 7 days). Supports X search operators.

    Args:
        query: Search query. Supports operators like 'from:user', 'has:links', '#hashtag', '-filter:retweets'
        count: Number of results (10-100, default 20)
    """
    data = await _x_client().search_recent(query, max_results=max(10, min(count, 100)))
    return format_tweet_list(data)


# ──────────────────────────────────────────────
# X API Tools — DMs
# ──────────────────────────────────────────────


@mcp.tool()
async def x_list_dms(count: int = 20) -> str:
    """List your recent DM messages. Requires OAuth with dm.read scope.

    Args:
        count: Number of DM events to fetch (1-100, default 20)
    """
    data = await _x_client().get_dm_events(max_results=min(count, 100))
    return format_dm_events(data)


@mcp.tool()
async def x_read_dm(conversation_id: str, count: int = 20) -> str:
    """Read messages from a specific DM conversation.

    Args:
        conversation_id: The DM conversation ID
        count: Number of messages (1-100, default 20)
    """
    data = await _x_client().get_dm_conversation(conversation_id, max_results=min(count, 100))
    return format_dm_events(data)


@mcp.tool()
async def x_send_dm(user_id: str, text: str) -> str:
    """Send a direct message to a user. Requires OAuth with dm.write scope.

    Args:
        user_id: The recipient's user ID
        text: Message text
    """
    data = await _x_client().send_dm(user_id, text)
    event = data.get("data", {})
    return f"DM sent (event ID: {event.get('dm_event_id', '?')})"


# ──────────────────────────────────────────────
# X API Tools — Bookmarks, Likes, Users
# ──────────────────────────────────────────────


@mcp.tool()
async def x_bookmarks(count: int = 20) -> str:
    """Get your bookmarked tweets. Requires OAuth token.

    Args:
        count: Number of bookmarks (1-100, default 20)
    """
    data = await _x_client().get_bookmarks(max_results=min(count, 100))
    return format_tweet_list(data)


@mcp.tool()
async def x_liked_tweets(username: str | None = None, count: int = 20) -> str:
    """Get liked tweets for yourself or another user.

    Args:
        username: Username or user ID (default: your account)
        count: Number of likes (1-100, default 20)
    """
    client = _x_client()
    user_id = None
    if username:
        if not username.isdigit():
            user_data = await client.get_user_by_username(username.lstrip("@"))
            user_id = user_data["data"]["id"]
        else:
            user_id = username
    data = await client.get_liked_tweets(user_id, max_results=min(count, 100))
    return format_tweet_list(data)


@mcp.tool()
async def x_like_tweet(tweet_id: str) -> str:
    """Like a tweet. Requires OAuth token.

    Args:
        tweet_id: ID of the tweet to like
    """
    await _x_client().like_tweet(tweet_id)
    return f"Liked tweet {tweet_id}."


@mcp.tool()
async def x_user_info(username: str) -> str:
    """Get detailed profile info for a user.

    Args:
        username: X username (without @) or user ID
    """
    client = _x_client()
    if username.isdigit():
        data = await client.get_user(username)
    else:
        data = await client.get_user_by_username(username.lstrip("@"))
    return format_user(data.get("data", {}))


@mcp.tool()
async def x_followers(username: str | None = None, count: int = 50) -> str:
    """List followers for yourself or another user.

    Args:
        username: Username or user ID (default: your account)
        count: Number of followers (1-1000, default 50)
    """
    client = _x_client()
    user_id = None
    if username:
        if not username.isdigit():
            user_data = await client.get_user_by_username(username.lstrip("@"))
            user_id = user_data["data"]["id"]
        else:
            user_id = username
    data = await client.get_followers(user_id, max_results=min(count, 1000))
    return format_user_list(data)


@mcp.tool()
async def x_following(username: str | None = None, count: int = 50) -> str:
    """List accounts you (or another user) follow.

    Args:
        username: Username or user ID (default: your account)
        count: Number of accounts (1-1000, default 50)
    """
    client = _x_client()
    user_id = None
    if username:
        if not username.isdigit():
            user_data = await client.get_user_by_username(username.lstrip("@"))
            user_id = user_data["data"]["id"]
        else:
            user_id = username
    data = await client.get_following(user_id, max_results=min(count, 1000))
    return format_user_list(data)


# ──────────────────────────────────────────────
# Intelligence Tools — Grok-powered
# ──────────────────────────────────────────────


@mcp.tool()
async def x_analyze_topic(topic: str) -> str:
    """Use Grok AI to analyze what X is saying about a topic right now. Returns insights with citations from real-time X data.

    Args:
        topic: Topic to analyze (e.g., 'AI agents', 'Claude Code', 'Bitcoin')
    """
    grok = _grok_client()
    query = (
        f"What is X/Twitter saying about '{topic}' right now? "
        f"Summarize the key conversations, notable voices, and prevailing sentiment. "
        f"Include specific tweets and usernames."
    )
    data = await grok.x_search(query)
    return format_grok_response(data)


@mcp.tool()
async def x_daily_digest(focus: str | None = None) -> str:
    """Generate an AI-powered daily digest of what's happening on X. Uses Grok with real-time X search.

    Args:
        focus: Optional focus area (e.g., 'AI', 'crypto', 'tech startups'). Defaults to general tech/AI.
    """
    grok = _grok_client()
    area = focus or "AI, LLMs, developer tools, and tech startups"
    query = (
        f"Generate a comprehensive daily digest of what's happening on X/Twitter today in: {area}. "
        f"Cover: (1) Top stories and announcements, (2) Notable threads and discussions, "
        f"(3) Trending topics, (4) Key people to pay attention to. "
        f"Include specific usernames, tweet excerpts, and engagement data. "
        f"Format as a clean briefing."
    )
    data = await grok.x_search(query)
    return format_grok_response(data)


@mcp.tool()
async def x_summarize_thread(tweet_id: str) -> str:
    """Use Grok to find and summarize a tweet thread. Provides key points and analysis.

    Args:
        tweet_id: ID of the first tweet in the thread (or any tweet in it)
    """
    # Fetch the tweet first for context
    client = _x_client()
    tweet_data = await client.get_tweet(tweet_id)
    tweet = tweet_data.get("data", {})
    author_id = tweet.get("author_id", "")
    text_preview = tweet.get("text", "")[:200]

    # Use Grok x_search to find and analyze the full thread
    grok = _grok_client()
    query = (
        f"Find and summarize the complete tweet thread starting from or containing this tweet: "
        f"'{text_preview}' (tweet ID: {tweet_id}). "
        f"Provide: (1) A summary of the thread's main argument, "
        f"(2) Key quotes, (3) Community reactions and notable replies."
    )
    data = await grok.x_search(query)
    return format_grok_response(data)


@mcp.tool()
async def x_analyze_account(username: str) -> str:
    """Use Grok to analyze an X account — their posting patterns, key topics, influence, and recent activity.

    Args:
        username: X username (without @)
    """
    grok = _grok_client()
    query = (
        f"Analyze the X/Twitter account @{username.lstrip('@')}. "
        f"Cover: (1) Who they are and what they do, "
        f"(2) Their main topics and posting style, "
        f"(3) Their recent notable tweets and threads, "
        f"(4) Their influence and engagement levels, "
        f"(5) Who they interact with most."
    )
    data = await grok.x_search(query)
    return format_grok_response(data)


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────


def main():
    """Run the MCP server."""
    if not config.X_BEARER_TOKEN:
        print("Warning: X_BEARER_TOKEN not set. X API tools will fail.", file=sys.stderr)
    if not config.X_USER_ID:
        print("Warning: X_USER_ID not set. Personal tools (timeline, bookmarks) will fail.", file=sys.stderr)
    if not config.XAI_API_KEY:
        print("Note: XAI_API_KEY not set. Intelligence tools (x_analyze_*, x_daily_digest) disabled.", file=sys.stderr)

    print("x-ai-mcp: starting server...", file=sys.stderr)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
