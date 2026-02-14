"""X AI MCP Server — X API tools + Grok intelligence."""

from __future__ import annotations

import json
import sys

from mcp.server.fastmcp import FastMCP

from . import config
from .cookie_client import CookieClient
from .formatters import (
    format_dm_events,
    format_grok_response,
    format_internal_conversations,
    format_internal_messages,
    format_tweet,
    format_tweet_list,
    format_user,
    format_user_list,
    format_xchat_conversations,
)
from .grok_client import GrokClient
from .x_client import XClient

mcp = FastMCP(
    "x-ai",
    host=config.MCP_HOST,
    port=config.MCP_PORT,
    stateless_http=True,
)

# Clients initialized lazily on first tool call
_x: XClient | None = None
_grok: GrokClient | None = None
_cookie: CookieClient | None = None


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


def _cookie_client() -> CookieClient:
    global _cookie
    if _cookie is None:
        if not config.X_AUTH_TOKEN or not config.X_CT0:
            raise RuntimeError(
                "X_AUTH_TOKEN and X_CT0 not set. Cookie-based DM access requires "
                "session cookies from a logged-in x.com browser session."
            )
        _cookie = CookieClient()
    return _cookie


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


def _split_dm_conversations(data: dict) -> tuple[list[dict], list[dict], dict[str, str]]:
    """Split DM events into real conversations vs message requests.

    Returns (real_convos, requests, user_map) where each list contains
    conversation dicts with 'conversation_id', 'events', 'participants'.
    user_map maps user_id -> @username.
    """
    events = data.get("data", [])
    includes = data.get("includes", {})
    my_id = config.X_USER_ID

    # Build user_id -> @username map from includes
    user_map: dict[str, str] = {}
    for u in includes.get("users", []):
        user_map[u["id"]] = f"@{u['username']}"

    # Group events by conversation
    convos: dict[str, list[dict]] = {}
    for e in events:
        cid = e.get("dm_conversation_id", "unknown")
        convos.setdefault(cid, []).append(e)

    real = []
    requests = []
    for cid, msgs in convos.items():
        senders = {e.get("sender_id") for e in msgs}
        entry = {"conversation_id": cid, "events": msgs, "participants": senders}
        if my_id in senders:
            real.append(entry)
        else:
            requests.append(entry)

    return real, requests, user_map


def _format_conversations(convos: list[dict], user_map: dict[str, str]) -> str:
    """Format grouped conversations for display."""
    if not convos:
        return "No conversations found."

    sections = []
    for c in convos:
        cid = c["conversation_id"]
        # Show most recent message per conversation
        msgs = sorted(c["events"], key=lambda e: e.get("created_at", ""))
        latest = msgs[-1]
        ts = latest.get("created_at", "")
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            ts_fmt = dt.strftime("[%Y-%m-%d %H:%M]")
        except (ValueError, AttributeError):
            ts_fmt = "[unknown]"

        participants = [user_map.get(p, f"user:{p}") for p in c["participants"]]
        sender = user_map.get(latest.get("sender_id", ""), f"user:{latest.get('sender_id', '?')}")
        text = latest.get("text", "").replace("\n", " ")
        if len(text) > 200:
            text = text[:200] + "..."

        sections.append(
            f"{ts_fmt} [{', '.join(participants)}] (conv:{cid})\n"
            f"  Latest from {sender}: {text}\n"
            f"  ({len(msgs)} message{'s' if len(msgs) != 1 else ''} in window)"
        )

    return "\n\n".join(sections)


@mcp.tool()
async def x_list_dms(count: int = 50) -> str:
    """List your actual DM conversations (where you've replied). Filters out unanswered message requests.

    Args:
        count: Number of DM events to scan (1-100, default 50). Higher = more conversations found.
    """
    data = await _x_client().get_dm_events(max_results=min(count, 100))
    real, _, user_map = _split_dm_conversations(data)
    header = f"Your DM conversations ({len(real)} active):\n\n"
    return header + _format_conversations(real, user_map)


@mcp.tool()
async def x_message_requests(count: int = 50) -> str:
    """List pending DM message requests — messages from people you haven't replied to.

    Args:
        count: Number of DM events to scan (1-100, default 50).
    """
    data = await _x_client().get_dm_events(max_results=min(count, 100))
    _, requests, user_map = _split_dm_conversations(data)
    header = f"Message requests ({len(requests)} pending):\n\n"
    return header + _format_conversations(requests, user_map)


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
# Internal DM Tools — Cookie-based (v1.1 API)
# ──────────────────────────────────────────────


@mcp.tool()
async def x_dm_inbox(count: int = 20) -> str:
    """List all DM conversations — both regular (REST API) and encrypted (XChat GraphQL).

    Shows conversation list with participant info, last message preview,
    and encryption status. Encrypted conversations are fetched from XChat
    and decrypted if private key is available.

    Args:
        count: Max conversations to return (default 20)
    """
    client = _cookie_client()

    # Fetch regular DMs from REST API
    data = await client.inbox_initial_state()
    inbox = data.get("inbox_initial_state", {})
    conversations = inbox.get("conversations", {})
    users = inbox.get("users", {})
    entries = inbox.get("entries", [])

    result = format_internal_conversations(conversations, users, entries, limit=count)

    # Fetch encrypted DMs from XChat GraphQL
    try:
        xchat_data = await client.xchat_inbox()
        items = xchat_data.get("data", {}).get("get_initial_chat_page", {}).get("items", [])
        if items:
            from .formatters import format_xchat_conversations
            xchat_result = format_xchat_conversations(items, limit=count)
            result += f"\n\n--- Encrypted Conversations (XChat) ---\n{xchat_result}"
    except Exception as e:
        result += f"\n\n[XChat inbox error: {e}]"

    return result


@mcp.tool()
async def x_dm_read_conversation(conversation_id: str, count: int = 50) -> str:
    """Read messages from a DM conversation.

    Automatically detects encrypted conversations (IDs starting with 'e')
    and uses XChat GraphQL + decryption. Regular conversations use REST API.

    Args:
        conversation_id: The conversation ID
        count: Max messages to fetch (default 50)
    """
    from .e2e_crypto import is_encrypted_conversation

    if is_encrypted_conversation(conversation_id):
        return await _read_xchat_conversation(conversation_id, count)

    client = _cookie_client()
    messages, users = await client.get_conversation_messages(conversation_id, limit=count)
    return format_internal_messages(messages, users, conversation_id)


async def _read_xchat_conversation(conversation_id: str, count: int) -> str:
    """Read and decrypt an XChat encrypted conversation."""
    from .e2e_crypto import (
        E2ECryptoError, decrypt_message, get_key_manager,
    )
    from .formatters import format_xchat_messages
    from .thrift_decoder import decode_message_event, extract_encrypted_conv_keys

    client = _cookie_client()
    xchat_data = await client.xchat_inbox()
    items = xchat_data.get("data", {}).get("get_initial_chat_page", {}).get("items", [])

    # Find the matching conversation
    target = None
    for item in items:
        detail = item.get("conversation_detail", {})
        cid = detail.get("conversation_id", "")
        if cid == conversation_id:
            target = item
            break

    if not target:
        return f"Conversation {conversation_id} not found in XChat inbox."

    # Decode messages from Thrift
    raw_msgs = target.get("latest_message_events", [])
    decoded_msgs = []
    for msg_b64 in raw_msgs:
        if isinstance(msg_b64, str):
            try:
                decoded_msgs.append(decode_message_event(msg_b64))
            except Exception:
                continue

    # Try to decrypt if we have the private key
    km = get_key_manager()
    conversation_key = None
    if km.has_keys:
        key_events = target.get("latest_conversation_key_change_events", [])
        if key_events:
            enc_keys = extract_encrypted_conv_keys(key_events)
            for _uid, enc_key_b64 in enc_keys.items():
                try:
                    conversation_key = km.decrypt_conversation_key(enc_key_b64)
                    break
                except (E2ECryptoError, Exception):
                    continue

    # Decrypt message text
    if conversation_key:
        for msg in decoded_msgs:
            enc_text = msg.get("encrypted_text", "")
            if enc_text:
                try:
                    msg["decrypted_text"] = decrypt_message(enc_text, conversation_key)
                except Exception as e:
                    msg["decrypted_text"] = f"[decryption failed: {e}]"

    # Build participant info
    detail = target.get("conversation_detail", {})
    participants = detail.get("participants_results", [])

    return format_xchat_messages(
        decoded_msgs, participants, conversation_id,
        has_key=conversation_key is not None, limit=count,
    )


@mcp.tool()
async def x_dm_send(conversation_id: str, text: str) -> str:
    """Send a DM via X's internal API (regular conversations only).

    Args:
        conversation_id: The conversation ID to send to
        text: Message text to send
    """
    client = _cookie_client()
    data = await client.send_message(conversation_id, text)
    entries = data.get("entries", [])
    if entries:
        return f"Message sent to conversation {conversation_id}"
    return f"Message sent (response: {json.dumps(data)[:200]})"


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────


def main():
    """Run the MCP server."""
    transport = config.MCP_TRANSPORT
    if transport not in ("stdio", "streamable-http", "sse"):
        print(f"Error: Unknown transport '{transport}'. Use stdio or streamable-http.", file=sys.stderr)
        sys.exit(1)

    if not config.X_BEARER_TOKEN:
        print("Warning: X_BEARER_TOKEN not set. X API tools will fail.", file=sys.stderr)
    if not config.X_USER_ID:
        print("Warning: X_USER_ID not set. Personal tools (timeline, bookmarks) will fail.", file=sys.stderr)
    if not config.XAI_API_KEY:
        print("Note: XAI_API_KEY not set. Intelligence tools (x_analyze_*, x_daily_digest) disabled.", file=sys.stderr)
    if config.X_AUTH_TOKEN and config.X_CT0:
        print("x-ai-mcp: Cookie auth active. Internal DM tools (x_dm_*) enabled.", file=sys.stderr)
    else:
        print("Note: X_AUTH_TOKEN/X_CT0 not set. Internal DM tools disabled.", file=sys.stderr)

    print(f"x-ai-mcp: starting server (transport={transport})...", file=sys.stderr)
    if transport == "streamable-http":
        print(f"x-ai-mcp: listening on {config.MCP_HOST}:{config.MCP_PORT}", file=sys.stderr)
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
