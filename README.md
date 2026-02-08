# x-ai-mcp

X (Twitter) MCP server with Grok-powered intelligence. Personal account access + AI analysis in one package.

**20 tools:** 16 X API tools for reading/writing + 4 Grok intelligence tools for real-time analysis.

## Setup

### 1. Install

```bash
git clone https://github.com/olivier-motium/x-ai-mcp.git
cd x-ai-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

### 2. Configure

Copy `.env.example` to `.env` and fill in:

```bash
# Required — X API bearer token (read-only operations)
X_BEARER_TOKEN=your_bearer_token

# Required — your X user ID
X_USER_ID=your_user_id

# Optional — OAuth for write ops (posting, DMs)
# Run: python scripts/auth_flow.py
X_CLIENT_ID=your_client_id

# Optional — xAI key for intelligence tools
XAI_API_KEY=your_xai_key
```

### 3. Get OAuth tokens (for write operations)

```bash
python scripts/auth_flow.py
```

Opens browser, authorizes your account, saves `token.json`. Tokens auto-refresh.

### 4. Add to Claude Code

```bash
claude mcp add x-ai \
  -e X_BEARER_TOKEN=xxx \
  -e X_USER_ID=xxx \
  -e XAI_API_KEY=xxx \
  -- python -m src.server
```

## Tools

### X API — Timeline & Tweets

| Tool | Description |
|------|-------------|
| `x_home_timeline` | Your home timeline |
| `x_user_tweets` | A user's recent tweets |
| `x_get_tweet` | Get a specific tweet |
| `x_post_tweet` | Post a tweet (OAuth) |
| `x_delete_tweet` | Delete your tweet (OAuth) |
| `x_search_tweets` | Search recent tweets (7 days) |

### X API — DMs

| Tool | Description |
|------|-------------|
| `x_list_dms` | Recent DM messages |
| `x_read_dm` | Read a DM conversation |
| `x_send_dm` | Send a DM (OAuth) |

### X API — Social

| Tool | Description |
|------|-------------|
| `x_bookmarks` | Your bookmarked tweets |
| `x_liked_tweets` | Liked tweets (you or others) |
| `x_like_tweet` | Like a tweet (OAuth) |
| `x_user_info` | User profile details |
| `x_followers` | List followers |
| `x_following` | List following |

### Intelligence — Grok-powered

| Tool | Description |
|------|-------------|
| `x_analyze_topic` | Real-time analysis of any topic on X |
| `x_daily_digest` | AI-powered daily briefing |
| `x_summarize_thread` | Summarize a tweet thread |
| `x_analyze_account` | Deep analysis of any X account |

## Daily Digest (standalone)

```bash
# Default (AI/tech focus)
python scripts/daily_digest.py

# Custom focus
python scripts/daily_digest.py --focus "crypto markets"

# Save to file
python scripts/daily_digest.py --focus "AI agents" --output digest.md
```

Cron it for daily briefings:
```bash
0 9 * * * cd /path/to/x-ai-mcp && .venv/bin/python scripts/daily_digest.py >> ~/digests.log
```

## Architecture

```
Bearer Token (read) ──┐
OAuth 2.0 PKCE (r/w) ─┤──→ X API v2 ──→ 16 MCP tools
                       │
xAI API Key ───────────┤──→ Grok (x_search + chat) ──→ 4 intelligence tools
                       │
Logfire (optional) ────┘──→ Observability dashboard
```

- **X client:** async httpx, auto rate-limit retry, OAuth token refresh
- **Grok client:** Chat Completions API for analysis, Responses API with x_search for real-time X data
- **Output:** Plain text, never raw JSON. Tweets formatted as `[date time] @user: text (metrics)`

## License

MIT
