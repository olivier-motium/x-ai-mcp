"""Configuration from environment variables."""

import os
from pathlib import Path


def get_required(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        raise RuntimeError(f"{key} environment variable is required")
    return val


# X API (v2 — official)
X_BEARER_TOKEN: str = os.environ.get("X_BEARER_TOKEN", "")
X_CLIENT_ID: str = os.environ.get("X_CLIENT_ID", "")
X_CLIENT_SECRET: str = os.environ.get("X_CLIENT_SECRET", "")
X_TOKEN_PATH: Path = Path(os.environ.get("X_TOKEN_PATH", "./token.json"))
X_USER_ID: str = os.environ.get("X_USER_ID", "")

# X internal API (cookie-based auth for encrypted DMs)
X_AUTH_TOKEN: str = os.environ.get("X_AUTH_TOKEN", "")
X_CT0: str = os.environ.get("X_CT0", "")
X_ENCRYPTION_PIN: str = os.environ.get("X_ENCRYPTION_PIN", "")
X_KEYS_PATH: Path = Path(os.environ.get("X_KEYS_PATH", "./x_device_keys.json"))

# xAI / Grok
XAI_API_KEY: str = os.environ.get("XAI_API_KEY", "") or os.environ.get("X_AI_API_KEY", "")
XAI_MODEL: str = os.environ.get("XAI_MODEL", "grok-4-1-fast")

# Server transport config
MCP_TRANSPORT: str = os.environ.get("MCP_TRANSPORT", "stdio")
MCP_HOST: str = os.environ.get("MCP_HOST", "0.0.0.0")
MCP_PORT: int = int(os.environ.get("MCP_PORT", "8420"))

# API base URLs
X_API_BASE = "https://api.x.com/2"
XAI_API_BASE = "https://api.x.ai/v1"

# Default tweet fields for rich responses
TWEET_FIELDS = "id,text,created_at,author_id,conversation_id,public_metrics,entities,referenced_tweets"
USER_FIELDS = "id,username,name,description,public_metrics,verified,profile_image_url,created_at"
EXPANSIONS = "author_id,referenced_tweets.id,attachments.media_keys"
MEDIA_FIELDS = "type,url,preview_image_url,alt_text"
