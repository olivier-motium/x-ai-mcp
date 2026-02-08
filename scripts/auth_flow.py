"""OAuth 2.0 PKCE flow for X API — run locally to get tokens.

Usage:
    python scripts/auth_flow.py

This starts a local server on port 8400, opens your browser to authorize,
and saves the token to token.json.
"""

import base64
import hashlib
import http.server
import json
import os
import secrets
import sys
import urllib.parse
import webbrowser

import httpx

CLIENT_ID = os.environ.get("X_CLIENT_ID", "c1ZoVThEZVR6RTBMS2t2RDJCeWo6MTpjaQ")
CLIENT_SECRET = os.environ.get("X_CLIENT_SECRET", "")
REDIRECT_URI = "http://localhost:8400/callback"
TOKEN_PATH = os.environ.get("X_TOKEN_PATH", "./token.json")

SCOPES = [
    "tweet.read", "tweet.write",
    "users.read",
    "dm.read", "dm.write",
    "bookmark.read", "bookmark.write",
    "like.read", "like.write",
    "follows.read", "follows.write",
    "list.read", "list.write",
    "offline.access",
]


def generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge."""
    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def build_auth_url(state: str, challenge: str) -> str:
    """Build the OAuth authorization URL."""
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(SCOPES),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"https://x.com/i/oauth2/authorize?{urllib.parse.urlencode(params)}"


def exchange_code(code: str, verifier: str) -> dict:
    """Exchange authorization code for tokens."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
        "client_id": CLIENT_ID,
    }
    auth = None
    if CLIENT_SECRET:
        auth = (CLIENT_ID, CLIENT_SECRET)

    resp = httpx.post(
        "https://api.x.com/2/oauth2/token",
        data=data,
        auth=auth,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    """Handle the OAuth callback."""

    code: str | None = None
    state: str | None = None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        CallbackHandler.code = params.get("code", [None])[0]
        CallbackHandler.state = params.get("state", [None])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>Authorized! You can close this tab.</h1>")

    def log_message(self, format, *args):
        pass  # Suppress request logging


def main():
    state = secrets.token_urlsafe(32)
    verifier, challenge = generate_pkce()

    auth_url = build_auth_url(state, challenge)
    print(f"Opening browser for authorization...")
    print(f"If it doesn't open, visit:\n{auth_url}\n")
    webbrowser.open(auth_url)

    # Wait for callback
    server = http.server.HTTPServer(("localhost", 8400), CallbackHandler)
    print("Waiting for callback on http://localhost:8400/callback ...")
    server.handle_request()

    if not CallbackHandler.code:
        print("Error: No authorization code received.", file=sys.stderr)
        sys.exit(1)

    if CallbackHandler.state != state:
        print("Error: State mismatch — possible CSRF.", file=sys.stderr)
        sys.exit(1)

    print("Authorization code received. Exchanging for tokens...")
    tokens = exchange_code(CallbackHandler.code, verifier)

    with open(TOKEN_PATH, "w") as f:
        json.dump(tokens, f, indent=2)

    print(f"\nTokens saved to {TOKEN_PATH}")
    print(f"Access token expires in: {tokens.get('expires_in', '?')}s")
    print(f"Scopes granted: {tokens.get('scope', '?')}")
    print("\nYou're all set! The MCP server will auto-refresh the token.")


if __name__ == "__main__":
    main()
