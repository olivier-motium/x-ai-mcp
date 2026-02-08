"""Standalone daily digest script — run via cron or manually.

Usage:
    python scripts/daily_digest.py
    python scripts/daily_digest.py --focus "AI agents"
    python scripts/daily_digest.py --focus "crypto" --output digest.md

Cron example (daily at 9 AM):
    0 9 * * * cd /path/to/x-ai-mcp && .venv/bin/python scripts/daily_digest.py >> digests.log
"""

import argparse
import asyncio
import os
import sys

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.grok_client import GrokClient
from src.formatters import format_grok_response
from src import config


async def generate_digest(focus: str | None = None) -> str:
    """Generate a daily digest using Grok x_search."""
    if not config.XAI_API_KEY:
        return "Error: XAI_API_KEY not set."

    grok = GrokClient()
    area = focus or "AI, LLMs, developer tools, and tech startups"

    print(f"Generating digest for: {area}", file=sys.stderr)

    data = await grok.x_search(
        f"Generate a comprehensive daily digest of what's happening on X/Twitter today in: {area}. "
        f"Cover: (1) Top stories and announcements, (2) Notable threads and discussions, "
        f"(3) Trending topics and sentiment, (4) Key people and accounts driving conversation. "
        f"Include specific usernames, tweet excerpts, and engagement metrics. "
        f"Format as a clean daily briefing with sections."
    )

    await grok.close()
    return format_grok_response(data)


def main():
    parser = argparse.ArgumentParser(description="Generate X daily digest with Grok AI")
    parser.add_argument("--focus", type=str, help="Focus area for the digest")
    parser.add_argument("--output", type=str, help="Save output to file")
    args = parser.parse_args()

    digest = asyncio.run(generate_digest(args.focus))

    if args.output:
        with open(args.output, "w") as f:
            f.write(digest)
        print(f"Digest saved to {args.output}", file=sys.stderr)
    else:
        print(digest)


if __name__ == "__main__":
    main()
