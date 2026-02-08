#!/usr/bin/env bash
# Deploy x-ai-mcp to the devbox as a StreamableHTTP MCP server.
#
# Prerequisites:
#   - SSH access to devbox (cc-devbox in ~/.ssh/config)
#   - token.json exists locally (run: python scripts/auth_flow.py)
#
# Usage:
#   bash deploy/setup.sh

set -euo pipefail

DEVBOX="cc-devbox"
REMOTE_DIR="/home/ubuntu/x-ai-mcp"

echo "=== x-ai-mcp devbox deployment ==="

# 1. Check token.json exists
if [ ! -f "token.json" ]; then
    echo "Error: token.json not found. Run 'python scripts/auth_flow.py' first."
    exit 1
fi

# 2. Sync the project to devbox (exclude .venv, __pycache__)
echo "[1/5] Syncing project to ${DEVBOX}:${REMOTE_DIR}..."
rsync -avz --delete \
    --exclude '.venv' \
    --exclude '__pycache__' \
    --exclude '.git' \
    --exclude '*.pyc' \
    . "${DEVBOX}:${REMOTE_DIR}/"

# 3. Copy token.json
echo "[2/5] Copying token.json..."
scp token.json "${DEVBOX}:${REMOTE_DIR}/token.json"

# 4. Set up venv and install deps on devbox
echo "[3/5] Installing dependencies on devbox..."
ssh "${DEVBOX}" "cd ${REMOTE_DIR} && \
    python3 -m venv .venv 2>/dev/null || true && \
    .venv/bin/pip install -q -e ."

# 5. Create .env if it doesn't exist
echo "[4/5] Checking .env file..."
ssh "${DEVBOX}" "[ -f ${REMOTE_DIR}/.env ] && echo '.env exists, skipping.' || echo 'ERROR: Create ${REMOTE_DIR}/.env with X API credentials first.' && exit 0"

# 6. Install and start systemd service
echo "[5/5] Installing systemd service..."
ssh "${DEVBOX}" "sudo cp ${REMOTE_DIR}/deploy/x-ai-mcp.service /etc/systemd/system/ && \
    sudo systemctl daemon-reload && \
    sudo systemctl enable x-ai-mcp && \
    sudo systemctl restart x-ai-mcp && \
    sleep 2 && \
    sudo systemctl status x-ai-mcp --no-pager"

echo ""
echo "=== Deployment complete ==="
echo "MCP endpoint: http://100.94.121.6:8420/mcp"
echo "Check logs:   ssh ${DEVBOX} 'journalctl -u x-ai-mcp -f'"
