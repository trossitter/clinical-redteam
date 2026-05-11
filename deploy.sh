#!/usr/bin/env bash
set -euo pipefail

SERVER="root@138.197.78.43"
SSH_KEY="$HOME/.ssh/copilot_do"
REMOTE_DIR="/opt/clinicalcopilot/agentforge"

echo "→ Syncing code to server..."
rsync -az --exclude='.venv' --exclude='__pycache__' --exclude='*.pyc' \
  --exclude='.env' --exclude='agentforge.db' --exclude='reports/' \
  --exclude='.git' --exclude='*.pptx' \
  -e "ssh -i $SSH_KEY" \
  ./ "$SERVER:$REMOTE_DIR/"

echo "→ Rebuilding and restarting agentforge container..."
ssh -i "$SSH_KEY" "$SERVER" "
  cd /opt/clinicalcopilot
  docker compose up -d --build agentforge
  docker compose ps agentforge
"

echo "✓ Deployed. Platform available at https://clinicalcopilot.org/agentforge"
