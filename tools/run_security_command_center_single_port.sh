#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f .env ]; then
  echo "[!] Project .env not found. Copy integrations/splunk_hackerone_jira/.env.example to .env first."
  exit 1
fi

printf '\n==> Building React dashboard\n'
cd "$ROOT_DIR/dashboard/frontend"
if [ ! -d node_modules ]; then
  npm install
fi
npm run build

printf '\n==> Starting backend and serving frontend at http://localhost:8090\n'
cd "$ROOT_DIR/dashboard/backend"
python3 -m pip install -q -r requirements.txt
python3 app.py
