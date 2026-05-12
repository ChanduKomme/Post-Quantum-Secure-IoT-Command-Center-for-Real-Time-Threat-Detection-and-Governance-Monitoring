#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ ! -f .env ]; then
  echo "[!] Project .env not found. Copy integrations/splunk_hackerone_jira/.env.example to .env first."
  exit 1
fi

cleanup() {
  if [ -n "${BACKEND_PID:-}" ]; then kill "$BACKEND_PID" 2>/dev/null || true; fi
  if [ -n "${FRONTEND_PID:-}" ]; then kill "$FRONTEND_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT

printf '\n==> Starting PQC IoT Security Command Center backend\n'
cd "$ROOT_DIR/dashboard/backend"
python3 -m pip install -q -r requirements.txt
python3 app.py &
BACKEND_PID=$!

printf '\n==> Starting React frontend\n'
cd "$ROOT_DIR/dashboard/frontend"
if [ ! -d node_modules ]; then
  npm install
fi
npm run dev &
FRONTEND_PID=$!

printf '\nDashboard is starting. Open: http://localhost:5173\n'
printf 'Backend API: http://localhost:8090\n'
printf 'Press Ctrl+C to stop.\n\n'
wait
