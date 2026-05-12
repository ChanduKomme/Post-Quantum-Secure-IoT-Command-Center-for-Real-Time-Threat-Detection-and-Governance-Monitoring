#!/usr/bin/env bash
# Convenience launcher for the host-side parts of the direct board-to-Splunk demo.
# It does not flash boards. It starts Splunk if present, checks HEC, opens firewall,
# and starts the robust discovery server.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${PQC_ENV_FILE:-$ROOT/.env}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
else
  echo "WARN: $ENV_FILE not found. Copy integrations/splunk_hackerone_jira/.env.example to .env and fill SPLUNK_HEC_TOKEN."
fi

HEC_PORT="${SPLUNK_HEC_PORT:-8088}"

if [[ -x /opt/splunk/bin/splunk ]]; then
  sudo /opt/splunk/bin/splunk start --run-as-root || true
fi

if command -v ufw >/dev/null 2>&1; then
  sudo ufw allow "${HEC_PORT}/tcp" || true
  sudo ufw allow 9998/udp || true
fi

echo "Testing local Splunk HEC on http://127.0.0.1:${HEC_PORT} ..."
if [[ -n "${SPLUNK_HEC_TOKEN:-}" && "${SPLUNK_HEC_TOKEN}" != "REPLACE_WITH_YOUR_SPLUNK_HEC_TOKEN" ]]; then
  curl -s "http://127.0.0.1:${HEC_PORT}/services/collector/event" \
    -H "Authorization: Splunk ${SPLUNK_HEC_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"index":"pqc_iot","sourcetype":"pqc:iot:event","event":{"event_type":"LOCAL_HEC_TEST","role":"host"}}' || true
  echo
else
  echo "WARN: SPLUNK_HEC_TOKEN not set; skipping curl test."
fi

echo "Starting robust Splunk discovery server. Keep this running; reset Receiver first, then Sender."
cd "$ROOT/integrations/splunk_hackerone_jira/splunk"
exec python3 splunk_discovery_server.py --hec-port "$HEC_PORT" --proactive
