
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rm -f "$ROOT/.env" "$ROOT"/*.env "$ROOT/integrations/splunk_hackerone_jira/.env" "$ROOT/thesis_demo/.env"
rm -f "$ROOT/pqc_attacks.zip" "$ROOT/integrations/splunk_hackerone_jira/governance.zip"
find "$ROOT" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$ROOT" -type f -name '*.pyc' -delete
rm -rf "$ROOT/sender/build_out" "$ROOT/Receiver/build_out" "$ROOT/sniffer/build_out"
mkdir -p "$ROOT/sender/build_out" "$ROOT/Receiver/build_out" "$ROOT/sniffer/build_out"
for d in sender Receiver sniffer; do
  cat > "$ROOT/$d/build_out/README_BUILD_REQUIRED.md" <<EOF
# Build output intentionally not committed

Run: bash tools/build_firmware.sh --role $d
EOF
done
echo "Cleaned secrets and generated firmware artifacts."
