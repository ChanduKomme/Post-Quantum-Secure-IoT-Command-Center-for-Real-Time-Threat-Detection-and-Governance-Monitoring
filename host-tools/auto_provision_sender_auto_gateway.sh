#!/usr/bin/env bash
# Auto-detect Receiver fingerprint + IP from serial, then provision Sender.
# Default: static gateway IP is NOT stored. Sender uses runtime broadcast discovery,
# so DHCP IP changes do not require editing security_profile.h again.
# The Receiver RNG pairing code is confirmed before the Sender profile is written.

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <receiver-serial-port> [sender-id] [--rebuild] [--echo]" >&2
  echo "Example:" >&2
  echo "  $0 /dev/ttyUSB0" >&2
  echo "  $0 /dev/ttyUSB0 0x53454E31 --rebuild" >&2
  echo "  $0 /dev/ttyUSB0 --yes --rebuild        # lab/demo: accept detected pairing code" >&2
  exit 1
fi

RECEIVER_PORT="$1"
SENDER_ID="0x53454E31"
shift || true

EXTRA_ARGS=()
for arg in "$@"; do
  case "$arg" in
    0x*|[0-9]*) SENDER_ID="$arg" ;;
    --rebuild|--echo) EXTRA_ARGS+=("$arg") ;;
    *) EXTRA_ARGS+=("$arg") ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

python3 "$SCRIPT_DIR/auto_provision_from_receiver_serial.py" \
  --receiver-port "$RECEIVER_PORT" \
  --sender-id "$SENDER_ID" \
  --ip-mode discovery \
  --out "$PROJECT_ROOT/sender/sender/include/security_profile.h" \
  "${EXTRA_ARGS[@]}"
