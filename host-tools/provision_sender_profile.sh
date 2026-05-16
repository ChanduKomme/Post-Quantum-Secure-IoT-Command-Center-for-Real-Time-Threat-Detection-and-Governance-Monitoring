#!/usr/bin/env bash


set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <fingerprint_hex> <gateway_ip> [sender_id] [--allow-discovery]" >&2
  echo ""
  echo "  fingerprint_hex   64 hex chars from receiver boot log"
  echo "  gateway_ip        Receiver IPv4 address (e.g. 192.168.1.75)"
  echo "  sender_id         Optional, default: 0x53454E31"
  echo "  --allow-discovery Optional: enable LAN discovery fallback"
  echo ""
  echo "Example:"
  echo "  $0 F533B2C6CDB08FF37C3E0E1BBA3D49651F8CA1DF7E75AA840E8F4AD963756929 192.168.1.75"
  exit 1
fi

FINGERPRINT_HEX="$1"
GATEWAY_IP="$2"
SENDER_ID="${3:-0x53454E31}"
ALLOW_DISCOVERY_FLAG=""

# Check for --allow-discovery in any argument
for arg in "$@"; do
  if [ "$arg" = "--allow-discovery" ]; then
    ALLOW_DISCOVERY_FLAG="--allow-discovery"
  fi
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT="$PROJECT_ROOT/sender/sender/include/security_profile.h"

python3 "$SCRIPT_DIR/provision_fingerprint.py" \
  --fingerprint-hex "$FINGERPRINT_HEX" \
  --gateway-ip "$GATEWAY_IP" \
  --sender-id "$SENDER_ID" \
  --out "$OUTPUT" \
  $ALLOW_DISCOVERY_FLAG

echo ""
echo "Next steps:"
echo "  cd sender && ./genromap"
echo "  blflash flash build_out/sender.bin --port /dev/ttyUSB1"
