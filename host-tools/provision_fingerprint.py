#!/usr/bin/env python3
"""
provision_fingerprint.py
─────────────────────────────────────────────────────────────────────────────
Generates sender/sender/include/security_profile.h with the provisioned
receiver fingerprint, gateway IP, and sender ID.

Run after booting the receiver once and copying the fingerprint from the
boot log line that starts with:
  [Receiver] PUBLIC KEY FINGERPRINT = ...

Usage:
  python3 host-tools/provision_fingerprint.py \\
    --fingerprint-hex <64-hex-chars> \\
    --gateway-ip <receiver-ipv4> \\
    --sender-id 0x53454E31 \\
    --out sender/sender/include/security_profile.h

Flags:
  --allow-discovery   Set PQC_ALLOW_BROADCAST_DISCOVERY=1 in the header
                      (default: 0, static IP only)
  --splunk-ip         Embed a static Splunk IP in receiver splunk_hec.h
                      (default: use auto-discovery)
"""

import argparse
import ipaddress
import pathlib
import re
import sys

HEADER_GUARD = "SECURITY_PROFILE_H"


def normalize_fingerprint(value: str) -> str:
    s = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
    if len(s) != 64:
        raise ValueError(
            f"Fingerprint must contain exactly 32 bytes / 64 hex characters "
            f"(got {len(s) // 2} bytes from: {value!r})"
        )
    return s


def normalize_sender_id(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise ValueError(
            f"sender_id must be a valid integer, e.g. 0x53454E31 (got {value!r})"
        ) from exc


def normalize_ip(value: str) -> str:
    if not value or value == '""' or value == "''":
        return ""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 address: {value!r}") from exc


def fingerprint_to_c_array(hexstr: str) -> str:
    parts = [f"0x{hexstr[i:i+2]}" for i in range(0, len(hexstr), 2)]
    lines = []
    for i in range(0, len(parts), 8):
        lines.append("    " + ", ".join(parts[i : i + 8]))
    return ",\n".join(lines)


def render_sender_header(
    fingerprint_hex: str,
    gateway_ip: str,
    sender_id: int,
    allow_discovery: bool,
) -> str:
    fp_array = fingerprint_to_c_array(fingerprint_hex)
    discovery_val = "1u" if allow_discovery else "0u"

    return f"""\
#ifndef {HEADER_GUARD}
#define {HEADER_GUARD}

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {{
#endif

#define PQC_META_MAGIC 0x504D4554u /* PMET */
#define PQC_PK_FINGERPRINT_LEN 32u

#define PQC_PK_AUTH_MODE_TOFU   0u
#define PQC_PK_AUTH_MODE_STRICT 1u

#ifndef PQC_PK_AUTH_MODE
#define PQC_PK_AUTH_MODE PQC_PK_AUTH_MODE_STRICT
#endif

#ifndef PQC_PROTOCOL_VERSION
#define PQC_PROTOCOL_VERSION 1u
#endif

#ifndef PQC_SENDER_ID
#define PQC_SENDER_ID 0x{sender_id:08X}u
#endif

/* Fixed receiver IP (empty string = use last known or discovery) */
#ifndef PQC_GATEWAY_STATIC_IP
#define PQC_GATEWAY_STATIC_IP "{gateway_ip}"
#endif

/* 1 = allow broadcast discovery fallback, 0 = static IP only */
#ifndef PQC_ALLOW_BROADCAST_DISCOVERY
#define PQC_ALLOW_BROADCAST_DISCOVERY {discovery_val}
#endif

#define PQC_KEY_STATUS_ACTIVE            1u
#define PQC_KEY_STATUS_REVOKED           2u
#define PQC_KEY_STATUS_ROTATION_REQUIRED 3u
#define PQC_KEY_STATUS_RETIRED           4u

#ifndef PQC_KEY_MAX_MESSAGES_DEFAULT
#define PQC_KEY_MAX_MESSAGES_DEFAULT 1000u
#endif

#ifndef PQC_RATE_LIMIT_WINDOW_MS
#define PQC_RATE_LIMIT_WINDOW_MS 1000u
#endif

#ifndef PQC_RATE_LIMIT_MAX_REQUESTS
#define PQC_RATE_LIMIT_MAX_REQUESTS 8u
#endif

#ifndef PQC_META_RATE_LIMIT_MAX_REQUESTS
#define PQC_META_RATE_LIMIT_MAX_REQUESTS 16u
#endif

#ifndef PQC_DATA_RATE_LIMIT_WINDOW_MS
#define PQC_DATA_RATE_LIMIT_WINDOW_MS 1000u
#endif

#ifndef PQC_DATA_RATE_LIMIT_MAX_REQUESTS
#define PQC_DATA_RATE_LIMIT_MAX_REQUESTS 8u
#endif

#ifndef PQC_ALLOWED_SENDER_ID
#define PQC_ALLOWED_SENDER_ID PQC_SENDER_ID
#endif

#ifndef PQC_PEER_TABLE_SIZE
#define PQC_PEER_TABLE_SIZE 8u
#endif

#ifndef PQC_PEER_FAILS_TO_BLOCK
#define PQC_PEER_FAILS_TO_BLOCK 5u
#endif

#ifndef PQC_PEER_BLOCK_MS
#define PQC_PEER_BLOCK_MS 30000u
#endif

typedef struct __attribute__((packed)) {{
    uint32_t magic;
    uint32_t key_id;
    uint32_t created_at_ms;
    uint32_t expires_at_ms;
    uint32_t message_count;
    uint32_t max_messages;
    uint8_t status;
    uint8_t rotation_required;
    uint8_t reserved0;
    uint8_t reserved1;
    uint8_t fingerprint[PQC_PK_FINGERPRINT_LEN];
}} GatewayKeyMetadataPayload;

static const uint8_t kProvisionedGatewayPkFingerprint[PQC_PK_FINGERPRINT_LEN] = {{
{fp_array}
}};

static inline bool pqc_fingerprint_is_provisioned(void) {{
    for (size_t i = 0; i < PQC_PK_FINGERPRINT_LEN; ++i) {{
        if (kProvisionedGatewayPkFingerprint[i] != 0u) {{
            return true;
        }}
    }}
    return false;
}}

#ifdef __cplusplus
}}
#endif

#endif /* {HEADER_GUARD} */
"""


def render_splunk_hec_static_host(splunk_ip: str, hec_port: str = "8088") -> str:
    """Return a one-liner #define to paste into splunk_hec.h or a CFLAGS addition."""
    return f"-DSPLUNK_STATIC_HOST=\\\"{splunk_ip}\\\" -DSPLUNK_HEC_PORT=\\\"{hec_port}\\\""


def default_sender_output(script_path: pathlib.Path) -> pathlib.Path:
    repo_root = script_path.resolve().parent.parent
    return repo_root / "sender" / "sender" / "include" / "security_profile.h"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Provision receiver fingerprint and gateway IP into sender security_profile.h",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--fingerprint-hex",
        required=True,
        metavar="HEX",
        help="Receiver public-key SHA-256 fingerprint as 64 hex chars (spaces allowed)",
    )
    parser.add_argument(
        "--gateway-ip",
        required=True,
        metavar="IP",
        help='Receiver IPv4 address, e.g. 192.168.1.50 (use "" for discovery)',
    )
    parser.add_argument(
        "--sender-id",
        default="0x53454E31",
        metavar="ID",
        help="Sender ID as integer, e.g. 0x53454E31 (default: %(default)s)",
    )
    parser.add_argument(
        "--allow-discovery",
        action="store_true",
        default=False,
        help="Enable broadcast discovery fallback (PQC_ALLOW_BROADCAST_DISCOVERY=1)",
    )
    parser.add_argument(
        "--splunk-ip",
        default="",
        metavar="IP",
        help="Optional: embed a static Splunk server IP into splunk_hec.h "
             "(default: use auto-discovery on the LAN)",
    )
    parser.add_argument(
        "--out",
        "--output",
        default=None,
        metavar="PATH",
        help="Output path for security_profile.h "
             "(default: sender/sender/include/security_profile.h)",
    )

    args = parser.parse_args()

    try:
        fingerprint_hex = normalize_fingerprint(args.fingerprint_hex)
        sender_id = normalize_sender_id(args.sender_id)
        gateway_ip = normalize_ip(args.gateway_ip)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    output_path = (
        pathlib.Path(args.out)
        if args.out
        else default_sender_output(pathlib.Path(__file__))
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rendered = render_sender_header(
        fingerprint_hex,
        gateway_ip,
        sender_id,
        args.allow_discovery,
    )
    output_path.write_text(rendered, encoding="utf-8")

    print(f"[OK] Wrote sender header:  {output_path}")
    print(f"     Fingerprint (hex):    {fingerprint_hex}")
    print(f"     Gateway IP:           {gateway_ip if gateway_ip else '<use discovery>'}")
    print(f"     Sender ID:            0x{sender_id:08X}")
    print(f"     Allow discovery:      {args.allow_discovery}")

    if args.splunk_ip:
        try:
            splunk_ip = normalize_ip(args.splunk_ip)
            cflags = render_splunk_hec_static_host(splunk_ip)
            print(f"\n[INFO] To use static Splunk IP ({splunk_ip}), add to bouffalo.mk:")
            print(f"       CFLAGS += {cflags}")
            print(f"       Or rebuild splunk_hec.h with #define SPLUNK_STATIC_HOST \"{splunk_ip}\"")
        except ValueError as exc:
            print(f"[WARN] --splunk-ip ignored: {exc}", file=sys.stderr)

    print(f"\n[NEXT] Rebuild sender:  cd Receiver && ./genromap  (or sender)")
    print(f"[NEXT] Flash sender:    blflash flash build_out/sender.bin --port /dev/ttyUSB1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
