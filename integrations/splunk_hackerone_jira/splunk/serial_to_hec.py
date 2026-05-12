#!/usr/bin/env python3
"""
Read UART/serial lines or an input file, normalize the data, and send events to Splunk HEC.

Accepted line formats:
1) JSON per line
2) key=value pairs separated by spaces
3) BL602 serial log lines: [tag] message content

Examples:
    python splunk/serial_to_hec.py --input-file sample_data/device_events.ndjson --env-file .env
    python splunk/serial_to_hec.py --serial-port /dev/ttyUSB0 --baudrate 2000000 --env-file .env
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import requests
from dotenv import dotenv_values

try:
    import serial  # type: ignore
except Exception:  # pragma: no cover
    serial = None

KV_RE = re.compile(r'(?P<key>[A-Za-z0-9_.-]+)=(?P<val>"[^"]*"|\S+)')

# BL602 serial log pattern: [tag] message
BL602_RE = re.compile(r'^\[(?P<tag>[^\]]+)\]\s+(?P<msg>.+)$')

# Map BL602 log keywords to structured event fields
BL602_EVENT_MAP = {
    "KEM + HKDF done":          {"event_type": "KEM_HKDF_DONE",       "severity": "info",   "role": "sender",   "action": "key_derived"},
    "AEAD encrypt done":        {"event_type": "AEAD_ENCRYPT_DONE",    "severity": "info",   "role": "sender",   "action": "message_encrypted"},
    "Message successfully":     {"event_type": "MSG_DELIVERED",        "severity": "info",   "role": "sender",   "action": "message_delivered"},
    "Decrypted msg":            {"event_type": "MSG_DECRYPTED",        "severity": "info",   "role": "gateway",  "action": "message_decrypted"},
    "REPLAY DETECTED":          {"event_type": "REPLAY_REJECT",        "severity": "medium", "role": "gateway",  "action": "message_dropped"},
    "AEAD AUTH FAIL":           {"event_type": "AEAD_AUTH_FAIL",       "severity": "high",   "role": "gateway",  "action": "packet_rejected"},
    "AUTH FAIL":                {"event_type": "PK_AUTH_FAIL",         "severity": "high",   "role": "gateway",  "action": "session_aborted"},
    "PK request received":      {"event_type": "PK_REQUEST",           "severity": "info",   "role": "gateway",  "action": "pk_served"},
    "Loaded KEM keypair":       {"event_type": "KEY_ACTIVE",           "severity": "info",   "role": "gateway",  "action": "keypair_loaded"},
    "Listening on UDP":         {"event_type": "MONITOR_ACTIVE",       "severity": "info",   "role": "gateway",  "action": "listening"},
    "Wi-Fi ready":              {"event_type": "WIFI_CONNECTED",       "severity": "info",   "role": "sender",   "action": "wifi_up"},
    "Connected to":             {"event_type": "WIFI_CONNECTED",       "severity": "info",   "role": "device",   "action": "wifi_up"},
    "Task started":             {"event_type": "BOOT_OK",              "severity": "info",   "role": "device",   "action": "boot_complete"},
    "TOO_MANY_REQUESTS":        {"event_type": "RATE_LIMIT_HIT",       "severity": "medium", "role": "gateway",  "action": "temporary_throttle"},
    "rotation_required":        {"event_type": "KEY_ROTATED",          "severity": "low",    "role": "gateway",  "action": "key_id_updated"},
    "URI mismatch":             {"event_type": "INVALID_REQUEST",      "severity": "medium", "role": "gateway",  "action": "request_dropped"},
    "No ACK":                   {"event_type": "MSG_RETRY",            "severity": "medium", "role": "sender",   "action": "retry_attempt"},
    "Task finished":            {"event_type": "TASK_COMPLETE",        "severity": "info",   "role": "sender",   "action": "session_complete"},
}

DEFAULT_SOURCE     = "pqc_iot_bl602"
DEFAULT_SOURCETYPE = "pqc:iot:event"
DEFAULT_INDEX      = "pqc_iot"


@dataclass
class Config:
    hec_url: str
    token: str
    index: str
    source: str
    sourcetype: str
    verify_tls: bool
    timeout_seconds: int


def load_env(path: Optional[str]) -> Dict[str, str]:
    values = {}
    if path:
        values.update({k: v for k, v in dotenv_values(path).items() if v is not None})
    for k, v in os.environ.items():
        values.setdefault(k, v)
    return values


def get_config(env: Dict[str, str], args: argparse.Namespace) -> Config:
    url = args.hec_url or env.get("SPLUNK_HEC_URL") or "https://localhost:8088"
    token = args.hec_token or env.get("SPLUNK_HEC_TOKEN") or "DRY_RUN_TOKEN"
    if not url or (not token and not getattr(args, "dry_run", False)):
        raise SystemExit("Missing SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN.")
    return Config(
        hec_url=url.rstrip("/") + "/services/collector/event",
        token=token,
        index=args.index or env.get("SPLUNK_INDEX", DEFAULT_INDEX),
        source=args.source or env.get("SPLUNK_SOURCE", DEFAULT_SOURCE),
        sourcetype=args.sourcetype or env.get("SPLUNK_SOURCETYPE", DEFAULT_SOURCETYPE),
        verify_tls=str(env.get("SPLUNK_VERIFY_TLS", "true")).lower() == "true",
        timeout_seconds=int(env.get("SPLUNK_TIMEOUT_SECONDS", "10")),
    )


def parse_bl602_line(line: str) -> Optional[Dict[str, object]]:
    """Parse BL602 serial log lines like: [sender] KEM + HKDF done, AEAD key ready"""
    m = BL602_RE.match(line.strip())
    if not m:
        return None
    tag = m.group("tag").strip()
    msg = m.group("msg").strip()

    # Match against known keywords
    for keyword, fields in BL602_EVENT_MAP.items():
        if keyword.lower() in msg.lower():
            event = dict(fields)
            event["device_id"] = tag
            event["message"]   = msg
            return event

    # BL602 line but unknown keyword — skip it (don't send as UNSPECIFIED)
    return None


def parse_line(line: str) -> Optional[Dict[str, object]]:
    line = line.strip()
    if not line:
        return None

    # JSON-line input
    if line.startswith("{"):
        data = json.loads(line)
        if not isinstance(data, dict):
            raise ValueError("JSON line must decode to an object.")
        return dict(data)

    # BL602 serial log line
    if line.startswith("["):
        return parse_bl602_line(line)

    # key=value input
    pairs = {}
    for match in KV_RE.finditer(line):
        key = match.group("key")
        val = match.group("val")
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        pairs[key] = val

    if not pairs:
        raise ValueError(f"Unable to parse line: {line}")
    return pairs


def canonicalize(event: Dict[str, object]) -> Optional[Dict[str, object]]:
    now = time.time()
    device_time = event.pop("ts", event.pop("time", None))
    if isinstance(device_time, (int, float)):
        event_time = float(device_time)
    else:
        event_time = now

    severity = str(event.get("severity", "info")).lower()
    event["severity"] = severity
    event.setdefault("device_id", "unknown-device")
    event.setdefault("role", "unknown")
    event.setdefault("event_type", "UNSPECIFIED_EVENT")
    event.setdefault("host_bridge", socket.gethostname())

    # Drop generic noise events — don't pollute Splunk
    if event.get("event_type") == "UNSPECIFIED_EVENT":
        return None

    # Lift nested details if present as JSON string
    details = event.get("details")
    if isinstance(details, str):
        try:
            event["details"] = json.loads(details)
        except Exception:
            event["details"] = {"raw": details}

    return {"time": event_time, "event": event}


def make_hec_payload(raw_events: Iterable[Dict[str, object]], config: Config) -> List[Dict[str, object]]:
    payload = []
    for ev in raw_events:
        canon = canonicalize(ev)
        if canon is None:
            continue
        payload.append(
            {
                "time": canon["time"],
                "host": socket.gethostname(),
                "source": config.source,
                "sourcetype": config.sourcetype,
                "index": config.index,
                "event": canon["event"],
            }
        )
    return payload


def send_batch(batch: List[Dict[str, object]], config: Config, dry_run: bool = False) -> None:
    if not batch:
        return
    if dry_run:
        print(json.dumps(batch[0], indent=2))
        print(f"[dry-run] would send {len(batch)} event(s) to {config.hec_url}")
        return

    headers = {
        "Authorization": f"Splunk {config.token}",
        "Content-Type": "application/json",
    }
    body = "\n".join(json.dumps(item) for item in batch)
    response = requests.post(
        config.hec_url,
        data=body.encode("utf-8"),
        headers=headers,
        timeout=config.timeout_seconds,
        verify=config.verify_tls,
    )
    if response.status_code >= 300:
        raise RuntimeError(f"HEC returned {response.status_code}: {response.text}")
    print(f"sent {len(batch)} event(s)")


def iter_input(args: argparse.Namespace, env: Dict[str, str]) -> Iterable[str]:
    if args.input_file:
        with open(args.input_file, "r", encoding="utf-8") as f:
            for line in f:
                yield line
        return

    port = args.serial_port or env.get("SERIAL_PORT")
    baudrate = int(args.baudrate or env.get("SERIAL_BAUDRATE", "2000000"))
    if not port:
        raise SystemExit("Provide --input-file or --serial-port/SERIAL_PORT.")
    if serial is None:
        raise SystemExit("pyserial is required for serial mode.")
    with serial.Serial(port, baudrate=baudrate, timeout=1) as ser:
        print(f"reading from {port} @ {baudrate} baud...", file=sys.stderr)
        while True:
            raw = ser.readline()
            if not raw:
                continue
            yield raw.decode("utf-8", errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file",    default=None)
    parser.add_argument("--input-file",  default=None)
    parser.add_argument("--serial-port", default=None)
    parser.add_argument("--baudrate",    default=None)
    parser.add_argument("--batch-size",  type=int, default=50)
    parser.add_argument("--source",      default=None)
    parser.add_argument("--sourcetype",  default=None)
    parser.add_argument("--index",       default=None)
    parser.add_argument("--hec-url",     default=None)
    parser.add_argument("--hec-token",   default=None)
    parser.add_argument("--dry-run",     action="store_true")
    args = parser.parse_args()

    env = load_env(args.env_file)
    if not args.dry_run and env.get("SPLUNK_HEC_TOKEN") == "REPLACE_WITH_YOUR_SPLUNK_HEC_TOKEN":
        raise SystemExit("SPLUNK_HEC_TOKEN is still the placeholder. Use --dry-run or configure a real local .env.")
    config = get_config(env, args)

    batch_raw: List[Dict[str, object]] = []
    for line in iter_input(args, env):
        try:
            parsed = parse_line(line)
            if parsed:
                batch_raw.append(parsed)
        except Exception as exc:
            print(f"[warn] parse error: {exc}", file=sys.stderr)
            continue

        if len(batch_raw) >= args.batch_size:
            send_batch(make_hec_payload(batch_raw, config), config, dry_run=args.dry_run)
            batch_raw.clear()

    if batch_raw:
        send_batch(make_hec_payload(batch_raw, config), config, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
