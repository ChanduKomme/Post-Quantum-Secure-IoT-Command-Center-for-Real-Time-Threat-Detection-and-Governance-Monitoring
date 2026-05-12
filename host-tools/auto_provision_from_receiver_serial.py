#!/usr/bin/env python3
"""Auto-provision Sender security profile from Receiver serial output.

This removes the manual copy/paste step for both the Receiver public-key
fingerprint and the Receiver/Gateway IP address.

Recommended secure workflow:
  1. Flash/boot Receiver.
  2. Connect Receiver over USB serial.
  3. Run this script.
  4. Reset Receiver if the fingerprint/IP were already printed before the
     script started.
  5. Rebuild/flash Sender.

Default behavior is the safest practical option for changing DHCP addresses:
  - fingerprint is pinned into sender/sender/include/security_profile.h
  - gateway IP is left empty
  - broadcast discovery is enabled, so Sender finds Receiver at runtime
  - Receiver RNG pairing code is checked before writing the Sender profile

This avoids blind trust of a fingerprint received over Wi-Fi. The fingerprint
and pairing code come from the physical USB serial connection/OLED display on
the Receiver.
"""
from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVISION_SCRIPT = ROOT / "host-tools" / "provision_fingerprint.py"
DEFAULT_OUT = ROOT / "sender" / "sender" / "include" / "security_profile.h"

IP_RE = re.compile(r"(?:\[wifi\]\s*)?IP\s*:?\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", re.I)
# Flexible matcher for byte-formatted or compact 64-hex fingerprints.
HEX_RE = re.compile(r"[0-9A-Fa-f]{2}")
COMPACT_FP_RE = re.compile(r"\b[0-9A-Fa-f]{64}\b")
FP_LABEL_RE = re.compile(r"(?:PUBLIC\s+KEY\s+FINGERPRINT|FINGERPRINT_HEX|fingerprint)", re.I)
PAIRING_RE = re.compile(r"(?:PAIRING_CODE|Pairing\s*Code|Pair)\s*[:= ]\s*([0-9]{6})", re.I)


def ensure_pyserial() -> None:
    if importlib.util.find_spec("serial") is None:
        print("ERROR: pyserial is not installed.", file=sys.stderr)
        print("Install it with:", file=sys.stderr)
        print("  python3 -m pip install pyserial", file=sys.stderr)
        raise SystemExit(2)


def valid_ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version != 4:
        return None
    return str(ip)


def extract_ip(line: str) -> str | None:
    m = IP_RE.search(line)
    if not m:
        return None
    return valid_ip(m.group(1))


def extract_pairing_code(line: str) -> str | None:
    m = PAIRING_RE.search(line)
    if not m:
        return None
    return m.group(1)


def compact_hex(value: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value).upper()


def parse_fingerprint_from_window(lines: list[str]) -> str | None:
    joined = "\n".join(lines)
    compact = COMPACT_FP_RE.search(joined)
    if compact:
        return compact.group(0).upper()

    # Find a label, then collect byte-looking tokens after it and from following lines.
    for idx, line in enumerate(lines):
        if not FP_LABEL_RE.search(line):
            continue
        tail = line.split("=", 1)[1] if "=" in line else line
        candidate_text = "\n".join([tail] + lines[idx + 1 : idx + 4])
        bytes_found = HEX_RE.findall(candidate_text)
        if len(bytes_found) >= 32:
            return "".join(bytes_found[:32]).upper()
    return None


def read_receiver_serial(port: str, baud: int, timeout: int, echo: bool, require_pairing: bool) -> tuple[str, str | None, str | None]:
    ensure_pyserial()
    import serial  # type: ignore

    print(f"[INFO] Listening on Receiver serial port {port} @ {baud} baud")
    print("[INFO] Reset the Receiver now if IP/fingerprint/pairing code were printed before this script started.")

    deadline = time.time() + timeout
    recent: list[str] = []
    fingerprint: str | None = None
    ip: str | None = None
    pairing_code: str | None = None

    with serial.Serial(port, baudrate=baud, timeout=0.5) as ser:
        while time.time() < deadline:
            raw = ser.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            if echo:
                print(f"[SERIAL] {line}")

            recent.append(line)
            if len(recent) > 10:
                recent.pop(0)

            if ip is None:
                ip = extract_ip(line) or ip
                if ip:
                    print(f"[OK] Detected Receiver IP: {ip}")

            if pairing_code is None:
                pairing_code = extract_pairing_code(line)
                if pairing_code:
                    print(f"[OK] Detected Receiver RNG pairing code: {pairing_code}")

            if fingerprint is None and FP_LABEL_RE.search("\n".join(recent)):
                fingerprint = parse_fingerprint_from_window(recent)
                if fingerprint:
                    print(f"[OK] Detected Receiver fingerprint: {fingerprint}")

            have_pairing = (pairing_code is not None) or not require_pairing
            if fingerprint and ip and have_pairing:
                return fingerprint, ip, pairing_code

    missing = []
    if not fingerprint:
        missing.append("fingerprint")
    if not ip:
        missing.append("IP address")
    if require_pairing and not pairing_code:
        missing.append("RNG pairing code")
    raise TimeoutError(f"Timed out after {timeout}s waiting for Receiver {', '.join(missing)}")


def confirm_pairing_code(detected: str | None, expected: str | None, assume_yes: bool, require_pairing: bool) -> None:
    if not require_pairing:
        print("[WARN] Pairing-code check disabled by --no-pairing-check")
        return
    if not detected:
        raise RuntimeError("Receiver did not print a pairing code")
    if expected is not None:
        if expected != detected:
            raise RuntimeError(f"Pairing code mismatch: entered {expected}, detected {detected}")
        print("[OK] Pairing code confirmed from command line")
        return
    if assume_yes:
        print("[WARN] --yes used: accepting detected pairing code without manual confirmation")
        return

    print("\n[PAIRING] Check the six-digit code shown on the Receiver OLED/serial output.")
    entered = input(f"[PAIRING] Type pairing code {detected} to confirm provisioning: ").strip()
    if entered != detected:
        raise RuntimeError("Pairing code not confirmed. Sender profile was not changed.")
    print("[OK] Pairing code confirmed")


def call_provision(fingerprint: str, gateway_ip: str, sender_id: str, out: Path, allow_discovery: bool) -> None:
    cmd = [
        sys.executable,
        str(PROVISION_SCRIPT),
        "--fingerprint-hex",
        fingerprint,
        "--gateway-ip",
        gateway_ip,
        "--sender-id",
        sender_id,
        "--out",
        str(out),
    ]
    if allow_discovery:
        cmd.append("--allow-discovery")
    subprocess.run(cmd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Auto-detect Receiver fingerprint/IP from serial and provision Sender",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--receiver-port", "--port", required=True, help="Receiver serial port, e.g. /dev/ttyUSB0")
    parser.add_argument("--baud", type=int, default=2000000, help="Serial baudrate, default: 2000000")
    parser.add_argument("--timeout", type=int, default=90, help="Seconds to wait for IP/fingerprint, default: 90")
    parser.add_argument("--sender-id", default="0x53454E31", help="Sender ID, default: 0x53454E31")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"Output header, default: {DEFAULT_OUT}")
    parser.add_argument(
        "--ip-mode",
        choices=["discovery", "static"],
        default="discovery",
        help=(
            "discovery: leave PQC_GATEWAY_STATIC_IP empty and enable broadcast discovery. "
            "static: write detected IP into header. Default: discovery"
        ),
    )
    parser.add_argument("--echo", action="store_true", help="Print Receiver serial lines while reading")
    parser.add_argument("--pairing-code", help="Expected six-digit Receiver pairing code. If omitted, prompt for confirmation.")
    parser.add_argument("--yes", action="store_true", help="Lab/demo mode: accept detected pairing code without interactive typing")
    parser.add_argument("--no-pairing-check", action="store_true", help="Disable RNG pairing-code confirmation. Not recommended outside quick lab tests.")
    parser.add_argument("--rebuild", action="store_true", help="Run tools/build_firmware.sh --role sender after provisioning")
    args = parser.parse_args()

    require_pairing = not args.no_pairing_check
    try:
        fingerprint, detected_ip, detected_pairing_code = read_receiver_serial(
            args.receiver_port, args.baud, args.timeout, args.echo, require_pairing
        )
        confirm_pairing_code(detected_pairing_code, args.pairing_code, args.yes, require_pairing)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.ip_mode == "discovery":
        gateway_ip = ""
        allow_discovery = True
        print("[INFO] IP mode: discovery")
        print("[INFO] Sender header will store no fixed gateway IP.")
        print("[INFO] Sender will discover Receiver automatically using broadcast /pqkem-meta.")
    else:
        gateway_ip = detected_ip or ""
        allow_discovery = True
        print("[INFO] IP mode: static + discovery fallback")
        print(f"[INFO] Sender header will store detected gateway IP: {gateway_ip}")

    call_provision(
        fingerprint=fingerprint,
        gateway_ip=gateway_ip,
        sender_id=args.sender_id,
        out=args.out,
        allow_discovery=allow_discovery,
    )

    if args.rebuild:
        build_script = ROOT / "tools" / "build_firmware.sh"
        subprocess.run(["bash", str(build_script), "--role", "sender"], check=True)

    print("\n[DONE] Sender provisioning completed.")
    print(f"       Receiver fingerprint pinned: {fingerprint}")
    print(f"       Receiver IP observed:        {detected_ip}")
    if require_pairing:
        print(f"       RNG pairing code confirmed:  {detected_pairing_code}")
    if args.ip_mode == "discovery":
        print("       Runtime gateway IP:          auto-discovery enabled")
    else:
        print(f"       Runtime gateway IP:          {gateway_ip} with discovery fallback")
    print("\nNext command:")
    print("  bash tools/build_firmware.sh --role sender")
    print("  cd sender && blflash flash build_out/sender.bin --port /dev/ttyUSB1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
