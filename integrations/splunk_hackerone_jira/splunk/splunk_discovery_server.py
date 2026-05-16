#!/usr/bin/env python3
"""Robust PQC-IoT Splunk Discovery Server.

Compatibility markers: proactive_broadcast, get_global_ipv4_interfaces.

Boards discover the Splunk HEC host over UDP/9998. This server replies with:
    PQC_SPLUNK_HOST:<advertise-ip>:<hec-port>

It ignores its own proactive broadcasts to avoid response loops.
"""
import argparse
import socket
import threading
import time

MAGIC_PREFIX = "PQC_SPLUNK_HOST"   


def get_primary_lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def calc_broadcast(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) != 4:
        return "255.255.255.255"
    return f"{parts[0]}.{parts[1]}.{parts[2]}.255"


def get_global_ipv4_interfaces():
    """Compatibility helper: returns the primary detected interface IP."""
    return [get_primary_lan_ip()]


def proactive_broadcast(sock: socket.socket, advertise_ip: str, hec_port: int, udp_port: int, interval: float) -> None:
    return broadcast_loop(sock, advertise_ip, hec_port, udp_port, interval)


def broadcast_loop(sock: socket.socket, advertise_ip: str, hec_port: int, udp_port: int, interval: float) -> None:
    msg = f"{MAGIC_PREFIX}:{advertise_ip}:{hec_port}".encode()
    targets = [("255.255.255.255", udp_port), (calc_broadcast(advertise_ip), udp_port)]
    while True:
        for target in targets:
            try:
                sock.sendto(msg, target)
            except Exception:
                pass
        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="PQC IoT Splunk Discovery Server")
    parser.add_argument("--listen-ip", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9998)
    parser.add_argument("--hec-port", type=int, default=8088)
    parser.add_argument("--advertise-ip", default=None)
    parser.add_argument("--proactive", action="store_true", help="periodically broadcast Splunk host info")
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()

    advertise_ip = args.advertise_ip or get_primary_lan_ip()
    response_text = f"{MAGIC_PREFIX}:{advertise_ip}:{args.hec_port}"
    response = response_text.encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind((args.listen_ip, args.port))

    print("=" * 64)
    print("PQC-IoT Splunk Discovery Server")
    print("=" * 64)
    print(f"Listening on      : {args.listen_ip}:{args.port}")
    print(f"Advertising IP   : {advertise_ip}")
    print(f"Splunk HEC port  : {args.hec_port}")
    print(f"Response message : {response_text}")
    print(f"Proactive mode   : {'ON' if args.proactive else 'OFF'}")
    print("=" * 64)
    print("Waiting for board discovery packets...")
    print("Press Ctrl+C to stop.\n")

    if args.proactive:
        threading.Thread(
            target=broadcast_loop,
            args=(sock, advertise_ip, args.hec_port, args.port, args.interval),
            daemon=True,
        ).start()

    while True:
        data, addr = sock.recvfrom(2048)
        text = data.decode(errors="replace").strip()
        client_ip, client_port = addr

        # Critical: ignore our own proactive discovery advertisements.
        if text.startswith(MAGIC_PREFIX):
            continue

        print(f"[{time.strftime('%H:%M:%S')}] board request from {client_ip}:{client_port} msg={text!r}")
        sock.sendto(response, addr)
        print(f"[{time.strftime('%H:%M:%S')}] unicast response -> {client_ip}:{client_port} {response_text}")
        try:
            directed = calc_broadcast(advertise_ip)
            sock.sendto(response, (directed, args.port))
            print(f"[{time.strftime('%H:%M:%S')}] broadcast response -> {directed}:{args.port}")
        except Exception as exc:
            print(f"[WARN] broadcast response failed: {exc}")


if __name__ == "__main__":
    main()
