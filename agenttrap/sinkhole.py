"""Runs INSIDE a container on the sandbox's private network; standard library only.

It is the only thing the sandbox can talk to. It answers every DNS lookup with its own address and
accepts connections on ports 80 and 443, logging what it sees as JSON lines on stdout:

  {"kind": "dns",  "name": "cfg-cdn.io"}
  {"kind": "http", "method": "POST", "host": "...", "path": "...", "headers": {...}, "body": "..."}
  {"kind": "tls",  "sni": "cfg-cdn.io"}

Plain HTTP is read in full (so a canary sent in the clear is visible) and answered with a fixture
payload when one is configured. HTTPS is NOT decrypted: only the server name from the TLS
handshake is logged. Nothing is ever forwarded anywhere, so there is nothing to exfiltrate to.

Environment: SINKHOLE_IP (own address), SINKHOLE_SERVED (JSON: URL -> response body).
"""

from __future__ import annotations

import json
import os
import socket
import threading

IP = os.environ.get("SINKHOLE_IP", "")
SERVED: dict[str, str] = json.loads(os.environ.get("SINKHOLE_SERVED", "{}"))
MAX_BODY = 1_000_000
_log_lock = threading.Lock()


def log(**event: object) -> None:
    with _log_lock:
        print(json.dumps(event), flush=True)


# ---- DNS -------------------------------------------------------------------------------------


def dns_name(packet: bytes) -> tuple[str, int]:
    """The queried name and the offset just past the question section."""
    labels, i = [], 12
    while packet[i]:
        labels.append(packet[i + 1 : i + 1 + packet[i]].decode(errors="replace"))
        i += packet[i] + 1
    return ".".join(labels), i + 5


def serve_dns() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    while True:
        packet, addr = sock.recvfrom(512)
        try:
            name, end = dns_name(packet)
            qtype = int.from_bytes(packet[end - 4 : end - 2], "big")
        except (IndexError, ValueError):
            continue
        log(kind="dns", name=name)
        header = packet[:2] + b"\x81\x80" + packet[4:6]
        question = packet[12:end]
        if qtype == 1:  # A record: point everything at ourselves
            answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(IP)
            sock.sendto(header + b"\x00\x01\x00\x00\x00\x00" + question + answer, addr)
        else:  # AAAA etc.: no records
            sock.sendto(header + b"\x00\x00\x00\x00\x00\x00" + question, addr)


# ---- HTTP (plain text only) --------------------------------------------------------------------


def read_http(conn: socket.socket) -> dict[str, object] | None:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    try:
        method, path, _version = lines[0].split(" ", 2)
    except ValueError:
        return None
    headers = {k.strip(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
    wanted = min(int(headers.get("Content-Length", "0") or 0), MAX_BODY)
    while len(body) < wanted:
        chunk = conn.recv(4096)
        if not chunk:
            break
        body += chunk
    host = headers.get("Host", "")
    return {"method": method, "host": host, "path": path, "headers": headers,
            "body": body.decode(errors="replace")}  # fmt: skip


def handle_http(conn: socket.socket) -> None:
    with conn:
        conn.settimeout(5)
        try:
            request = read_http(conn)
        except OSError:
            return
        if request is None:
            return
        log(kind="http", **request)
        payload = SERVED.get(f"http://{request['host']}{request['path']}", "").encode()
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
            + f"Content-Length: {len(payload)}\r\n\r\n".encode()
            + payload
        )


# ---- TLS (server name only) ----------------------------------------------------------------------


def sni_from_client_hello(data: bytes) -> str | None:
    """The server name in a TLS ClientHello, or None. The handshake is never completed."""
    try:
        if data[0] != 0x16:
            return None
        i = 43  # record header (5) + handshake header (4) + version (2) + random (32)
        i += 1 + data[i]  # session id
        i += 2 + int.from_bytes(data[i : i + 2], "big")  # cipher suites
        i += 1 + data[i]  # compression methods
        end = i + 2 + int.from_bytes(data[i : i + 2], "big")
        i += 2
        while i + 4 <= end:
            ext_type = int.from_bytes(data[i : i + 2], "big")
            ext_len = int.from_bytes(data[i + 2 : i + 4], "big")
            if ext_type == 0:  # server_name
                name_len = int.from_bytes(data[i + 7 : i + 9], "big")
                return data[i + 9 : i + 9 + name_len].decode(errors="replace")
            i += 4 + ext_len
    except IndexError:
        pass
    return None


def handle_tls(conn: socket.socket) -> None:
    with conn:
        conn.settimeout(5)
        try:
            hello = conn.recv(4096)
        except OSError:
            return
        log(kind="tls", sni=sni_from_client_hello(hello))


def serve_tcp(port: int, handler) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    while True:
        conn, _ = sock.accept()
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def main() -> None:
    for target, args in (
        (serve_dns, ()),
        (serve_tcp, (80, handle_http)),
        (serve_tcp, (443, handle_tls)),
    ):
        threading.Thread(target=target, args=args, daemon=True).start()
    log(kind="ready")
    threading.Event().wait()


if __name__ == "__main__":
    main()
