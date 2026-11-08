#!/usr/bin/env python3
"""Lab simulasi perangkat IoMT (mock) - hanya untuk audit di loopback, data sintetis.

Perangkat:
  127.0.10.11 pompa infus       : Telnet (23) + HTTP (80), admin/admin
  127.0.10.12 pemantau jantung  : HTTP (80), kredensial non-default
  127.0.10.13 gateway           : Telnet (23), kredensial default ditolak
  127.0.10.14 perangkat hardened: hanya TCP 443 (accept-then-close, bukan TLS)

Flag --hardened mensimulasikan remediasi pada .11: Telnet dicabut, HTTP menolak admin/admin.
"""
import argparse
import base64
import socket
import threading

HOST_PUMP = "127.0.10.11"
HOST_MONITOR = "127.0.10.12"
HOST_GATEWAY = "127.0.10.13"
HOST_HARDENED = "127.0.10.14"


def serve(host, port, handler, backlog=16):
    """Buat server socket threaded sederhana; satu thread per koneksi."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(backlog)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=_handle_safely, args=(handler, conn), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv


def _handle_safely(handler, conn):
    try:
        handler(conn)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _recv_line(conn):
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace").strip("\r\n")


def telnet_handler(banner, valid_user, valid_pass):
    """Telnet-like: banner lalu prompt login/password, tanpa negosiasi IAC asli."""
    def handler(conn):
        conn.sendall((banner + "\r\n").encode())
        conn.sendall(b"login: ")
        user = _recv_line(conn)
        conn.sendall(b"Password: ")
        pw = _recv_line(conn)
        if valid_user is not None and user == valid_user and pw == valid_pass:
            conn.sendall(b"$ ")
        else:
            conn.sendall(b"Login incorrect\r\n")
    return handler


def _recv_http_request(conn):
    conn.settimeout(2)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace")


def _parse_basic_auth(request_text):
    for line in request_text.split("\r\n"):
        if line.lower().startswith("authorization:"):
            return line.split(":", 1)[1].strip()
    return None


def http_handler(valid_user, valid_pass, always_reject=False):
    """HTTP minimal dengan Basic auth; selalu menolak bila always_reject=True."""
    def handler(conn):
        req = _recv_http_request(conn)
        auth = _parse_basic_auth(req)
        ok = False
        if auth and not always_reject and auth.lower().startswith("basic "):
            try:
                raw = base64.b64decode(auth.split(" ", 1)[1])
                user, _, pw = raw.decode().partition(":")
                ok = user == valid_user and pw == valid_pass
            except (ValueError, UnicodeDecodeError):
                ok = False
        if ok:
            body = b"OK"
            status = b"200 OK"
        else:
            body = b"Unauthorized"
            status = b"401 Unauthorized"
        headers = b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n"
        if not ok:
            headers += b'WWW-Authenticate: Basic realm="iomt"\r\n'
        conn.sendall(b"HTTP/1.1 " + status + b"\r\n" + headers + b"\r\n" + body)
    return handler


def closer_handler(conn):
    """Perangkat hardened: terima koneksi lalu tutup, tanpa protokol apa pun."""


def main():
    parser = argparse.ArgumentParser(description="Mock IoMT device lab (loopback-only)")
    parser.add_argument("--hardened", action="store_true",
                         help="simulate remediation on .11 (Telnet removed, HTTP admin/admin rejected)")
    args = parser.parse_args()

    if not args.hardened:
        serve(HOST_PUMP, 23, telnet_handler("PUMP-A1 fw 1.2.0", "admin", "admin"))
    serve(HOST_PUMP, 80, http_handler(
        None if args.hardened else "admin",
        None if args.hardened else "admin",
        always_reject=args.hardened,
    ))
    serve(HOST_MONITOR, 80, http_handler("monitor-ops", "Xk9-synthetic-Str0ng"))
    serve(HOST_GATEWAY, 23, telnet_handler("GATEWAY fw 2.0", None, None))
    serve(HOST_HARDENED, 443, closer_handler)

    print(f"iomt_lab ready (hardened={args.hardened})", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
