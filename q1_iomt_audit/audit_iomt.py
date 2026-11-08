#!/usr/bin/env python3
"""Audit port/layanan IoMT - defensif, report-only, lab tertutup."""
import argparse, base64, ipaddress, json, socket, sys, time
from collections import Counter; from concurrent.futures import ThreadPoolExecutor

TIMEOUT, MAX_WORKERS, MAX_ATTEMPTS_PER_SERVICE = 0.5, 16, 3
PORTS = {23: "Telnet", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-alt"}
CREDS = [("admin", "admin"), ("root", "root"), ("admin", "1234")]  # kredensial default sintetis
RFC1918 = [ipaddress.ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]  # RFC 1918 s3


def check_scope(cidr, authorized):
    # Pagar lingkup: pesan penolakan (str), atau None jika audit boleh jalan.
    # Wajib izin, hanya loopback/RFC 1918, minimal /24 (NIST SP 800-115).
    if not authorized: return "DENIED: --authorized is required."
    try: net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e: return f"DENIED: invalid CIDR ({e})."
    if net.version != 4 or not (net.is_loopback or any(net.subnet_of(r) for r in RFC1918)):
        return "DENIED: target is not loopback or RFC1918, outside lab scope."
    return "DENIED: prefix shorter than /24 is not allowed." if net.prefixlen < 24 else None


def try_telnet(ip, port):
    # Coba tiap kredensial default; koneksi baru per percobaan (hindari lockout).
    for user, pw in CREDS[:MAX_ATTEMPTS_PER_SERVICE]:
        try:
            with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
                s.settimeout(TIMEOUT)
                s.recv(256); s.sendall((user + "\r\n").encode())  # lewati "login: "
                s.recv(256); s.sendall((pw + "\r\n").encode())  # lewati "Password: "
                reply = s.recv(256).decode(errors="replace")
        except OSError: return None
        if "$" in reply: return (user, pw)
        time.sleep(0.2)
    return None


def _http_get(ip, port, token=None):
    # GET mentah lewat raw socket; kembalikan kode status HTTP atau None.
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
            req = f"GET / HTTP/1.1\r\nHost: {ip}\r\n" + (f"Authorization: Basic {token}\r\n" if token else "")
            s.sendall((req + "Connection: close\r\n\r\n").encode())
            s.settimeout(TIMEOUT); data = s.recv(512).decode(errors="replace")
        return data.split(" ")[1] if data.startswith("HTTP/") else None
    except (OSError, IndexError): return None


def try_http(ip, port):
    # Tanpa autentikasi dulu, lalu kredensial default. -> (no_auth, credentials)
    if _http_get(ip, port) == "200": return True, None
    for user, pw in CREDS[:MAX_ATTEMPTS_PER_SERVICE]:
        token = base64.b64encode(f"{user}:{pw}".encode()).decode()
        if _http_get(ip, port, token) == "200": return False, (user, pw)
        time.sleep(0.2)
    return False, None


def classify_risk(service, credentials, no_auth):
    # Report-only, tidak memblokir. Kata sandi tidak pernah dicetak apa adanya.
    if credentials is not None: return "CRITICAL", f"Default credentials accepted ({credentials[0]}/***)."
    if no_auth: return "CRITICAL", "HTTP management service without authentication."
    if service == "Telnet": return "HIGH", "Telnet open (cleartext), default credentials rejected."
    if service in ("HTTP", "HTTP-alt"): return "MEDIUM", "HTTP without TLS, default credentials rejected."
    return "INFO", "Only port 443 open."


def scan_host(ip):
    findings = []
    for port, service in PORTS.items():
        try:
            with socket.create_connection((ip, port), timeout=TIMEOUT) as s:
                s.settimeout(TIMEOUT)
                try: banner = s.recv(256).decode(errors="replace").strip().split("\r\n")[0]
                except OSError: banner = ""
        except OSError: continue
        credentials, no_auth = None, False
        if service == "Telnet": credentials = try_telnet(ip, port)
        elif service in ("HTTP", "HTTP-alt"): no_auth, credentials = try_http(ip, port)
        risk, finding = classify_risk(service, credentials, no_auth)
        findings.append({"host": ip, "port": port, "service": service, "banner": banner, "risk": risk, "finding": finding})
    return findings


def print_report(all_findings):
    print(f"{'Host':<14}{'Port':<6}{'Service':<10}{'Banner':<24}{'Risk':<10}Finding")
    for t in all_findings:
        print(f"{t['host']:<14}{t['port']:<6}{t['service']:<10}{t['banner'][:22]:<24}{t['risk']:<10}{t['finding']}")
    summary = Counter(t["risk"] for t in all_findings)
    print("Summary:", ", ".join(f"{k}={v}" for k, v in sorted(summary.items())))


def main(argv=None):
    ap = argparse.ArgumentParser(description="IoMT port/service audit (closed lab)")
    for flag, kw in (("--cidr", {"required": True}), ("--authorized", {"action": "store_true"}), ("--json-out", {})):
        ap.add_argument(flag, **kw)
    args = ap.parse_args(argv)
    denial = check_scope(args.cidr, args.authorized)
    if denial: print(denial, file=sys.stderr); return 2
    host_list = [str(h) for h in ipaddress.ip_network(args.cidr, strict=False).hosts()]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        all_findings = [t for host_findings in ex.map(scan_host, host_list) for t in host_findings]
    print_report(all_findings)
    if args.json_out:
        with open(args.json_out, "w") as f: json.dump(all_findings, f, indent=2, ensure_ascii=False)
    return 1 if any(t["risk"] == "CRITICAL" for t in all_findings) else 0


if __name__ == "__main__":
    sys.exit(main())
