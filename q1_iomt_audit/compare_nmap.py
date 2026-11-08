#!/usr/bin/env python3
"""Bandingkan temuan JSON audit_iomt dengan hasil nmap (oracle independen).

Dipakai oleh run.sh untuk memverifikasi bahwa himpunan (host, port) yang
dilaporkan audit_iomt.py sama persis dengan himpunan port terbuka menurut nmap.
"""
import json
import re
import sys


def read_json_pairs(path):
    # Pasangan (host, port) dari laporan JSON audit_iomt.
    with open(path) as f:
        data = json.load(f)
    return {(t["host"], t["port"]) for t in data}


def read_nmap_gnmap(path):
    """Ekstrak pasangan (host, port) berstatus 'open' dari berkas -oG nmap."""
    pairs = set()
    with open(path) as f:
        for line in f:
            if not line.startswith("Host:") or "Ports:" not in line:
                continue
            host = line.split()[1]
            for port_str, state, _proto in re.findall(r"(\d+)/(open|closed|filtered)/(\w+)", line):
                if state == "open":
                    pairs.add((host, int(port_str)))
    return pairs


def main():
    if len(sys.argv) != 3:
        print("usage: compare_nmap.py <report.json> <nmap.gnmap>", file=sys.stderr)
        return 2
    from_json = read_json_pairs(sys.argv[1])
    from_nmap = read_nmap_gnmap(sys.argv[2])
    if from_json == from_nmap:
        print(f"MATCH: {len(from_json)} (host, port) pairs identical to nmap.")
        return 0
    print("MISMATCH")
    only_json = sorted(from_json - from_nmap)
    only_nmap = sorted(from_nmap - from_json)
    if only_json:
        print("Only in audit_iomt report:", only_json)
    if only_nmap:
        print("Only in nmap:", only_nmap)
    return 1


if __name__ == "__main__":
    sys.exit(main())
