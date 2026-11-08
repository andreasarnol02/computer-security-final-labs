"""Cadangan terenkripsi AES-256-GCM dengan izin baca-saja (lab ujian, data sintetis)."""
import argparse, hashlib, io, os, pathlib, stat, subprocess, sys, tarfile, tempfile, time
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"RSBK1"                           # penanda format; bersama timestamp menjadi AAD
HDR_LEN, NONCE_LEN = len(MAGIC) + 14, 12   # timestamp YYYYmmddHHMMSS (UTC); nonce 96-bit acak (NIST SP 800-38D)


def die(code, message):
    print(message, file=sys.stderr)
    sys.exit(code)


def load_key(path, dest=None):
    # Aturan kunci: tepat 32 byte, mode 0400/0600, tidak di dalam dest_dir. Isi kunci tak pernah dicetak.
    try:
        with open(path, "rb") as f:
            mode, key = stat.S_IMODE(os.fstat(f.fileno()).st_mode), f.read(33)
    except OSError as e:
        die(2, f"DENIED: key cannot be read ({e.strerror})")
    if mode not in (0o400, 0o600) or len(key) != 32:
        die(2, f"DENIED: key must be exactly 32 bytes with mode 0400/0600 (now mode {mode:04o}, length {len(key)})")
    if dest and os.path.commonpath([os.path.realpath(path), os.path.realpath(dest)]) == os.path.realpath(dest):
        die(2, "DENIED: key file is inside the backup destination directory")
    return key


def write_atomic(path, data):   # berkas sementara di direktori yang sama -> fsync -> os.replace (atomik)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)   # produksi: fsync juga direktorinya agar rename durabel
    finally:
        pathlib.Path(tmp).unlink(missing_ok=True)


def make_immutable(path):   # chattr +i butuh CAP_LINUX_IMMUTABLE + filesystem ext4/xfs; tidak boleh crash
    try:
        r = subprocess.run(["chattr", "+i", path], capture_output=True, text=True)
        ok, reason = r.returncode == 0, r.stderr.strip() or f"code {r.returncode}"
    except OSError as e:
        ok, reason = False, f"chattr unavailable ({e.strerror})"
    print(f"chattr +i {os.path.basename(path)}: " + ("SUCCESS" if ok else f"FAILED ({reason}) - WARNING: only the 0400 permission applies"))


def open_archive(path, key):   # header (magic+timestamp) = AAD: ubahan metadata ikut terdeteksi
    raw = pathlib.Path(path).read_bytes()
    header, nonce, ct = raw[:HDR_LEN], raw[HDR_LEN:HDR_LEN + NONCE_LEN], raw[HDR_LEN + NONCE_LEN:]
    if not header.startswith(MAGIC) or len(ct) < 16:
        die(3, "FAILED: header not recognized or file truncated. The archive cannot be trusted.")
    try:
        return AESGCM(key).decrypt(nonce, ct, header)
    except InvalidTag:
        die(3, "AUTHENTICATION FAILED: archive corrupted/modified (body or header), or wrong key. Do not restore.")


def cmd_backup(a):
    key = load_key(a.key_file, a.dest_dir)
    buf = io.BytesIO()   # CATATAN: seluruh arsip diproses di memori. Produksi WAJIB memecah (chunk/stream)
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:   # dengan nonce unik per potongan.
        tar.add(a.src_dir, arcname=os.path.basename(os.path.abspath(a.src_dir)))
    ts = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    header, nonce = MAGIC + ts.encode(), os.urandom(NONCE_LEN)
    blob = header + nonce + AESGCM(key).encrypt(nonce, buf.getvalue(), header)
    os.makedirs(a.dest_dir, exist_ok=True)
    if not os.access(a.dest_dir, os.W_OK):
        os.chmod(a.dest_dir, 0o700)   # dibuka sementara oleh pemilik: batas izin baca-saja
    enc = os.path.join(a.dest_dir, ts + ".tar.gz.enc")
    if os.path.exists(enc):
        die(1, f"DENIED: {enc} already exists (not overwritten)")
    write_atomic(enc, blob)
    write_atomic(enc + ".sha256", f"{hashlib.sha256(blob).hexdigest()}  {os.path.basename(enc)}\n".encode())
    for p in (enc, enc + ".sha256"):
        os.chmod(p, 0o400)
        make_immutable(p)
    os.chmod(a.dest_dir, 0o500)
    print(f"Archive: {enc} ({len(blob)} bytes); file 0400, directory 0500")


def cmd_restore(a):   # verify = daftar anggota; restore = ekstraksi aman (filter "data")
    data = open_archive(a.file, load_key(a.key_file))
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        if a.cmd == "restore":
            os.makedirs(a.out_dir, exist_ok=True)
            tar.extractall(a.out_dir, filter="data")
            print(f"OK: restored to {a.out_dir}")
        else:
            print("Archive members:", *tar.getnames(), sep="\n  ")
            print("OK: authentication succeeded")


def main():
    p = argparse.ArgumentParser(description="Read-only AES-256-GCM backup")
    sp = p.add_subparsers(dest="cmd", required=True)
    for name, arguments, fn in (("backup", ("src_dir", "dest_dir"), cmd_backup),
                                ("verify", ("file",), cmd_restore), ("restore", ("file", "out_dir"), cmd_restore)):
        s = sp.add_parser(name)
        for x in arguments:
            s.add_argument(x)
        s.add_argument("--key-file", required=True)
        s.set_defaults(fn=fn)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
