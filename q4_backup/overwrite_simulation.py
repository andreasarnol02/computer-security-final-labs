#!/usr/bin/env python3
"""Model penimpaan massal yang TIDAK berbahaya, hanya untuk lab ujian di kontainer terisolasi.

Batas keras: hanya direktori yang diberikan sebagai argumen, hanya di bawah /lab_runtime/ dan hanya
bila berisi berkas penanda .lab_marker. Tidak ada jaringan, persistensi, penyebaran, enkripsi,
catatan tebusan, atau manipulasi proses. Penanda sendiri tidak pernah disentuh.
"""
import collections, os, stat, sys

ROOT, MARKER = "/lab_runtime/", ".lab_marker"


def is_allowed(d):
    real = os.path.realpath(d)   # realpath: symlink/".." tidak bisa keluar dari /lab_runtime/
    return real.startswith(ROOT) and os.path.isfile(os.path.join(real, MARKER))


def overwrite(d):
    done, refused = 0, collections.Counter()
    for dirpath, _, filenames in os.walk(d, onerror=lambda e: refused.update([f"unreadable directory: {e.strerror}"])):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if name == MARKER or not stat.S_ISREG(os.lstat(p).st_mode) or not os.path.realpath(p).startswith(ROOT):
                continue   # lewati penanda, symlink/non-reguler, dan apa pun di luar /lab_runtime/
            try:
                fd = os.open(p, os.O_WRONLY | os.O_NOFOLLOW)   # tanpa O_TRUNC: gagal bila tak punya izin tulis
                with os.fdopen(fd, "wb") as f:
                    f.write(os.urandom(os.fstat(fd).st_size)); f.flush(); os.fsync(fd)
                done += 1
            except OSError as e:
                refused.update([e.strerror])
    return done, refused


def main(args):
    if not args:
        sys.exit("usage: overwrite_simulation.py DIR [DIR ...]")
    rejected = [d for d in args if not is_allowed(d)]
    if rejected:
        print(f"REFUSING TO START: not under {ROOT} or missing {MARKER}: {rejected}", file=sys.stderr)
        sys.exit(2)
    for d in args:
        done, refused = overwrite(d)
        detail = ", ".join(f"{k}: {v}" for k, v in refused.items()) or "-"
        print(f"{d}: overwritten={done} refused={sum(refused.values())} ({detail})")


if __name__ == "__main__":
    main(sys.argv[1:])
