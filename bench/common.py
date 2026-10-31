"""Deterministic file IO for benchmark records.

Every artifact that later gets hashed goes through here, so line endings, key order,
float formatting and path separators are decided once rather than per call site.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "bench"
DIGEST_PREFIX = "sha256:"

# Floats are quantized before they reach a hashed artifact: repr length is stable across
# interpreters, but accumulated rounding is not, and BH-08 requires byte-identical tables.
QUANT = 6


class BenchError(Exception):
    """Fatal harness error; the CLI turns it into exit code 2."""


def quantize(value, digits=QUANT):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return value
    if isinstance(value, int):
        return value
    if value != value or value in (float("inf"), float("-inf")):
        raise BenchError("non-finite value in a hashed artifact: %r" % (value,))
    return round(float(value), digits)


def canonical_json(value):
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"


def write_text(path, text):
    """Atomic LF-only UTF-8 write. Never use Path.write_text for hashed artifacts."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=str(path.parent), delete=False,
        prefix=".%s.%d.tmp." % (path.name, os.getpid()))
    try:
        with handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, str(path))
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise
    return path


def write_json(path, value):
    return write_text(path, canonical_json(value))


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256_bytes(data):
    return DIGEST_PREFIX + hashlib.sha256(data).hexdigest()


def sha256_file(path, chunk=1 << 20):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return DIGEST_PREFIX + digest.hexdigest()


def rel_path(path):
    """POSIX-style path relative to the repo root, for refs stored in records.

    Absolute paths and drive letters are rejected: a record that names /mnt/c/... or
    C:\\Users\\... cannot be reproduced on another host, and would leak local layout.
    """
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        raise BenchError("path is outside the repository and not comparable across hosts: %s" % path)


def resolve(relref):
    path = (ROOT / str(relref)).resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError:
        raise BenchError("reference escapes the repository: %s" % relref)
    return path


def pure_rel_ok(ref):
    text = str(ref)
    if not text or text.startswith("/") or "\\" in text or ":" in text:
        return False
    parts = text.split("/")
    return not any(part in ("", ".", "..") for part in parts)


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def timestamp_tag():
    return time.strftime("%Y%m%d", time.gmtime())


def dir_size_mb(path):
    total = 0
    for root, _, files in os.walk(str(path)):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return round(total / (1024.0 * 1024.0), QUANT)
