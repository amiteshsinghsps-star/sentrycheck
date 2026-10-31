"""Download a checksum-verified, local k3s binary for disposable API-server tests.

This does not install a service or modify an existing cluster.
"""
import argparse
import hashlib
from pathlib import Path
import re
import urllib.request


def fetch(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "sentrycheck-test-setup/0.1"}), timeout=90)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="v1.35.0+k3s1")
    parser.add_argument("--out", type=Path, default=Path(".cache/linux/bin"))
    args = parser.parse_args()
    if not re.fullmatch(r"v1\.\d+\.\d+\+k3s\d+", args.version):
        raise ValueError("invalid k3s version")
    base = "https://github.com/k3s-io/k3s/releases/download/" + args.version + "/"
    with fetch(base + "sha256sum-amd64.txt") as response:
        sums = response.read(1024 * 1024).decode()
    expected = next((line.split()[0] for line in sums.splitlines() if len(line.split()) == 2 and line.split()[1].lstrip("*./") == "k3s"), None)
    if not expected:
        raise ValueError("release lacks k3s checksum")
    args.out.mkdir(parents=True, exist_ok=True)
    destination = args.out / "k3s"
    if destination.is_file():
        with destination.open("rb") as old:
            if hashlib.file_digest(old, "sha256").hexdigest() == expected:
                print("Verified existing", args.version, expected)
                return
        raise ValueError("existing binary differs; choose a fresh output directory")
    temporary = args.out / "k3s.download"
    digest, total = hashlib.sha256(), 0
    try:
        with fetch(base + "k3s") as source, temporary.open("wb") as output:
            while block := source.read(1024 * 1024):
                total += len(block)
                if total > 200 * 1024 * 1024:
                    raise ValueError("k3s download exceeds size budget")
                digest.update(block)
                output.write(block)
        if digest.hexdigest() != expected:
            raise ValueError("k3s checksum mismatch")
        temporary.replace(destination)
        destination.chmod(0o755)
    finally:
        temporary.unlink(missing_ok=True)
    print("Verified", args.version, total, "bytes; sha256", expected)


if __name__ == "__main__":
    main()
