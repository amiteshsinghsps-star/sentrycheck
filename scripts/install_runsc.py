"""Install checksum-verified runsc and the release's gvisor-bin companions.

Archives are streamed. Identical existing files are reused; new files are staged
until the complete archive checksum is verified. No registry/runtime is configured.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import urllib.request

def request(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "sentrycheck-setup/0.1"}), timeout=90)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="20260921.0")
    parser.add_argument("--arch", choices=["x86_64", "aarch64"], default="x86_64")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--list-assets", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"\d{8}\.\d+", args.version):
        raise ValueError("invalid runtime version")
    args.out.mkdir(parents=True, exist_ok=True)
    base = "https://github.com/google/gvisor/releases/download/release-" + args.version + "/"
    name = "gvisor-" + args.arch + ".tar.bz2"
    with request(base + "SHA256SUMS") as response:
        sums = response.read(1024 * 1024).decode()
    expected = next((line.split()[0] for line in sums.splitlines() if len(line.split()) == 2 and line.split()[1].lstrip("*") == name), None)
    if expected is None:
        raise ValueError("release lacks the selected archive checksum")

    class HashingReader:
        def __init__(self, source):
            self.source, self.hash, self.count = source, hashlib.sha256(), 0
        def read(self, size=-1):
            data = self.source.read(size)
            self.count += len(data)
            if self.count > 300 * 1024 * 1024:
                raise ValueError("archive exceeds size budget")
            self.hash.update(data)
            return data

    hashes, staged, unchanged = {}, [], []
    with tempfile.TemporaryDirectory(prefix=".release-", dir=args.out) as temporary:
        temporary = Path(temporary)
        with request(base + name) as source:
            stream = HashingReader(source)
            with tarfile.open(fileobj=stream, mode="r|bz2") as archive:
                for member in archive:
                    path = PurePosixPath(member.name)
                    if not member.isfile() or path.is_absolute():
                        continue
                    parts = path.parts
                    wanted = parts in [("runsc",), ("containerd-shim-runsc-v1",)] or len(parts) == 2 and parts[0] == "gvisor-bin" and re.fullmatch(r"[A-Za-z0-9_-]+", parts[1])
                    if not wanted:
                        continue
                    key = str(path)
                    if key in hashes or member.size > 300 * 1024 * 1024:
                        raise ValueError("duplicate or oversized runtime component")
                    print(key, member.size, "bytes", flush=True)
                    destination = args.out.joinpath(*parts)
                    existing = None
                    if destination.is_file() and not destination.is_symlink() and destination.stat().st_size == member.size:
                        with destination.open("rb") as old:
                            existing = hashlib.file_digest(old, "sha256").hexdigest()
                    content_hash = hashlib.sha256()
                    stage = temporary.joinpath(*parts)
                    output = None
                    if not args.list_assets and existing is None:
                        required = member.size + 32 * 1024 * 1024
                        if required > shutil.disk_usage(args.out).free:
                            raise ValueError(f"need {required} free bytes to stage {key} with a 32 MiB reserve")
                        stage.parent.mkdir(parents=True, exist_ok=True)
                        output = stage.open("wb")
                    try:
                        content = archive.extractfile(member)
                        while chunk := content.read(1024 * 1024):
                            content_hash.update(chunk)
                            if output:
                                output.write(chunk)
                    finally:
                        if output:
                            output.close()
                    hashes[key] = content_hash.hexdigest()
                    if args.list_assets:
                        continue
                    if existing is not None:
                        if existing != hashes[key]:
                            raise ValueError("existing component differs; select a fresh --out directory: " + key)
                        unchanged.append(key)
                    else:
                        staged.append((stage, destination))
            while stream.read(1024 * 1024):
                pass
            if "runsc" not in hashes or stream.hash.hexdigest() != expected:
                raise ValueError("archive checksum mismatch or missing runsc")
        if args.list_assets:
            return
        for stage, destination in staged:
            destination.parent.mkdir(parents=True, exist_ok=True)
            stage.replace(destination)
            destination.chmod(0o755)
        for key in unchanged:
            args.out.joinpath(*PurePosixPath(key).parts).chmod(0o755)
    manifest = {"version": args.version, "architecture": args.arch, "archive_sha256": expected, "components": hashes}
    (args.out / "install-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("Installed verified gVisor release", args.version, "with", len(hashes), "components", flush=True)

if __name__ == "__main__":
    main()
