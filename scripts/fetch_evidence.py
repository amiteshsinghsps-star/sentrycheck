"""Fetch primary sources and record content hashes; never infer release support from live docs."""
import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import sys
import urllib.request
from datetime import datetime, timezone

SOURCES = {
    "gvisor-compatibility": "https://gvisor.dev/docs/user_guide/compatibility/",
    "gvisor-amd64": "https://gvisor.dev/docs/user_guide/compatibility/linux/amd64/",
    "gvisor-releases": "https://api.github.com/repos/google/gvisor/releases?per_page=3",
    "kubernetes-validation": "https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/",
    "kubernetes-mutation": "https://kubernetes.io/docs/reference/access-authn-authz/mutating-admission-policy/",
    "kubernetes-runtimeclass": "https://kubernetes.io/docs/concepts/containers/runtime-class/",
    "gvisor-performance": "https://gvisor.dev/docs/architecture_guide/performance/",
    "gvisor-filesystem": "https://gvisor.dev/docs/user_guide/filesystem/",
    "release-ref": "https://api.github.com/repos/google/gvisor/git/ref/tags/release-20260921.0",
    "release-tag": "https://api.github.com/repos/google/gvisor/git/tags/5a15761b5dcfe8ca10c7e8eaf5f1ae57b7c059f5",
    "release-tree": "https://api.github.com/repos/google/gvisor/git/trees/release-20260921.0?recursive=1",
    "release-amd64": "https://raw.githubusercontent.com/google/gvisor/release-20260921.0/pkg/sentry/syscalls/linux/linux64.go",
    "release-compatibility": "https://raw.githubusercontent.com/google/gvisor/26f3455a4cb9a377354c33aeac049080a077c79c/g3doc/user_guide/compatibility.md",
    "release-strace": "https://raw.githubusercontent.com/google/gvisor/26f3455a4cb9a377354c33aeac049080a077c79c/pkg/sentry/strace/strace.go",
    "release-config": "https://raw.githubusercontent.com/google/gvisor/26f3455a4cb9a377354c33aeac049080a077c79c/runsc/config/config.go",
    "release-sidecar-install": "https://raw.githubusercontent.com/google/gvisor/26f3455a4cb9a377354c33aeac049080a077c79c/runsc/cmd/install_sidecars.go",
    "release-containerd": "https://raw.githubusercontent.com/google/gvisor/26f3455a4cb9a377354c33aeac049080a077c79c/g3doc/user_guide/containerd/quick_start.md",
}

def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "sentrycheck-evidence/0.1"})
    with urllib.request.urlopen(request, timeout=35) as response:
        data = response.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024:
            raise ValueError("source exceeds size limit")
        return data

def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("docs/evidence"))
    parser.add_argument("--source", choices=SOURCES, action="append")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    manifest_path = args.out / "sources.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    failures = []
    for name in args.source or SOURCES:
        url = SOURCES[name]
        try:
            data = fetch(url)
            text = data.decode("utf-8")
            if not name.endswith("releases") and not name.startswith("release-"):
                text = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", "", text, flags=re.S)
                text = html.unescape(re.sub(r"<[^>]+>", " ", text))
                text = re.sub(r"[ \t]+", " ", text)
                text = re.sub(r"\n\s*\n", "\n\n", text)
            (args.out / (name + ".txt")).write_text(text, encoding="utf-8", newline="\n")
            manifest[name] = {"url": url, "retrieved_at": datetime.now(timezone.utc).isoformat(),
                              "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            print(name, len(data), manifest[name]["sha256"])
        except Exception as exc:
            failures.append(name)
            print(name, "FAILED", str(exc), file=sys.stderr)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    return int(bool(failures))

if __name__ == "__main__":
    raise SystemExit(main())
