"""Retrieve bounded primary sources for the 2026-09-26 implementation review.

Outputs preserve original bytes. The manifest includes SHA-256 and retrieval time.
Mutable GitHub repository sources are resolved to commit IDs before retrieval.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent
LIMIT = 8 * 1024 * 1024
GV = "26f3455a4cb9a377354c33aeac049080a077c79c"


def retrieve(name, url):
    req = urllib.request.Request(url, headers={"User-Agent": "SENTRYCHECK-primary-source-review/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            data = response.read(LIMIT + 1)
            final_url = response.url
        if len(data) > LIMIT:
            raise ValueError("source exceeds 8 MiB limit")
        (ROOT / (name + ".txt")).write_bytes(data)
        return name, {"url": url, "final_url": final_url,
                      "retrieved_at": datetime.now(timezone.utc).isoformat(),
                      "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
    except Exception as exc:
        return name, {"url": url, "retrieved_at": datetime.now(timezone.utc).isoformat(), "error": str(exc)}


def main():
    sources = {
        "gvisor-platforms": f"https://raw.githubusercontent.com/google/gvisor/{GV}/g3doc/user_guide/platforms.md",
        "gvisor-debugging": f"https://raw.githubusercontent.com/google/gvisor/{GV}/g3doc/user_guide/debugging.md",
        "gvisor-install": f"https://raw.githubusercontent.com/google/gvisor/{GV}/g3doc/user_guide/install.md",
        "gvisor-sidecars": f"https://raw.githubusercontent.com/google/gvisor/{GV}/runsc/config/config.go",
        "gvisor-oci": f"https://raw.githubusercontent.com/google/gvisor/{GV}/g3doc/user_guide/quick_start/oci.md",
        "github-sarif": "https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning",
        "github-sarif-upload": "https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github",
    }
    repos = {
        "oci": ("opencontainers/image-spec", "v1.1.1", ["descriptor.md", "image-index.md", "config.md", "layer.md"]),
        "kata": ("kata-containers/kata-containers", "main", ["docs/installation.md", "docs/hypervisors.md", "docs/design/architecture/README.md", "docs/design/virtualization.md"]),
        "kubernetes": ("kubernetes/website", "main", ["content/en/docs/concepts/containers/runtime-class.md", "content/en/docs/reference/access-authn-authz/validating-admission-policy.md", "content/en/docs/reference/access-authn-authz/mutating-admission-policy.md"]),
        "sarif": ("oasis-tcs/sarif-spec", "main", ["sarif-2.1/schema/sarif-schema-2.1.0.json"]),
    }
    manifest_path = ROOT / "sources.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    for prefix, (repo, ref, paths) in repos.items():
        name, result = retrieve(prefix + "-revision", f"https://api.github.com/repos/{repo}/commits/{ref}")
        manifest[name] = result
        if "error" in result:
            continue
        revision = json.loads((ROOT / (name + ".txt")).read_text(encoding="utf-8"))["sha"]
        for path in paths:
            name = prefix + "-" + path.removesuffix(".md").removesuffix(".json").split("/")[-1]
            sources[name] = f"https://raw.githubusercontent.com/{repo}/{revision}/{path}"
    with ThreadPoolExecutor(max_workers=5) as pool:
        for name, result in pool.map(lambda x: retrieve(*x), sources.items()):
            manifest[name] = result
            print(name, result.get("bytes", result.get("error")), flush=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return int(any("error" in manifest[x] for x in sources))


if __name__ == "__main__":
    raise SystemExit(main())
