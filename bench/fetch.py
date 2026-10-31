"""Phase 5: digest-pinned workload images, fetched without a Docker daemon.

An anonymous registry-v2 client: discover the auth realm from a 401, take a pull token, read the
manifest, resolve a manifest list down to exactly one linux/amd64 manifest the way the scanner's own
image.rs does, then store the blobs in an OCI layout with every digest verified before it is kept.

PRD section 7.7 forbids redistributing layers. Layer blobs therefore land under bench/images, which is
git-ignored, while the pin record - digests, sizes, media types and config identity - is what gets
published. `--manifest-only` produces the pin without downloading layer blobs.
"""
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from bench import BENCH_VERSION
from bench.common import (BENCH, ROOT, BenchError, canonical_json, now_iso, rel_path, sha256_bytes, sha256_file, write_json)

IMAGES = BENCH / "images"
PINS = IMAGES / "pins.json"
INDEX_MEDIA = ("application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json")
MANIFEST_MEDIA = ("application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json")
ACCEPT = ", ".join(INDEX_MEDIA + MANIFEST_MEDIA)
USER_AGENT = "sentrycheck-bench/%s (digest-pinned workload fetch)" % BENCH_VERSION
MAX_BLOB = 2 << 30


def parse_reference(reference):
    """docker.io/library/python:3.12-slim -> (registry host, repository, reference, pinned digest).

    The host is only recognised when a first path segment carries a dot, a colon or is localhost, which
    is how the container tools themselves decide it; "python:3.12" has no slash and so is a Docker Hub
    repository, not a host called "python".
    """
    text = str(reference)
    slash = text.find("/")
    head = text[:slash]
    if slash < 0 or (":" not in head and "." not in head and head != "localhost"):
        registry, path = "docker.io", text
    else:
        registry, path = head, text[slash + 1:]
    digest = None
    name, at, hexpart = path.partition("@sha256:")
    if at:
        digest = "sha256:" + hexpart
        if not re.fullmatch(r"[0-9a-f]{64}", digest[7:]):
            raise BenchError("not a canonical sha256 digest: %s" % reference)
        path = name
    if ":" in path:
        base, _, candidate = path.rpartition(":")
        # A colon inside the last segment is a tag; "python:3.12" is a repository and a tag, not a host.
        path, tag = (base, candidate) if "/" not in candidate else (path, "latest")
    else:
        tag = "latest"
    if registry == "docker.io" and "/" not in path:
        path = "library/" + path
    if not path or not tag:
        raise BenchError("malformed image reference: %s" % reference)
    host = "registry-1.docker.io" if registry == "docker.io" else registry
    return host, path.lower(), (digest or tag), digest


def is_index(media):
    return media in INDEX_MEDIA


def select_platform(index, arch):
    """One linux/<arch> manifest out of a manifest list, mirroring the scanner's select()."""
    if index.get("schemaVersion") != 2:
        raise BenchError("manifest list schemaVersion must be 2, found %r" % index.get("schemaVersion"))
    candidates = [item for item in index.get("manifests", [])
                  if item.get("mediaType") in INDEX_MEDIA + MANIFEST_MEDIA]
    if not candidates:
        raise BenchError("manifest list carries no recognizable image descriptor")
    matches = [item for item in candidates
               if (item.get("platform") or {}).get("architecture") == arch
               and (item.get("platform") or {}).get("os") == "linux"]
    if len(matches) != 1 and len(candidates) == 1 and "platform" not in candidates[0]:
        # A single descriptor with no platform field is what a plain image pushed as an index looks like.
        matches = candidates
    if len(matches) != 1:
        raise BenchError("expected exactly one linux/%s entry, found %d of %d" % (arch, len(matches), len(candidates)))
    return matches[0]


def _open(url, headers, timeout):
    request = urllib.request.Request(url, headers=dict(headers, **{"User-Agent": USER_AGENT}))
    return urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context())


def anonymous_token(challenge, registry, repository, timeout):
    fields = dict(re.findall(r'(\w+)\s*=\s*"([^"]*)"', challenge))
    realm = fields.get("realm")
    if not realm:
        raise BenchError("registry answered 401 without a bearer realm: %r" % challenge)
    query = {"service": fields.get("service") or registry,
             "scope": fields.get("scope") or ("repository:%s:pull" % repository)}
    with _open(realm + "?" + urllib.parse.urlencode(query), {}, timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    token = payload.get("token") or payload.get("access_token")
    if not token:
        raise BenchError("token endpoint %s returned no token" % realm)
    return token


def get(url, registry, repository, timeout, token=None):
    """GET, answering an auth challenge once. Returns (body, digest header, content type, token)."""
    headers = {"Accept": ACCEPT}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    try:
        response = _open(url, headers, timeout)
    except urllib.error.HTTPError as error:
        if error.code != 401 or token is not None:
            raise
        retry_token = anonymous_token(error.headers.get("WWW-Authenticate") or "", registry, repository, timeout)
        response = _open(url, dict(headers, Authorization="Bearer %s" % retry_token), timeout)
        token = retry_token
    with response:
        body = response.read(MAX_BLOB + 1)
        if len(body) > MAX_BLOB:
            raise BenchError("response larger than the harness blob limit: %s" % url)
        header = response.headers.get("Docker-Content-Digest")
        ctype = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    return body, header, ctype, token


def verify(data, expected, what):
    actual = sha256_bytes(data)
    if actual != expected:
        raise BenchError("%s integrity failure: advertised %s, bytes hash to %s" % (what, expected, actual))
    return actual


def write_blob(directory, data, digest):
    path = directory / "blobs" / "sha256" / digest.split(":", 1)[1]
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file() and sha256_file(path) != digest:
        raise BenchError("existing blob %s does not hash to its own name; refusing to overwrite" % digest)
    if not path.is_file():
        path.write_bytes(data)
    return path


def blob_url(registry, repository, digest):
    return "https://%s/v2/%s/blobs/%s" % (registry, urllib.parse.quote(repository, safe="/"),
                                          urllib.parse.quote(digest, safe=":@"))


def manifest_base(registry, repository):
    return "https://%s/v2/%s/manifests/" % (registry, urllib.parse.quote(repository, safe="/"))


def resolve_manifest(reference, registry, repository, ref, timeout, arch="amd64"):
    """Return (body, digest, media type, token) for the single linux manifest behind a reference."""
    base = manifest_base(registry, repository)
    body, header, ctype, token = get(base + urllib.parse.quote(ref, safe=":"), registry, repository, timeout)
    media = ctype or (json.loads(body).get("mediaType") if body[:1] == b"{" else None)
    digest = header or sha256_bytes(body)
    if not media:
        raise BenchError("registry returned no media type for %s" % reference)
    if is_index(media):
        entry = select_platform(json.loads(body), arch)
        digest = entry["digest"]
        media = entry.get("mediaType") or media
        body, header, ctype, token = get(base + urllib.parse.quote(digest), registry, repository, timeout, token)
        if header and header != digest:
            raise BenchError("registry served a body hashing to %s under the digest it called %s" % (header, digest))
        media = ctype or media
    verify(body, digest, "manifest")
    if media not in MANIFEST_MEDIA:
        raise BenchError("resolved document is not an image manifest (%s)" % media)
    return body, digest, media, token


def fetch(reference, out, arch="amd64", timeout=60, manifest_only=False):
    registry, repository, ref, pinned = parse_reference(reference)
    body, digest, media, token = resolve_manifest(reference, registry, repository, ref, timeout, arch)
    if pinned and pinned != digest:
        raise BenchError("%s resolves to %s, not the pinned %s" % (reference, digest, pinned))
    manifest = json.loads(body)
    config_descriptor = manifest.get("config")
    if not config_descriptor or not str(config_descriptor.get("digest", "")).startswith("sha256:"):
        raise BenchError("manifest %s carries no usable config descriptor" % digest[:19])
    directory = Path(out)
    written = [{"digest": digest, "bytes": len(body), "role": "manifest", "stored": True}]
    if not manifest_only:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "oci-layout").write_bytes(canonical_json({"imageLayoutVersion": "1.0.0"}).encode("utf-8"))
        write_blob(directory, body, digest)
    config_body, _, _, token = get(blob_url(registry, repository, config_descriptor["digest"]),
                                   registry, repository, timeout, token)
    verify(config_body, config_descriptor["digest"], "config")
    config = json.loads(config_body)
    if not manifest_only:
        write_blob(directory, config_body, config_descriptor["digest"])
        written.append({"digest": config_descriptor["digest"], "bytes": len(config_body),
                        "role": "config", "stored": True})
    layers = []
    for layer in manifest.get("layers", []):
        entry = {"digest": layer["digest"], "size": layer.get("size"),
                 "mediaType": layer.get("mediaType"), "stored": not manifest_only}
        if not manifest_only:
            blob, _, _, token = get(blob_url(registry, repository, layer["digest"]),
                                    registry, repository, timeout, token)
            verify(blob, layer["digest"], "layer %s" % layer["digest"][:19])
            entry["bytes"] = len(blob)
            entry["gzip"] = blob[:2] == b"\x1f\x8b"
            write_blob(directory, blob, layer["digest"])
            written.append(entry)
        layers.append(entry)
    if not manifest.get("layers"):
        raise BenchError("manifest %s lists no layers; this is not a workload image" % digest[:19])
    index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
             "manifests": [{"mediaType": media, "digest": digest, "size": len(body),
                            "platform": {"architecture": config.get("architecture", arch),
                                         "os": config.get("os", "linux")}}]}
    if not manifest_only:
        write_json(directory / "index.json", index)
    return {
        "reference": reference,
        "source_url": ("https://hub.docker.com/r/" + repository) if registry == "registry-1.docker.io"
                      else ("https://" + registry + "/" + repository),
        "registry": registry,
        "repository": repository,
        "requested": ref,
        "pinned_digest": pinned,
        "manifest_digest": digest,
        "manifest_media_type": media,
        "config_digest": config_descriptor["digest"],
        "config_os": config.get("os"),
        "config_architecture": config.get("architecture"),
        "rootfs_diff_ids": (config.get("rootfs") or {}).get("diff_ids", []),
        "layers": layers,
        "total_bytes": sum(item.get("bytes") or 0 for item in written),
        "layers_stored": not manifest_only,
        "layout": None if manifest_only else rel_path(directory),
        "index_digest": None if manifest_only else sha256_file(directory / "index.json"),
        "fetched_at": now_iso(),
    }


def load_pins():
    if not PINS.is_file():
        return {}
    return {entry["reference"]: entry for entry in json.loads(PINS.read_text(encoding="utf-8"))["pins"]}


def record_pin(record):
    pins = load_pins()
    previous = pins.get(record["reference"])
    record["first_pinned_at"] = (previous or {}).get("first_pinned_at", record["fetched_at"])
    record["digest_changed"] = bool(previous) and previous.get("manifest_digest") != record["manifest_digest"]
    pins[record["reference"]] = record
    write_json(PINS, {"schema_version": "1.0",
                      "title": "digest-pinned workload images (PRD section 7.7)",
                      "redistribution": "layer blobs stay on this host under bench/images; only digests, "
                                        "sizes, media types and config identity are published",
                      "pins": [pins[key] for key in sorted(pins)]})
    return PINS


def verify_pins():
    """Re-hash every stored pin so a case cannot be scored against a quietly replaced image."""
    if not PINS.is_file():
        return {"file": "bench/images/pins.json", "checked": 0,
                "failures": ["no workload image has been pinned; run bench fetch"]}
    failures, checked = [], 0
    document = json.loads(PINS.read_text(encoding="utf-8"))
    for pin in document["pins"]:
        name = pin["reference"]
        if not pin.get("layers_stored"):
            continue
        checked += 1
        layout = Path(ROOT / pin["layout"])
        if not layout.is_dir():
            failures.append("%s: pinned layout %s is missing" % (name, pin["layout"]))
            continue
        if sha256_file(layout / "index.json") != pin["index_digest"]:
            failures.append("%s: index.json no longer hashes to the pinned value" % name)
        for role, descriptor in (("manifest", {"digest": pin["manifest_digest"]}),
                                 ("config", {"digest": pin["config_digest"]}),
                                 * [("layer", item) for item in pin["layers"]]):
            blob = layout / "blobs" / "sha256" / descriptor["digest"].split(":", 1)[1]
            if not blob.is_file():
                failures.append("%s: %s blob %s is not stored" % (name, role, descriptor["digest"][:19]))
            elif sha256_file(blob) != descriptor["digest"]:
                failures.append("%s: %s blob %s does not hash to its own name" % (name, role, descriptor["digest"][:19]))
    return {"file": "bench/images/pins.json", "checked": checked, "failures": failures}


def pin_for(reference):
    return load_pins().get(str(reference))


def layout_name(reference):
    """A filesystem-safe, predictable directory name for one image reference."""
    text = re.sub(r"[^A-Za-z0-9.+-]+", "-", str(reference)).strip("-")
    return text[:80] or "image"


def command_fetch(args):
    out = Path(args.out) if args.out else IMAGES / layout_name(args.reference)
    try:
        record = fetch(args.reference, out, arch=args.arch, timeout=args.timeout,
                       manifest_only=args.manifest_only)
    except urllib.error.HTTPError as error:
        raise BenchError("registry refused %s: HTTP %d" % (args.reference, error.code))
    except urllib.error.URLError as error:
        raise BenchError("registry unreachable: %s" % error.reason)
    path = record_pin(record)
    print("reference  %s" % record["reference"])
    print("digest     %s" % record["manifest_digest"])
    print("media      %s" % record["manifest_media_type"])
    print("platform   %s/%s" % (record["config_os"], record["config_architecture"]))
    print("layers     %d, %s bytes%s" % (len(record["layers"]), record["total_bytes"],
                                         "" if record["layers_stored"] else "; descriptors only"))
    print("layout     %s" % (record["layout"] or "not written"))
    if record["digest_changed"]:
        print("  NOTE the mutable reference moved to a different digest since the last pin")
    if (record["config_os"], record["config_architecture"]) != ("linux", "amd64"):
        print("  NOTE image config is %s/%s, not linux/amd64" % (record["config_os"], record["config_architecture"]))
    print("pins       %s" % rel_path(path))
    return 0
