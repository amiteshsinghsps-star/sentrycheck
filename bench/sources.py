"""Phase 4: the PRD section 14 link library, fetched and recorded as evidence.

This is a link-integrity checker with a download side effect. Each URL the PRD cites is fetched once,
kept under bench/sources/docs, and recorded with its final URL, HTTP status, byte count and digest. A
404, a redirect or a blocked request is written down as a finding; nothing is retried until it looks
successful, because the PRD's own rule is that a citation is only as good as the page behind it.
"""
import gzip
import io
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from bench.common import BENCH, now_iso, rel_path, sha256_bytes, write_json

SOURCES = BENCH / "sources"
DOCS = SOURCES / "docs"
USER_AGENT = "sentrycheck-bench/0.1 (reference link integrity check; not a crawler)"
MAX_BYTES = 40 * 1024 * 1024
PAUSE = 0.15

SECTIONS = {
    "14.1": "gvisor-and-runtimes",
    "14.2": "image-datasets-and-sources",
    "14.3": "syscall-tests-and-fuzzing",
    "14.4": "performance-tools",
    "14.5": "benchmark-methodology",
    "14.6": "prior-art",
    "14.7": "kubernetes-and-supply-chain",
}

# (section, resource label as cited in PRD 14, url, note)
LIBRARY = [
    ("14.1", "gVisor application compatibility guide", "https://gvisor.dev/docs/user_guide/compatibility/",
     "states that trying the workload is the practical way to know"),
    ("14.1", "gVisor performance guide", "https://gvisor.dev/docs/architecture_guide/performance/", "workload families; dated"),
    ("14.1", "gVisor main repository", "https://github.com/google/gvisor", "source, issues, releases"),
    ("14.1", "gVisor syscall tests directory", "https://github.com/google/gvisor/tree/master/test/syscalls/linux", "upstream conformance tests"),
    ("14.1", "gVisor benchmarks pull request", "https://github.com/google/gvisor/pull/7989", "syscallbench, hackbench, sysbench, fio additions"),
    ("14.1", "gVisor CI pipeline run (Buildkite)", "https://buildkite.com/gvisor/pipeline/builds/35298", "benchmark families run in upstream CI"),
    ("14.1", "gVisor users list: fio reproduction thread", "https://groups.google.com/g/gvisor-users/c/CHJOPOb7kCk", "maintainer note on guide age and Systrap"),
    ("14.1", "Kubernetes discuss: fio direct I/O under gVisor", "https://discuss.kubernetes.io/t/not-able-to-disable-caching-during-fio-i-o-test-gvisor-vs-runc/19886", "methodology pitfall"),
    ("14.1", "Kata Containers software overview", "https://www.katacontainers.io/software/", "hypervisors, architectures, nested virtualization"),
    ("14.1", "Kata hypervisor comparison", "https://github.com/kata-containers/kata-containers/blob/c64b07f98144/docs/hypervisors.md", "hypervisor feature table"),
    ("14.1", "Kata architecture document", "https://github.com/kata-containers/kata-containers/blob/c64b07f98144/docs/design/architecture", "shimv2 design"),

    ("14.2", "Docker Hub image configuration dataset (Zenodo, CCGRID 2023)",
     "https://commons.datacite.org/doi.org/10.5281/zenodo.7602499", "200,986 entries, 21 features"),
    ("14.2", "Large-scale Docker Hub data set (Lin, Nadi, Khazaei)",
     "https://pacs.eecs.yorku.ca/pubs/pdf/lin2020docker.pdf", "3,364,529 images, 378,615 repositories"),
    ("14.2", "Large-Scale Analysis of the Docker Hub Dataset (Zhao et al.)",
     "https://par.nsf.gov/servlets/purl/10167826", "layer and file characterization"),
    ("14.2", "Understanding the Security Risks of Docker Hub (Liu et al.)",
     "https://www-users.cse.umn.edu/~kjlu/papers/docker.pdf", "2,227,244 images"),
    ("14.2", "Third-party packages in Docker Hub images (Zenodo)", "https://zenodo.org/records/4075044", "190.3 MB replication package"),
    ("14.2", "Secrets in container images study (arXiv)", "https://arxiv.org/pdf/2307.03958", "crawling and sampling method; API limits"),
    ("14.2", "Docker Official Images program", "https://github.com/docker-library/official-images", "preferred curated image source"),
    ("14.2", "docker-library organization", "https://github.com/docker-library", "packaging repositories"),
    ("14.2", "Official Images explanation (docs mirror)", "https://docker-docs.uclv.cu/docker-hub/official_images/", "program rules"),
    ("14.2", "OCI Image Format Specification (v1.0.1)", "https://github.com/opencontainers/image-spec/blob/v1.0.1/spec.md", "manifest, index, layers, config"),
    ("14.2", "OCI Image Layout (v1.0.1)", "https://github.com/opencontainers/image-spec/blob/v1.0.1/image-layout.md", "oci-layout, index.json, blobs structure"),
    ("14.2", "OCI Image Format Specification (main branch)", "https://github.com/opencontainers/image-spec/blob/main/spec.md", "current version"),

    ("14.3", "Linux Test Project", "https://github.com/linux-test-project/ltp", "kernel and syscall tests; runltp -f syscalls"),
    ("14.3", "LTP mailing list archive", "https://lore.kernel.org/ltp/", "patches and discussion"),
    ("14.3", "LTP overview article", "https://www.redhat.com/es/blog/linux-test-project-ltp", "install and run walkthrough"),
    ("14.3", "gVisor syscall tests vendored in Fuchsia",
     "https://fuchsia.googlesource.com/fuchsia/+/main/third_party/gvisor_syscall_tests/", "example of expectations tracking"),
    ("14.3", "DragonOS gVisor test integration", "https://docs.dragonos.org.cn/locales/en/kernel/ktest/gvisor_syscall_test.html", "whitelist and blocklist runner"),
    ("14.3", "Rust Fuzz Book", "https://rust-fuzz.github.io/book/", "cargo-fuzz and afl.rs"),
    ("14.3", "Rust Fuzz Book (single page)", "https://rust-fuzz.github.io/book/print.html", "full text"),
    ("14.3", "OSS-Fuzz: Rust integration", "https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang", "continuous fuzzing setup"),

    ("14.4", "sysbench repository", "https://github.com/akopytov/sysbench", "CPU, memory, fileio, threads, mutex, OLTP tests"),
    ("14.4", "sysbench manual (Debian man page mirror)", "https://www.unix.com/man-page/debian/1/sysbench/", "test modes and options"),
    ("14.4", "sysbench usage notes (secondary)", "https://cloud-atlas.readthedocs.io/zh-cn/latest/performance/performance_tools/sysbench.html",
     "the CPU test is pure user-space compute with no syscalls"),
    ("14.4", "fio repository", "https://github.com/axboe/fio", "flexible I/O tester"),
    ("14.4", "fio documentation", "https://fio.readthedocs.io/", "job options, I/O engines"),
    ("14.4", "fio README (Debian sources)", "https://sources.debian.org/src/fio/3.41-2/README.rst", "build, docs generation"),
    ("14.4", "fio performance testing slides",
     "https://novalug.org/presentation_materials/IO_Loadtesting_with_Fio--2024-04-20/fio.pdf", "example job file with ramp_time, direct, time_based, numjobs"),
    ("14.4", "fio and direct I/O explanation (secondary)",
     "https://intel.com/content/www/us/en/developer/articles/technical/evaluate-performance-for-storage-performance-development-kit-spdk-based-nvme-ssd.html",
     "why direct=1 matters for disk tests"),
    ("14.4", "Edera benchmarking write-up (vendor blog, secondary)",
     "https://edera.dev/stories/faster-than-runc-benchmarking-edera-on-amazon-eks", "sysbench plus fio, five runs, mean and standard deviation"),
    ("14.4", "gvisor_analysis (third-party)", "https://github.com/ethangyoung/gvisor_analysis", "small benchmark collection"),

    ("14.5", "Statistically Rigorous Java Performance Evaluation (OOPSLA 2007)",
     "https://dri.es/files/oopsla07-georges.pdf", "why best-of-N reporting misleads; confidence intervals"),
    ("14.5", "summary of the above (secondary)",
     "https://blog.acolyer.org/2017/11/06/statistically-rigorous-java-performance-evaluation/", "readable walkthrough"),
    ("14.5", "Rigorous replay compilation (OOPSLA 2008)", "https://dri.es/files/oopsla08-georges.pdf", "matched-pair comparison for tighter intervals"),
    ("14.5", "Evaluate collaboratory: twelve ways to report performance",
     "https://evaluate.inf.usi.ch/biblio/tg/S7a9e.html", "listing page; the primary paper is still to locate"),
    ("14.5", "Evaluate collaboratory: STABILIZER", "https://evaluate.inf.usi.ch/biblio/tg/Sf33f.html",
     "listing; randomization for sound performance evaluation"),
    ("14.5", "ICPE 2017 companion paper on statistical methods",
     "https://research.spec.org/icpe_proceedings/2017/companion/p185.pdf", "confidence intervals versus hypothesis tests"),

    ("14.6", "Confine (RAID 2020)", "https://usenix.org/conference/raid2020/presentation/ghavanmnia",
     "automated syscall policy generation; 150 public Docker images"),
    ("14.6", "Confine PDF via NSF PAR", "https://par.nsf.gov//servlets/purl/10219922", "method details"),
    ("14.6", "Confine project site", "https://www3.cs.stonybrook.edu/~sghavamnia/confine", "install, user guide, step-by-step"),
    ("14.6", "Confine source code", "https://github.com/shamedgh/confine", "prototype repository"),
    ("14.6", "Confine journal extension (2023)", "https://www3.cs.stonybrook.edu/~mikepo/papers/confine.cose23.pdf",
     "27 Docker images; fine-grained filtering"),
    ("14.6", "Attack surface reduction thesis summary", "https://www.cs.stonybrook.edu/node/877701", "temporal filtering context"),

    ("14.7", "Kubernetes ValidatingAdmissionPolicy API reference (v1)",
     "https://kubernetes.io/docs/reference/kubernetes-api/admissionregistration/validating-admission-policy-v1/", "fields, CEL expression semantics"),
    ("14.7", "Validating Admission Policy (v1.35 docs)",
     "https://v1-35.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/", "bindings, params, validation actions"),
    ("14.7", "Admission policies tutorial (v1.36 docs)",
     "https://v1-36.docs.kubernetes.io/docs/tutorials/cluster-management/admission-policies/", "MutatingAdmissionPolicy needs 1.36 or later"),
    ("14.7", "Validating Admission Policy (v1.30, stable)",
     "https://v1-30.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy", "stability reference"),
    ("14.7", "SLSA specification (current, v1.2)", "https://slsa.dev/spec/", "tracks, levels, attestation formats"),
    ("14.7", "SLSA levels (v1.1)", "https://slsa.dev/spec/v1.1/levels", "build L1 to L3 summary"),
    ("14.7", "SLSA requirements (v1.0)", "https://slsa.dev/spec/v1.0/requirements", "normative requirements"),
    ("14.7", "Sigstore and in-toto workshop repository (secondary)", "https://github.com/michaelvl/sigstore-in-toto-workshop",
     "cosign provenance verification example"),
    ("14.7", "Signing versus provenance explainer (secondary)", "https://guptadeepak.com/guides/verified-builds-slsa-sigstore/", "why both are needed"),
]

# PRD section 15: named resources with no verified URL. They are recorded so the gap is visible.
NOT_LOCATED = [
    ("Hoefler and Belli primary paper (SC15)", "reporting rules for BM-09"),
    ("Official Sigstore documentation and in-toto specification", "attestation design"),
    ("Firecracker and Cloud Hypervisor official repositories", "possible additional runtimes"),
    ("iperf3, hackbench official pages", "network and scheduler overhead"),
    ("Phoronix Test Suite or UnixBench official pages", "optional broad overhead suites"),
    ("Zenodo or data-repository deposit guidance", "dataset DOI"),
    ("statistical references for Wilson interval, McNemar, Cohen's kappa, Holm correction", "section 4.3 citations"),
    ("WCAG 2.2 specification", "BM-11"),
    ("System Usability Scale reference", "BM-12"),
    ("Linux per-architecture syscall tables (kernel source)", "BM-02 validation"),
    ("Kubernetes CEL cost and limits documentation", "BM-10 CEL cost checks"),
    ("Kubernetes conformance or e2e testing docs", "BM-10 matrix design"),
    ("additional prior art on sandbox compatibility (beyond Confine)", "master PRD survey"),
]

EXTENSIONS = {
    "application/pdf": ".pdf",
    "text/html": ".html",
    "application/json": ".json",
    "text/plain": ".txt",
    "text/markdown": ".md",
    "application/xml": ".xml",
    "text/xml": ".xml",
}


def slugify(text):
    slug = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return slug[:60] or "resource"


def github_raw(url):
    """The raw counterpart of a github.com blob URL, so the document text is kept, not the page chrome."""
    parts = urllib.parse.urlsplit(url)
    if parts.netloc != "github.com" or "/blob/" not in parts.path:
        return None
    head, _, tail = parts.path.partition("/blob/")
    if not tail:
        return None
    return urllib.parse.urlunsplit(("https", "raw.githubusercontent.com", head + "/" + tail, "", ""))


def classify(status, error):
    if error is not None:
        return "error"
    if status is None:
        return "error"
    if 200 <= status < 300:
        return "ok"
    if 300 <= status < 400:
        return "redirect"
    if status == 404:
        return "not-found"
    if status in (401, 403):
        return "blocked"
    if status == 429:
        return "rate-limited"
    if 500 <= status < 600:
        return "server-error"
    return "other"


def fetch(url, timeout):
    """One GET. Returns (status, final_url, body, content_type, error); never raises."""
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "gzip",
        "Connection": "close"})
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(MAX_BYTES + 1)
            truncated = len(body) > MAX_BYTES
            if truncated:
                body = body[:MAX_BYTES]
            if (response.headers.get("Content-Encoding") or "").lower() == "gzip":
                try:
                    body = gzip.GzipFile(fileobj=io.BytesIO(body)).read()
                except (OSError, gzip.BadGzipFile):
                    pass
            ctype = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            return response.status, response.geturl(), body, ctype, None
    except urllib.error.HTTPError as error:
        return error.code, url, b"", "", None
    except Exception as error:  # a link check must record the failure, not abort the run
        return None, url, b"", "", "%s: %s" % (type(error).__name__, str(error)[:200])


def extension_for(ctype, url, body):
    if ctype in EXTENSIONS:
        return EXTENSIONS[ctype]
    if body[:5] == b"%PDF-":
        return ".pdf"
    path = urllib.parse.urlsplit(url).path
    if path.endswith(tuple(EXTENSIONS.values())):
        return "." + path.rsplit(".", 1)[1].lower()
    return ".bin"


def record_for(entry, timeout):
    started = now_iso()
    status, final_url, body, ctype, error = fetch(entry["url"], timeout)
    outcome = classify(status, error)
    record = {
        "section": entry["section"],
        "resource": entry["resource"],
        "note": entry["note"],
        "url": entry["url"],
        "final_url": final_url,
        "http_status": status,
        "outcome": outcome,
        "content_type": ctype or None,
        "bytes": len(body),
        "content_sha256": sha256_bytes(body) if body else None,
        "retrieved_at": started,
        "error": error,
        "file": None,
    }
    if outcome == "ok":
        raw = github_raw(entry["url"])
        if raw:
            raw_status, _, raw_body, raw_ctype, raw_error = fetch(raw, timeout)
            if classify(raw_status, raw_error) == "ok":
                record["raw_url"] = raw
                body, ctype = raw_body, raw_ctype
                record["content_type"] = ctype or None
                record["bytes"] = len(body)
                record["content_sha256"] = sha256_bytes(body)
        name = "%s--%s--%s%s" % (entry["section"], slugify(entry["resource"]),
                                 record["content_sha256"].split(":")[1][:12],
                                 extension_for(ctype, record["final_url"], body))
        DOCS.mkdir(parents=True, exist_ok=True)
        (DOCS / name).write_bytes(body)
        record["file"] = rel_path(DOCS / name)
    return record


def build_library():
    entries = []
    for section, resource, url, note in LIBRARY:
        entries.append({"section": section, "resource": resource, "url": url, "note": note})
    return entries


def command_sources(args):
    out = Path(args.out)
    manifest_path = out / "manifest.json"
    previous = {}
    if manifest_path.is_file():
        previous = {row["url"]: row for row in json.loads(manifest_path.read_text(encoding="utf-8"))["entries"]}
    entries = []
    for entry in build_library():
        if args.only and not any(needle in entry["url"] for needle in args.only):
            # Only the named links are re-fetched; the rest keep their previous recording.
            if entry["url"] in previous:
                entries.append(previous[entry["url"]])
            continue
        entries.append(record_for(entry, args.timeout))
        time.sleep(PAUSE)
    counts = {}
    for record in entries:
        counts[record["outcome"]] = counts.get(record["outcome"], 0) + 1
    document = {
        "schema_version": "1.0",
        "title": "SENTRYCHECK benchmark reference link library (PRD section 14) as fetched",
        "policy": "each URL is fetched once; a failure is recorded as a finding and never retried into success",
        "user_agent": USER_AGENT,
        "link_count": len(entries),
        "outcome_counts": dict(sorted(counts.items())),
        "entries": sorted(entries, key=lambda record: (record["section"], record["url"])),
        "not_located": [{"resource": name, "needed_for": purpose, "url": None}
                        for name, purpose in NOT_LOCATED],
    }
    write_json(manifest_path, document)
    (out / "README.md").write_text(summarize(document), encoding="utf-8", newline="\n")
    print("links=%d %s" % (len(entries), " ".join("%s=%d" % item for item in sorted(counts.items()))))
    for record in document["entries"]:
        if record["outcome"] != "ok":
            print("  FINDING %-13s %s" % (record["outcome"], record["url"]))
    print("wrote %s" % rel_path(manifest_path))
    # A broken citation is a finding, not a harness failure: exit 0 unless nothing could be fetched.
    return 1 if counts.get("ok", 0) == 0 else 0


def summarize(document):
    lines = [
        "# Reference document library",
        "",
        "Fetched from the PRD section 14 link library by `python -m bench sources`.",
        "Every entry records the URL that was tried, the URL it actually resolved to, the HTTP status,",
        "the byte count and the digest of what was kept. Failures stay in the manifest as findings.",
        "",
        "| outcome | count |",
        "|---|---|",
    ]
    for outcome, count in sorted(document["outcome_counts"].items()):
        lines.append("| %s | %d |" % (outcome, count))
    lines += ["", "## Findings", ""]
    findings = [row for row in document["entries"] if row["outcome"] != "ok"]
    if not findings:
        lines.append("None: every cited link returned content.")
    for row in findings:
        lines.append("* **%s** (%s) `%s` - %s%s" % (
            row["resource"], row["outcome"], row["url"],
            row["error"] or "HTTP %s" % row["http_status"],
            "" if row["final_url"] == row["url"] else "; resolved to %s" % row["final_url"]))
    lines += ["", "## Named in the PRD with no verified URL (section 15)", ""]
    for item in document["not_located"]:
        lines.append("* %s - needed for %s" % (item["resource"], item["needed_for"]))
    lines += [
        "",
        "## Licensing and redistribution",
        "",
        "These files are kept locally as retrieved evidence for this study, not redistributed as part of",
        "any published dataset. A bundle intended for publication ships the digests and URLs in",
        "`manifest.json` and leaves the upstream documents where they live (PRD section 7.7, NF-09).",
        "",
    ]
    return "\n".join(lines)


def verify_sources(root=None):
    """Re-hash every kept document and report drift, for `bench verify --all`."""
    path = Path(root or SOURCES) / "manifest.json"
    if not path.is_file():
        return {"file": "bench/sources/manifest.json", "checked": 0,
                "failures": ["reference library has not been fetched; run bench sources"]}
    from bench.common import resolve, sha256_file
    failures = []
    checked = 0
    document = json.loads(path.read_text(encoding="utf-8"))
    for record in document["entries"]:
        if not record.get("file"):
            continue
        target = resolve(record["file"])
        checked += 1
        if not target.is_file():
            failures.append("%s: kept document is missing (%s)" % (record["resource"], record["file"]))
        elif sha256_file(target) != record["content_sha256"]:
            failures.append("%s: digest drift on %s" % (record["resource"], record["file"]))
    return {"file": "bench/sources/manifest.json", "checked": checked, "failures": failures}


if __name__ == "__main__":
    sys.exit(command_sources(type("A", (), {
        "out": str(SOURCES), "timeout": 45, "only": None})()))
