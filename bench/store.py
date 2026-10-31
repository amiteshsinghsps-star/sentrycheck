"""BH-06 content-addressed result store and `bench verify`.

Artifacts live in the run directory so they are reviewable in a diff, and every one of
them is additionally identified by digest in bench/runs/index.json. `verify` recomputes
all of it: a single flipped byte in a trace must be reported, because the whole value of
the evidence tier rests on digests binding the bytes a verdict was derived from.
"""
import hashlib
from pathlib import Path

from bench import BENCH_VERSION
from bench.common import (BENCH, QUANT, ROOT, BenchError, canonical_json, pure_rel_ok, read_json, rel_path,
                         resolve, sha256_bytes, sha256_file, write_json)
from bench import schemas

INDEX = "index.json"


class RunStore:
    def __init__(self, root=None):
        self.root = Path(root) if root else BENCH / "runs"

    def run_dir(self, record):
        # The run id is part of the path: one case scanned twice on one day is two measurements,
        # and a store that overwrote the first would silently shrink the sample it reports on.
        return self.root / ("%s-%s" % (record["started_at"][:10].replace("-", ""), record["host_id"])) \
            / record["case_id"] / record["run_id"]

    def put(self, record, artifacts):
        """Write one run record plus its artifacts; returns the run directory.

        artifacts maps a relative name to bytes or a source path. Names must be repo-safe
        relative paths, otherwise records become host-specific and unverifiable elsewhere.
        """
        directory = self.run_dir(record)
        refs = {"report": None, "traces": [], "outputs": [], "logs": []}
        staged = []
        written_bytes = 0
        # Every artifact is hashed and sized before a single byte reaches the store, so the
        # derived fields below are final when the record is checked. A record that fails its
        # contract then leaves nothing behind: a directory of evidence without run.json is
        # unreadable by the analyzer and unaccountable by verify.
        for name, payload in sorted(artifacts.items()):
            if not pure_rel_ok(name):
                raise BenchError("artifact name must be a repo-relative POSIX path: %r" % name)
            if isinstance(payload, (bytes, bytearray)):
                data = bytes(payload)
            elif isinstance(payload, Path) or (isinstance(payload, str) and Path(payload).is_file()):
                data = Path(payload).read_bytes()
            else:
                raise BenchError("artifact %s is neither bytes nor an existing file" % name)
            written_bytes += len(data)
            digest = sha256_bytes(data)
            stored = "%s/%s" % (rel_path(directory), name)
            staged.append((directory / name, data))
            if name == "report.json":
                refs["report"] = {"path": stored, "sha256": digest}
            elif name.endswith(".trace") or "/traces/" in "/" + name:
                refs["traces"].append({"kind": "sandbox" if "sandbox" in name else "native", "path": stored, "sha256": digest})
            elif "/outputs/" in "/" + name:
                refs["outputs"].append({"stream": "stderr" if "stderr" in name else "stdout", "path": stored, "sha256": digest})
            else:
                refs["logs"].append({"path": stored, "sha256": digest})
        record["artifacts"] = {
            "report": refs["report"],
            "traces": sorted(refs["traces"], key=lambda item: item["path"]),
            "outputs": sorted(refs["outputs"], key=lambda item: item["path"]),
            "logs": sorted(refs["logs"], key=lambda item: item["path"]),
        }
        # Recorded here rather than by the caller: the size has to be final before run.json
        # is hashed, otherwise re-writing the record after indexing desynchronizes the store.
        resources = record.setdefault("resources", {})
        resources["disk_mb"] = round(written_bytes / (1024.0 * 1024.0), QUANT)
        schemas.check("run", record, record.get("run_id", "?"))
        for target, data in staged:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        directory.mkdir(parents=True, exist_ok=True)
        write_json(directory / "run.json", record)
        self.index()
        return directory

    def records(self, suite=None, valid_only=False):
        out = []
        if not self.root.exists():
            return out
        for path in sorted(self.root.glob("*/*/*/run.json")):
            record = read_json(path)
            if suite and record.get("suite") != suite:
                continue
            if valid_only and not record.get("valid"):
                continue
            record["_path"] = str(path)
            out.append(record)
        return out

    def index(self, write=True):
        """Rebuild the digest index. Deterministic: sorted paths, sorted keys."""
        artifacts = {}
        runs = []
        for path in sorted(self.root.rglob("*"), key=str) if self.root.exists() else []:
            if not path.is_file() or path == self.root / INDEX:
                # The index describes every other file; hashing its own previous contents
                # would make every rebuild differ from the last one.
                continue
            rel = rel_path(path)
            digest = sha256_file(path)
            artifacts.setdefault(digest, []).append(rel)
            if path.name == "run.json":
                record = read_json(path)
                runs.append({"run_id": record["run_id"], "case_id": record["case_id"], "suite": record["suite"],
                             "path": rel, "sha256": digest, "valid": record["valid"]})
        duplicates = {digest: paths for digest, paths in artifacts.items() if len(paths) > 1}
        payload = {"schema_version": "1.0", "harness_version": BENCH_VERSION,
                   "runs": runs, "artifact_count": len(artifacts), "artifacts": dict(sorted(artifacts.items())),
                   "duplicate_digests": dict(sorted(duplicates.items()))}
        if write and self.root.exists():
            write_json(self.root / INDEX, payload)
        return payload

    def merge_from(self, source_path, hosts_dir=None):
        """BH-11: merge run records and artifacts from another host directory into this store."""
        import shutil
        source_dir = Path(source_path)
        if not source_dir.exists():
            raise BenchError("source path does not exist: %s" % source_path)
        source_store = RunStore(source_dir)
        records = source_store.records()
        if not records:
            raise BenchError("no run records found in %s" % source_path)

        merged_runs = 0
        merged_hosts = set()
        hosts_target = BENCH / "hosts"
        hosts_target.mkdir(parents=True, exist_ok=True)

        source_hosts_dir = Path(hosts_dir) if hosts_dir else source_dir.parent / "hosts"
        if not source_hosts_dir.exists() and (source_dir / "hosts").exists():
            source_hosts_dir = source_dir / "hosts"

        for record in records:
            host_id = record["host_id"]
            merged_hosts.add(host_id)
            if source_hosts_dir.is_dir():
                host_file = source_hosts_dir / ("%s.json" % host_id)
                target_host_file = hosts_target / ("%s.json" % host_id)
                if host_file.is_file() and not target_host_file.exists():
                    shutil.copy2(host_file, target_host_file)

            run_dir = self.run_dir(record)
            src_dir = Path(record["_path"]).parent
            if run_dir.resolve() != src_dir.resolve():
                run_dir.mkdir(parents=True, exist_ok=True)
                for item in src_dir.rglob("*"):
                    if item.is_file():
                        rel = item.relative_to(src_dir)
                        dest = run_dir / rel
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(item, dest)
                merged_runs += 1

        self.index()
        return {"merged_runs": merged_runs, "hosts": sorted(merged_hosts)}


    def verify(self, deep=True):
        """Recompute every recorded digest. Returns a report with explicit failure lists."""
        problems = []
        checked = 0
        records = self.records()
        for record in records:
            path = Path(record.pop("_path"))
            try:
                schemas.check("run", record, record["run_id"])
            except BenchError as error:
                problems.append("%s: %s" % (rel_path(path), str(error).splitlines()[0]))
                continue
            for item in self._artifact_items(record):
                checked += 1
                problem = self._check_artifact(record["run_id"], item)
                if problem:
                    problems.append(problem)
        index_problems = []
        index_path = self.root / INDEX
        if deep and index_path.exists():
            expected = self.index(write=False)
            if canonical_json(expected) != canonical_json(read_json(index_path)):
                index_problems.append("%s does not match a fresh rebuild of the store" % rel_path(index_path))
        return {"runs": len(records), "artifacts_checked": checked, "ok": not (problems or index_problems),
                "problems": sorted(problems), "index_problems": sorted(index_problems)}

    @staticmethod
    def _artifact_items(record):
        groups = record.get("artifacts", {})
        items = []
        for group in ("report", "logs"):
            value = groups.get(group)
            items.extend(value if isinstance(value, list) else ([value] if value else []))
        items.extend(groups.get("traces", []))
        items.extend(groups.get("outputs", []))
        return items

    @staticmethod
    def _check_artifact(run_id, item):
        if not pure_rel_ok(item["path"]):
            return "%s: unsafe artifact path %r" % (run_id, item["path"])
        target = resolve(item["path"])
        if not target.is_file():
            return "%s: missing artifact %s" % (run_id, item["path"])
        actual = sha256_file(target)
        if actual != item["sha256"]:
            return "%s: digest mismatch on %s (recorded %s, found %s)" % (run_id, item["path"], item["sha256"][:19], actual[:19])
        return None


def command_merge(args):
    store = RunStore(args.root or (BENCH / "runs"))
    result = store.merge_from(args.source, args.hosts)
    print("BH-11 merged %d runs from host(s) %s into %s" % (
        result["merged_runs"], ", ".join(result["hosts"]), rel_path(store.root)))
    return 0


def command_verify(args):
    store = RunStore(args.root)
    report = store.verify(deep=True)
    extra = []
    if args.all:
        for bundle in sorted((BENCH / "datasets").glob("*/checksums.txt")) if (BENCH / "datasets").exists() else []:
            extra.append(verify_checksum_file(bundle))
        from bench.sources import verify_sources
        from bench.fetch import verify_pins
        extra.append(verify_sources())
        extra.append(verify_pins())
    if args.prereg:
        extra.append(verify_preregistration())
    print("runs=%d artifacts_checked=%d problems=%d" % (report["runs"], report["artifacts_checked"], len(report["problems"])))
    for problem in report["problems"] + report["index_problems"]:
        print("  FAIL %s" % problem)
    for item in extra:
        for line in item["failures"]:
            print("  FAIL %s" % line)
        print("  %s: %d entries checked" % (item["file"], item["checked"]))
    failed = bool(report["problems"] or report["index_problems"] or any(item["failures"] for item in extra))
    return 1 if failed else 0


def verify_checksum_file(path):
    path = Path(path)
    failures = []
    checked = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, rel = line.partition("  ")
        checked += 1
        target = (path.parent / rel).resolve()
        try:
            target.relative_to(ROOT.resolve())
        except ValueError:
            failures.append("%s: checksum entry escapes the bundle: %s" % (path, rel))
            continue
        if not target.is_file():
            failures.append("%s: missing file %s" % (path, rel))
            continue
        if sha256_file(target) != digest:
            failures.append("%s: digest mismatch %s" % (path, rel))
    return {"file": rel_path(path), "checked": checked, "failures": failures}


def verify_preregistration():
    marker = BENCH / "analysis" / "preregistration.json"
    if not marker.exists():
        return {"file": "bench/analysis/preregistration.json", "checked": 0,
                "failures": ["pre-registration is missing; scored runs are not allowed without it"]}
    payload = read_json(marker)
    recorded = payload.get("registration_sha256")
    body = {key: value for key, value in payload.items() if key not in ("registration_sha256", "registered_at")}
    current = "sha256:" + hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    failures = []
    if recorded and recorded != current:
        failures.append("pre-registration content changed after registration (%s != %s); use the deviation log" % (recorded[:19], current[:19]))
    if not recorded:
        failures.append("pre-registration has no registration_sha256; it is not yet sealed")
    return {"file": "bench/analysis/preregistration.json", "checked": 1 if recorded else 0, "failures": failures}


def require_preregistration():
    """Scored analysis is refused, not merely warned, when the registration is not intact.

    A broken seal means someone edited the registered plan after it was fixed; letting the analyzer run
    would make every downstream number uninterpretable.
    """
    report = verify_preregistration()
    if report["failures"]:
        raise BenchError("refusing to score: " + "; ".join(report["failures"]))
    return report
