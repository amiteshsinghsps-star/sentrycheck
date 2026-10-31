"""Generate the public JSON Schema contracts; no code generation dependency required."""
import json
from pathlib import Path

def obj(properties, required=None):
    return {"type": "object", "properties": properties, "required": list(properties) if required is None else required, "additionalProperties": False}
def string(): return {"type": "string"}
def number(): return {"type": "integer", "minimum": 0}
def boolean(): return {"type": "boolean"}
def array(items): return {"type": "array", "items": items}
def nullable(value): return {"anyOf": [value, {"type": "null"}]}
def ref(name): return {"$ref": "#/$defs/" + name}
def enum(values): return {"type": "string", "enum": values.split()}

def write_json(path, value):
    # Pinned LF: these contracts are hashed by the benchmark harness, so a Windows
    # checkout must not emit CRLF and change their digest.
    path = Path(path)
    text = json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return text.encode("utf-8")

LABEL_CLASSES = "hard-failure silent-degradation tolerated compatible performance-regression indeterminate"
SUITES = " ".join("BM-%02d" % i for i in range(1, 15))


def bench_contracts(digest):
    """Case, run, label and host contracts for the benchmark harness (PRD v2 sections 6.3-6.4)."""
    ident = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{2,63}$"}
    relpath = {"type": "string", "pattern": "^[A-Za-z0-9._@/-]+$"}
    def ref_obj(**extra):
        return obj(dict(extra, path=relpath, sha256=digest))
    rater = obj({"id": string(), "kind": enum("human rule-adjudicator"), "label_class": enum(LABEL_CLASSES), "confidence": enum("high medium low"), "rationale": string()})
    case = obj({
        "schema_version": {"const": "1.0"},
        "case_id": ident,
        "group": string(),
        "image": obj({"reference": nullable(string()), "local_path": nullable(relpath), "digest": nullable(digest), "source_url": nullable(string()), "license": nullable(string()), "architecture": enum("amd64 arm64"), "media_type": nullable(string()), "layer_digests": array(digest)}),
        "profile": obj({"kind": enum("oci-layout oci-ref fixture-binary command"), "path": relpath, "sha256": digest, "coverage_notes": string()}),
        "runtime": obj({"name": enum("gvisor kata runc"), "release": string(), "platform": nullable(string()), "flags": array(string())}),
        "suites": array(enum(SUITES)),
        "host_classes": array(string()),
        "expected_interfaces": array(string()),
        "label": nullable(obj({"class": enum(LABEL_CLASSES), "confidence": enum("high medium low"), "label_source": enum("independent-raters rule-adjudicator author-upstream"), "rater_a": nullable(rater), "rater_b": nullable(rater), "adjudicator": nullable(rater), "evidence": array(string()), "linked_evidence": array(obj({"kind": enum("log trace url file run"), "ref": string(), "sha256": nullable(digest), "note": string()}))})),
        "split": enum("development validation test reserve"),
        "tags": array(string()),
        "added_in": string(),
        "retired_in": nullable(string()),
        "notes": string(),
    })
    run = obj({
        "schema_version": {"const": "1.0"},
        "run_id": string(),
        "case_id": ident,
        "suite": enum(SUITES),
        "host_id": ident,
        "started_at": string(),
        "ended_at": string(),
        "seed": {"type": "integer", "minimum": 0},
        "order_index": {"type": "integer", "minimum": 0},
        "order_pattern": nullable(string()),
        "tool": obj({"name": string(), "version": string(), "git_commit": nullable(string()), "binary_sha256": digest}),
        "kb": obj({"snapshot_version": string(), "sha256": digest, "max_age_days": {"type": "integer", "minimum": 0}}),
        "runtime": obj({"name": enum("gvisor kata runc"), "release": string(), "platform": nullable(string()), "binary_sha256": nullable(digest)}),
        # "preflight" is deliberately not in the required list: the store is append-only and
        # content-addressed, so records written before BH-05 wiring must keep verifying. New runs
        # always carry it, and a missing key means "this predates the check", never "the check passed".
        "environment": obj({"governor": nullable(string()), "smt": nullable(string()), "cores": array({"type": "integer", "minimum": 0}), "load_before": nullable({"type": "number"}), "free_disk_mb": nullable({"type": "integer"}), "clock_synced": nullable(boolean()), "work_root": string(), "host_load_controlled": boolean(), "preflight": nullable(obj({"live_capable": boolean(), "timing_capable": boolean(), "failed": array(string())}))},
                           required=["governor", "smt", "cores", "load_before", "free_disk_mb", "clock_synced", "work_root", "host_load_controlled"]),
        "predicted": nullable(obj({"class": enum(LABEL_CLASSES), "tier": nullable(enum("static-only dynamic-native-only dynamic-runsc-diff dynamic-kata-diff")), "complete": boolean(), "status": enum("complete incomplete"), "finding_severities": array(string()), "incomplete_reason_codes": array(string())})),
        "repetitions": obj({"native_exits": array(nullable({"type": "integer"})), "sandbox_exits": array(nullable({"type": "integer"})), "native_durations_ms": array({"type": "integer", "minimum": 0}), "sandbox_durations_ms": array({"type": "integer", "minimum": 0})}),
        "artifacts": obj({"report": nullable(ref_obj()), "traces": array(obj({"kind": enum("native sandbox guest diagnostic"), "path": relpath, "sha256": digest})), "outputs": array(obj({"stream": enum("stdout stderr"), "path": relpath, "sha256": digest})), "logs": array(ref_obj())}),
        "timings_ms": obj({"scan": nullable({"type": "integer", "minimum": 0}), "total": nullable({"type": "integer", "minimum": 0})}),
        "resources": obj({"peak_rss_mb": nullable({"type": "number"}), "disk_mb": nullable({"type": "number"})}),
        "valid": boolean(),
        "invalid_reason": nullable(string()),
        "notes": string(),
    })
    label = obj({
        "schema_version": {"const": "1.0"},
        "case_id": ident,
        "recorded_at": string(),
        "rater": rater,
        "evidence": array(obj({"kind": enum("log trace url file run exit-code output-diff"), "ref": string(), "sha256": nullable(digest), "note": string()})),
        "notes": string(),
    })
    host = obj({
        "schema_version": {"const": "1.0"},
        "host_id": ident,
        "recorded_at": string(),
        "platform": string(),
        "os_release": string(),
        "kernel": string(),
        "architecture": string(),
        "cpu": obj({"model": nullable(string()), "cores": {"type": "integer", "minimum": 1}, "threads_per_core": nullable({"type": "integer", "minimum": 1}), "governor": nullable(string()), "smt": nullable(string()), "turbo": nullable(string()), "pinning": nullable(string())}),
        "memory": obj({"total_mb": nullable({"type": "integer", "minimum": 0}), "swap": nullable(string()), "transparent_hugepage": nullable(string())}),
        "numa": nullable(string()),
        "storage": obj({"work_root": string(), "filesystem": nullable(string()), "free_mb": nullable({"type": "integer", "minimum": 0}), "device": nullable(string())}),
        "network": nullable(string()),
        "clock": obj({"timezone": string(), "synced": nullable(boolean()), "unix_now": {"type": "integer", "minimum": 0}}),
        "load_average": obj({"one": nullable({"type": "number"}), "five": nullable({"type": "number"}), "fifteen": nullable({"type": "number"})}),
        "virtualization": obj({"is_wsl": nullable(boolean()), "nested_kvm": nullable(boolean()), "provider": nullable(string())}),
        "tools": array(obj({"name": string(), "path": nullable(string()), "sha256": nullable(digest), "version": nullable(string())})),
        "host_load_controlled": boolean(),
        "notes": string(),
    })
    contracts = [("case", "SENTRYCHECK benchmark case contract", case), ("run", "SENTRYCHECK benchmark run record", run), ("label", "SENTRYCHECK benchmark label record", label), ("host", "SENTRYCHECK benchmark host record", host)]
    directory = Path("bench/schema")
    directory.mkdir(parents=True, exist_ok=True)
    for name, title, schema in contracts:
        schema.update({"$schema": "https://json-schema.org/draft/2020-12/schema", "title": title, "$id": "urn:sentrycheck:bench:%s:1.0" % name})
        write_json(directory / ("%s.schema.json" % name), schema)
    return [name for name, _, _ in contracts]


def main():
    digest = {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"}
    definitions = {}
    definitions["target"] = obj({"name": enum("gvisor kata"), "version": string(), "architecture": string()})
    definitions["citation"] = obj({"title": string(), "url": {"type": "string", "format": "uri", "pattern": "^https://"}, "source_revision": nullable(string()), "retrieved_at": string()})
    definitions["capability"] = obj({"syscall": nullable(string()), "syscall_number": nullable(number()), "subsystem": nullable(string()), "architecture": string(),
        "resolution_confidence": enum("static-certain static-probable unresolvable"), "source_binary": string(), "source_digest": digest, "source_offset": nullable({"type": "string", "pattern": "^0x[0-9a-f]+$"}), "note": string()})
    definitions["fingerprint"] = obj({k: string() for k in ["source_binary", "kind", "value", "note"]})
    definitions["capabilitySet"] = obj({"interpretation": string(), "capabilities": array(ref("capability")), "fingerprints": array(ref("fingerprint")), "elf_files": number(), "cache_hits": number(), "warnings": array(string())})
    definitions["candidate"] = obj({"gap_id": string(), "category": string(), "source_binary": string(), "syscall": nullable(string()), "version_match": boolean(), "description": string(), "citation": ref("citation")})
    definitions["profile"] = obj({"name": string(), "description": string(), "command": array(string()), "env": array(string()), "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 3600}, "repetitions": {"type": "integer", "minimum": 1, "maximum": 20}, "expected_exit_code": {"type": "integer"}, "compare_stdout": boolean(), "compare_stderr": boolean(), "timing_ratio": {"type": "number", "exclusiveMinimum": 1}, "timing_min_native_ms": number(), "coverage": enum("smoke representative")})
    definitions["event"] = obj({"syscall": string(), "arguments": string(), "result": string(), "return_value": nullable({"type": "integer"}), "errno": nullable(string()), "line": number()})
    counts = {"type": "object", "additionalProperties": number()}
    definitions["traceSummary"] = obj({"syscalls": counts, "errors": counts, "event_count": number(), "unfinished_count": number(), "unparsed_lines": number(), "truncated": boolean(), "discarded_guest_records": number(), "diagnostic_lines": number()}, ["syscalls", "errors", "event_count", "unfinished_count", "unparsed_lines", "truncated"])
    definitions["run"] = obj({"runtime": string(), "runtime_version": string(), "exit_code": nullable({"type": "integer"}), "timed_out": boolean(), "duration_ms": number(),
        "stdout_sha256": digest, "stderr_sha256": digest, "stdout_ref": string(), "stderr_ref": string(), "trace_ref": string(), "trace_sha256": digest, "trace_kind": enum("strace-guest runsc-guest"), "trace_summary": ref("traceSummary"), "events": array(ref("event")), "infrastructure_error": nullable(string())})
    tier = enum("static-only dynamic-native-only dynamic-runsc-diff dynamic-kata-diff")
    definitions["dynamic"] = obj({"evidence_tier": tier, "provenance": enum("locally-executed imported-user-supplied"), "profile": ref("profile"), "profile_sha256": digest, "native": array(ref("run")), "sandbox": array(ref("run")), "exercised_syscalls": array(string()), "fallback_observations": array(string()), "warnings": array(string())})
    definitions["finding"] = obj({"id": string(), "gap_id": string(), "category": string(), "failure_class": enum("F1 F2 F3 unconfirmed"), "severity": enum("hard-failure silent-degradation performance-regression compatibility-risk"), "evidence_tier": tier, "description": string(), "source_binary": nullable(string()), "static_evidence": nullable(ref("capability")), "dynamic_evidence": {"type": "object"}, "kb_citation": ref("citation"), "causality": string()})
    definitions["finding"]["allOf"] = [{"if": {"properties": {"severity": {"const": "hard-failure"}}}, "then": {"properties": {"evidence_tier": enum("dynamic-runsc-diff dynamic-kata-diff")}}}]
    report = obj({"schema_version": {"const": "1.0"}, "image": string(), "image_digest": nullable(digest), "platform": string(), "scanned_at": {"type": "string", "format": "date-time"}, "sentrycheck_version": string(), "kb_snapshot_version": string(), "kb_age_days": nullable(number()), "target_runtime": ref("target"), "status": enum("complete incomplete"), "assessment": enum("incompatibility-observed performance-regression-observed no-incompatibility-observed-in-profile insufficient-evidence"), "findings": array(ref("finding")), "candidate_gaps": array(ref("candidate")), "capability_set": ref("capabilitySet"), "capability_set_only": array(ref("capability")), "dynamic": nullable(ref("dynamic")), "silent_fallback_check": obj({"performed": boolean(), "cluster_context_available": boolean(), "note": string()}), "limitations": array(string()), "incomplete_reasons": array(string()), "duration_ms": number()})
    report.update({"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "SENTRYCHECK evidence report 1.0", "$defs": definitions})
    directory = Path("schema")
    directory.mkdir(exist_ok=True)
    write_json(directory / "report.schema.json", report)
    profile = dict(definitions["profile"])
    profile["required"] = ["name"]
    profile.update({"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "SENTRYCHECK workload profile"})
    write_json(directory / "profile.schema.json", profile)
    names = bench_contracts(digest)
    print("Wrote public report and profile schemas; bench %s schemas" % "/".join(names))

if __name__ == "__main__":
    main()
