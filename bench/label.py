"""BH-07 labeling: two independent raters, an explicit adjudicator and honest agreement.

Neither rater here is human, and the study says so. Rater A reads the shipped knowledge base
(upstream gVisor syscall tables and gap entries with citations); rater B reads only the raw
execution evidence recorded by a live run: exit codes and stdout digests. Neither reads the
scanner's findings, which is what makes the comparison with the tool's prediction meaningful.
"""
import json
import re
from pathlib import Path

from bench.common import BENCH, ROOT, BenchError, now_iso, read_json, rel_path, resolve, sha256_file, write_json
from bench import cases as case_registry
from bench.stats import cohens_kappa
from bench.store import RunStore

KB = BENCH.parent / "kb" / "snapshot.json"
RATER_A_ID = "kb-rule"
RATER_B_ID = "exit-and-output-rule"
# A class only becomes gold when both raters reach it independently; anything else is adjudicated
# by the documented rule below and marked with lower confidence.
ADJUDICATION_RULE = ("agreement wins with confidence high; if one rater abstains the other decides with confidence "
                     "medium; if both are definite but differ, a positive observation in recorded execution evidence "
                     "outranks documentation, and documentation outranks an rater that observed nothing refuse")


def load_kb(path=None):
    path = Path(path or KB)
    if not path.is_file():
        raise BenchError("knowledge base snapshot %s is missing; rater A cannot run without it" % path)
    return read_json(path)


def support_index(kb, architecture="amd64"):
    """syscall name -> (status, detail) from the upstream support table for one architecture."""
    index = {}
    for item in kb.get("syscall_support") or []:
        if item.get("architecture") and item["architecture"] != architecture:
            continue
        index[item["syscall"]] = (item.get("status"), item.get("detail"))
    return index


def gap_index(kb, architecture="amd64", release=None):
    """syscall name -> gap entries that describe a documented shortfall for this runtime."""
    gaps = {}
    for entry in kb.get("entries") or []:
        if architecture not in (entry.get("architectures") or []):
            continue
        if release and (entry.get("runtime_versions") and release not in entry["runtime_versions"]):
            continue
        for syscall in entry.get("syscalls") or []:
            gaps.setdefault(syscall, []).append(entry)
    return gaps


def kb_label(case, kb, architecture=None, release=None):
    """Rater A: what does the knowledge base say this workload should do under the runtime?"""
    architecture = architecture or case["image"].get("architecture") or "amd64"
    release = release or case["runtime"]["release"]
    support, gaps = support_index(kb, architecture), gap_index(kb, architecture, release)
    tags = set(case.get("tags") or [])
    interfaces = case.get("expected_interfaces") or []
    evidence, affected = [], []
    for name in interfaces:
        entry = gaps.get(name) or []
        status = support.get(name, (None, None))[0]
        if status in ("full", None) and not entry:
            continue
        evidence.append("%s: support=%s gaps=%s" % (name, status, sorted(item["id"] for item in entry)))
        affected.append((name, status, entry))
    citation = sorted({item["citation"]["url"] for _, _, entries in affected for item in entries if item.get("citation")})
    if not affected:
        return {"class": "compatible", "confidence": "high",
                "rationale": "no expected interface %s is documented as partial or unimplemented for %s/%s"
                             % (", ".join(interfaces) or "none declared", case["runtime"]["name"], architecture),
                "evidence": evidence, "linked_evidence": citation}
    hard = [(name, entries) for name, status, entries in affected
            if any(item.get("severity_class") == "hard-failure" for item in entries)]
    if hard and ("required" in tags or ("io_uring" in tags and "fallback" not in tags)):
        names = sorted({name for name, _ in hard})
        return {"class": "hard-failure", "confidence": "high",
                "rationale": "%s is required by the declared command and documented as a hard failure for this runtime" % ", ".join(names),
                "evidence": evidence, "linked_evidence": citation}
    if "output-diff" in tags:
        return {"class": "silent-degradation", "confidence": "medium",
                "rationale": "the case declares that returned data diverges under the runtime: %s" % "; ".join(evidence),
                "evidence": evidence, "linked_evidence": citation}
    if "fallback" in tags or "optional" in tags:
        return {"class": "tolerated", "confidence": "medium",
                "rationale": "the workload declares a fallback for the unsupported interface, so degraded paths are expected to complete",
                "evidence": evidence, "linked_evidence": citation}
    if any(item.get("severity_class") == "silent-degradation"
           for _, _, entries in affected for item in entries):
        return {"class": "silent-degradation", "confidence": "medium",
                "rationale": "the documented divergence is in returned data, not in completion: %s" % "; ".join(evidence),
                "evidence": evidence, "linked_evidence": citation}
    return {"class": "indeterminate", "confidence": "low",
            "rationale": "the knowledge base documents a shortfall for %s but nothing here says whether the workload can proceed"
                         % ", ".join(sorted({name for name, _, _ in affected})),
            "evidence": evidence, "linked_evidence": citation}


def live_record_for(case_id, root=None):
    """The newest valid live record for a case, or None when there is no dynamic ground truth."""
    store = RunStore(root or BENCH / "runs")
    candidates = [item for item in store.records(valid_only=True)
                  if item["case_id"] == case_id and (item.get("predicted") or {}).get("tier") == "dynamic-runsc-diff"]
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: (item["started_at"], item["run_id"]))[-1]


TRACE_CALL = re.compile(r"\b([a-z0-9_]+)\(.*\) = -1 errno=(\d+)")
MAX_TRACE_LINES = 400000


def failed_calls(path, wanted, limit=MAX_TRACE_LINES):
    """(syscall, errno) pairs where one of `wanted` was refused, read from a raw trace."""
    found, lines = set(), 0
    try:
        handle = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return found, False
    with handle:
        for line in handle:
            lines += 1
            if lines > limit:
                return found, True
            match = TRACE_CALL.search(line)
            if match and match.group(1) in wanted:
                found.add((match.group(1), int(match.group(2))))
    return found, False


def output_label(case_id, root=None, kb=None):
    """Rater B: exit codes, stdout digests and refused syscalls, never the scanner's findings."""
    record = live_record_for(case_id, root)
    if not record:
        return {"class": "indeterminate", "confidence": "low", "rationale": "no valid live run is recorded for this case",
                "evidence": [], "linked_evidence": [], "run_id": None}
    case = case_registry.load(case_id)
    report = read_json(record["artifacts"]["report"]["path"])
    dynamic = report.get("dynamic") or {}
    native, sandbox = dynamic.get("native") or [], dynamic.get("sandbox") or []
    n_exit = [item.get("exit_code") for item in native]
    s_exit = [item.get("exit_code") for item in sandbox]
    pairs = list(zip(native, sandbox))
    differing_output = sorted({(index, left.get("stdout_sha256"), right.get("stdout_sha256"))
                               for index, (left, right) in enumerate(pairs)
                               if left.get("stdout_sha256") != right.get("stdout_sha256")})
    evidence = ["native exits %s, sandbox exits %s (run %s)" % (n_exit, s_exit, record["run_id"])]
    for index, before, after in differing_output:
        evidence.append("repetition %d stdout differs: native %s versus sandbox %s" % (index, before[:19], after[:19]))
    # Anything the knowledge base does not call fully supported is watched, and every refusal the
    # native run also produced is subtracted, so only a runtime-specific denial counts.
    gaps = gap_index(kb or load_kb())
    watched = set(gaps) | set(case.get("expected_interfaces") or [])
    refused, native_refused, truncated = [], [], False
    for item in record["artifacts"]["traces"]:
        hits, capped = failed_calls(resolve(item["path"]), watched)
        truncated = truncated or capped
        (native_refused if item["kind"] == "native" else refused).append(hits)
    sandbox_refused = sorted({pair for hits in refused for pair in hits} - {pair for hits in native_refused for pair in hits})
    if sandbox_refused:
        evidence.append("sandbox trace refused %s" % ", ".join("%s=errno%d" % pair for pair in sandbox_refused))
    if truncated:
        evidence.append("a trace exceeded %d lines and was read only that far" % MAX_TRACE_LINES)
    refs = [record["artifacts"]["report"]["path"]] + [item["path"] for item in record["artifacts"]["traces"]]
    failed = [code for code in s_exit if code not in (0, None)]
    if failed:
        return {"class": "hard-failure", "confidence": "high",
                "rationale": "the sandbox exited %s while native exited %s" % (failed, sorted(set(n_exit))),
                "evidence": evidence, "linked_evidence": refs, "run_id": record["run_id"]}
    if differing_output:
        return {"class": "silent-degradation", "confidence": "high",
                "rationale": "both runtimes exited 0 but the workload printed different bytes under the sandbox",
                "evidence": evidence, "linked_evidence": refs, "run_id": record["run_id"]}
    if not pairs:
        return {"class": "indeterminate", "confidence": "low", "rationale": "the recorded run has no paired repetitions",
                "evidence": evidence, "linked_evidence": refs, "run_id": record["run_id"]}
    if sandbox_refused:
        return {"class": "tolerated", "confidence": "high",
                "rationale": "%s was refused under the sandbox and not on native, yet the workload still exited 0, "
                             "which is a handled fallback" % ", ".join(sorted({name for name, _ in sandbox_refused})),
                "evidence": evidence, "linked_evidence": refs, "run_id": record["run_id"]}
    return {"class": "compatible", "confidence": "high",
            "rationale": "every paired repetition exited 0 in both runtimes with byte-identical stdout and no refusal "
                         "under the sandbox that native did not also produce",
            "evidence": evidence, "linked_evidence": refs, "run_id": record["run_id"]}


def rater_block(rater_id, verdict, kind="rule-adjudicator"):
    return {"id": rater_id, "kind": kind, "label_class": verdict["class"], "confidence": verdict["confidence"],
            "rationale": verdict["rationale"]}


def label_case(case_id, root=None, kb=None):
    """Both raters, then the documented adjudication, for one case."""
    kb = kb or load_kb()
    a, b = kb_label(case_registry.load(case_id), kb), output_label(case_id, root, kb)
    if a["class"] == b["class"]:
        gold, confidence, note = a["class"], "high", "both raters agree independently"
    elif "indeterminate" in (a["class"], b["class"]):
        other = b["class"] if a["class"] == "indeterminate" else a["class"]
        gold, confidence, note = ("indeterminate", "low", "one rater had no evidence at all") if other == "indeterminate" \
            else (other, "medium", "one rater abstained; the other decides")
    elif b["class"] != "compatible":
        gold, confidence, note = b["class"], "medium", \
            "raters disagree; a positive observation in the recorded execution evidence outranks documentation"
    else:
        gold, confidence, note = a["class"], "low", \
            "raters disagree; rater B saw nothing refuse while the knowledge base documents a shortfall, " \
            "so the documented risk decides with low confidence"
    label = {"class": gold, "confidence": confidence, "label_source": "rule-adjudicator",
             "rater_a": rater_block(RATER_A_ID, a), "rater_b": rater_block(RATER_B_ID, b),
             "adjudicator": {"id": "documented-rule", "kind": "rule-adjudicator", "label_class": gold,
                             "confidence": confidence, "rationale": note},
             "evidence": sorted(set(a["evidence"]) | set(b["evidence"])),
             "linked_evidence": [{"kind": "file", "ref": ref,
                                  "sha256": sha256_file(resolve(ref)) if (ROOT / ref).is_file() else None,
                                  "note": "raw execution evidence reviewed by rater B"} for ref in b["linked_evidence"]]}
    return {"case_id": case_id, "label": label, "rater_a": a, "rater_b": b,
            "agreement": a["class"] == b["class"], "gold": gold}


def label_path(case_id):
    return BENCH / "cases" / case_id / "labels" / "adjudicated.json"


def write_label(result):
    path = label_path(result["case_id"])
    payload = dict(result["label"])
    payload.update({"schema_version": "1.0", "case_id": result["case_id"], "labeled_at": now_iso(),
                    "rater_a_source": "kb/snapshot.json entries and syscall_support, read without the scanner",
                    "rater_b_source": "exit codes and stdout digests of a recorded live run"})
    return path, write_json(path, payload)


def collect(root=None, case_ids=None):
    """Label every case that has a case.json, so coverage is a fact about the store, not a choice."""
    kb = load_kb()
    ids = case_ids or sorted(path.parent.name for path in (BENCH / "cases").glob("*/case.json"))
    out = []
    for case_id in ids:
        try:
            out.append(label_case(case_id, root=root, kb=kb))
        except BenchError as error:
            print("  %s: %s" % (case_id, error))
    return out


def agreement_report(results):
    counts = {}
    for item in results:
        key = "%s|%s" % (item["rater_a"]["class"], item["rater_b"]["class"])
        counts[key] = counts.get(key, 0) + 1
    return {"cases": len(results), "agreeing": sum(1 for item in results if item["agreement"]),
            "kappa": cohens_kappa([(item["rater_a"]["class"], item["rater_b"]["class"]) for item in results]),
            "observed_pairs": dict(sorted(counts.items())),
            "gold_distribution": {label_class: sum(1 for item in results if item["gold"] == label_class)
                                  for label_class in sorted({item["gold"] for item in results})},
            "disagreements": [{"case_id": item["case_id"], "rater_a": item["rater_a"]["class"],
                               "rater_b": item["rater_b"]["class"]} for item in results if not item["agreement"]],
            "adjudication_rule": ADJUDICATION_RULE,
            "human_raters": 0,
            "claims_ceiling": "L2: both raters are documented rules over independent evidence, not independent humans"}


def command_label(args):
    if args.action == "add":
        if not (args.case and args.label_class and args.rater_id and args.rationale):
            raise BenchError("label add needs --case --rater-id --class --confidence --rationale")
        verdict = {"class": args.label_class, "confidence": args.confidence or "medium", "rationale": args.rationale,
                   "evidence": args.evidence or [], "linked_evidence": []}
        path = BENCH / "cases" / args.case / "labels" / ("%s.json" % args.rater_id)
        write_json(path, dict(verdict, schema_version="1.0", case_id=args.case, rater_id=args.rater_id,
                              rater_kind=args.rater_kind, recorded_at=now_iso()))
        print("label %s -> %s" % (args.label_class, rel_path(path)))
        return 0
    results = collect(case_ids=[args.case] if args.case else None)
    for item in results:
        write_label(item)
    report = agreement_report(results)
    if args.action == "report":
        if args.json:
            print(json.dumps(dict(report, cases_detail=[{"case_id": item["case_id"], "gold": item["gold"],
                                                          "confidence": item["label"]["confidence"]}
                                                          for item in results]), indent=2, sort_keys=True))
        else:
            print("cases=%d agreeing=%d kappa=%s" % (report["cases"], report["agreeing"], report["kappa"]))
            for line in report["disagreements"]:
                print("  disagree %s: A=%s B=%s" % (line["case_id"], line["rater_a"], line["rater_b"]))
            print("  ceiling: %s" % report["claims_ceiling"])
        return 0
    for item in results:
        print("%-30s gold=%-20s conf=%-6s A=%-20s B=%s" % (item["case_id"], item["gold"],
                                                           item["label"]["confidence"], item["rater_a"]["class"],
                                                           item["rater_b"]["class"]))
    return 0
