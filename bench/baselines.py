"""BH-09 baselines B0 and B5, computed from already-recorded runs.

Both baselines are reimplementations inside the harness, on purpose: the study makes no claim
about any third-party tool. Each reads the same recorded inputs the scanner saw and applies one
deliberately naive rule, so a table can say what the knowledge base and the dynamic evidence add
beyond "grep the syscall list" or "did it exit zero".
"""
from bench.common import BENCH, BenchError, read_json, rel_path, sha256_file, write_json
from bench.label import load_kb, support_index
from bench.store import RunStore

ARMS = {"b0": "B0_naive", "b3": "B3_confine_style", "b5": "B5_justrun"}


def dynamic_runs(store, suite=None):
    """Live records that carry a dynamic evidence tier, newest per case."""
    newest = {}
    for record in store.records(valid_only=True):
        if suite and record["suite"] != suite:
            continue
        if (record.get("predicted") or {}).get("tier") not in ("dynamic-runsc-diff", "dynamic-native-only"):
            continue
        current = newest.get(record["case_id"])
        if current is None or record["started_at"] > current["started_at"]:
            newest[record["case_id"]] = record
    return newest


def naive_verdict(record, support, runtime):
    """B0: flag anything that reaches a syscall the runtime does not fully implement."""
    report = read_json(record["artifacts"]["report"]["path"])
    dynamic = report.get("dynamic") or {}
    reached = sorted(set(dynamic.get("exercised_syscalls") or []))
    flagged = sorted({name for name in reached if (support.get(name, ("full",))[0] or "full") != "full"})
    label = "hard-failure" if flagged else "compatible"
    return {"class": label, "rule": "flag the workload if any reached syscall is not fully implemented",
            "inputs": {"runtime": runtime, "reached_syscalls": len(reached), "flagged": flagged},
            "correct": label == _gold(record["case_id"])}


def confine_style_verdict(record, support, runtime):
    """B3: Confine-style static extraction adapted to report unsupported-by-runtime syscalls."""
    report = read_json(record["artifacts"]["report"]["path"])
    cap_set = report.get("capability_set") or {}
    static_caps = sorted({c.get("syscall") for c in cap_set.get("capabilities", []) if c.get("syscall")})
    unsupported = sorted({name for name in static_caps if (support.get(name, ("full",))[0] or "full") in ("unimplemented", "unsupported")})
    if unsupported:
        label = "hard-failure"
    elif static_caps:
        label = "compatible"
    else:
        label = "indeterminate"
    return {"class": label, "rule": "flag workload if any statically extracted syscall is unsupported by runtime",
            "inputs": {"runtime": runtime, "extracted_syscalls": len(static_caps), "flagged": unsupported},
            "correct": label == _gold(record["case_id"])}


def justrun_verdict(record):
    """B5: run once, look at the exit code, say nothing else."""
    exits = [code for code in (record["repetitions"].get("sandbox_exits") or []) if code is not None]
    if not exits:
        return {"class": "indeterminate", "rule": "run once and read the exit code",
                "inputs": {"sandbox_exits": exits}, "correct": False}
    label = "compatible" if all(code == 0 for code in exits) else "hard-failure"
    return {"class": label, "rule": "run once and read the exit code",
            "inputs": {"sandbox_exits": exits}, "correct": label == _gold(record["case_id"])}


def _gold(case_id):
    path = BENCH / "cases" / case_id / "labels" / "adjudicated.json"
    if not path.is_file():
        raise BenchError("case %s has no adjudicated label; run bench label report before a baseline" % case_id)
    return read_json(path)["class"]


def compute(arm, root=None, suite=None):
    store = RunStore(root or BENCH / "runs")
    kb = load_kb()
    support = support_index(kb)
    rows = {}
    for case_id, record in sorted(dynamic_runs(store, suite).items()):
        report = record["artifacts"]["report"]
        base = {"case_id": case_id, "suite": record["suite"], "run_id": record["run_id"],
                "source_report": report["path"], "source_sha256": report["sha256"],
                "gold": _gold(case_id), "tool_prediction": (record.get("predicted") or {}).get("class"),
                "harness_note": "derived from recorded bytes; no new execution"}
        if arm == "b0":
            payload = {"arm": "B0_naive", **naive_verdict(record, support, kb.get("snapshot_version"))}
        elif arm == "b3":
            payload = {"arm": "B3_confine_style", **confine_style_verdict(record, support, kb.get("snapshot_version"))}
        else:
            payload = {"arm": "B5_justrun", **justrun_verdict(record)}
        rows[case_id] = dict(base, **payload)
    return rows


def write_rows(rows, arm, root=None):
    directory = BENCH / "baselines" / arm
    directory.mkdir(parents=True, exist_ok=True)
    for case_id, row in sorted(rows.items()):
        write_json(directory / ("%s.json" % case_id), row)
    return directory


def command_baselines(args):
    arms = ["b0", "b3", "b5"] if args.which in ("both", "all") else [args.which]
    for arm in arms:
        rows = compute(arm, suite=None)
        if args.case:
            rows = {key: value for key, value in rows.items() if key == args.case}
        if not rows:
            raise BenchError("no recorded dynamic run exists for %s" % arm)
        directory = write_rows(rows, arm)
        hits = sum(1 for row in rows.values() if row["correct"])
        print("%s: %d cases, %d matched the adjudicated label -> %s" % (ARMS[arm], len(rows), hits, rel_path(directory)))
        for case_id, row in sorted(rows.items()):
            print("  %-30s %-20s gold=%-20s tool=%s" % (case_id, row["class"], row["gold"], row["tool_prediction"]))
    return 0


def load_baselines(arm, root=None):
    """Read back computed baselines so the analyzer never recomputes them differently."""
    directory = BENCH / "baselines" / arm
    rows = {}
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        row = read_json(path)
        row["_path"], row["_sha256"] = rel_path(path), sha256_file(path)
        rows[row["case_id"]] = row
    return rows
