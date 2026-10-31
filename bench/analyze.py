"""BH-08 analysis: every published number resolves to a recorded run or it is not published.

This module reads bench/runs, the adjudicated labels and the computed baselines, and writes
tables and figures. It never runs the scanner, never accepts a number from the caller and fails
loudly when a registered hypothesis has no recorded input: an empty cell is reported as missing,
not as zero. Output is deterministic by construction (sorted keys, quantized floats, LF newlines,
no timestamps), which is what makes the BM-13 byte-identity claim testable.
"""
import json
from pathlib import Path

from bench import baselines as baselines_module
from bench import stats
from bench.common import BENCH, BenchError, quantize, read_json, rel_path, resolve, sha256_file, write_json
from bench.predict import LABEL_CLASSES
from bench.store import RunStore, require_preregistration

SUITES_ORDERED = ("BM-01", "BM-02", "BM-03", "BM-04", "BM-07", "BM-08", "BM-13", "BM-14")
TABLES = "tables"
FIGURES = "figures"


class Missing(Exception):
    """Raised when a registered statistic has no recorded input to compute from."""


def gold_labels(case_ids=None):
    directory = BENCH / "cases"
    rows = {}
    for path in sorted(directory.glob("*/labels/adjudicated.json")):
        record = read_json(path)
        if case_ids and record["case_id"] not in case_ids:
            continue
        rows[record["case_id"]] = {"class": record["class"], "confidence": record["confidence"],
                                   "label_path": rel_path(path), "label_sha256": sha256_file(path)}
    return rows


def scored_runs(root, suite=None):
    """Valid records that carry a prediction, newest per (case, suite, pattern, position).

    The position is part of the key on purpose: an ABBA block holds four different arms, and a
    store keyed only by the block label would silently keep one arm per case and score the wrong
    thing.
    """
    store = RunStore(root)
    rows = {}
    for record in store.records(valid_only=True):
        if suite and record["suite"] != suite:
            continue
        if not record.get("predicted"):
            continue
        key = (record["case_id"], record["suite"], record["order_pattern"], record["order_index"])
        current = rows.get(key)
        if current is None or record["started_at"] > current["started_at"]:
            rows[key] = record
    return rows


def _primary(rows, case_id, suite):
    """The compatibility arm for a case in a suite: dynamic tier if present, else any arm."""
    candidates = [record for key, record in sorted(rows.items()) if key[0] == case_id and key[1] == suite]
    if not candidates:
        raise Missing("no recorded run for case %s in suite %s" % (case_id, suite))
    dynamic = [record for record in candidates if record["predicted"]["tier"] == "dynamic-runsc-diff"]
    return (dynamic or candidates)[0]


def _rate(hits, count, arm):
    interval = stats.wilson(hits, count)
    return {"arm": arm, "hits": hits, "count": count, "rate": interval["point"],
            "low": interval["low"], "high": interval["high"], "method": interval["method"]}


def verdict_accuracy(root=BENCH / "runs", suite="BM-01"):
    """H1 endpoint: tool, B0 and B5 accuracy against the adjudicated labels on the same cases."""
    rows = scored_runs(root)
    cases = sorted({key[0] for key in rows if key[1] == suite})
    gold = gold_labels(set(cases))
    b0 = baselines_module.load_baselines("b0")
    b3 = baselines_module.load_baselines("b3")
    b5 = baselines_module.load_baselines("b5")
    has_b3 = bool(b3 and all(case_id in b3 for case_id in cases))
    table, pairs_tool_b0, pairs_tool_b5, pairs_b0_b5, pairs_tool_b3 = [], [], [], [], []
    for case_id in cases:
        if case_id not in gold:
            raise Missing("case %s has a recorded run but no adjudicated label" % case_id)
        record = _primary(rows, case_id, suite)
        tool = record["predicted"]["class"]
        naive, justrun = (b0.get(case_id) or {}).get("class"), (b5.get(case_id) or {}).get("class")
        confine = (b3.get(case_id) or {}).get("class") if has_b3 else None
        if naive is None or justrun is None:
            raise Missing("baseline prediction missing for %s; run bench baselines both" % case_id)
        correct = {"tool": tool == gold[case_id]["class"], "b0": naive == gold[case_id]["class"],
                   "b5": justrun == gold[case_id]["class"]}
        if has_b3:
            correct["b3"] = confine == gold[case_id]["class"]
        row_entry = {"case_id": case_id, "run_id": record["run_id"], "gold": gold[case_id]["class"],
                     "gold_confidence": gold[case_id]["confidence"], "tool": tool, "b0_naive": naive,
                     "b5_justrun": justrun, "tool_correct": correct["tool"], "b0_correct": correct["b0"],
                     "b5_correct": correct["b5"], "tier": record["predicted"]["tier"],
                     "report_sha256": record["artifacts"]["report"]["sha256"]}
        if has_b3:
            row_entry["b3_confine"] = confine
            row_entry["b3_correct"] = correct["b3"]
            pairs_tool_b3.append((correct["tool"], correct["b3"]))
        table.append(row_entry)
        pairs_tool_b0.append((correct["tool"], correct["b0"]))
        pairs_tool_b5.append((correct["tool"], correct["b5"]))
        pairs_b0_b5.append((correct["b0"], correct["b5"]))
    if not table:
        raise Missing("suite %s has no valid recorded run to score" % suite)
    tests = {"tool_vs_b0": stats.mcnemar_exact(pairs_tool_b0), "tool_vs_b5": stats.mcnemar_exact(pairs_tool_b5),
             "b0_vs_b5": stats.mcnemar_exact(pairs_b0_b5)}
    names = ["tool_vs_b0", "tool_vs_b5", "b0_vs_b5"]
    if has_b3:
        tests["tool_vs_b3"] = stats.mcnemar_exact(pairs_tool_b3)
        names.append("tool_vs_b3")
    corrected = stats.holm([tests[key]["p_value"] for key in names])
    for name, p_value, reject in zip(names, corrected["adjusted"], corrected["reject"]):
        tests[name].update({"holm_adjusted_p": p_value, "holm_reject": reject})
    rates = {}
    arms_to_check = ("tool", "b0", "b3", "b5") if has_b3 else ("tool", "b0", "b5")
    for arm in arms_to_check:
        hits = sum(1 for row in table if row["%s_correct" % arm])
        rates[arm] = _rate(hits, len(table), arm)
    return {"suite": suite, "cases": table, "accuracy": rates, "paired_tests": tests,
            "holm_alpha": corrected["alpha"],
            "coverage_note": "every case here has a recorded dynamic run; nothing is imputed"}


def coverage(root=BENCH / "runs"):
    """PRD principle 5: the incomplete-scan rate is a reported quantity, never hidden."""
    store = RunStore(root)
    rows = []
    for suite in SUITES_ORDERED:
        records = [record for record in store.records() if record["suite"] == suite]
        if not records:
            rows.append({"suite": suite, "runs": 0, "valid": 0, "invalid": 0, "complete": 0, "incomplete": 0,
                         "dynamic_tier": 0, "status": "not run"})
            continue
        valid = [record for record in records if record["valid"]]
        reports = []
        for record in valid:
            report = record.get("artifacts", {}).get("report")
            if report:
                reports.append(read_json(resolve(report["path"])))
        complete = sum(1 for report in reports if report.get("status") == "complete")
        tiers = {}
        for record in valid:
            tier = (record.get("predicted") or {}).get("tier") or "none"
            tiers[tier] = tiers.get(tier, 0) + 1
        rows.append({"suite": suite, "runs": len(records), "valid": len(valid), "invalid": len(records) - len(valid),
                     "complete": complete, "incomplete": len(reports) - complete,
                     "dynamic_tier": tiers.get("dynamic-runsc-diff", 0), "tiers": dict(sorted(tiers.items())),
                     "incomplete_rate": quantize((len(reports) - complete) / len(reports)) if reports else None})
    return rows


def confusion(root=BENCH / "runs", suite="BM-01"):
    """Gold class against predicted class over the scored cases."""
    table = verdict_accuracy(root, suite)["cases"]
    matrix = {gold: {predicted: 0 for predicted in LABEL_CLASSES} for gold in LABEL_CLASSES}
    for row in table:
        matrix[row["gold"]][row["tool"]] += 1
    return matrix


def stability(root=BENCH / "runs"):
    """BM-14: does the same case get the same class in every recorded live block?"""
    rows = scored_runs(root, "BM-14")
    per_case = {}
    for (case_id, _suite, pattern, _index), record in sorted(rows.items()):
        per_case.setdefault(case_id, []).append({"order_pattern": pattern, "order_index": record["order_index"],
                                                 "class": record["predicted"]["class"], "run_id": record["run_id"]})
    table = []
    for case_id, attempts in sorted(per_case.items()):
        classes = sorted({item["class"] for item in attempts})
        table.append({"case_id": case_id, "attempts": len(attempts), "classes": classes,
                      "stable": len(classes) == 1, "detail": json.dumps(attempts, sort_keys=True)})
    if not table:
        raise Missing("BM-14 has no recorded live runs")
    return table


def ablation(root=BENCH / "runs"):
    """BM-04: the static arm's class against the live arm's class on the same case."""
    rows = scored_runs(root, "BM-04")
    cases = sorted({key[0] for key in rows})
    gold = gold_labels(set(cases))
    table = []
    for case_id in cases:
        if case_id not in gold:
            raise Missing("BM-04 case %s has runs but no adjudicated label" % case_id)
        static = [record for (name, _s, _p, _i), record in sorted(rows.items())
                  if name == case_id and record["predicted"]["tier"] == "static-only"]
        live = [record for (name, _s, _p, _i), record in sorted(rows.items())
                if name == case_id and record["predicted"]["tier"] == "dynamic-runsc-diff"]
        if not static or not live:
            raise Missing("BM-04 case %s is missing a %s arm" % (case_id, "static" if not static else "live"))
        table.append({"case_id": case_id, "gold": gold[case_id]["class"],
                      "static_class": static[0]["predicted"]["class"], "static_runs": len(static),
                      "live_class": live[0]["predicted"]["class"], "live_runs": len(live),
                      "static_correct": static[0]["predicted"]["class"] == gold[case_id]["class"],
                      "live_correct": live[0]["predicted"]["class"] == gold[case_id]["class"],
                      "static_ids": [record["run_id"] for record in static],
                      "live_ids": [record["run_id"] for record in live]})
    if not table:
        raise Missing("BM-04 has no recorded runs; run bench suite BM-04")
    return table


def latency(root=BENCH / "runs"):
    """Observed execution time per arm. The host is uncontrolled, so this is descriptive only."""
    rows = scored_runs(root)
    per_case = {}
    for (case_id, suite, _pattern, _index), record in sorted(rows.items()):
        if record["predicted"]["tier"] != "dynamic-runsc-diff":
            continue
        native = record["repetitions"]["native_durations_ms"]
        sandbox = record["repetitions"]["sandbox_durations_ms"]
        if not native or not sandbox:
            continue
        per_case.setdefault(case_id, []).append({"suite": suite, "run_id": record["run_id"],
                                                 "native_ms": stats.nearest_rank(native, 50),
                                                 "sandbox_ms": stats.nearest_rank(sandbox, 50)})
    table = []
    for case_id, items in sorted(per_case.items()):
        native = [item["native_ms"] for item in items]
        sandbox = [item["sandbox_ms"] for item in items]
        ratio = stats.quantize(sum(sandbox) / sum(native)) if sum(native) else None
        table.append({"case_id": case_id, "runs": len(items), "run_ids": [item["run_id"] for item in items],
                      "native_median_ms": stats.nearest_rank(native, 50),
                      "sandbox_median_ms": stats.nearest_rank(sandbox, 50),
                      "sandbox_over_native": ratio})
    ratios = [row["sandbox_over_native"] for row in table if row["sandbox_over_native"]]
    return {"cases": table, "geometric_mean_ratio": quantize(stats.geometric_mean(ratios)) if ratios else None,
            "warning": "measured on an uncontrolled desktop host under WSL2; these are observations, "
                       "not a performance claim (PRD principle 4)"}


def sample_size_note(root=BENCH / "runs", suite="BM-01"):
    """PRD 4.4: recall is measured over the positives only, and few positives mean a wide interval."""
    table = verdict_accuracy(root, suite)["cases"]
    positives = [row for row in table if row["gold"] in ("hard-failure", "silent-degradation")]
    detected = sum(1 for row in positives if row["tool"] == row["gold"])
    note = stats.sample_size_note(len(positives), quantize(detected / len(positives)) if positives else None)
    return {"suite": suite, "positives": note["positives"], "detected": detected,
            "recall": note["achieved"], "interval_half_width": note["half_width"],
            "target_half_width": note["target_half_width"], "recall_interval": note["interval"],
            "warning": note["warning"]}


def write_table(path, header, rows):
    """CSV with LF newlines and no free formatting; the digest of this file is the number."""
    lines = [",".join(header)]
    for row in rows:
        lines.append(",".join(_cell(row.get(name)) for name in header))
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    return path


def _cell(value):
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return repr(quantize(value)) if isinstance(value, float) else str(value)
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    text = text.replace("\"", "\"\"")
    return '"%s"' % text if ("," in text or "\"" in text or " " in text) else text


def svg_chart(path, title, labels, series, unit, note=None):
    """Standalone bars: no scripts, no external resources, stable byte output."""
    width, left, top = 960, 320, 70
    row_height = max(48, 22 * len(series) + 10)
    height = top + row_height * len(labels) + (60 if note else 45)
    maximum = max((value for _, values, _ in series for value in values if value is not None), default=1) or 1
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img">' % (width, height, width, height),
             '<title>%s</title><rect width="100%%" height="100%%" fill="#f9faf7"/>' % _escape(title),
             '<text x="24" y="30" font-family="sans-serif" font-size="19" fill="#183c3a">%s</text>' % _escape(title)]
    for index, label in enumerate(labels):
        y = top + index * row_height
        parts.append('<text x="24" y="%d" font-family="sans-serif" font-size="12">%s</text>' % (y + 14, _escape(label)))
        for offset, (name, values, color) in enumerate(series):
            value = values[index]
            if value is None:
                continue
            bar = max(0.0, value) / maximum * (width - left - 190)
            line_y = y + offset * 22
            parts.append('<rect x="%d" y="%d" width="%.2f" height="15" fill="%s"/>' % (left, line_y, bar, color))
            parts.append('<text x="%.2f" y="%d" font-family="sans-serif" font-size="11">%s %.3f %s</text>'
                         % (left + bar + 7, line_y + 12, _escape(name), value, _escape(unit)))
    if note:
        parts.append('<text x="24" y="%d" font-family="sans-serif" font-size="11" fill="#5a6b68">%s</text>'
                     % (height - 22, _escape(note)))
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(parts) + "</svg>\n")
    return path


def _escape(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def build(root=BENCH / "runs", out=BENCH / "analysis"):
    """Compute every table, then write it; returns the manifest of what was produced."""
    tables_dir = Path(out) / TABLES
    figures_dir = Path(out) / FIGURES
    tables_dir.mkdir(parents=True, exist_ok=True)
    figures_dir.mkdir(parents=True, exist_ok=True)
    produced, notes = {}, []

    h1 = verdict_accuracy(root, "BM-01")
    columns = ["case_id", "run_id", "gold", "gold_confidence", "tool", "b0_naive", "b5_justrun",
               "tool_correct", "b0_correct", "b5_correct", "tier", "report_sha256"]
    write_table(tables_dir / "h1-verdict-accuracy.csv", columns, h1["cases"])
    write_json(tables_dir / "h1-accuracy-summary.json",
               {"accuracy": h1["accuracy"], "paired_tests": h1["paired_tests"],
                "sample_size": sample_size_note(root, "BM-01")})
    produced["h1-verdict-accuracy.csv"] = h1["cases"]

    matrix = confusion(root, "BM-01")
    write_table(tables_dir / "confusion-bm01.csv", ["gold"] + list(LABEL_CLASSES),
                [dict({"gold": gold}, **{predicted: matrix[gold][predicted] for predicted in LABEL_CLASSES})
                 for gold in LABEL_CLASSES])
    write_table(tables_dir / "coverage.csv",
                ["suite", "runs", "valid", "invalid", "complete", "incomplete", "dynamic_tier", "status",
                 "incomplete_rate"], coverage(root))
    write_table(tables_dir / "stability-bm14.csv",
                ["case_id", "attempts", "stable", "classes"], stability(root))
    write_table(tables_dir / "ablation-bm04.csv",
                ["case_id", "gold", "static_class", "live_class", "static_correct", "live_correct",
                 "static_runs", "live_runs"], ablation(root))
    observed = latency(root)
    write_table(tables_dir / "latency-observations.csv",
                ["case_id", "runs", "native_median_ms", "sandbox_median_ms", "sandbox_over_native"], observed["cases"])
    write_json(tables_dir / "latency-summary.json", {"geometric_mean_ratio": observed["geometric_mean_ratio"],
                                                     "warning": observed["warning"]})
    labels = gold_labels()
    write_table(tables_dir / "labels.csv", ["case_id", "class", "confidence", "label_path", "label_sha256"],
                [labels[key] for key in sorted(labels)])
    agreement = label_report()
    write_json(tables_dir / "rater-agreement.json", agreement)
    missing = not_run(root)
    write_table(tables_dir / "not-run.csv", ["suite", "reason", "runbook"], missing)

    cases = [row["case_id"] for row in h1["cases"]]
    svg_chart(figures_dir / "verdict-accuracy.svg", "Verdict accuracy against adjudicated labels (BM-01)",
              ["tool", "B0 naive", "B5 just-run"], [("", [h1["accuracy"][arm]["rate"] for arm in ("tool", "b0", "b5")], "#2f7d76")],
              "", note="Wilson 95 percent intervals are printed in tables/h1-accuracy-summary.json")
    svg_chart(figures_dir / "latency-ratio.svg", "Median sandbox time over median native time (observed, uncontrolled host)",
              [row["case_id"] for row in observed["cases"]],
              [("ratio", [row["sandbox_over_native"] for row in observed["cases"]], "#3f6fb5")], "x",
              note=observed["warning"])
    for name, values, color in [("tool", [1 if row["tool_correct"] else 0 for row in h1["cases"]], "#2f7d76"),
                                ("b0", [1 if row["b0_correct"] else 0 for row in h1["cases"]], "#b5651d"),
                                ("b5", [1 if row["b5_correct"] else 0 for row in h1["cases"]], "#7a4ea3")]:
        svg_chart(figures_dir / ("per-case-%s.svg" % name), "Per-case correctness: %s" % name, cases,
                  [("correct", values, color)], "", note="1 = matched the adjudicated label")
    notes.append("BM-01 has %d scored cases; %d disagree with the tool" %
                 (len(cases), sum(1 for row in h1["cases"] if not row["tool_correct"])))

    manifest = {"schema_version": "1.0", "root": rel_path(Path(root)), "tables": {}, "figures": {}, "notes": notes,
                "hypotheses_without_runs": [entry["suite"] for entry in missing]}
    # Keyed relative to the output directory: the same tables written to a different --out must
    # produce a comparable manifest, otherwise BM-13's cross-interpreter diff measures the path.
    for path in sorted(tables_dir.glob("*")):
        manifest["tables"][path.name] = sha256_file(path)
    for path in sorted(figures_dir.glob("*")):
        manifest["figures"][path.name] = sha256_file(path)
    return manifest


def label_report():
    from bench import label as label_module
    return label_module.agreement_report(label_module.collect())


def not_run(root):
    """Which registered suites have no recorded input here, and why."""
    store = RunStore(root)
    recorded = {record["suite"] for record in store.records()}
    runbooks = {"BM-02": "bench/specs/BM-02.md", "BM-03": "bench/specs/BM-03.md", "BM-05": "bench/specs/NOT-RUN.md",
                "BM-06": "bench/specs/NOT-RUN.md", "BM-07": "bench/specs/BM-07.md", "BM-08": "bench/specs/BM-08.md",
                "BM-09": "bench/specs/NOT-RUN.md", "BM-10": "bench/specs/NOT-RUN.md", "BM-11": "bench/specs/NOT-RUN.md",
                "BM-12": "bench/specs/NOT-RUN.md"}
    reasons = {"BM-09": "no bare-metal host and no KVM-controlled timing lab on this machine",
               "BM-10": "no Kubernetes 1.35/1.36 cluster reachable from this host",
               "BM-11": "accessibility review needs a rendered product surface, not this repository",
               "BM-12": "human-subject study: no participants were recruited (IRB would be required)",
               "BM-05": "a full 200-rule KB audit needs reviewer time beyond this session",
               "BM-06": "cross-tool comparison needs second-party tools that are not installed here"}
    rows = []
    # BM-02 and BM-08 write tables directly without run records; treat the CSV as presence evidence.
    csv_tables = {path.stem for path in (BENCH / "analysis" / "tables").glob("*.csv")} if (BENCH / "analysis" / "tables").exists() else set()
    bm02_done = "bm02_static_extraction" in csv_tables
    bm08_done = "bm08_scalability" in csv_tables
    for suite in ("BM-02", "BM-03", "BM-05", "BM-06", "BM-07", "BM-08", "BM-09", "BM-10", "BM-11", "BM-12"):
        if suite in recorded:
            continue
        if suite == "BM-02" and bm02_done:
            continue
        if suite == "BM-08" and bm08_done:
            continue
        rows.append({"suite": suite, "reason": reasons.get(suite, "no driver executed on this host"),
                    "runbook": runbooks.get(suite, "bench/specs/NOT-RUN.md")})
    return rows


def command_analyze(args):
    require_preregistration()
    root = resolve(args.root) if not Path(args.root).is_absolute() else Path(args.root)
    try:
        manifest = build(root, args.out)
    except Missing as error:
        raise BenchError("analysis refused: %s" % error)
    write_json(Path(args.out) / "analysis-manifest.json", manifest)
    print("tables=%d figures=%d manifest=%s" % (len(manifest["tables"]), len(manifest["figures"]),
                                                rel_path(Path(args.out) / "analysis-manifest.json")))
    h1 = verdict_accuracy(root)
    arms = [("tool", "scanner  "), ("b0", "B0 naive")]
    if "b3" in h1["accuracy"]:
        arms.append(("b3", "B3 confine"))
    arms.append(("b5", "B5 just-run"))
    for arm, name in arms:
        entry = h1["accuracy"][arm]
        print("  %s %d/%d = %.3f (Wilson %.3f..%.3f)" % (name, entry["hits"], entry["count"], entry["rate"],
                                                         entry["low"], entry["high"]))
    print("  McNemar tool vs B5 p=%.4f, tool vs B0 p=%.4f (Holm adjusted)"
          % (h1["paired_tests"]["tool_vs_b5"]["holm_adjusted_p"], h1["paired_tests"]["tool_vs_b0"]["holm_adjusted_p"]))
    if args.suites:
        print("  restricted to %s (tables are computed over everything recorded)" % " ".join(args.suites))
    return 0
