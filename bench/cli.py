"""BH-01: `python -m bench <subcommand>` entry point.

Subcommands mirror PRD v2 BH-01: hostinfo, fetch, run, label, analyze, publish, verify,
plus the suite drivers (predict, faults, fuzz-corpus, sources, baselines, preflight).
Exit codes match the scanner's convention: 0 success, 1 a measured failure, 2 harness or
usage error.
"""
import argparse
import json
import sys

from bench import BENCH_VERSION
from bench.common import BENCH, ROOT, BenchError, write_json


def build_parser():
    parser = argparse.ArgumentParser(prog="bench", description="SENTRYCHECK benchmark harness")
    parser.add_argument("--version", action="version", version="bench %s" % BENCH_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    info = sub.add_parser("hostinfo", help="record the measurement environment (BH-03)")
    info.add_argument("--host-id")
    info.add_argument("--out", default=str(BENCH / "hosts" / "host.json"))
    info.add_argument("--tools", nargs="*")
    info.add_argument("--work-root", help="where live work will actually run; on WSL this must be the ext4 home, not /mnt/c")

    schemas = sub.add_parser("schemas", help="validate the contract schemas and print their digests")
    schemas.add_argument("--json", action="store_true")

    pre = sub.add_parser("preflight", help="check disk, load, clock and runtime checksums (BH-05)")
    pre.add_argument("--host", help="host record to check against")
    pre.add_argument("--min-free-mb", type=int, default=4096)
    pre.add_argument("--max-load", type=float, default=None)
    pre.add_argument("--work-root")
    pre.add_argument("--json", action="store_true")

    fetch = sub.add_parser("fetch", help="pull a digest-pinned image into an OCI layout (BH-01 fetch)")
    fetch.add_argument("reference", help="image name, or name@sha256:... for a pinned digest")
    fetch.add_argument("--arch", default="amd64")
    fetch.add_argument("--out", help="OCI layout directory; defaults under bench/images")
    fetch.add_argument("--timeout", type=int, default=60)
    fetch.add_argument("--manifest-only", action="store_true",
                       help="pin digests and config only; do not download layer blobs")

    run = sub.add_parser("run", help="execute a case and record it (BH-04)")
    run.add_argument("--case", required=True)
    run.add_argument("--suite", required=True)
    run.add_argument("--host", required=True, help="host record path")
    run.add_argument("--binary", help="sentrycheck binary; defaults to the build under target/debug")
    run.add_argument("--seed", type=int, required=True)
    run.add_argument("--out", help="run directory; defaults under bench/runs")
    run.add_argument("--repetitions", type=int, default=3)
    run.add_argument("--max-kb-age-days", type=int, default=None,
                     help="explicit KB age budget; required for reproducible records")
    run.add_argument("--live", action="store_true", help="run native/sandbox executions, not just the scan")
    run.add_argument("--runc-bin")
    run.add_argument("--runsc-bin")
    run.add_argument("--runsc-platform", help="recorded platform axis, e.g. systrap or kvm")
    run.add_argument("--order-index", type=int, default=0, help="position within the ABBA sequence")
    run.add_argument("--order-pattern", help="sequence label, e.g. ABBA or single")
    run.add_argument("--run-id", help="override the generated run id (suite drivers pre-allocate them)")
    run.add_argument("--timeout", type=int, default=900)
    run.add_argument("--dry-run", action="store_true")

    label = sub.add_parser("label", help="two-rater labeling workflow and agreement (BH-07)")
    label.add_argument("action", choices=["add", "list", "report"])
    label.add_argument("--case")
    label.add_argument("--rater-id")
    label.add_argument("--rater-kind", choices=["human", "rule-adjudicator"], default="human")
    label.add_argument("--class", dest="label_class")
    label.add_argument("--confidence", choices=["high", "medium", "low"])
    label.add_argument("--rationale")
    label.add_argument("--evidence", nargs="*")
    label.add_argument("--json", action="store_true")

    predict = sub.add_parser("predict", help="apply the BT-01 report-to-class mapping to reports")
    predict.add_argument("reports", nargs="*", help="report.json files or directories")
    predict.add_argument("--root", default=str(BENCH / "runs"))
    predict.add_argument("--out", help="write the prediction table here")

    analyze = sub.add_parser("analyze", help="deterministic metrics, tables and figures (BH-08)")
    analyze.add_argument("--root", default=str(BENCH / "runs"))
    analyze.add_argument("--out", default=str(BENCH / "analysis"))
    analyze.add_argument("--suites", nargs="*")

    verify = sub.add_parser("verify", help="re-hash every stored artifact and detect tampering (BH-06)")
    verify.add_argument("--root", default=str(BENCH / "runs"))
    verify.add_argument("--all", action="store_true", help="also verify sources and dataset bundles")
    verify.add_argument("--prereg", action="store_true", help="check the pre-registration hash")

    merge = sub.add_parser("merge", help="multi-host support: merge runs from another host (BH-11)")
    merge.add_argument("source", help="source directory containing run records to merge")
    merge.add_argument("--root", default=str(BENCH / "runs"), help="target store root")
    merge.add_argument("--hosts", help="source hosts directory; defaults to source.parent/hosts")

    publish = sub.add_parser("publish", help="build the versioned dataset bundle (BH-10)")
    publish.add_argument("--version", default="bench-0.1")
    publish.add_argument("--root", default=str(BENCH / "runs"))
    publish.add_argument("--out", default=str(BENCH / "datasets"))
    publish.add_argument("--force", action="store_true", help="rewrite an existing published version")

    dash = sub.add_parser("dashboard", help="generate the static dashboard report (BH-12)")
    dash.add_argument("--root", default=str(BENCH / "runs"))
    dash.add_argument("--out", default=str(BENCH / "analysis" / "dashboard"))

    cases = sub.add_parser("cases", help="case registry operations")
    cases.add_argument("action", choices=["list", "validate", "import-corpus", "validate-submission"])
    cases.add_argument("--out", default=str(BENCH / "cases"))
    cases.add_argument("--file", help="path to a case submission file for validate-submission")

    faults = sub.add_parser("faults", help="BM-03 trace fault-injection corpus (BH-14)")
    faults.add_argument("--seed", type=int, default=1)
    faults.add_argument("--out", default=str(BENCH / "cases" / "fault-corpus"))
    faults.add_argument("--count", type=int, default=48)

    corpus = sub.add_parser("adversarial", help="BM-07 adversarial/malformed-input corpus")
    corpus.add_argument("--seed", type=int, default=1)
    corpus.add_argument("--count", type=int, default=24)
    corpus.add_argument("--out", default=str(BENCH / "cases" / "adversarial"))

    sources = sub.add_parser("sources", help="download the reference link library (PRD section 14)")
    sources.add_argument("--out", default=str(BENCH / "sources"))
    sources.add_argument("--timeout", type=int, default=45)
    sources.add_argument("--only", nargs="*", help="re-fetch only the links containing these substrings")

    baseline = sub.add_parser("baselines", help="run B0 naive and B5 just-run baselines (BH-09)")
    baseline.add_argument("which", choices=["b0", "b3", "b5", "both", "all"])
    baseline.add_argument("--case")
    baseline.add_argument("--out", default=str(BENCH / "runs"))

    estimator = sub.add_parser("estimate", help="cost and time estimator per suite (BH-15)")
    estimator.add_argument("suite", nargs="?", default="all", help="suite to estimate (BM-01, BM-04, etc., or all)")
    estimator.add_argument("--repetitions", type=int, default=3)

    suites = sub.add_parser("suite", help="run a whole suite driver (live matrix, gcc corpus, ladders, rebuild)")
    suites.add_argument("which", choices=["BM-01", "BM-02", "BM-03", "BM-04", "BM-07", "BM-08", "BM-13", "BM-14"])
    suites.add_argument("--case", help="restrict the sweep to one case id")
    suites.add_argument("--host")
    suites.add_argument("--binary")
    suites.add_argument("--out", default=str(BENCH / "runs"))
    suites.add_argument("--seed", type=int, default=20261031)
    suites.add_argument("--repetitions", type=int, default=3,
                        help="must equal the profile's pinned repetitions; the scanner has no override")
    suites.add_argument("--max-kb-age-days", type=int, default=400)
    suites.add_argument("--runsc-platform", default="systrap")
    suites.add_argument("--timeout", type=int, default=900)
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "hostinfo": "bench.hostinfo",
        "schemas": "bench.schemas",
        "preflight": "bench.preflight",
        "fetch": "bench.fetch",
        "run": "bench.runner",
        "label": "bench.label",
        "predict": "bench.predict",
        "analyze": "bench.analyze",
        "verify": "bench.store",
        "merge": "bench.store",
        "publish": "bench.publish",
        "dashboard": "bench.dashboard",
        "cases": "bench.cases",
        "faults": "bench.faults",
        "adversarial": "bench.adversarial",
        "sources": "bench.sources",
        "baselines": "bench.baselines",
        "estimate": "bench.estimator",
        "suite": "bench.suites",
    }
    try:
        import importlib
        module = importlib.import_module(handlers[args.command])
        entry = getattr(module, "command_" + args.command.replace("-", "_"), None)
        if entry is None:
            raise BenchError("subcommand %s is not implemented" % args.command)
        return entry(args)
    except BenchError as error:
        print("bench: error: %s" % error, file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 2


if __name__ == "__main__":
    sys.exit(main())
