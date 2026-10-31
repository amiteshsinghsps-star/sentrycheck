# Comparing release knowledge bases

`sentrycheck kb diff` compares two explicitly supplied snapshots without changing the active KB or contacting a network service:

```sh
sentrycheck kb diff kb/old.json kb/new.json
sentrycheck kb diff kb/old.json kb/new.json --format json > kb-changes.json
```

The arguments are **snapshot files**, not release names. Obtain historical snapshots through the source-pinned importer; do not relabel the current table as an older release:

```sh
python scripts/update_kb.py --version 20260914.0 --out artifacts/kb/20260914.0.json
python scripts/update_kb.py --version 20260921.0 --out artifacts/kb/20260921.0.json
sentrycheck kb diff artifacts/kb/20260914.0.json artifacts/kb/20260921.0.json --format json
```

These are reproduction commands, not a claim that either download has been run. The importer resolves the release tag to an immutable commit, hashes the downloaded table and compatibility prose, and checks the syscall constructor implementation against a reviewed hash. A changed constructor hash stops the import until its semantics are reviewed. The offline importer options are documented by `python scripts/update_kb.py --help`.

## Reading the result

Rows are matched by runtime, architecture and syscall name, in deterministic sorted order. The existing schema 1.0 support table has implicit gVisor ownership and must name exactly one gVisor release. Diff rejects ambiguous multi-release tables and snapshots claiming an additional runtime matrix. Kata comparisons require a future format with explicit row ownership.

The result separates:

- **Added/removed rows:** a row is present in one snapshot only. Removal means unknown support in that snapshot, never an inferred `unimplemented` status.
- **Support status changes:** transitions among `full`, `partial` and `unimplemented`.
- **Documentation changes:** a support note changed; this alone does not establish a behavioral change.
- **Syscall number changes:** tracked separately so a renumbered row is visible.
- **Source location changes:** line movement is provenance, not a compatibility regression.
- **Gap-definition changes:** status, description, category, matching rules and other definitions changed.
- **Gap-provenance changes:** release, dates or citations changed, without implying that support changed.

Each changed row includes the old/new values and a commit-pinned citation. Snapshot identities include the original input-byte SHA-256, release, source commit and declared source hashes. A source-commit change alone does not label every unchanged syscall as a support change. A renamed syscall appears as removal plus addition, since a name change cannot safely be assumed to preserve semantics.

The command validates input shape, duplicate row names/numbers, supported architectures/statuses, pinned release/citation consistency and gap-to-table mappings. **It does not authenticate a user-supplied snapshot or re-download its sources.** `authenticated` and `source_hashes_verified` are therefore false; the input hash identifies bytes, not their trustworthiness. Use the source importer and preserve its source files when independently verifying a published comparison.

Exit code **0** means the comparison succeeded, including when differences exist. **2** means invalid input or another operational error. This informational command never emits the scan command's hard-failure exit code 1.

## Limits on longitudinal claims

This is a comparison of declared release support, not execution-based workload accuracy. It cannot demonstrate that a workload will start working, stop working, or use a newly supported syscall. Re-run the same workload profile under both releases to establish those outcomes.

The importer records retrieval dates in `first_observed` and `last_verified`. Those dates do not reveal when a runtime defect first appeared, and subtracting days from them cannot produce a measured detection-accuracy decay curve. A defensible accuracy study needs historical snapshots plus independently labeled outcomes for the same workload/runtime versions; label simulated withholding experiments as simulations.

## Validation

```sh
cargo test -p sentrycheck-kb --locked
cargo build -p sentrycheck-cli --locked
python -m unittest discover -s tests -p test_kb_diff.py -v
```

Tests deliberately mutate the bundled snapshot to exercise additions, removals, status/documentation/source changes, changed release provenance, ordering, and invalid inputs. Synthetic mutations are test fixtures and are not presented as real release drift or benchmark results.
