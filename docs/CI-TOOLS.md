# Diagnostics and CI report tools

SENTRYCHECK includes environment diagnostics, report validation/diff, SARIF export, and an offline Astro viewer added in 0.4. Report schema version remains `1.0`; `sentrycheck_version` identifies the analyzer release. These commands do not install runtimes, configure a cluster, publish reports, or upload SARIF.

`sentrycheck report render report.json --output report.html` creates a self-contained page with no Node runtime or server requirement. It exits 0 for successful rendering even when the scan failed or was incomplete. See [REPORT-VIEWER.md](REPORT-VIEWER.md) for KB matching, output replacement, local imports, and reduced SARIF evidence.

## Check prerequisites

```sh
# Full native/runsc comparison prerequisites on Linux.
sentrycheck doctor --runtime gvisor --version 20260921.0 \
  --profile profiles/python.toml --runsc-bin .cache/linux/bin/runsc --format json

# Static/offline use, including a Windows development machine.
sentrycheck doctor --static-only --format json

# Native tracing without a local sandbox comparison.
sentrycheck doctor --native-only --profile profiles/python.toml
```

The default mode is hybrid. `--static-only` and `--native-only` are mutually exclusive. Common scan options such as `--kb`, `--cache`, `--max-kb-age-days`, `--platform`, `--runc-bin`, `--strace-bin`, and `--runsc-bin` select the environment being checked. `--output doctor.json` saves the JSON result regardless of the displayed format.

Checks cover KB release/age, an optional profile, OS and architecture for live execution, and bounded `--version` probes of the configured trusted tools. Hybrid gVisor checks also cover the documented Linux 5.6 minimum and the pinned release's required `gvisor-bin` companions. Companion presence is not a checksum or launch attestation. The kernel requirement is not imposed on native-only tracing. Missing skopeo is a warning because local OCI layouts do not need it.

Exit `0` means no checked prerequisite failed; warnings can remain. Exit `2` means a prerequisite failed or an option/input was invalid. No profile, smoke-only coverage, native-only evidence, and unresolved namespace/cgroup permissions are visible warnings. A successful doctor run does not predict whether a workload passes or prove node isolation. Only an actual scan exercises the runtime. Direct Kata VM execution remains unsupported and reports that limitation.

## Validate a saved report

JSON reports have a 128 MiB budget, shared by scanning, annotation, validation, and Go signing/verification. The aggregate report can exceed the separate 32 MiB budget for an individual captured trace. Larger requested scans must reduce repetitions or trace volume; they cannot emit a clean result beyond the report budget.

```sh
sentrycheck report validate report.json --format json
sentrycheck report validate report.json --artifacts-root . --output validation.json
```

Validation checks report structure and consistency: schema, target platform, digest syntax, profile hash, evidence tiers, runtime versions, trace event counts, finding references, observed outcome classes, and completeness requirements. Syscall and errno summary maps are recomputed from embedded events. A complete report needs local native/sandbox repetitions. For each runtime whose repetitions all satisfy the profile, compared output must be stable; varying failure diagnostics do not invalidate an observed failure. Fabricated or omitted observed failure classes and mismatched finding references are rejected.

Version 0.3 adds optional `trace_summary.discarded_guest_records` and `diagnostic_lines` counters without changing schema version `1.0`. Discarded guest records, unfinished calls, and truncation prevent completeness; recognized diagnostic lines do not. Missing counters in an older report default to zero for reading, but do not retroactively establish that its older parser checked for record loss. Raw-artifact validation uses the current parser, so older summaries can fail that check after a parser upgrade. Retain the original report and rerun the workload when a current-version attestation is required.

`--artifacts-root` additionally reads referenced stdout, stderr, and guest traces, checks their SHA-256 hashes, and re-parses trace files to compare events and summaries. Each file has a 32 MiB limit. Relative references are resolved beneath that root, not beside the report; absolute references must resolve inside it. Choose the root corresponding to the saved paths. For example, references starting `artifacts/runs/...` use the workspace as their root, while `native-0/guest.trace` can use that run's directory. A Windows process cannot directly resolve Linux `/mnt/...` references: validate them in the original Linux environment or preserve a deliberately portable artifact layout.

Exit `0` means the report is consistent and any requested artifact checks passed. **A valid report can still describe an incomplete or failed scan.** Check `scan_status` and use a scan gate for compatibility decisions. Invalid reports, inaccessible/escaping references, hash mismatches, and changed trace interpretations exit `2`. Validation emits `authenticated: false`; it does not authenticate execution or establish the correctness of an arbitrary KB citation. Hashes detect changes relative to a report, not a dishonest report producer.

For trusted CI authorship and binding to exact report bytes, use the Go verifier:

```sh
sentrycheck-admission attest --report report.json --key ci-private.pem \
  --key-id ci --output report.attestation.json
sentrycheck-admission verify --file report.attestation.json --public-key ci-public.pem \
  --key-id ci --report report.json
```

Without `--report`, `verify` checks the signed claim. With it, verification also matches the supplied report's exact bytes against the signed report digest. Even JSON whitespace changes alter that digest, so retain the original report. Signature validity establishes the trusted signer's claim; it does not make guest-writable native traces tamper-proof or establish hardware attestation. See [SECURITY.md](../SECURITY.md).

## Compare scan results

```sh
sentrycheck report diff baseline.json current.json --format json --output comparison.json
sentrycheck report diff baseline.json current.json --fail-on silent-degradation
```

The comparison first validates both reports. A regression gate is comparable only when both are complete local comparisons with the same analyzer version, KB snapshot, runtime name/release/architecture, profile hash, and evidence tier. Different image digests are expected when evaluating a new image and are included in the result.

Finding identity uses gap, category, severity, evidence tier, and source binary. Per-run finding numbers and trace paths are not used as stable keys. Output includes `added`, `not_observed_in_current`, `unchanged_count`, report hashes, image digests, and reasons for a non-comparable result. Absence from the current findings does not prove that a failure is fixed or all relevant paths were exercised. Host configuration is not fingerprinted; keep the execution environment consistent, particularly for timing comparisons.

| Exit | Meaning |
| --- | --- |
| `0` | Comparable reports with no newly added finding matching `--fail-on`. Existing findings may remain. |
| `1` | Comparable reports with a newly added finding matching `--fail-on`. |
| `2` | Invalid reports or an incomplete/non-comparable experiment. |

The default selected severity is `hard-failure`; `silent-degradation`, `performance-regression`, and `compatibility-risk` are also accepted. An incomplete comparison always exits `2`, even when its informational difference contains a new failure. Use the current scan's own exit code when any existing selected failure should block CI.

Analyzer upgrades require a new baseline. Version 0.2 changed syscall correlations to unconfirmed risks and reports one confirmed workload failure; version 0.3 tightens trace completeness and corrects KB descriptions and capability-error classifications. Do not edit an older report's version to make it comparable; rerun the baseline and candidate with the same version and KB.

## Export SARIF 2.1.0

```sh
# Export a saved report; --output writes SARIF for this subcommand.
sentrycheck report sarif report.json --output report.sarif

# Associate findings with a real repository build/deployment context.
sentrycheck report sarif report.json --source-file Dockerfile --source-line 1 \
  --output report.sarif

# During scanning, stdout is SARIF and --output remains the complete JSON report.
sentrycheck scan image-oci --profile profiles/python.toml \
  --format sarif --source-file Dockerfile --output report.json > report.sarif
```

SARIF includes rule citations, evidence tiers, causal limitations, profile and image identity, scan status, and properties for binary/static/dynamic evidence. Hard failures map to `error`, compatibility risks to `note`, and other findings to `warning`. Static candidates do not become confirmed findings. Incomplete reports set `invocations[].executionSuccessful` to false and include diagnostic notifications. Export preserves the report's scan exit contract: `1` for a selected finding, otherwise `2` for incomplete evidence, otherwise `0`. JSON/SARIF files are still emitted for those analysis outcomes; malformed input exits `2` without a valid export.

`--source-file` must name an existing file relative to the working directory. `--source-line` defaults to `1`, must be positive and within that file, and requires `--source-file`. All exported findings receive that explicit review context. It is a user-supplied association, not a claim that ELF analysis recovered a source-code line. Choose a path that actually belongs to the checked-out repository; the command does not infer a source mapping or check Git tracking.

Without a mapping, the export is valid general SARIF but does not promise visible GitHub code scanning alerts. GitHub requires a source location to display an alert; a container's `/usr/lib/...` path is not a repository source file. The exporter includes its own stable `sentrycheckFinding/v1` fingerprint, while GitHub documents support for `primaryLocationLineHash`. The custom fingerprint alone therefore does not guarantee GitHub deduplication. Review uploaded results in the chosen SARIF consumer; this release does not automatically upload them or claim an end-to-end GitHub integration test.

Use [the primary-source review](DEEP-REVIEW.md) for the OASIS schema and GitHub-specific constraints, and [the validation record](VALIDATION.md) for checks actually performed.
