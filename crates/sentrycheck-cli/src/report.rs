use crate::args::Args;
use sentrycheck_core::model::{Finding, Report, MAX_REPORT_BYTES, SCHEMA_VERSION};
use sentrycheck_core::util::{atomic_write, checked_join, read_bounded, sha256, validate_digest};
use sentrycheck_core::Result;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const SEVERITIES: &[&str] = &[
    "hard-failure",
    "silent-degradation",
    "performance-regression",
    "compatibility-risk",
];

pub fn severity(args: &Args) -> Result<&str> {
    let value = args.value("fail-on").unwrap_or("hard-failure");
    if !SEVERITIES.contains(&value) {
        return Err("invalid --fail-on severity".into());
    }
    Ok(value)
}

pub fn load(path: &Path) -> Result<(Report, String)> {
    let bytes = read_bounded(path, MAX_REPORT_BYTES)?;
    let report: Report = serde_json::from_slice(&bytes).map_err(|e| format!("report JSON: {e}"))?;
    validate(&report)?;
    Ok((report, sha256(&bytes)))
}

// Semantic consistency is separate from authentication. Only the Go verifier checks signatures.
pub fn validate(report: &Report) -> Result<()> {
    if report.schema_version != SCHEMA_VERSION {
        return Err("unsupported report schema version".into());
    }
    if !matches!(report.status.as_str(), "complete" | "incomplete")
        || (report.status == "complete") != report.incomplete_reasons.is_empty()
    {
        return Err("report status contradicts incomplete_reasons".into());
    }
    if !matches!(report.target_runtime.name.as_str(), "gvisor" | "kata")
        || !matches!(
            report.target_runtime.architecture.as_str(),
            "amd64" | "arm64" | "386"
        )
        || report.target_runtime.version.is_empty()
        || report.platform != format!("linux/{}", report.target_runtime.architecture)
    {
        return Err("invalid or inconsistent target runtime/platform".into());
    }
    if let Some(digest) = &report.image_digest {
        validate_digest(digest)?;
    }
    for cap in report
        .capability_set
        .capabilities
        .iter()
        .chain(&report.capability_set_only)
    {
        validate_digest(&cap.source_digest)?;
    }
    let mut ids = BTreeSet::new();
    for finding in &report.findings {
        if finding.id.is_empty() || !ids.insert(&finding.id) || finding.gap_id.is_empty() {
            return Err("empty or duplicate finding identifier".into());
        }
        let class = match finding.severity.as_str() {
            "hard-failure" => "F1",
            "silent-degradation" => "F2",
            "performance-regression" => "F3",
            "compatibility-risk" => "unconfirmed",
            _ => return Err("unknown finding severity".into()),
        };
        if finding.failure_class != class || !finding.kb_citation.url.starts_with("https://") {
            return Err("finding has inconsistent failure class or missing HTTPS citation".into());
        }
        let dynamic = report
            .dynamic
            .as_ref()
            .ok_or("static capability sets cannot contain findings")?;
        if finding.evidence_tier != dynamic.evidence_tier
            || finding.severity != "compatibility-risk" && dynamic.sandbox.is_empty()
        {
            return Err("finding overstates its dynamic evidence".into());
        }
        let reference = |run: &sentrycheck_core::model::RunObservation| {
            json!({
            "runtime":run.runtime,"runtime_version":run.runtime_version,"exit_code":run.exit_code,
            "timed_out":run.timed_out,"trace_excerpt_ref":run.trace_ref,"trace_sha256":run.trace_sha256,
            "stdout_ref":run.stdout_ref,"stderr_ref":run.stderr_ref,"duration_ms":run.duration_ms})
        };
        let expected = json!({"profile_sha256":dynamic.profile_sha256,"provenance":dynamic.provenance,
            "native":dynamic.native.iter().map(reference).collect::<Vec<_>>(),
            "sandbox":dynamic.sandbox.iter().map(reference).collect::<Vec<_>>()});
        if finding.dynamic_evidence != expected {
            return Err("finding evidence references contradict the report observations".into());
        }
    }
    if let Some(dynamic) = &report.dynamic {
        sentrycheck_dynamic::profile::validate(&dynamic.profile)?;
        if sha256(&serde_json::to_vec(&dynamic.profile).map_err(|e| e.to_string())?)
            != dynamic.profile_sha256
        {
            return Err("profile digest mismatch".into());
        }
        let tier = if dynamic.sandbox.is_empty() {
            "dynamic-native-only"
        } else if report.target_runtime.name == "gvisor" {
            "dynamic-runsc-diff"
        } else {
            "dynamic-kata-diff"
        };
        if dynamic.evidence_tier != tier
            || !matches!(
                dynamic.provenance.as_str(),
                "locally-executed" | "imported-user-supplied"
            )
        {
            return Err("invalid dynamic evidence tier/provenance".into());
        }
        for run in dynamic.native.iter().chain(&dynamic.sandbox) {
            for digest in [&run.stdout_sha256, &run.stderr_sha256, &run.trace_sha256] {
                validate_digest(digest)?;
            }
            if run.trace_summary.event_count != run.events.len()
                || !matches!(run.trace_kind.as_str(), "strace-guest" | "runsc-guest")
            {
                return Err("invalid guest trace summary".into());
            }
            let mut syscalls = BTreeMap::new();
            let mut errors = BTreeMap::new();
            for event in &run.events {
                *syscalls.entry(event.syscall.clone()).or_insert(0_u64) += 1;
                if let Some(errno) = &event.errno {
                    *errors
                        .entry(format!("{}:{errno}", event.syscall))
                        .or_insert(0_u64) += 1;
                }
            }
            if syscalls != run.trace_summary.syscalls || errors != run.trace_summary.errors {
                return Err("trace syscall/error totals contradict stored events".into());
            }
        }
        for run in &dynamic.native {
            if run.runtime != "runc" || run.trace_kind != "strace-guest" {
                return Err("native observations must be runc guest traces".into());
            }
        }
        for run in &dynamic.sandbox {
            if run.runtime != report.target_runtime.name
                || sentrycheck_kb::normalize_version(&run.runtime_version)
                    != sentrycheck_kb::normalize_version(&report.target_runtime.version)
                || report.target_runtime.name == "gvisor" && run.trace_kind != "runsc-guest"
            {
                return Err("sandbox observation differs from target runtime".into());
            }
        }
        // Re-derive observable severity classes with the scan interpreter. This is
        // consistency checking, not authentication or causal syscall attribution.
        let derived = sentrycheck_kb::KnowledgeBase::bundled()?.findings(
            &report.capability_set,
            dynamic,
            &report.target_runtime,
        );
        let observed: BTreeSet<_> = derived
            .iter()
            .filter(|f| f.severity != "compatibility-risk")
            .map(|f| f.severity.as_str())
            .collect();
        let claimed: BTreeSet<_> = report
            .findings
            .iter()
            .filter(|f| f.severity != "compatibility-risk")
            .map(|f| f.severity.as_str())
            .collect();
        if observed != claimed {
            return Err("findings contradict observed workload outcomes".into());
        }
        if report.status == "complete" {
            for stdout in [true, false] {
                if !(if stdout {
                    dynamic.profile.compare_stdout
                } else {
                    dynamic.profile.compare_stderr
                }) {
                    continue;
                }
                for runs in [&dynamic.native, &dynamic.sandbox] {
                    if runs
                        .iter()
                        .all(|r| sentrycheck_kb::successful(r, dynamic.profile.expected_exit_code))
                    {
                        if let Some(first) = runs.first() {
                            if runs.iter().any(|r| {
                                if stdout {
                                    r.stdout_sha256 != first.stdout_sha256
                                } else {
                                    r.stderr_sha256 != first.stderr_sha256
                                }
                            }) {
                                return Err(
                                    "complete report has non-deterministic declared output".into(),
                                );
                            }
                        }
                    }
                }
            }
        }
        if report.status == "complete"
            && (report.image_digest.is_none()
                || dynamic.provenance != "locally-executed"
                || dynamic.profile.coverage != "representative"
                || dynamic.native.len() != dynamic.profile.repetitions
                || dynamic.sandbox.len() != dynamic.profile.repetitions
                || dynamic.native.iter().any(|run| {
                    !sentrycheck_kb::successful(run, dynamic.profile.expected_exit_code)
                })
                || dynamic.native.iter().chain(&dynamic.sandbox).any(|run| {
                    run.infrastructure_error.is_some()
                        || run.trace_summary.truncated
                        || run.trace_summary.event_count == 0
                        || run.trace_summary.unfinished_count > 0
                        || run.trace_summary.discarded_guest_records > 0
                }))
        {
            return Err("complete report lacks required local comparison evidence".into());
        }
    } else if report.status == "complete" {
        return Err("complete report has no dynamic evidence".into());
    }
    let assessment = if report
        .findings
        .iter()
        .any(|f| matches!(f.severity.as_str(), "hard-failure" | "silent-degradation"))
    {
        "incompatibility-observed"
    } else if report
        .findings
        .iter()
        .any(|f| f.severity == "performance-regression")
    {
        "performance-regression-observed"
    } else if report.status == "complete" {
        "no-incompatibility-observed-in-profile"
    } else {
        "insufficient-evidence"
    };
    if report.assessment != assessment {
        return Err("assessment contradicts findings/status".into());
    }
    Ok(())
}

fn artifacts(report: &Report, root: &Path) -> Result<usize> {
    let root = root
        .canonicalize()
        .map_err(|e| format!("artifact root: {e}"))?;
    let mut count = 0;
    if let Some(dynamic) = &report.dynamic {
        for run in dynamic.native.iter().chain(&dynamic.sandbox) {
            for (reference, digest) in [
                (&run.stdout_ref, &run.stdout_sha256),
                (&run.stderr_ref, &run.stderr_sha256),
                (&run.trace_ref, &run.trace_sha256),
            ] {
                let path = Path::new(reference);
                // Windows canonical paths carry an extended-length prefix. Normalize
                // absolute references too, then enforce containment before reading.
                let absolute;
                let relative = if path.is_absolute() {
                    absolute = path.canonicalize().map_err(|e| e.to_string())?;
                    absolute
                        .strip_prefix(&root)
                        .map_err(|_| "artifact reference escapes --artifacts-root")?
                } else {
                    path
                };
                let relative = relative.to_str().ok_or("artifact path is not UTF-8")?;
                // Windows reports may have native separators; reject them in relative portable refs.
                let resolved =
                    checked_join(&root, &relative.replace(std::path::MAIN_SEPARATOR, "/"))?;
                let bytes = read_bounded(&resolved, 32 * 1024 * 1024)?;
                if sha256(&bytes) != *digest {
                    return Err(format!("artifact digest mismatch: {reference}"));
                }
                if reference == &run.trace_ref {
                    let text =
                        std::str::from_utf8(&bytes).map_err(|_| "trace artifact is not UTF-8")?;
                    let (events, mut summary) =
                        sentrycheck_dynamic::trace::parse(text, &run.trace_kind);
                    // The retained prefix cannot independently reveal a suffix lost
                    // to the capture budget. A conservative truncation flag cannot
                    // upgrade a report to complete.
                    summary.truncated |= run.trace_summary.truncated;
                    // Older parsers may differ. Re-scan before claiming a report matches this parser.
                    if serde_json::to_value(&events).map_err(|e| e.to_string())?
                        != serde_json::to_value(&run.events).map_err(|e| e.to_string())?
                        || serde_json::to_value(&summary).map_err(|e| e.to_string())?
                            != serde_json::to_value(&run.trace_summary)
                                .map_err(|e| e.to_string())?
                    {
                        return Err(format!(
                            "trace interpretation differs from report: {reference}"
                        ));
                    }
                }
                count += 1;
            }
        }
    }
    Ok(count)
}

fn identity(finding: &Finding) -> String {
    // Length-delimited serialization prevents collisions from separators inside paths/IDs.
    serde_json::to_string(&(
        &finding.gap_id,
        &finding.category,
        &finding.severity,
        &finding.evidence_tier,
        &finding.source_binary,
    ))
    .expect("string tuple serialization")
}

pub fn source_location(args: &Args) -> Result<Option<Value>> {
    let Some(file) = args.value("source-file") else {
        if args.value("source-line").is_some() {
            return Err("--source-line requires --source-file".into());
        }
        return Ok(None);
    };
    let path = sentrycheck_core::util::safe_relative(file)?;
    if !path.is_file() {
        return Err("--source-file must identify an existing repository file relative to the working directory".into());
    }
    let line: u64 = args
        .value("source-line")
        .unwrap_or("1")
        .parse()
        .map_err(|_| "--source-line must be a positive integer")?;
    if line == 0 {
        return Err("--source-line must be positive".into());
    }
    let bytes = read_bounded(&path, 4 * 1024 * 1024)?;
    if line > bytes.split(|c| *c == b'\n').count() as u64 {
        return Err("--source-line is beyond the source file".into());
    }
    let normalized = path
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let uri: String = normalized
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    Ok(Some(
        json!({"physicalLocation":{"artifactLocation":{"uri":uri},"region":{"startLine":line}},
        "message":{"text":"User-supplied container build/deployment context; this is not an inferred ELF source-code location."}}),
    ))
}

pub fn sarif(report: &Report, location: Option<&Value>) -> Value {
    let mut gaps = BTreeMap::new();
    for finding in &report.findings {
        gaps.entry(&finding.gap_id).or_insert(&finding.kb_citation);
    }
    let indexes: BTreeMap<_, _> = gaps.keys().enumerate().map(|(i, id)| (*id, i)).collect();
    let rules: Vec<_> = gaps.iter().map(|(id, citation)| json!({
        "id":id, "shortDescription":{"text":citation.title}, "helpUri":citation.url,
        "help":{"text":format!("Evidence: {}. Findings are limited to the declared workload profile.",citation.url)},
        "properties":{"citation":citation}
    })).collect();
    let results: Vec<_> = report.findings.iter().map(|finding| {
        let mut result = json!({
        "ruleId":finding.gap_id, "ruleIndex":indexes[&finding.gap_id],
        "level": match finding.severity.as_str() { "hard-failure" => "error", "compatibility-risk" => "note", _ => "warning" },
        "message":{"text":format!("{}\nEvidence: {}. Causality: {}",finding.description,finding.evidence_tier,finding.causality)},
        "partialFingerprints":{"sentrycheckFinding/v1":sha256(identity(finding).as_bytes())[7..]},
        // ELF offsets and image paths are not source-code line locations.
        "properties":{"severity":finding.severity,"failureClass":finding.failure_class,
            "findingId":finding.id,"category":finding.category,"kbCitation":finding.kb_citation,
            "evidenceTier":finding.evidence_tier,"sourceBinary":finding.source_binary,
            "staticEvidence":finding.static_evidence,"dynamicEvidence":finding.dynamic_evidence,
            "causality":finding.causality}
        });
        if let Some(location)=location { result["locations"]=json!([location]); }
        result
    }).collect();
    let notifications: Vec<_> = report
        .incomplete_reasons
        .iter()
        .map(|reason| json!({"level":"warning","message":{"text":reason}}))
        .collect();
    json!({"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{
        "tool":{"driver":{"name":"SENTRYCHECK","version":report.sentrycheck_version,"rules":rules}},
        "invocations":[{"executionSuccessful":report.status=="complete","toolExecutionNotifications":notifications}],
        "results":results,
        "properties":{"schemaVersion":report.schema_version,"image":report.image,"imageDigest":report.image_digest,
            "scannedAt":report.scanned_at,"durationMs":report.duration_ms,
            "evidenceTier":report.dynamic.as_ref().map(|d|d.evidence_tier.as_str()).unwrap_or("static-only"),
            "targetRuntime":report.target_runtime,"kbSnapshot":report.kb_snapshot_version,
            "scanStatus":report.status,"assessment":report.assessment,"limitations":report.limitations,
            "profileSha256":report.dynamic.as_ref().map(|d| &d.profile_sha256),
            "provenance":report.dynamic.as_ref().map(|d| &d.provenance),
            "staticCandidates":report.candidate_gaps.len(),"nodeIsolationChecked":false}
    }]})
}

pub fn run(mut args: Args) -> Result<i32> {
    if args.positionals.is_empty() {
        return Err("report requires validate, diff, sarif, render, compare, or extract".into());
    }
    let command = args.positionals.remove(0);
    match command.as_str() {
        "render" => crate::render::run(args),
        "compare" => crate::matrix::compare(args),
        "extract" => crate::matrix::extract(args),
        "validate" => {
            args.only(&["format", "artifacts-root", "output"], &[])?;
            let path = Path::new(args.single_positional("report file")?);
            let bytes = read_bounded(path, MAX_REPORT_BYTES)?;
            let document: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            if document["report_kind"] == "runtime-comparison" {
                crate::matrix::validate(&document)?;
                let mut checked = 0;
                if let Some(root) = args.value("artifacts-root") {
                    for child in document["reports"]
                        .as_array()
                        .ok_or("matrix reports absent")?
                    {
                        let child: Report =
                            serde_json::from_value(child.clone()).map_err(|e| e.to_string())?;
                        checked += artifacts(&child, Path::new(root))?;
                    }
                }
                let count = args.value("artifacts-root").map(|_| checked);
                let result = json!({"valid":true,"report_sha256":sha256(&bytes),
                    "scan_status":document["status"],"artifacts_checked":count,"authenticated":false,
                    "note":"Comparison and embedded report consistency only; no signature authentication."});
                emit(&args, &result, "Runtime comparison is consistent. Per-runtime evidence grades remain unchanged; signature not checked.")?;
                return Ok(0);
            }
            let (report, digest) = load(path)?;
            let count = args
                .value("artifacts-root")
                .map(|root| artifacts(&report, Path::new(root)))
                .transpose()?;
            let result = json!({"valid":true,"report_sha256":digest,"scan_status":report.status,
                "artifacts_checked":count,"authenticated":false,
                "note":"Semantic consistency and optional artifact integrity only. Use sentrycheck-admission verify for signature authentication."});
            emit(&args, &result, &format!("Report is consistent; scan status: {}. Artifacts checked: {}. Signature not checked.",report.status,count.map(|n|n.to_string()).unwrap_or("not requested".into())))?;
            Ok(0)
        }
        "sarif" => {
            args.only(&["output", "fail-on", "source-file", "source-line"], &[])?;
            let (report, _) = load(Path::new(args.single_positional("report file")?))?;
            let fail_on = severity(&args)?;
            let location = source_location(&args)?;
            let value = serde_json::to_vec_pretty(&sarif(&report, location.as_ref()))
                .map_err(|e| e.to_string())?;
            if let Some(path) = args.value("output") {
                atomic_write(Path::new(path), &value)?;
            }
            println!("{}", String::from_utf8_lossy(&value));
            Ok(report.exit_code(fail_on))
        }
        "diff" => diff(args),
        _ => Err(format!("unknown report subcommand {command}")),
    }
}

fn emit(args: &Args, value: &Value, human: &str) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    if let Some(path) = args.value("output") {
        atomic_write(Path::new(path), &bytes)?;
    }
    if args.format()? == "json" {
        println!("{}", String::from_utf8_lossy(&bytes));
    } else {
        println!("{human}");
    }
    Ok(())
}

fn diff(args: Args) -> Result<i32> {
    args.only(&["format", "output", "fail-on"], &[])?;
    if args.positionals.len() != 2 {
        return Err("report diff requires BASELINE CURRENT".into());
    }
    let fail_on = severity(&args)?;
    let (baseline, baseline_hash) = load(Path::new(&args.positionals[0]))?;
    let (current, current_hash) = load(Path::new(&args.positionals[1]))?;
    let mut reasons = Vec::new();
    if baseline.target_runtime != current.target_runtime {
        reasons.push("Target runtime/release/architecture changed.");
    }
    if baseline.kb_snapshot_version != current.kb_snapshot_version {
        reasons.push("Knowledge base snapshot changed.");
    }
    if baseline.sentrycheck_version != current.sentrycheck_version {
        reasons.push("Analyzer version changed.");
    }
    match (&baseline.dynamic, &current.dynamic) {
        (Some(a), Some(b))
            if a.profile_sha256 == b.profile_sha256 && a.evidence_tier == b.evidence_tier => {}
        _ => reasons.push("Workload profile or evidence tier differs/is missing."),
    }
    if baseline.status != "complete" || current.status != "complete" {
        reasons.push("Both scans must be complete local comparisons.");
    }
    let previous: BTreeMap<_, _> = baseline.findings.iter().map(|f| (identity(f), f)).collect();
    let next: BTreeMap<_, _> = current.findings.iter().map(|f| (identity(f), f)).collect();
    let added: Vec<_> = next
        .iter()
        .filter(|(key, _)| !previous.contains_key(*key))
        .map(|(_, f)| *f)
        .collect();
    let removed: Vec<_> = previous
        .iter()
        .filter(|(key, _)| !next.contains_key(*key))
        .map(|(_, f)| *f)
        .collect();
    let unchanged = next
        .keys()
        .filter(|key| previous.contains_key(*key))
        .count();
    let selected = added.iter().any(|f| f.severity == fail_on);
    let comparable = reasons.is_empty();
    let result = json!({"schema_version":"1.0","comparable":comparable,"comparison_limits":reasons,
        "baseline_report_sha256":baseline_hash,"current_report_sha256":current_hash,
        "baseline_image_digest":baseline.image_digest,"current_image_digest":current.image_digest,
        "added":added,"not_observed_in_current":removed,"unchanged_count":unchanged,
        "selected_regression":comparable && selected,
        "note":"Report comparison does not authenticate reports or establish that an unobserved finding is fixed. Compare the same environment; host configuration is not fingerprinted."});
    emit(
        &args,
        &result,
        &format!(
            "Comparison: {}. Added: {}; not observed now: {}; unchanged: {}.{}",
            if comparable {
                "comparable"
            } else {
                "incomplete"
            },
            added.len(),
            removed.len(),
            unchanged,
            if comparable {
                String::new()
            } else {
                format!(" {}", reasons.join(" "))
            }
        ),
    )?;
    Ok(if !comparable {
        2
    } else if selected {
        1
    } else {
        0
    })
}
