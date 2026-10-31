//! A comparison envelope retains separately validated, single-runtime reports.
//! It never upgrades imported evidence into a live three-runtime experiment.
use crate::{args::Args, report};
use sentrycheck_core::model::{Report, RunObservation, MAX_REPORT_BYTES};
use sentrycheck_core::util::{atomic_write, read_bounded, sha256};
use sentrycheck_core::Result;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn load(path: &Path) -> Result<Value> {
    serde_json::from_slice(&read_bounded(path, MAX_REPORT_BYTES)?)
        .map_err(|e| format!("report JSON: {e}"))
}

fn typed(value: &Value) -> Result<Report> {
    let result: Report = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
    report::validate(&result)?;
    let version = result.target_runtime.version.as_str();
    let normalized = sentrycheck_kb::normalize_version(version);
    if normalized.is_empty()
        || matches!(normalized.as_str(), "unversioned" | "unknown" | "latest")
        || version.trim() != version
        || version.chars().any(char::is_control)
    {
        return Err("runtime comparisons require explicit pinned runtime versions".into());
    }
    Ok(result)
}

fn intact(run: &RunObservation) -> bool {
    run.infrastructure_error.is_none()
        && run.trace_summary.event_count > 0
        && !run.trace_summary.truncated
        && run.trace_summary.unfinished_count == 0
        && run.trace_summary.discarded_guest_records == 0
}

fn stable(runs: &[RunObservation], stdout: bool) -> Option<&str> {
    let first = runs.first()?;
    runs.iter()
        .all(|run| {
            if stdout {
                run.stdout_sha256 == first.stdout_sha256
            } else {
                run.stderr_sha256 == first.stderr_sha256
            }
        })
        .then_some(if stdout {
            first.stdout_sha256.as_str()
        } else {
            first.stderr_sha256.as_str()
        })
}

fn outcome(report: &Report) -> &'static str {
    let Some(d) = &report.dynamic else {
        return "unavailable";
    };
    if d.sandbox.len() != d.profile.repetitions || !d.sandbox.iter().all(intact) {
        return "unavailable";
    }
    let count = d
        .sandbox
        .iter()
        .filter(|run| sentrycheck_kb::successful(run, d.profile.expected_exit_code))
        .count();
    if count == d.sandbox.len() {
        "success"
    } else if count == 0 {
        "failure"
    } else {
        "mixed"
    }
}

pub fn compose(mut values: Vec<Value>) -> Result<Value> {
    if values.len() != 2 {
        return Err("comparison requires exactly one gVisor and one Kata report".into());
    }
    values.sort_by_key(|value| {
        value["target_runtime"]["name"]
            .as_str()
            .unwrap_or("")
            .to_string()
    });
    let mut input_size = 0_u64;
    for value in &values {
        input_size += serde_json::to_vec(value).map_err(|e| e.to_string())?.len() as u64;
        if input_size > MAX_REPORT_BYTES {
            return Err("combined report exceeds the 128 MiB report budget".into());
        }
    }
    let reports = values.iter().map(typed).collect::<Result<Vec<_>>>()?;
    let (a, b) = (&reports[0], &reports[1]);
    if a.target_runtime.name != "gvisor" || b.target_runtime.name != "kata" {
        return Err("comparison requires exactly one gVisor and one Kata report".into());
    }
    if a.image_digest.is_none() || a.image_digest != b.image_digest || a.platform != b.platform {
        return Err("reports must bind the same OCI image digest and architecture".into());
    }
    let mut limits = Vec::new();
    let mut stdout_difference = None;
    let mut stderr_difference = None;
    let mut outcome_difference = None;
    let mut profile_sha256 = None;
    if let (Some(ad), Some(bd)) = (&a.dynamic, &b.dynamic) {
        if ad.profile_sha256 != bd.profile_sha256 {
            return Err("reports use different workload profiles".into());
        }
        profile_sha256 = Some(ad.profile_sha256.clone());
        for (name, d) in [("gvisor", ad), ("kata", bd)] {
            if d.native.len() != d.profile.repetitions
                || !d.native.iter().all(|r| {
                    intact(r) && sentrycheck_kb::successful(r, d.profile.expected_exit_code)
                })
            {
                limits.push(format!(
                    "{name}: a complete successful native baseline is required."
                ));
            }
            if d.sandbox.len() != d.profile.repetitions || !d.sandbox.iter().all(intact) {
                limits.push(format!("{name}: sandbox observations are missing, incomplete, or contain infrastructure errors."));
            }
        }
        let native_versions = |runs: &[RunObservation]| {
            runs.iter()
                .map(|r| r.runtime_version.clone())
                .collect::<BTreeSet<_>>()
        };
        if native_versions(&ad.native) != native_versions(&bd.native) {
            limits.push("The two native baselines declare different runc versions.".into());
        }
        for (stdout, asserted) in [
            (true, ad.profile.compare_stdout),
            (false, ad.profile.compare_stderr),
        ] {
            if asserted
                && (stable(&ad.native, stdout).is_none()
                    || stable(&ad.native, stdout) != stable(&bd.native, stdout))
            {
                limits.push(format!(
                    "Native baseline {} is unstable or differs between the separate runs.",
                    if stdout { "stdout" } else { "stderr" }
                ));
            }
        }
        if limits.is_empty() {
            let signature = |runs: &[RunObservation]| {
                let mut outcomes: Vec<_> =
                    runs.iter().map(|r| (r.exit_code, r.timed_out)).collect();
                outcomes.sort();
                outcomes
            };
            outcome_difference = Some(signature(&ad.sandbox) != signature(&bd.sandbox));
            if ad.profile.compare_stdout {
                stdout_difference = stable(&ad.sandbox, true)
                    .zip(stable(&bd.sandbox, true))
                    .map(|(x, y)| x != y);
            }
            if ad.profile.compare_stderr {
                stderr_difference = stable(&ad.sandbox, false)
                    .zip(stable(&bd.sandbox, false))
                    .map(|(x, y)| x != y);
            }
        }
    } else {
        limits.push("Both runtime reports need dynamic observations to compare outcomes; static capabilities remain unconfirmed.".into());
    }
    let mut incomplete: Vec<_> = reports
        .iter()
        .flat_map(|r| {
            r.incomplete_reasons
                .iter()
                .map(move |reason| format!("{}: {reason}", r.target_runtime.name))
        })
        .collect();
    incomplete.extend(limits.iter().cloned());
    let status = if incomplete.is_empty() {
        "complete"
    } else {
        "incomplete"
    };
    let assessment = if reports
        .iter()
        .any(|r| r.assessment == "incompatibility-observed")
    {
        "incompatibility-observed"
    } else if reports
        .iter()
        .any(|r| r.assessment == "performance-regression-observed")
    {
        "performance-regression-observed"
    } else if status == "complete" {
        "no-incompatibility-observed-in-profile"
    } else {
        "insufficient-evidence"
    };
    let mut digests = serde_json::Map::new();
    for (r, value) in reports.iter().zip(&values) {
        digests.insert(
            r.target_runtime.name.clone(),
            Value::String(sha256(
                &serde_json::to_vec(value).map_err(|e| e.to_string())?,
            )),
        );
    }
    Ok(json!({
        "schema_version":"1.1", "report_kind":"runtime-comparison", "image_digest":a.image_digest,
        "platform":a.platform, "target_runtimes":[a.target_runtime,b.target_runtime],
        "profile_sha256":profile_sha256, "status":status, "assessment":assessment,
        "incomplete_reasons":incomplete, "reports":values, "report_digests":digests,
        "authenticated":false,
        "digest_encoding":"SHA-256 of compact serde_json serialization of each embedded JSON object; not the original source-file bytes.",
        "cross_runtime":{
            "comparable":limits.is_empty(), "comparison_limits":limits,
            "baseline_relationship":"separate-native-executions",
            "locally_collected_pair":limits.is_empty() && reports.iter().all(|r| r.dynamic.as_ref().is_some_and(|d| d.provenance == "locally-executed")),
            "outcomes":{"gvisor":outcome(a),"kata":outcome(b)},
            "outcome_difference":outcome_difference, "stdout_difference":stdout_difference, "stderr_difference":stderr_difference,
            "timing_samples_ms":reports.iter().map(|r| json!({"runtime":r.target_runtime.name,"native":r.dynamic.as_ref().map(|d|d.native.iter().map(|x|x.duration_ms).collect::<Vec<_>>()),"sandbox":r.dynamic.as_ref().map(|d|d.sandbox.iter().map(|x|x.duration_ms).collect::<Vec<_>>())})).collect::<Vec<_>>()
        },
        "limitations":[
            "This envelope combines two separate native-versus-sandbox experiments; there is no shared native execution or new three-way evidence tier.",
            "Per-report evidence grades, imported provenance, coverage and incomplete reasons are preserved. JSON consistency is not authentication.",
            "Equal image/profile identities do not establish equal host configuration or runtime settings; no runtime recommendation or causal attribution is made.",
            "Timing samples include startup and unequal tracing overhead. They are not a causal performance ranking.",
            "A null output difference means no comparable deterministic assertion, not equality. Failed workloads may have different diagnostics.",
            "Extracted schema 1.0 JSON must be signed again for admission; reserialization does not preserve signatures over original source bytes."
        ]
    }))
}

pub fn validate(value: &Value) -> Result<()> {
    if value["schema_version"] != "1.1" || value["report_kind"] != "runtime-comparison" {
        return Err("expected schema 1.1 runtime-comparison envelope".into());
    }
    let reports = value["reports"]
        .as_array()
        .ok_or("comparison lacks embedded reports")?;
    if compose(reports.clone())? != *value {
        return Err(
            "comparison summary, digests, ordering or metadata contradict embedded reports".into(),
        );
    }
    Ok(())
}

fn emit(args: &Args, value: &Value, inputs: &[&Path]) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err("combined report exceeds the 128 MiB report budget".into());
    }
    if let Some(output) = args.value("output") {
        let output = Path::new(output);
        if let Ok(canonical) = output.canonicalize() {
            if inputs
                .iter()
                .any(|input| input.canonicalize().is_ok_and(|path| path == canonical))
            {
                return Err("refusing to overwrite an input report".into());
            }
        }
        atomic_write(output, &bytes)?;
    }
    if args.format()? == "json" {
        println!("{}", String::from_utf8_lossy(&bytes));
    } else if value["report_kind"] == "runtime-comparison" {
        println!(
            "Runtime comparison: {} / {}",
            value["status"].as_str().unwrap_or("unknown"),
            value["assessment"].as_str().unwrap_or("unknown")
        );
        for r in value["reports"].as_array().ok_or("missing reports")? {
            println!(
                "  {} {}: {} [{}; {}]",
                r["target_runtime"]["name"].as_str().unwrap_or(""),
                r["target_runtime"]["version"].as_str().unwrap_or(""),
                r["assessment"].as_str().unwrap_or(""),
                r["dynamic"]["evidence_tier"]
                    .as_str()
                    .unwrap_or("static-only"),
                r["dynamic"]["provenance"]
                    .as_str()
                    .unwrap_or("no dynamic execution")
            );
        }
        println!("Separate native baselines; comparable outcomes: {}. See JSON for per-runtime evidence and limitations.", value["cross_runtime"]["comparable"]);
    } else {
        println!("Extracted {} report; original signatures are not preserved. Sign the extracted bytes for admission.", value["target_runtime"]["name"].as_str().unwrap_or(""));
    }
    Ok(())
}

fn exit_code(value: &Value, fail_on: &str) -> i32 {
    if value["reports"].as_array().is_some_and(|reports| {
        reports.iter().any(|r| {
            r["findings"]
                .as_array()
                .is_some_and(|findings| findings.iter().any(|f| f["severity"] == fail_on))
        })
    }) {
        1
    } else if value["status"] != "complete" {
        2
    } else {
        0
    }
}

pub fn compare(args: Args) -> Result<i32> {
    args.only(&["output", "format", "fail-on"], &[])?;
    args.format()?;
    let fail_on = report::severity(&args)?;
    if args.positionals.len() != 2 {
        return Err("report compare requires GVISOR.json KATA.json".into());
    }
    let inputs: Vec<_> = args.positionals.iter().map(Path::new).collect();
    let value = compose(
        inputs
            .iter()
            .map(|path| load(path))
            .collect::<Result<_>>()?,
    )?;
    emit(&args, &value, &inputs)?;
    Ok(exit_code(&value, fail_on))
}

pub fn extract(args: Args) -> Result<i32> {
    args.only(&["runtime", "output", "format"], &[])?;
    args.format()?;
    if args.value("output").is_none() {
        return Err("report extract requires --output FILE".into());
    }
    let runtime = args
        .value("runtime")
        .filter(|r| matches!(*r, "gvisor" | "kata"))
        .ok_or("--runtime must select gvisor or kata")?;
    let input = Path::new(args.single_positional("runtime-comparison file")?);
    let value = load(input)?;
    validate(&value)?;
    let extracted = value["reports"]
        .as_array()
        .and_then(|reports| {
            reports
                .iter()
                .find(|r| r["target_runtime"]["name"] == runtime)
        })
        .ok_or("runtime report is absent")?;
    emit(&args, extracted, &[input])?;
    Ok(0)
}

pub fn scan(args: Args) -> Result<i32> {
    const SHARED: &[&str] = &[
        "platform",
        "profile",
        "cache",
        "kb",
        "max-kb-age-days",
        "runc-bin",
        "runsc-bin",
        "strace-bin",
        "fail-on",
    ];
    let mut allowed = SHARED.to_vec();
    allowed.extend([
        "runtime",
        "gvisor-version",
        "kata-version",
        "gvisor-evidence",
        "kata-evidence",
        "format",
        "output",
        "artifacts",
    ]);
    if args.value("version").is_some() || args.value("evidence").is_some() {
        return Err("multi-runtime scans require separate --gvisor-version/--kata-version and optional --gvisor-evidence/--kata-evidence".into());
    }
    args.only(&allowed, &["static-only", "native-only", "no-cache"])?;
    args.format()?;
    let fail_on = report::severity(&args)?;
    let image = args.single_positional("image path or reference")?;
    if !matches!(args.value("runtime"), Some("gvisor,kata" | "kata,gvisor")) {
        return Err("multi-runtime scan requires --runtime gvisor,kata".into());
    }
    let versions: Vec<_> = ["gvisor-version", "kata-version"]
        .iter()
        .map(|key| {
            args.value(key)
                .filter(|v| {
                    !v.trim().is_empty() && !matches!(*v, "unversioned" | "unknown" | "latest")
                })
                .ok_or_else(|| format!("--{key} must pin an explicit runtime release"))
        })
        .collect::<Result<_>>()?;
    if args.value("gvisor-evidence").is_some() != args.value("kata-evidence").is_some() {
        return Err(
            "supply both --gvisor-evidence and --kata-evidence for an imported comparison".into(),
        );
    }
    let mut values = Vec::new();
    for (runtime, version) in ["gvisor", "kata"].into_iter().zip(versions) {
        let mut child_args = vec![
            "scan".to_string(),
            image.to_string(),
            "--runtime".into(),
            runtime.into(),
            "--version".into(),
            version.into(),
            "--format".into(),
            "json".into(),
        ];
        for key in SHARED {
            if let Some(value) = args.value(key) {
                child_args.extend([format!("--{key}"), value.into()]);
            }
        }
        for flag in ["static-only", "native-only", "no-cache"] {
            if args.flag(flag) {
                child_args.push(format!("--{flag}"));
            }
        }
        if let Some(evidence) = args.value(&format!("{runtime}-evidence")) {
            child_args.extend(["--evidence".into(), evidence.into()]);
        }
        let artifacts = PathBuf::from(args.value("artifacts").unwrap_or(".sentrycheck/artifacts"))
            .join(runtime);
        child_args.extend(["--artifacts".into(), artifacts.display().to_string()]);
        let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .args(child_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("{runtime} scan: {e}"))?;
        let mut bytes = Vec::new();
        let read = child
            .stdout
            .take()
            .ok_or("child stdout unavailable")?
            .take(MAX_REPORT_BYTES + 1)
            .read_to_end(&mut bytes);
        if read.is_err() || bytes.len() as u64 > MAX_REPORT_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{runtime} scan exceeded the output budget or could not be read"
            ));
        }
        let status = child.wait().map_err(|e| e.to_string())?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
            format!("{runtime} scan did not produce a valid report ({status}): {e}")
        })?;
        let report = typed(&value)?;
        if status.code() != Some(report.exit_code(fail_on))
            || report.target_runtime.name != runtime
            || sentrycheck_kb::normalize_version(&report.target_runtime.version)
                != sentrycheck_kb::normalize_version(version)
        {
            return Err(format!(
                "{runtime} child report contradicts its request or exit status"
            ));
        }
        values.push(value);
    }
    let value = compose(values)?;
    let mut inputs = vec![Path::new(image)];
    for key in ["gvisor-evidence", "kata-evidence", "profile", "kb"] {
        if let Some(path) = args.value(key) {
            inputs.push(Path::new(path));
        }
    }
    emit(&args, &value, &inputs)?;
    Ok(exit_code(&value, fail_on))
}
