use crate::{profile, summarize};
use sentrycheck_core::model::{DynamicAnalysis, RunObservation, TargetRuntime, WorkloadProfile};
use sentrycheck_core::util::{checked_join, read_bounded, sha256, validate_digest};
use sentrycheck_core::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRun {
    pub runtime: String,
    pub runtime_version: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub stdout: String,
    pub stdout_sha256: String,
    pub stderr: String,
    pub stderr_sha256: String,
    pub trace: String,
    pub trace_sha256: String,
    pub trace_kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    pub schema_version: String,
    pub image_digest: String,
    pub target_runtime: TargetRuntime,
    pub profile: WorkloadProfile,
    pub profile_sha256: String,
    pub native: Vec<EvidenceRun>,
    pub sandbox: Vec<EvidenceRun>,
}

fn load_run(
    root: &Path,
    run: EvidenceRun,
    target: &TargetRuntime,
    sandbox: bool,
) -> Result<RunObservation> {
    if run.runtime
        != if sandbox {
            target.name.as_str()
        } else {
            "runc"
        }
    {
        return Err("evidence runtime does not match the requested analysis".into());
    }
    let expected_kind = if sandbox && target.name == "gvisor" {
        "runsc-guest"
    } else {
        "strace-guest"
    };
    if run.trace_kind != expected_kind {
        return Err(format!(
            "expected {expected_kind}; host launcher traces are not guest evidence"
        ));
    }
    if sandbox
        && run.runtime_version.trim_start_matches("release-")
            != target.version.trim_start_matches("release-")
    {
        return Err("evidence sandbox version does not match the target version".into());
    }
    let stdout = read_bounded(&checked_join(root, &run.stdout)?, 32 * 1024 * 1024)?;
    let stderr = read_bounded(&checked_join(root, &run.stderr)?, 32 * 1024 * 1024)?;
    let trace = read_bounded(&checked_join(root, &run.trace)?, 32 * 1024 * 1024)?;
    if sha256(&stdout) != run.stdout_sha256
        || sha256(&stderr) != run.stderr_sha256
        || sha256(&trace) != run.trace_sha256
    {
        return Err("evidence artifact digest mismatch".into());
    }
    let (events, trace_summary) = crate::trace::parse(
        std::str::from_utf8(&trace).map_err(|_| "trace is not UTF-8")?,
        &run.trace_kind,
    );
    Ok(RunObservation {
        runtime: run.runtime,
        runtime_version: run.runtime_version,
        exit_code: run.exit_code,
        timed_out: run.timed_out,
        duration_ms: run.duration_ms,
        stdout_sha256: run.stdout_sha256,
        stderr_sha256: run.stderr_sha256,
        stdout_ref: checked_join(root, &run.stdout)?.display().to_string(),
        stderr_ref: checked_join(root, &run.stderr)?.display().to_string(),
        trace_ref: checked_join(root, &run.trace)?.display().to_string(),
        trace_sha256: run.trace_sha256,
        trace_kind: run.trace_kind,
        events,
        trace_summary,
        infrastructure_error: None,
    })
}

pub fn import(
    path: &Path,
    digest: Option<&str>,
    target: &TargetRuntime,
    requested_profile: Option<&WorkloadProfile>,
) -> Result<DynamicAnalysis> {
    let bundle: EvidenceBundle = serde_json::from_slice(&read_bounded(path, 1024 * 1024)?)
        .map_err(|e| format!("evidence manifest: {e}"))?;
    if bundle.schema_version != "1.0" {
        return Err("unsupported evidence schema".into());
    }
    validate_digest(&bundle.image_digest)?;
    if digest != Some(&bundle.image_digest) {
        return Err("evidence is not bound to the scanned OCI manifest digest".into());
    }
    if bundle.target_runtime != *target {
        return Err("evidence target runtime or architecture differs from scan target".into());
    }
    profile::validate(&bundle.profile)?;
    let profile_digest = sha256(&serde_json::to_vec(&bundle.profile).map_err(|e| e.to_string())?);
    if profile_digest != bundle.profile_sha256 {
        return Err("evidence profile digest mismatch".into());
    }
    if let Some(requested) = requested_profile {
        if sha256(&serde_json::to_vec(requested).map_err(|e| e.to_string())?) != profile_digest {
            return Err("supplied profile differs from evidence profile".into());
        }
    }
    if bundle.native.is_empty() || bundle.native.len() > 20 || bundle.sandbox.len() > 20 {
        return Err("evidence contains invalid run counts".into());
    }
    let root = path.parent().unwrap_or_else(|| Path::new("."));
    let native = bundle
        .native
        .into_iter()
        .map(|run| load_run(root, run, target, false))
        .collect::<Result<Vec<_>>>()?;
    let sandbox = bundle
        .sandbox
        .into_iter()
        .map(|run| load_run(root, run, target, true))
        .collect::<Result<Vec<_>>>()?;
    let mut result = DynamicAnalysis {
        evidence_tier: if sandbox.is_empty() { "dynamic-native-only" } else if target.name == "gvisor" { "dynamic-runsc-diff" } else { "dynamic-kata-diff" }.into(),
        provenance: "imported-user-supplied".into(), profile: bundle.profile, profile_sha256: profile_digest, native, sandbox,
        exercised_syscalls: vec![], fallback_observations: vec![], warnings: vec!["Imported evidence hashes prove artifact integrity, not execution provenance. A complete/clean gate requires locally collected runs; trusted CI can sign independently collected reports.".into()],
    };
    summarize(&mut result);
    Ok(result)
}
