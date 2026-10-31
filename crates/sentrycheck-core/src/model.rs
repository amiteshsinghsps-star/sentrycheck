use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "1.0";
// A report aggregates several individually bounded traces and can exceed one trace.
pub const MAX_REPORT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetRuntime {
    pub name: String,
    pub version: String,
    pub architecture: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionConfidence {
    StaticCertain,
    StaticProbable,
    Unresolvable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    pub syscall: Option<String>,
    pub syscall_number: Option<u64>,
    pub subsystem: Option<String>,
    pub architecture: String,
    pub resolution_confidence: ResolutionConfidence,
    pub source_binary: String,
    pub source_digest: String,
    pub source_offset: Option<String>,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fingerprint {
    pub source_binary: String,
    pub kind: String,
    pub value: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub interpretation: String,
    pub capabilities: Vec<Capability>,
    pub fingerprints: Vec<Fingerprint>,
    pub elf_files: usize,
    pub cache_hits: usize,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Citation {
    pub title: String,
    pub url: String,
    pub source_revision: Option<String>,
    pub retrieved_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateGap {
    pub gap_id: String,
    pub category: String,
    pub source_binary: String,
    pub syscall: Option<String>,
    pub version_match: bool,
    pub description: String,
    pub citation: Citation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceEvent {
    pub syscall: String,
    pub arguments: String,
    pub result: String,
    pub return_value: Option<i64>,
    pub errno: Option<String>,
    pub line: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceSummary {
    pub syscalls: BTreeMap<String, u64>,
    pub errors: BTreeMap<String, u64>,
    pub event_count: usize,
    pub unfinished_count: usize,
    pub unparsed_lines: usize,
    #[serde(default)]
    pub discarded_guest_records: usize,
    #[serde(default)]
    pub diagnostic_lines: usize,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunObservation {
    pub runtime: String,
    pub runtime_version: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_ref: String,
    pub stderr_ref: String,
    pub trace_ref: String,
    pub trace_sha256: String,
    pub trace_kind: String,
    pub trace_summary: TraceSummary,
    pub events: Vec<TraceEvent>,
    pub infrastructure_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkloadProfile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_repetitions")]
    pub repetitions: usize,
    #[serde(default)]
    pub expected_exit_code: i32,
    #[serde(default)]
    pub compare_stdout: bool,
    #[serde(default)]
    pub compare_stderr: bool,
    #[serde(default = "default_ratio")]
    pub timing_ratio: f64,
    #[serde(default = "default_minimum")]
    pub timing_min_native_ms: u64,
    #[serde(default = "default_coverage")]
    pub coverage: String,
}

fn default_timeout() -> u64 {
    30
}
fn default_repetitions() -> usize {
    3
}
fn default_ratio() -> f64 {
    2.0
}
fn default_minimum() -> u64 {
    100
}
fn default_coverage() -> String {
    "smoke".into()
}

impl Default for WorkloadProfile {
    fn default() -> Self {
        Self {
            name: "image-default-smoke".into(),
            description: "Image ENTRYPOINT/CMD only; startup coverage is limited.".into(),
            command: vec![],
            env: vec![],
            timeout_seconds: default_timeout(),
            repetitions: 1,
            expected_exit_code: 0,
            compare_stdout: false,
            compare_stderr: false,
            timing_ratio: default_ratio(),
            timing_min_native_ms: default_minimum(),
            coverage: default_coverage(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DynamicAnalysis {
    pub evidence_tier: String,
    pub provenance: String,
    pub profile: WorkloadProfile,
    pub profile_sha256: String,
    pub native: Vec<RunObservation>,
    pub sandbox: Vec<RunObservation>,
    pub exercised_syscalls: Vec<String>,
    pub fallback_observations: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub gap_id: String,
    pub category: String,
    pub failure_class: String,
    pub severity: String,
    pub evidence_tier: String,
    pub description: String,
    pub source_binary: Option<String>,
    pub static_evidence: Option<Capability>,
    pub dynamic_evidence: serde_json::Value,
    pub kb_citation: Citation,
    pub causality: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SilentFallbackCheck {
    pub performed: bool,
    pub cluster_context_available: bool,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub image: String,
    pub image_digest: Option<String>,
    pub platform: String,
    pub scanned_at: String,
    pub sentrycheck_version: String,
    pub kb_snapshot_version: String,
    pub kb_age_days: Option<u64>,
    pub target_runtime: TargetRuntime,
    pub status: String,
    pub assessment: String,
    pub findings: Vec<Finding>,
    pub candidate_gaps: Vec<CandidateGap>,
    pub capability_set: CapabilitySet,
    pub capability_set_only: Vec<Capability>,
    pub dynamic: Option<DynamicAnalysis>,
    pub silent_fallback_check: SilentFallbackCheck,
    pub limitations: Vec<String>,
    pub incomplete_reasons: Vec<String>,
    pub duration_ms: u64,
}

impl Report {
    pub fn exit_code(&self, fail_on: &str) -> i32 {
        if self
            .findings
            .iter()
            .any(|finding| finding.severity == fail_on)
        {
            1
        } else if self.status != "complete" {
            2
        } else {
            0
        }
    }
}
