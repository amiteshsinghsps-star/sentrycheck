use sentrycheck_core::model::*;
use sentrycheck_core::util::{now_seconds, read_bounded};
use sentrycheck_core::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub mod diff;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Gap {
    pub id: String,
    pub runtime: String,
    pub runtime_versions: Vec<String>,
    pub architectures: Vec<String>,
    pub category: String,
    pub status: String,
    pub description: String,
    pub syscalls: Vec<String>,
    pub syscall_numbers: Vec<u64>,
    pub subsystems: Vec<String>,
    pub severity_class: String,
    pub first_observed: String,
    pub last_verified: String,
    pub citation: Citation,
    pub applicability: String,
}

impl Gap {
    pub fn applies(&self, target: &TargetRuntime) -> bool {
        self.runtime == target.name
            && self
                .runtime_versions
                .contains(&normalize_version(&target.version))
            && self.architectures.contains(&target.architecture)
    }
    fn matches(&self, capability: &Capability) -> bool {
        self.architectures.contains(&capability.architecture)
            && (capability
                .syscall
                .as_ref()
                .is_some_and(|name| self.syscalls.contains(name))
                || capability
                    .syscall_number
                    .is_some_and(|number| self.syscall_numbers.contains(&number))
                || capability
                    .subsystem
                    .as_ref()
                    .is_some_and(|name| self.subsystems.contains(name)))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KnowledgeBase {
    pub schema_version: String,
    pub snapshot_version: String,
    pub created_at: String,
    pub created_at_unix: u64,
    pub runtime_releases: BTreeMap<String, Vec<String>>,
    pub source_commit: String,
    pub source_hashes: BTreeMap<String, String>,
    pub syscall_support: Vec<serde_json::Value>,
    pub entries: Vec<Gap>,
    pub runtime_fallback_rules: Vec<serde_json::Value>,
    pub notes: Vec<String>,
}

pub fn normalize_version(version: &str) -> String {
    version.trim().trim_start_matches("release-").to_string()
}

impl KnowledgeBase {
    pub fn bundled() -> Result<Self> {
        Self::from_bytes(include_bytes!("../../../kb/snapshot.json"))
    }
    pub fn load(path: &Path) -> Result<Self> {
        Self::from_bytes(&read_bounded(path, 16 * 1024 * 1024)?)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let kb: Self = serde_json::from_slice(bytes).map_err(|e| format!("KB JSON: {e}"))?;
        if kb.schema_version != "1.0" || kb.entries.is_empty() || kb.entries.len() > 20_000 {
            return Err("unsupported/empty/oversized knowledge base".into());
        }
        if kb.created_at_unix > now_seconds() + 86400 {
            return Err("KB timestamp is in the future".into());
        }
        let mut identifiers = BTreeSet::new();
        for gap in &kb.entries {
            if !identifiers.insert(&gap.id) {
                return Err(format!("duplicate gap ID: {}", gap.id));
            }
            if !gap.citation.url.starts_with("https://")
                || gap.citation.title.is_empty()
                || gap.citation.retrieved_at.is_empty()
            {
                return Err(format!("{} lacks a checkable citation", gap.id));
            }
            if gap.applicability == "release-pinned"
                && (gap.runtime_versions.is_empty()
                    || gap.architectures.is_empty()
                    || gap.citation.source_revision.is_none())
            {
                return Err(format!("{} is not release-pinned", gap.id));
            }
            if !matches!(
                gap.applicability.as_str(),
                "release-pinned" | "observational"
            ) {
                return Err(format!("{} has unknown applicability", gap.id));
            }
        }
        for id in [
            "gap-observed-workload-failure",
            "gap-observed-output-divergence",
            "gap-observed-filesystem-divergence",
            "gap-observed-performance-regression",
            "gap-runtime-isolation-mismatch",
        ] {
            if !identifiers.contains(&id.to_string()) {
                return Err(format!("KB missing required interpretation entry {id}"));
            }
        }
        Ok(kb)
    }
    pub fn age_days(&self) -> u64 {
        now_seconds().saturating_sub(self.created_at_unix) / 86400
    }
    pub fn covers(&self, target: &TargetRuntime) -> bool {
        self.runtime_releases
            .get(&target.name)
            .is_some_and(|versions| versions.contains(&normalize_version(&target.version)))
            && self.entries.iter().any(|gap| gap.applies(target))
    }
    pub fn get(&self, id: &str) -> Option<&Gap> {
        self.entries.iter().find(|gap| gap.id == id)
    }
    pub fn candidates(
        &self,
        capabilities: &CapabilitySet,
        target: &TargetRuntime,
    ) -> Vec<CandidateGap> {
        let mut result = Vec::new();
        let mut seen = BTreeSet::new();
        for capability in &capabilities.capabilities {
            for gap in self
                .entries
                .iter()
                .filter(|gap| gap.runtime == target.name && gap.matches(capability))
            {
                if !seen.insert((gap.id.clone(), capability.source_binary.clone())) {
                    continue;
                }
                result.push(CandidateGap {
                    gap_id: gap.id.clone(),
                    category: gap.category.clone(),
                    source_binary: capability.source_binary.clone(),
                    syscall: capability.syscall.clone(),
                    version_match: gap.applies(target),
                    description: format!("Unconfirmed static candidate. {}", gap.description),
                    citation: gap.citation.clone(),
                });
            }
        }
        result
    }

    pub fn findings(
        &self,
        capabilities: &CapabilitySet,
        dynamic: &DynamicAnalysis,
        target: &TargetRuntime,
    ) -> Vec<Finding> {
        let native_ok = !dynamic.native.is_empty()
            && dynamic
                .native
                .iter()
                .all(|run| successful(run, dynamic.profile.expected_exit_code));
        if !native_ok {
            return vec![];
        }
        if dynamic.sandbox.is_empty() {
            return self.native_risks(capabilities, dynamic, target);
        }
        if !dynamic.sandbox.iter().all(|run| {
            normalize_version(&run.runtime_version) == normalize_version(&target.version)
                && run.infrastructure_error.is_none()
                && run.trace_summary.event_count > 0
        }) {
            return vec![];
        }
        let mut results = Vec::new();
        let failed: Vec<_> = dynamic
            .sandbox
            .iter()
            .filter(|run| !successful(run, dynamic.profile.expected_exit_code))
            .collect();
        if !failed.is_empty() {
            // A failed workload is direct evidence of F1. Individual errno differences
            // are only candidate explanations: an unrelated, tolerated libc probe can
            // fail in exactly the same run. Keep that distinction machine-readable.
            let gap = self.get("gap-observed-workload-failure").unwrap();
            results.push(Self::finding(gap, capabilities, dynamic, "hard-failure", "F1", format!("Native profile passed; {} of {} sandbox executions failed or exceeded the declared timeout. Review stdout, stderr, and guest traces to determine the cause. Syscall correlations are reported separately as unconfirmed compatibility risks.", failed.len(), dynamic.sandbox.len()), "observed-failure; root cause unknown"));
            let mut correlated = BTreeSet::new();
            for event in failed
                .iter()
                .flat_map(|run| &run.events)
                .filter(|event| event.errno.is_some())
            {
                if !dynamic
                    .native
                    .iter()
                    .flat_map(|run| &run.events)
                    .any(|native| {
                        native.syscall == event.syscall
                            && native.errno.is_none()
                            && native.return_value.is_some_and(|v| v >= 0)
                    })
                {
                    continue;
                }
                for gap in self
                    .entries
                    .iter()
                    .filter(|gap| gap.applies(target) && gap.syscalls.contains(&event.syscall))
                {
                    if !correlated.insert(gap.id.clone()) {
                        continue;
                    }
                    results.push(Self::finding(
                        gap,
                        capabilities,
                        dynamic,
                        "compatibility-risk",
                        "unconfirmed",
                        format!(
                            "Candidate explanation for an observed workload failure: native profile passed; sandbox profile failed and {} returned {}. A failed probe may have been tolerated; root cause requires confirmation. {}",
                            event.syscall,
                            event.errno.as_deref().unwrap_or("an error"),
                            gap.description
                        ),
                        "correlated-syscall-error; root cause not proven",
                    ));
                }
            }
            let filesystem = failed.iter().flat_map(|run| &run.events).any(|event| {
                matches!(event.errno.as_deref(), Some("ENOENT" | "ENOTDIR" | "ELOOP"))
                    && matches!(
                        event.syscall.as_str(),
                        "open" | "openat" | "openat2" | "stat" | "statx" | "newfstatat"
                    )
                    && !dynamic
                        .native
                        .iter()
                        .flat_map(|run| &run.events)
                        .any(|native| {
                            native.syscall == event.syscall && native.errno == event.errno
                        })
            });
            if filesystem {
                let gap = self.get("gap-observed-filesystem-divergence").unwrap();
                results.push(Self::finding(gap, capabilities, dynamic, "compatibility-risk", "unconfirmed", "An observed sandbox workload failure included a filesystem-path error absent from native traces. This may be a tolerated lookup; matching syscall names and errno values does not establish path equivalence or causality.".into(), "correlated-filesystem-error; root cause not proven"));
            }
        }
        if failed.is_empty() && dynamic.native.len() == dynamic.sandbox.len() {
            let stdout_diff = dynamic.profile.compare_stdout
                && stable_hash(&dynamic.native, true)
                && stable_hash(&dynamic.sandbox, true)
                && dynamic.native[0].stdout_sha256 != dynamic.sandbox[0].stdout_sha256;
            let stderr_diff = dynamic.profile.compare_stderr
                && stable_hash(&dynamic.native, false)
                && stable_hash(&dynamic.sandbox, false)
                && dynamic.native[0].stderr_sha256 != dynamic.sandbox[0].stderr_sha256;
            if stdout_diff || stderr_diff {
                let gap = self.get("gap-observed-output-divergence").unwrap();
                results.push(Self::finding(gap, capabilities, dynamic, "silent-degradation", "F2", format!("Both runtimes returned the expected exit code, but declared deterministic output differed (stdout: {stdout_diff}, stderr: {stderr_diff}). Repetitions within each runtime were stable."), "observed-output-divergence; semantic impact requires profile assertions"));
            }
            if dynamic.native.len() >= 3 && dynamic.sandbox.len() >= 3 {
                let native_median =
                    median(dynamic.native.iter().map(|run| run.duration_ms).collect());
                let sandbox_median =
                    median(dynamic.sandbox.iter().map(|run| run.duration_ms).collect());
                // Require the slowest native sample to be faster than the fastest sandbox
                // sample as well as a median ratio, to reduce noisy timing false alarms.
                let separated = dynamic
                    .native
                    .iter()
                    .map(|run| run.duration_ms)
                    .max()
                    .unwrap_or(0)
                    < dynamic
                        .sandbox
                        .iter()
                        .map(|run| run.duration_ms)
                        .min()
                        .unwrap_or(0);
                if native_median >= dynamic.profile.timing_min_native_ms
                    && separated
                    && sandbox_median as f64 > native_median as f64 * dynamic.profile.timing_ratio
                {
                    let gap = self.get("gap-observed-performance-regression").unwrap();
                    results.push(Self::finding(gap, capabilities, dynamic, "performance-regression", "F3", format!("Median elapsed time increased from {native_median} ms to {sandbox_median} ms over {} repetitions. Includes container startup and tracing overhead; this is not a netstack-specific measurement.", dynamic.native.len()), "observed-timing; subsystem attribution unknown"));
                }
            }
        }
        for (index, finding) in results.iter_mut().enumerate() {
            finding.id = format!("finding-{:04}", index + 1);
        }
        results
    }

    fn native_risks(
        &self,
        capabilities: &CapabilitySet,
        dynamic: &DynamicAnalysis,
        target: &TargetRuntime,
    ) -> Vec<Finding> {
        let exercised: BTreeSet<_> = dynamic
            .native
            .iter()
            .flat_map(|run| &run.events)
            .filter(|e| e.errno.is_none() && e.return_value.is_some_and(|r| r >= 0))
            .map(|e| &e.syscall)
            .collect();
        let mut findings = Vec::new();
        for gap in self.entries.iter().filter(|gap| {
            gap.applies(target) && gap.syscalls.iter().any(|name| exercised.contains(name))
        }) {
            let mut finding = Self::finding(gap, capabilities, dynamic, "compatibility-risk", "unconfirmed", format!("Observed natively, but not tested in the target sandbox. {} This is not a confirmed workload failure.", gap.description), "native-use-only; sandbox behavior unknown");
            finding.id = format!("finding-{:04}", findings.len() + 1);
            findings.push(finding);
        }
        findings
    }

    fn finding(
        gap: &Gap,
        capabilities: &CapabilitySet,
        dynamic: &DynamicAnalysis,
        severity: &str,
        class: &str,
        description: String,
        causality: &str,
    ) -> Finding {
        let mut static_evidence = capabilities
            .capabilities
            .iter()
            .find(|cap| gap.matches(cap))
            .cloned();
        if let Some(candidate) = &mut static_evidence {
            candidate.note.push_str(" This static site is not attributed to the dynamic event; guest traces do not resolve ELF offsets.");
        }
        Finding {
            id: String::new(),
            gap_id: gap.id.clone(),
            category: gap.category.clone(),
            failure_class: class.into(),
            severity: severity.into(),
            evidence_tier: dynamic.evidence_tier.clone(),
            description,
            source_binary: static_evidence
                .as_ref()
                .map(|cap| cap.source_binary.clone()),
            static_evidence,
            dynamic_evidence: json!({"profile_sha256": dynamic.profile_sha256, "provenance": dynamic.provenance,
                "native": dynamic.native.iter().map(run_reference).collect::<Vec<_>>(), "sandbox": dynamic.sandbox.iter().map(run_reference).collect::<Vec<_>>() }),
            kb_citation: gap.citation.clone(),
            causality: causality.into(),
        }
    }
}

fn run_reference(run: &RunObservation) -> serde_json::Value {
    json!({"runtime": run.runtime, "runtime_version": run.runtime_version, "exit_code": run.exit_code, "timed_out": run.timed_out, "trace_excerpt_ref": run.trace_ref, "trace_sha256": run.trace_sha256, "stdout_ref": run.stdout_ref, "stderr_ref": run.stderr_ref, "duration_ms": run.duration_ms})
}

pub fn successful(run: &RunObservation, expected: i32) -> bool {
    run.exit_code == Some(expected)
        && !run.timed_out
        && run.infrastructure_error.is_none()
        && run.trace_summary.event_count > 0
}

fn stable_hash(runs: &[RunObservation], stdout: bool) -> bool {
    let get = |run: &RunObservation| {
        if stdout {
            run.stdout_sha256.clone()
        } else {
            run.stderr_sha256.clone()
        }
    };
    runs.first()
        .is_some_and(|first| runs.iter().all(|run| get(run) == get(first)))
}

fn median(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    values[values.len() / 2]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(runtime: &str, exit_code: i32, errors: bool) -> RunObservation {
        let events: Vec<_> = ["rseq", "io_uring_setup"]
            .into_iter()
            .map(|syscall| TraceEvent {
                syscall: syscall.into(),
                arguments: String::new(),
                result: if errors { "-1 ENOSYS" } else { "0" }.into(),
                return_value: Some(if errors { -1 } else { 0 }),
                errno: errors.then(|| "ENOSYS".into()),
                line: 1,
            })
            .collect();
        RunObservation {
            runtime: runtime.into(),
            runtime_version: "20260921.0".into(),
            exit_code: Some(exit_code),
            timed_out: false,
            duration_ms: 100,
            stdout_sha256: String::new(),
            stderr_sha256: String::new(),
            stdout_ref: String::new(),
            stderr_ref: String::new(),
            trace_ref: String::new(),
            trace_sha256: String::new(),
            trace_kind: String::new(),
            trace_summary: TraceSummary {
                event_count: events.len(),
                ..TraceSummary::default()
            },
            events,
            infrastructure_error: None,
        }
    }

    #[test]
    fn syscall_correlations_cannot_be_mistaken_for_proven_failure_causes() {
        let kb = KnowledgeBase::bundled().unwrap();
        let target = TargetRuntime {
            name: "gvisor".into(),
            version: "20260921.0".into(),
            architecture: "amd64".into(),
        };
        let mut dynamic = DynamicAnalysis {
            evidence_tier: "dynamic-runsc-diff".into(),
            provenance: "locally-executed".into(),
            profile: WorkloadProfile::default(),
            profile_sha256: String::new(),
            native: vec![run("runc", 0, false)],
            sandbox: vec![run("gvisor", 42, true)],
            exercised_syscalls: vec![],
            fallback_observations: vec![],
            warnings: vec![],
        };
        let findings = kb.findings(&CapabilitySet::default(), &dynamic, &target);
        let confirmed: Vec<_> = findings
            .iter()
            .filter(|finding| finding.severity == "hard-failure")
            .collect();
        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0].gap_id, "gap-observed-workload-failure");
        let correlations: Vec<_> = findings
            .iter()
            .filter(|finding| finding.severity == "compatibility-risk")
            .collect();
        assert!(correlations.len() >= 2);
        assert!(correlations
            .iter()
            .all(|finding| finding.failure_class == "unconfirmed"));
        // Tolerating both errors without a workload failure must not raise F1 or
        // speculate about a broken fallback merely because ENOSYS was observed.
        dynamic.sandbox[0].exit_code = Some(0);
        assert!(kb
            .findings(&CapabilitySet::default(), &dynamic, &target)
            .is_empty());
        dynamic.native[0].exit_code = Some(1);
        dynamic.sandbox[0].exit_code = Some(42);
        assert!(kb
            .findings(&CapabilitySet::default(), &dynamic, &target)
            .is_empty());
    }
    #[test]
    fn bundled_sources_are_pinned_and_valid() {
        let kb = KnowledgeBase::bundled().unwrap();
        assert!(kb.entries.len() > 200);
        assert!(kb.covers(&TargetRuntime {
            name: "gvisor".into(),
            version: "20260921.0".into(),
            architecture: "amd64".into()
        }));
        assert!(!kb.covers(&TargetRuntime {
            name: "gvisor".into(),
            version: "20990101.0".into(),
            architecture: "amd64".into()
        }));
        assert!(!kb.covers(&TargetRuntime {
            name: "kata".into(),
            version: "3.0.0".into(),
            architecture: "amd64".into()
        }));
    }

    #[test]
    fn capability_error_stubs_are_unimplemented_even_with_capabilities() {
        let kb = KnowledgeBase::bundled().unwrap();
        let gap = kb
            .entries
            .iter()
            .find(|gap| gap.id == "gap-gvisor-amd64-reboot")
            .unwrap();
        assert_eq!(gap.status, "unimplemented");
        assert!(gap.description.contains("EPERM without CAP_SYS_BOOT"));
        assert!(gap.description.contains("ENOSYS with that capability"));
        assert!(kb.source_hashes.contains_key("syscalls.go"));
        let read = kb
            .syscall_support
            .iter()
            .find(|row| row["architecture"] == "amd64" && row["syscall"] == "read")
            .unwrap();
        assert_eq!(read["status"], "full");
        assert_eq!(read["detail"], "Fully Supported.");
    }
    #[test]
    fn static_candidates_never_enter_findings() {
        let cap = Capability {
            syscall: Some("io_uring_setup".into()),
            syscall_number: Some(425),
            subsystem: Some("io_uring".into()),
            architecture: "amd64".into(),
            resolution_confidence: ResolutionConfidence::StaticCertain,
            source_binary: "/test".into(),
            source_digest: "hash".into(),
            source_offset: Some("0x100".into()),
            note: String::new(),
        };
        let set = CapabilitySet {
            capabilities: vec![cap],
            ..CapabilitySet::default()
        };
        let target = TargetRuntime {
            name: "gvisor".into(),
            version: "20260921.0".into(),
            architecture: "amd64".into(),
        };
        let kb = KnowledgeBase::bundled().unwrap();
        assert!(!kb.candidates(&set, &target).is_empty());
        let dynamic = DynamicAnalysis {
            evidence_tier: "static-only".into(),
            provenance: "local".into(),
            profile: WorkloadProfile::default(),
            profile_sha256: String::new(),
            native: vec![],
            sandbox: vec![],
            exercised_syscalls: vec![],
            fallback_observations: vec![],
            warnings: vec![],
        };
        assert!(kb.findings(&set, &dynamic, &target).is_empty());
    }
}
