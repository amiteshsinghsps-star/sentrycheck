pub mod evidence;
pub mod profile;
pub mod runner;
pub mod trace;

use sentrycheck_core::model::DynamicAnalysis;
use std::collections::BTreeSet;

pub fn summarize(analysis: &mut DynamicAnalysis) {
    analysis.exercised_syscalls = analysis
        .native
        .iter()
        .chain(&analysis.sandbox)
        .flat_map(|run| run.events.iter().map(|event| event.syscall.clone()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    for run in analysis.native.iter().chain(&analysis.sandbox) {
        if run.trace_summary.event_count == 0 {
            analysis
                .warnings
                .push(format!("{} has no parsed guest syscalls", run.trace_ref));
        }
        if run.trace_summary.truncated
            || run.trace_summary.unfinished_count > 0
            || run.trace_summary.discarded_guest_records > 0
        {
            analysis.warnings.push(format!(
                "{} contains truncated, discarded, or unfinished guest trace data",
                run.trace_ref
            ));
        }
        if let Some(error) = &run.infrastructure_error {
            analysis.warnings.push(format!("{}: {error}", run.runtime));
        }
    }
    let native_ok = !analysis.native.is_empty()
        && analysis.native.iter().all(|run| {
            run.exit_code == Some(analysis.profile.expected_exit_code)
                && !run.timed_out
                && run.infrastructure_error.is_none()
        });
    let sandbox_ok = !analysis.sandbox.is_empty()
        && analysis.sandbox.iter().all(|run| {
            run.exit_code == Some(analysis.profile.expected_exit_code)
                && !run.timed_out
                && run.infrastructure_error.is_none()
        });
    if !native_ok {
        analysis.warnings.push("Native baseline did not satisfy the profile; target-runtime compatibility cannot be inferred from this run.".into());
    }
    if native_ok && sandbox_ok {
        let failed_probes: BTreeSet<_> = analysis
            .sandbox
            .iter()
            .flat_map(|run| &run.events)
            .filter(|event| matches!(event.errno.as_deref(), Some("ENOSYS" | "EOPNOTSUPP")))
            .map(|event| event.syscall.clone())
            .collect();
        for syscall in failed_probes {
            analysis.fallback_observations.push(format!("Sandbox returned an unsupported-operation error for {syscall}, but the profile returned its expected exit code. An error was tolerated; inspect declared output assertions before inferring a successful fallback."));
        }
    }
}
