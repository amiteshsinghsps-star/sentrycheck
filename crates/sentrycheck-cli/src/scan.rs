use crate::{args::Args, cache_dir, load_kb};
use sentrycheck_core::image::load_path;
use sentrycheck_core::model::*;
use sentrycheck_core::util::{atomic_write, now_seconds, sha256, timestamp};
use sentrycheck_core::Result;
use sentrycheck_dynamic::{evidence, profile, runner};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn acquire(reference: &str, cache: &Path, architecture: &str) -> Result<PathBuf> {
    if Path::new(reference).exists() {
        return Ok(PathBuf::from(reference));
    }
    if reference.starts_with('-') || reference.contains('\0') {
        return Err("invalid image reference".into());
    }
    let digest = sha256(format!("{reference}/{architecture}").as_bytes());
    let destination = cache.join("images").join(&digest[7..]).join(format!(
        "{}-{}",
        now_seconds(),
        std::process::id()
    ));
    std::fs::create_dir_all(&destination).map_err(|e| e.to_string())?;
    let transport = if reference.starts_with("docker-archive:")
        || reference.starts_with("oci-archive:")
        || reference.starts_with("docker://")
    {
        reference.to_string()
    } else {
        format!("docker://{reference}")
    };
    let output = format!("oci:{}:scan", destination.display());
    // Registry auth is delegated to the user's existing skopeo credential configuration.
    // A fresh copy resolves mutable tags on every scan; ELF content is cached separately.
    let status = std::process::Command::new("skopeo").args(["copy","--preserve-digests","--override-os","linux","--override-arch",architecture,&transport,&output])
        .stdout(std::process::Stdio::null()).status().map_err(|e| format!("Registry/archive inputs need skopeo in PATH ({e}). Alternatively pass a local OCI image layout."))?;
    if !status.success() {
        return Err("skopeo image acquisition failed".into());
    }
    Ok(destination)
}

pub fn run(args: Args) -> Result<i32> {
    args.only(
        &[
            "runtime",
            "version",
            "platform",
            "profile",
            "evidence",
            "format",
            "output",
            "cache",
            "artifacts",
            "kb",
            "max-kb-age-days",
            "runc-bin",
            "runsc-bin",
            "strace-bin",
            "fail-on",
            "source-file",
            "source-line",
        ],
        &["static-only", "native-only", "no-cache"],
    )?;
    let image_ref = args.single_positional("image/ELF/rootfs path")?;
    let format = match args.value("format") {
        Some("sarif") => "sarif",
        _ => args.format()?,
    };
    if format != "sarif"
        && (args.value("source-file").is_some() || args.value("source-line").is_some())
    {
        return Err("--source-file/--source-line require --format sarif".into());
    }
    let location = crate::report::source_location(&args)?;
    let fail_on = crate::report::severity(&args)?;
    if args.flag("static-only") && (args.flag("native-only") || args.value("evidence").is_some())
        || args.flag("native-only") && args.value("evidence").is_some()
    {
        return Err("--static-only, --native-only, and --evidence are mutually exclusive".into());
    }
    let platform = args.value("platform").unwrap_or("linux/amd64");
    let architecture = platform
        .strip_prefix("linux/")
        .filter(|a| matches!(*a, "amd64" | "arm64" | "386"))
        .ok_or("--platform must be linux/amd64, linux/arm64, or linux/386")?;
    let start = Instant::now();
    let kb = load_kb(&args)?;
    let runtime = args.value("runtime").unwrap_or("gvisor");
    if !matches!(runtime, "gvisor" | "kata") {
        return Err("--runtime must be gvisor or kata".into());
    }
    let version = args
        .value("version")
        .map(String::from)
        .or_else(|| {
            kb.runtime_releases
                .get(runtime)
                .and_then(|versions| versions.last().cloned())
        })
        .unwrap_or("unversioned".into());
    let target = TargetRuntime {
        name: runtime.into(),
        version: sentrycheck_kb::normalize_version(&version),
        architecture: architecture.into(),
    };
    let max_age: u64 = args
        .value("max-kb-age-days")
        .unwrap_or("30")
        .parse()
        .map_err(|_| "--max-kb-age-days must be an integer")?;
    let cache = cache_dir(&args);
    let path = acquire(image_ref, &cache, architecture)?;
    let mut image = load_path(&path, architecture)?;
    image.reference = image_ref.into();
    let capabilities = sentrycheck_static::scan(
        &image,
        if args.flag("no-cache") {
            None
        } else {
            Some(&cache)
        },
    );
    let supplied_profile = args
        .value("profile")
        .map(|path| profile::load(Path::new(path)))
        .transpose()?;
    let mut incomplete = Vec::new();
    if image.digest.is_none() {
        incomplete.push(
            "Input has no OCI manifest digest; it cannot be bound to a deployed image.".into(),
        );
    }
    if !kb.covers(&target) {
        incomplete.push(format!(
            "KB has no verified release coverage for {} {} on {}.",
            target.name, target.version, target.architecture
        ));
    }
    if kb.age_days() > max_age {
        incomplete.push(format!(
            "KB snapshot is {} days old (maximum {max_age}).",
            kb.age_days()
        ));
    }
    if capabilities.elf_files == 0 {
        incomplete.push("No ELF binaries were found; script/interpreter and mounted executable coverage is unknown.".into());
    }
    let dynamic = if args.flag("static-only") {
        incomplete.push("Static-only scan: capability candidates are unconfirmed.".into());
        None
    } else if let Some(path) = args.value("evidence") {
        Some(evidence::import(
            Path::new(path),
            image.digest.as_deref(),
            &target,
            supplied_profile.as_ref(),
        )?)
    } else {
        let options = runner::Options {
            artifacts: PathBuf::from(args.value("artifacts").unwrap_or(".sentrycheck/artifacts")),
            runc: PathBuf::from(args.value("runc-bin").unwrap_or("runc")),
            runsc: PathBuf::from(args.value("runsc-bin").unwrap_or("runsc")),
            strace: PathBuf::from(args.value("strace-bin").unwrap_or("strace")),
            native_only: args.flag("native-only"),
        };
        match runner::run(
            &image,
            &supplied_profile.clone().unwrap_or_default(),
            &target,
            &options,
        ) {
            Ok(analysis) => Some(analysis),
            Err(error) => {
                incomplete.push(error);
                None
            }
        }
    };
    if let Some(analysis) = &dynamic {
        if analysis.sandbox.is_empty() {
            incomplete.push("Native-only evidence cannot confirm target sandbox compatibility or runtime fallback behavior.".into());
        }
        if analysis.provenance != "locally-executed" {
            incomplete.push("Execution provenance is user-supplied; imported traces are not a clean CI attestation.".into());
        }
        if analysis.profile.coverage != "representative" {
            incomplete.push("Only smoke/startup coverage was supplied; representative workload coverage is missing.".into());
        }
        if analysis.native.len() != analysis.profile.repetitions
            || !analysis.sandbox.is_empty()
                && analysis.sandbox.len() != analysis.profile.repetitions
        {
            incomplete
                .push("The requested number of workload repetitions did not complete.".into());
        }
        if !analysis
            .native
            .iter()
            .all(|run| sentrycheck_kb::successful(run, analysis.profile.expected_exit_code))
        {
            incomplete.push("The native baseline did not satisfy the workload profile.".into());
        }
        if analysis.native.iter().chain(&analysis.sandbox).any(|run| {
            run.infrastructure_error.is_some()
                || run.trace_summary.event_count == 0
                || run.trace_summary.truncated
                || run.trace_summary.unfinished_count > 0
                || run.trace_summary.discarded_guest_records > 0
        }) {
            incomplete.push("Guest trace collection is missing, truncated, or incomplete.".into());
        }
        for stdout in [true, false] {
            if if stdout {
                analysis.profile.compare_stdout
            } else {
                analysis.profile.compare_stderr
            } {
                for runs in [&analysis.native, &analysis.sandbox] {
                    // Deterministic output is the oracle for successful profiles.
                    // Failed runs may include timestamps/PIDs in diagnostics; that
                    // does not invalidate an independently observed hard failure.
                    if !runs.iter().all(|run| {
                        sentrycheck_kb::successful(run, analysis.profile.expected_exit_code)
                    }) {
                        continue;
                    }
                    if let Some(first) = runs.first() {
                        if runs.iter().any(|run| {
                            if stdout {
                                run.stdout_sha256 != first.stdout_sha256
                            } else {
                                run.stderr_sha256 != first.stderr_sha256
                            }
                        }) {
                            incomplete.push(format!("Declared deterministic {} varied within the same runtime; the profile needs normalization.",if stdout {"stdout"} else {"stderr"}));
                        }
                    }
                }
            }
        }
    }
    let candidates = kb.candidates(&capabilities, &target);
    let findings = dynamic
        .as_ref()
        .map(|analysis| kb.findings(&capabilities, analysis, &target))
        .unwrap_or_default();
    // These tracers identify syscall names, not ELF file offsets. An observation of
    // read() somewhere in the image must not mark every static read() site covered.
    let capability_set_only = capabilities.capabilities.clone();
    let report = Report {
        schema_version:SCHEMA_VERSION.into(),image:image_ref.into(),image_digest:image.digest,platform:platform.into(),scanned_at:timestamp(now_seconds()),
        sentrycheck_version:env!("CARGO_PKG_VERSION").into(),kb_snapshot_version:kb.snapshot_version.clone(),kb_age_days:Some(kb.age_days()),target_runtime:target,
        status:if incomplete.is_empty() {"complete"} else {"incomplete"}.into(),
        assessment:if findings.iter().any(|f|matches!(f.severity.as_str(),"hard-failure"|"silent-degradation")) {"incompatibility-observed"} else if findings.iter().any(|f| f.severity == "performance-regression") {"performance-regression-observed"} else if incomplete.is_empty() {"no-incompatibility-observed-in-profile"} else {"insufficient-evidence"}.into(),
        findings,candidate_gaps:candidates,capability_set:capabilities,capability_set_only,dynamic,
        silent_fallback_check:SilentFallbackCheck {performed:false,cluster_context_available:false,note:"An image scan cannot establish node runtime identity. Use the node probe and admission controller; binary presence alone is not isolation attestation.".into()},
        limitations:vec!["Results cover only the declared profile and environment; absence of a finding is not proof of compatibility.".into(),"Static resolution does not establish reachability, syscall arguments, or a complete capability upper bound for dynamically generated code.".into(),"Output comparisons require deterministic profile assertions; unobserved filesystem, cgroup, and networking semantics remain unknown.".into(),"Elapsed-time comparisons include unequal tracer/runtime startup overhead and do not establish a netstack/gofer root cause.".into()],
        incomplete_reasons:incomplete,duration_ms:start.elapsed().as_millis() as u64,
    };
    let json = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    if json.len() as u64 > MAX_REPORT_BYTES {
        return Err(
            "report exceeds the 128 MiB budget; reduce workload repetitions or trace volume".into(),
        );
    }
    if let Some(output) = args.value("output") {
        atomic_write(Path::new(output), &json)?;
    }
    if format == "json" {
        println!("{}", String::from_utf8_lossy(&json));
    } else if format == "sarif" {
        println!(
            "{}",
            serde_json::to_string_pretty(&crate::report::sarif(&report, location.as_ref()))
                .map_err(|e| e.to_string())?
        );
    } else {
        human(&report);
    }
    Ok(report.exit_code(fail_on))
}

fn human(report: &Report) {
    println!(
        "SENTRYCHECK — {}\nImage: {}\nDigest: {}\nTarget: {} {} ({})\nKB: {}\n",
        report.assessment,
        report.image,
        report
            .image_digest
            .as_deref()
            .unwrap_or("unbound local input"),
        report.target_runtime.name,
        report.target_runtime.version,
        report.platform,
        report.kb_snapshot_version
    );
    println!(
        "Capability set (unconfirmed): {} candidates in {} ELF files; {} cache hits",
        report.capability_set.capabilities.len(),
        report.capability_set.elf_files,
        report.capability_set.cache_hits
    );
    println!(
        "KB candidate matches: {} (static candidates are not findings)",
        report.candidate_gaps.len()
    );
    if let Some(dynamic) = &report.dynamic {
        println!(
            "Dynamic evidence: {} / {} / profile {}\nGuest syscalls observed: {}",
            dynamic.evidence_tier,
            dynamic.provenance,
            dynamic.profile.name,
            dynamic.exercised_syscalls.len()
        );
        for note in &dynamic.fallback_observations {
            println!("  Observation: {note}");
        }
        for warning in &dynamic.warnings {
            println!("  Coverage: {warning}");
        }
    }
    println!("\nFindings: {}", report.findings.len());
    for finding in &report.findings {
        println!(
            "  [{} | {}] {}\n    {}\n    Causality: {}\n    {}",
            finding.severity,
            finding.evidence_tier,
            finding.gap_id,
            finding.description,
            finding.causality,
            finding.kb_citation.url
        );
    }
    if !report.incomplete_reasons.is_empty() {
        println!("\nScan incomplete:");
        for reason in &report.incomplete_reasons {
            println!("  - {reason}");
        }
    }
    for warning in report.capability_set.warnings.iter().take(10) {
        println!("  Static coverage: {warning}");
    }
    if report.capability_set.warnings.len() > 10 {
        println!(
            "  ... {} additional static warnings in JSON",
            report.capability_set.warnings.len() - 10
        );
    }
    println!(
        "\nNode isolation: not checked by image scanning.\nDuration: {} ms",
        report.duration_ms
    );
}
