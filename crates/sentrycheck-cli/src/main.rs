mod args;
mod doctor;
mod kb_diff;
mod matrix;
mod render;
mod report;
mod scan;

use args::Args;
use sentrycheck_core::util::{atomic_write, read_bounded};
use sentrycheck_core::Result;
use sentrycheck_kb::KnowledgeBase;
use std::path::PathBuf;

const HELP: &str = "SENTRYCHECK 0.5.0 — evidence-graded sandbox compatibility analysis

USAGE
  sentrycheck scan <image> [OPTIONS]
  sentrycheck ci-gate <image> [--fail-on hard-failure] [OPTIONS]
  sentrycheck kb list [--format json] [--kb FILE]
  sentrycheck kb update [--version YYYYMMDD.N | --file SNAPSHOT] [--cache DIR]
  sentrycheck kb diff OLD.json NEW.json [--format human|json]
  sentrycheck explain <gap-id> [--format json] [--kb FILE]
  sentrycheck annotate --report FILE [--output FILE]
  sentrycheck doctor [--static-only | --native-only] [--format json] [OPTIONS]
  sentrycheck report validate FILE [--artifacts-root DIR] [--format json]
  sentrycheck report diff BASELINE CURRENT [--fail-on hard-failure] [--format json]
  sentrycheck report sarif FILE [--output FILE]
  sentrycheck report render FILE --output report.html|DIRECTORY [--kb FILE] [--force]
  sentrycheck report compare GVISOR.json KATA.json [--output matrix.json] [--format json]
  sentrycheck report extract MATRIX.json --runtime gvisor|kata --output report.json
  sentrycheck bench <subcommand> [OPTIONS]

SCAN OPTIONS
  --runtime gvisor|kata      Target runtime (default: gvisor)
                            Use gvisor,kata with --gvisor-version and --kata-version for a comparison
  --gvisor-evidence FILE     Optional existing gVisor traces for a multi-runtime scan
  --kata-evidence FILE       Existing Kata guest traces; live Kata collection uses the CRI helper
  --version VERSION         Exact release (default: bundled KB release)
  --platform linux/amd64    Also linux/arm64 and linux/386
  --profile FILE            TOML/JSON workload profile; otherwise a limited startup smoke test
  --static-only             Extract unconfirmed capability candidates only
  --native-only             Trace via runc without executing runsc
  --evidence FILE           Analyze a digest-bound, externally collected evidence bundle
  --format human|json|sarif Output format (SARIF is available for scans)
  --output FILE             Also write the complete JSON report
  --cache DIR               Incremental ELF cache (default: .sentrycheck/cache)
  --no-cache                Disable ELF result cache
  --artifacts DIR           Trace/run artifacts (default: .sentrycheck/artifacts)
  --kb FILE                 Override the cached/bundled knowledge base
  --max-kb-age-days N       Mark stale KBs incomplete (default: 30)
  --runc-bin PATH           Native OCI runtime
  --runsc-bin PATH          gVisor OCI runtime
  --strace-bin PATH         Trusted host strace (static or dynamically linked)
  --source-file PATH        Optional SARIF repository context (explicit user mapping)
  --source-line N           Mapped source line (default: 1; requires --source-file)

INPUTS
  OCI layout, local ELF, rootfs directory, or registry reference via skopeo.
  Prefix docker-archive: or oci-archive: for archive transports.

EXIT CODES
  0  No selected failure found in a complete, bounded scan
  1  Finding matches --fail-on (default: hard-failure)
  2  Incomplete/degraded scan, unsupported environment, or invalid input

Static-only results are capability sets, never compatibility verdicts.
Live execution requires Linux. No scan establishes node runtime isolation.
Rendering creates an offline Astro viewer; exit 0 means export succeeded, not compatibility.
";

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("sentrycheck: {error}");
            2
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32> {
    let mut arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.is_empty()
        || arguments == ["--help"]
        || arguments == ["-h"]
        || arguments == ["help"]
    {
        print!("{HELP}");
        return Ok(0);
    }
    if arguments == ["--version"] {
        println!("sentrycheck {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    let command = arguments.remove(0);
    if command == "bench" {
        return bench_command(arguments);
    }
    if arguments.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{HELP}");
        return Ok(0);
    }
    let args = Args::parse(arguments)?;
    match command.as_str() {
        "scan" | "ci-gate" if args.value("runtime").is_some_and(|v| v.contains(',')) => {
            matrix::scan(args)
        }
        "scan" | "ci-gate" => scan::run(args),
        "doctor" => doctor::run(args),
        "report" => report::run(args),
        "explain" => {
            args.only(&["format", "kb", "cache"], &[])?;
            let id = args.single_positional("gap ID")?;
            let kb = load_kb(&args)?;
            let gap = kb
                .get(id)
                .ok_or_else(|| format!("unknown gap {id}; run sentrycheck kb list"))?;
            if args.format()? == "json" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(gap).map_err(|e| e.to_string())?
                );
            } else {
                println!("{}\n{}\nRuntime: {} {:?}; architecture: {:?}\nStatus: {} / {}\n{}\nSource: {}\nRevision: {}\nVerified: {}\n\nA static reference to this entry is not a confirmed failure.",gap.id,gap.description,gap.runtime,gap.runtime_versions,gap.architectures,gap.category,gap.status,gap.applicability,gap.citation.url,gap.citation.source_revision.as_deref().unwrap_or("observational"),gap.last_verified);
            }
            Ok(0)
        }
        "kb" => kb_command(args),
        "annotate" => annotate(args),
        _ => Err(format!("unknown command {command}; use --help")),
    }
}

pub fn cache_dir(args: &Args) -> PathBuf {
    PathBuf::from(args.value("cache").unwrap_or(".sentrycheck/cache"))
}

pub fn load_kb(args: &Args) -> Result<KnowledgeBase> {
    if let Some(path) = args.value("kb") {
        return KnowledgeBase::load(&PathBuf::from(path));
    }
    let cached = cache_dir(args).join("kb.json");
    if cached.exists() {
        KnowledgeBase::load(&cached)
    } else {
        KnowledgeBase::bundled()
    }
}

fn kb_command(args: Args) -> Result<i32> {
    if args.positionals.first().map(String::as_str) == Some("diff") {
        return kb_diff::run(args);
    }
    match args.single_positional("kb subcommand")? {
        "list" => {
            args.only(&["format", "kb", "cache"], &[])?;
            let kb = load_kb(&args)?;
            if args.format()? == "json" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&kb).map_err(|e| e.to_string())?
                );
            } else {
                println!("KB {} ({} days old)\n", kb.snapshot_version, kb.age_days());
                for gap in kb.entries {
                    println!(
                        "{:<49} {:<13} {:<16} {}",
                        gap.id,
                        gap.category,
                        gap.status,
                        gap.runtime_versions.join(",")
                    );
                }
            }
            Ok(0)
        }
        "update" => {
            args.only(&["version", "file", "cache"], &[])?;
            if args.value("file").is_some() && args.value("version").is_some() {
                return Err("--file and --version are mutually exclusive for kb update".into());
            }
            let cache = cache_dir(&args);
            let destination = cache.join("kb.json");
            if let Some(path) = args.value("file") {
                let kb = KnowledgeBase::load(&PathBuf::from(path))?;
                atomic_write(
                    &destination,
                    &serde_json::to_vec_pretty(&kb).map_err(|e| e.to_string())?,
                )?;
            } else {
                let script = cache.join("update_kb.py");
                atomic_write(&script, include_bytes!("../../../scripts/update_kb.py"))?;
                let candidate = cache.join("kb-candidate.json");
                let python = if cfg!(windows) { "python" } else { "python3" };
                let mut command = std::process::Command::new(python);
                command.arg(&script).arg("--out").arg(&candidate);
                if let Some(version) = args.value("version") {
                    command.arg("--version").arg(version);
                }
                let status = command
                    .status()
                    .map_err(|e| format!("KB updater requires Python 3 and HTTPS access: {e}"))?;
                if !status.success() {
                    return Err("KB refresh failed; existing snapshot retained".into());
                }
                let kb = KnowledgeBase::load(&candidate)?;
                atomic_write(
                    &destination,
                    &serde_json::to_vec_pretty(&kb).map_err(|e| e.to_string())?,
                )?;
            }
            println!("Validated KB saved to {}", destination.display());
            Ok(0)
        }
        other => Err(format!("unknown kb subcommand {other}")),
    }
}

fn annotate(args: Args) -> Result<i32> {
    args.only(&["report", "output"], &[])?;
    if !args.positionals.is_empty() {
        return Err("annotate takes --report FILE".into());
    }
    let path = PathBuf::from(args.value("report").ok_or("--report FILE is required")?);
    let bytes = read_bounded(&path, sentrycheck_core::model::MAX_REPORT_BYTES)?;
    let report: sentrycheck_core::model::Report =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    report::validate(&report)?;
    let digest = report
        .image_digest
        .as_deref()
        .ok_or("report must identify an OCI manifest digest")?;
    let annotation = serde_json::json!({"io.sentrycheck.report.sha256": sentrycheck_core::util::sha256(&bytes),
        "io.sentrycheck.image.digest":digest, "io.sentrycheck.runtime":report.target_runtime.name,
        "io.sentrycheck.runtime.version":report.target_runtime.version, "io.sentrycheck.schema":"1.0"});
    let output = serde_json::to_vec_pretty(&annotation).map_err(|e| e.to_string())?;
    if let Some(path) = args.value("output") {
        atomic_write(&PathBuf::from(path), &output)?;
    }
    println!("{}", String::from_utf8_lossy(&output));
    eprintln!("Annotation metadata created. Sign and publish the original report with sentrycheck-admission attest; annotations alone are not trusted by admission.");
    Ok(0)
}

fn bench_command(args: Vec<String>) -> Result<i32> {
    let python = if cfg!(windows) { "python" } else { "python3" };
    let mut command = std::process::Command::new(python);
    command.arg("-m").arg("bench");
    for arg in args {
        command.arg(arg);
    }
    let status = command
        .status()
        .map_err(|e| format!("failed to invoke bench harness via {python}: {e}"))?;
    Ok(status.code().unwrap_or(2))
}
