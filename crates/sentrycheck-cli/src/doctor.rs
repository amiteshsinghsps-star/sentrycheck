use crate::{args::Args, load_kb};
use sentrycheck_core::model::TargetRuntime;
use sentrycheck_core::util::{atomic_write, now_seconds, read_bounded};
use sentrycheck_core::Result;
use serde_json::{json, Value};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn executable(name: &str) -> Option<PathBuf> {
    let path = Path::new(name);
    let candidates = if path.is_absolute() || path.components().count() > 1 {
        vec![path.to_path_buf()]
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join(path))
            .collect()
    };
    candidates.into_iter().find_map(|p| {
        let meta = fs::metadata(&p).ok()?;
        if !meta.is_file() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o111 == 0 {
                return None;
            }
        }
        p.canonicalize().ok()
    })
}

struct Capture(PathBuf);
impl Drop for Capture {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("stdout"));
        let _ = fs::remove_file(self.0.join("stderr"));
        let _ = fs::remove_dir(&self.0);
    }
}

// Trusted local --version probes only. File capture avoids blocked/full pipes.
fn probe(binary: &Path) -> Result<String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("sentrycheck-doctor-{}-{stamp}", std::process::id()));
    fs::create_dir(&directory).map_err(|e| e.to_string())?;
    let capture = Capture(directory);
    let out = capture.0.join("stdout");
    let err = capture.0.join("stderr");
    let mut child = Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(File::create(&out).map_err(|e| e.to_string())?)
        .stderr(File::create(&err).map_err(|e| e.to_string())?)
        .spawn()
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    loop {
        let excessive = [&out, &err]
            .iter()
            .any(|p| fs::metadata(p).is_ok_and(|m| m.len() > 65536));
        if excessive || started.elapsed() > Duration::from_secs(3) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("version probe exceeded its 3-second/64-KiB budget".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = read_bounded(&out, 65536)?;
                let stderr = read_bounded(&err, 65536)?;
                if !status.success() {
                    return Err(format!(
                        "version probe failed: {}",
                        String::from_utf8_lossy(&stderr)
                            .chars()
                            .take(512)
                            .collect::<String>()
                    ));
                }
                return Ok(String::from_utf8_lossy(&stdout)
                    .chars()
                    .take(4096)
                    .collect());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.to_string());
            }
        }
    }
}

fn check(checks: &mut Vec<Value>, id: &str, state: &str, detail: impl Into<String>) {
    checks.push(json!({"id":id,"status":state,"detail":detail.into()}));
}

pub fn run(args: Args) -> Result<i32> {
    args.only(
        &[
            "format",
            "output",
            "runtime",
            "version",
            "platform",
            "kb",
            "cache",
            "max-kb-age-days",
            "runc-bin",
            "runsc-bin",
            "strace-bin",
            "profile",
        ],
        &["static-only", "native-only"],
    )?;
    if !args.positionals.is_empty() {
        return Err("doctor takes options, not an image".into());
    }
    if args.flag("static-only") && args.flag("native-only") {
        return Err("doctor modes are mutually exclusive".into());
    }
    let format = args.format()?;
    let kb = load_kb(&args)?;
    let runtime = args.value("runtime").unwrap_or("gvisor");
    if !matches!(runtime, "gvisor" | "kata") {
        return Err("--runtime must be gvisor or kata".into());
    }
    let platform = args.value("platform").unwrap_or("linux/amd64");
    let arch = platform
        .strip_prefix("linux/")
        .filter(|a| matches!(*a, "amd64" | "arm64" | "386"))
        .ok_or("unsupported --platform")?;
    let version = args
        .value("version")
        .map(String::from)
        .or_else(|| {
            kb.runtime_releases
                .get(runtime)
                .and_then(|v| v.last().cloned())
        })
        .unwrap_or("unversioned".into());
    let target = TargetRuntime {
        name: runtime.into(),
        version: sentrycheck_kb::normalize_version(&version),
        architecture: arch.into(),
    };
    let age: u64 = args
        .value("max-kb-age-days")
        .unwrap_or("30")
        .parse()
        .map_err(|_| "invalid --max-kb-age-days")?;
    let mut checks = vec![];
    check(
        &mut checks,
        "knowledge-base",
        if kb.covers(&target) && kb.age_days() <= age {
            "pass"
        } else {
            "fail"
        },
        format!(
            "Snapshot {}; age {} days; exact target covered: {}",
            kb.snapshot_version,
            kb.age_days(),
            kb.covers(&target)
        ),
    );
    if let Some(path) = args.value("profile") {
        let profile = sentrycheck_dynamic::profile::load(Path::new(path))?;
        check(
            &mut checks,
            "profile",
            if profile.coverage == "representative" {
                "pass"
            } else {
                "warning"
            },
            format!(
                "{}; {} repetitions; coverage {}",
                profile.name, profile.repetitions, profile.coverage
            ),
        );
    } else {
        check(
            &mut checks,
            "profile",
            "warning",
            "No profile checked. Image default invocation supplies smoke coverage only.",
        );
    }
    if !args.flag("static-only") {
        check(
            &mut checks,
            "linux",
            if cfg!(target_os = "linux") {
                "pass"
            } else {
                "fail"
            },
            format!(
                "Host OS: {}; live execution requires Linux",
                std::env::consts::OS
            ),
        );
        let host = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "386",
            other => other,
        };
        check(
            &mut checks,
            "architecture",
            if host == arch { "pass" } else { "fail" },
            format!("Host {host}; target {arch}; cross-architecture live execution is unsupported"),
        );
        #[cfg(target_os = "linux")]
        {
            let kernel = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
            let numbers: Vec<u64> = kernel
                .trim()
                .split('.')
                .take(2)
                .filter_map(|p| p.parse().ok())
                .collect();
            let supported = numbers.len() == 2 && (numbers[0], numbers[1]) >= (5, 6);
            if runtime == "gvisor" && !args.flag("native-only") {
                check(
                    &mut checks,
                    "kernel",
                    if supported { "pass" } else { "fail" },
                    format!("Kernel {}; gVisor documents Linux >= 5.6", kernel.trim()),
                );
            }
            let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
            let uid = status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("unknown");
            check(&mut checks,"permissions","warning",format!("Effective UID {uid}; namespaces, ptrace, cgroups and nested-container policy must allow OCI execution. Only a live scan confirms this."));
        }
        for (id, option, default) in [
            ("runc", "runc-bin", "runc"),
            ("strace", "strace-bin", "strace"),
            ("runsc", "runsc-bin", "runsc"),
        ] {
            if id == "runsc" && (args.flag("native-only") || runtime != "gvisor") {
                continue;
            }
            let name = args.value(option).unwrap_or(default);
            match executable(name) {
                Some(path) => match probe(&path) {
                    Ok(output) => {
                        let release = output
                            .split_whitespace()
                            .map(sentrycheck_kb::normalize_version)
                            .find(|v| v == &target.version);
                        let ok = id != "runsc" || release.is_some();
                        check(
                            &mut checks,
                            id,
                            if ok { "pass" } else { "fail" },
                            format!(
                                "{}: {}{}",
                                path.display(),
                                output.lines().next().unwrap_or("no version output"),
                                if ok {
                                    String::new()
                                } else {
                                    format!("; expected exact release {}", target.version)
                                }
                            ),
                        );
                        // Companion layout is established for this pinned release, not all future releases.
                        if id == "runsc" && target.version == "20260921.0" {
                            let companions =
                                path.parent().unwrap_or(Path::new(".")).join("gvisor-bin");
                            let missing: Vec<_> = [
                                "gvisor_sentry",
                                "gvisor-sentry-prewarmer",
                                "checkpointgofer",
                                "runsc-fd-parking",
                                "runsc-metric-server",
                            ]
                            .into_iter()
                            .filter(|name| {
                                executable(&companions.join(name).to_string_lossy()).is_none()
                            })
                            .collect();
                            check(
                                &mut checks,
                                "gvisor-companions",
                                if missing.is_empty() { "pass" } else { "fail" },
                                if missing.is_empty() {
                                    format!("Release companions present at {} (presence check; no checksum/launch attestation)",companions.display())
                                } else {
                                    format!("Missing release companions: {}. Install the complete release archive.",missing.join(", "))
                                },
                            );
                        }
                    }
                    Err(error) => check(
                        &mut checks,
                        id,
                        "fail",
                        format!("{}: {error}", path.display()),
                    ),
                },
                None => check(
                    &mut checks,
                    id,
                    "fail",
                    format!("{name} is missing or not executable"),
                ),
            }
        }
        if runtime == "kata" && !args.flag("native-only") {
            check(&mut checks,"kata-live","fail","Direct Kata execution is not implemented. Import guest traces; VM execution needs hardware virtualization and a configured hypervisor.");
        }
        if args.flag("native-only") {
            check(
                &mut checks,
                "native-only",
                "warning",
                "Native tracing cannot produce a complete sandbox comparison.",
            );
        }
    }
    check(
        &mut checks,
        "registry-transport",
        if executable("skopeo").is_some() {
            "pass"
        } else {
            "warning"
        },
        "Registry/archive inputs need skopeo; local OCI layouts do not.",
    );
    let ready = checks.iter().all(|c| c["status"] != "fail");
    let result = json!({"schema_version":"1.0","checked_at_unix":now_seconds(),"mode":if args.flag("static-only"){"static"}else if args.flag("native-only"){"native"}else{"hybrid"},
        "status":if ready{"prerequisites-satisfied"}else{"not-ready"},"target_runtime":target,"checks":checks,
        "note":"Read-only prerequisite checks, not a workload test or node isolation attestation. No runtime is installed or configured."});
    let bytes = serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?;
    if let Some(path) = args.value("output") {
        atomic_write(Path::new(path), &bytes)?;
    }
    if format == "json" {
        println!("{}", String::from_utf8_lossy(&bytes));
    } else {
        println!(
            "SENTRYCHECK environment: {}",
            result["status"].as_str().unwrap_or("not-ready")
        );
        for c in checks {
            println!(
                "[{}] {}: {}",
                c["status"].as_str().unwrap_or("fail"),
                c["id"].as_str().unwrap_or("check"),
                c["detail"].as_str().unwrap_or("")
            );
        }
        println!("{}", result["note"].as_str().unwrap_or(""));
    }
    Ok(if ready { 0 } else { 2 })
}
