use sentrycheck_core::image::Image;
use sentrycheck_core::model::{DynamicAnalysis, TargetRuntime, WorkloadProfile};
use sentrycheck_core::Result;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Options {
    pub artifacts: PathBuf,
    pub runc: PathBuf,
    pub runsc: PathBuf,
    pub strace: PathBuf,
    pub native_only: bool,
}

pub fn run(
    image: &Image,
    profile: &WorkloadProfile,
    target: &TargetRuntime,
    options: &Options,
) -> Result<DynamicAnalysis> {
    crate::profile::validate(profile)?;
    #[cfg(target_os = "linux")]
    {
        linux::run(image, profile, target, options)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (image, target, options);
        Err("Live workload execution requires Linux with runc and strace; use --evidence for offline trace analysis or --static-only for capability extraction.".into())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use sentrycheck_core::image::{materialize, FileContent, MAX_FILE};
    use sentrycheck_core::model::RunObservation;
    use sentrycheck_core::util::{atomic_write, checked_join, now_seconds, read_bounded, sha256};
    use sentrycheck_static::elf::Elf;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const OUTPUT_LIMIT: u64 = 32 * 1024 * 1024;
    const RESERVED: &str = "__sentrycheck";

    fn executable(path: &std::path::Path) -> Result<PathBuf> {
        if path.components().count() > 1 || path.is_absolute() {
            return fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()));
        }
        for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
            let candidate = directory.join(path);
            if candidate.is_file() {
                return fs::canonicalize(candidate).map_err(|e| e.to_string());
            }
        }
        Err(format!(
            "{} is not installed or not in PATH",
            path.display()
        ))
    }

    fn small_command(command: &mut Command) -> Result<String> {
        // Trusted host utilities only; cap their lifetime and capture output to files
        // through the runtime's normal output collector below for untrusted workloads.
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        let start = Instant::now();
        loop {
            if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                break;
            }
            if start.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                let _ = child.wait();
                return Err("host utility exceeded timeout".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(2048)
                .collect());
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .chars()
            .take(65536)
            .collect())
    }

    fn version(binary: &std::path::Path, gvisor: bool) -> Result<String> {
        let output = small_command(Command::new(binary).arg("--version"))?;
        if gvisor {
            for word in output.split_whitespace() {
                let value = word.trim_start_matches("release-");
                if value.split_once('.').is_some_and(|(date, rev)| {
                    date.len() == 8
                        && date.bytes().all(|b| b.is_ascii_digit())
                        && !rev.is_empty()
                        && rev.bytes().all(|b| b.is_ascii_digit())
                }) {
                    return Ok(value.into());
                }
            }
            return Err("runsc --version did not identify an exact release YYYYMMDD.N".into());
        }
        Ok(output.lines().next().unwrap_or("unknown").trim().into())
    }

    fn inject_tracer(
        root: &std::path::Path,
        tracer: &std::path::Path,
        architecture: &str,
    ) -> Result<Vec<String>> {
        let data = read_bounded(tracer, MAX_FILE)?;
        let elf = Elf::parse(&data)?;
        if elf.architecture() != architecture {
            return Err("host strace architecture differs from the image".into());
        }
        let directory = checked_join(root, RESERVED)?;
        fs::create_dir(&directory).map_err(|e| e.to_string())?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777))
            .map_err(|e| e.to_string())?;
        let binary = directory.join("strace");
        fs::write(&binary, &data).map_err(|e| e.to_string())?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o555))
            .map_err(|e| e.to_string())?;
        let mut prefix = Vec::new();
        if let Some(interpreter) = elf.interpreter {
            let libraries = small_command(Command::new("ldd").arg(tracer))?;
            if libraries.contains("not found") {
                return Err(
                    "host strace has missing shared libraries; supply a static --strace-bin".into(),
                );
            }
            let libdir = directory.join("lib");
            fs::create_dir(&libdir).map_err(|e| e.to_string())?;
            let mut paths = libraries
                .split_whitespace()
                .filter(|word| word.starts_with('/'))
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            paths.push(PathBuf::from(&interpreter));
            for library in paths {
                let name = library.file_name().ok_or("invalid tracer library path")?;
                let bytes = read_bounded(
                    &fs::canonicalize(&library).map_err(|e| e.to_string())?,
                    MAX_FILE,
                )?;
                let destination = libdir.join(name);
                if destination.exists() && read_bounded(&destination, MAX_FILE)? != bytes {
                    return Err("colliding tracer library basenames".into());
                }
                fs::write(destination, bytes).map_err(|e| e.to_string())?;
            }
            let name = std::path::Path::new(&interpreter)
                .file_name()
                .ok_or("invalid interpreter")?
                .to_string_lossy();
            let loader = libdir.join(name.as_ref());
            fs::set_permissions(loader, fs::Permissions::from_mode(0o555))
                .map_err(|e| e.to_string())?;
            prefix.extend([
                format!("/{RESERVED}/lib/{name}"),
                "--library-path".into(),
                format!("/{RESERVED}/lib"),
            ]);
        }
        prefix.extend([
            format!("/{RESERVED}/strace"),
            "-f".into(),
            "-qq".into(),
            "-s".into(),
            "256".into(),
            "-o".into(),
            format!("/{RESERVED}/native.trace"),
            "--".into(),
        ]);
        Ok(prefix)
    }

    fn image_user(image: &Image) -> Result<(u32, u32)> {
        let configured = &image.config.user;
        if configured.is_empty() {
            return Ok((0, 0));
        }
        let (user, group) = configured
            .split_once(':')
            .map(|(u, g)| (u, Some(g)))
            .unwrap_or((configured, None));
        let table = |path: &str| match image.files.get(path).map(|f| &f.content) {
            Some(FileContent::Regular(data)) => String::from_utf8_lossy(data).into_owned(),
            _ => String::new(),
        };
        let passwd = table("etc/passwd");
        let row = passwd
            .lines()
            .filter_map(|line| {
                let fields = line.split(':').collect::<Vec<_>>();
                (fields.len() >= 4 && (fields[0] == user || fields[2] == user)).then_some(fields)
            })
            .next();
        let uid = user
            .parse::<u32>()
            .ok()
            .or_else(|| row.as_ref().and_then(|r| r[2].parse().ok()))
            .ok_or("could not resolve image USER")?;
        let default_gid = row.as_ref().and_then(|r| r[3].parse().ok()).unwrap_or(0);
        let gid = if let Some(group) = group {
            if let Ok(numeric) = group.parse::<u32>() {
                numeric
            } else {
                table("etc/group")
                    .lines()
                    .find_map(|line| {
                        let fields = line.split(':').collect::<Vec<_>>();
                        if fields.len() >= 3 && fields[0] == group {
                            fields[2].parse().ok()
                        } else {
                            None
                        }
                    })
                    .ok_or("could not resolve image group")?
            }
        } else {
            default_gid
        };
        Ok((uid, gid))
    }

    fn cleanup(binary: &std::path::Path, state: &std::path::Path, id: &str) -> Result<()> {
        let _ = small_command(
            Command::new(binary)
                .arg("--root")
                .arg(state)
                .args(["kill", "--all", id, "KILL"]),
        );
        // Both supported runtimes make `delete --force` idempotent for absent
        // containers. Any error means stop/deletion is unverified. Do not infer
        // absence from runtime-specific state filenames or a filtered list API.
        small_command(
            Command::new(binary)
                .arg("--root")
                .arg(state)
                .args(["delete", "--force", id]),
        )
        .map(|_| ())
    }

    struct RunSpec<'a> {
        image: &'a Image,
        profile: &'a WorkloadProfile,
        target: &'a TargetRuntime,
        binary: &'a std::path::Path,
        tracer: &'a std::path::Path,
        runtime_version: &'a str,
        directory: &'a std::path::Path,
        sandbox: bool,
        index: usize,
    }

    fn once(spec: RunSpec<'_>) -> Result<RunObservation> {
        let RunSpec {
            image,
            profile,
            target,
            binary,
            tracer,
            runtime_version,
            directory,
            sandbox,
            index,
        } = spec;
        let bundle = directory.join("bundle");
        fs::create_dir_all(&bundle).map_err(|e| e.to_string())?;
        let root = bundle.join("rootfs");
        materialize(image, &root)?;
        let mut args = if profile.command.is_empty() {
            image.config.command()
        } else {
            profile.command.clone()
        };
        if args.is_empty() {
            return Err("image has no ENTRYPOINT/CMD; supply --profile with a command".into());
        }
        if !sandbox {
            let mut prefix = inject_tracer(&root, tracer, &image.architecture)?;
            prefix.extend(args);
            args = prefix;
        }
        let metadata = fs::metadata("/proc/self").map_err(|e| e.to_string())?;
        let host_uid = metadata.uid();
        let host_gid = metadata.gid();
        let (uid, gid) = image_user(image)?;
        if host_uid != 0 && (uid != 0 || gid != 0) {
            return Err("rootless execution currently supports USER 0 only; use a dedicated rootful CI runner for non-root image users".into());
        }
        let mut env = BTreeMap::new();
        env.insert(
            "PATH".to_string(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        );
        for pair in image.config.env.iter().chain(&profile.env) {
            if let Some((key, value)) = pair.split_once('=') {
                env.insert(key.to_string(), value.to_string());
            }
        }
        let mut config = json!({
            "ociVersion":"1.1.0", "root":{"path":"rootfs","readonly":false}, "hostname":"sentrycheck",
            "process":{"terminal":false,"user":{"uid":uid,"gid":gid},"args":args,
                "env":env.into_iter().map(|(k,v)| format!("{k}={v}")).collect::<Vec<_>>(),
                "cwd":if image.config.working_dir.is_empty() { "/" } else { &image.config.working_dir },
                "noNewPrivileges":true,"capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]},
                "rlimits":[{"type":"RLIMIT_NOFILE","hard":1024,"soft":1024},{"type":"RLIMIT_FSIZE","hard":134217728,"soft":134217728}]},
            "mounts":[{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","noexec","nodev"]},
                {"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","strictatime","mode=755","size=65536k"]},
                {"destination":"/dev/pts","type":"devpts","source":"devpts","options":["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620"]},
                {"destination":"/dev/shm","type":"tmpfs","source":"shm","options":["nosuid","noexec","nodev","mode=1777","size=65536k"]},
                {"destination":"/tmp","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","mode=1777","size=134217728"]},
                {"destination":"/run","type":"tmpfs","source":"tmpfs","options":["nosuid","nodev","mode=755","size=16777216"]}],
            "linux":{"namespaces":[{"type":"pid"},{"type":"network"},{"type":"ipc"},{"type":"uts"},{"type":"mount"}],
                "maskedPaths":["/proc/kcore","/proc/keys","/proc/timer_list","/proc/sched_debug","/sys/firmware"],
                "readonlyPaths":["/proc/sys","/proc/sysrq-trigger","/proc/irq","/proc/bus"]}
        });
        if host_uid != 0 {
            config["linux"]["namespaces"]
                .as_array_mut()
                .unwrap()
                .push(json!({"type":"user"}));
            config["linux"]["uidMappings"] = json!([{"containerID":0,"hostID":host_uid,"size":1}]);
            config["linux"]["gidMappings"] = json!([{"containerID":0,"hostID":host_gid,"size":1}]);
        } else {
            config["linux"]["resources"] = json!({"memory":{"limit":536870912},"pids":{"limit":128},"cpu":{"quota":100000,"period":100000}});
        }
        atomic_write(
            &bundle.join("config.json"),
            &serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?,
        )?;
        let state = directory.join("state");
        fs::create_dir_all(&state).map_err(|e| e.to_string())?;
        let stdout_path = directory.join("stdout.txt");
        let stderr_path = directory.join("stderr.txt");
        let runtime_log = directory.join("runtime.log");
        let trace_path = directory.join("guest.trace");
        let native_trace_path = root.join(RESERVED).join("native.trace");
        let id = format!(
            "sc-{}-{}-{index}",
            std::process::id(),
            if sandbox { "sandbox" } else { "native" }
        );
        let mut command = Command::new(binary);
        command
            .arg("--root")
            .arg(&state)
            .arg("--log")
            .arg(&runtime_log);
        if host_uid != 0 {
            command.arg("--rootless=true");
        }
        if sandbox {
            command
                .args(["--platform=systrap", "--network=none", "--strace"])
                .arg(format!("--debug-log={}", trace_path.display()));
        }
        command
            .arg("run")
            .arg("--bundle")
            .arg(&bundle)
            .arg(&id)
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                File::create(&stdout_path).map_err(|e| e.to_string())?,
            ))
            .stderr(Stdio::from(
                File::create(&stderr_path).map_err(|e| e.to_string())?,
            ));
        let start = Instant::now();
        let mut child = command.spawn().map_err(|e| format!("runtime spawn: {e}"))?;
        let mut timed_out = false;
        let mut infrastructure_error = None;
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            if [
                &stdout_path,
                &stderr_path,
                &trace_path,
                &runtime_log,
                &native_trace_path,
            ]
            .iter()
            .any(|path| {
                fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.len() > OUTPUT_LIMIT)
            }) {
                infrastructure_error =
                    Some("output/trace exceeded the 32 MiB capture budget".into());
                let _ = child.kill();
                break child.wait().map_err(|e| e.to_string())?;
            }
            if start.elapsed() >= Duration::from_secs(profile.timeout_seconds) {
                timed_out = true;
                let _ = child.kill();
                break child.wait().map_err(|e| e.to_string())?;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        let duration_ms = start.elapsed().as_millis() as u64;
        cleanup(binary, &state, &id).map_err(|error| {
            format!(
                "runtime cleanup unverified: {error}; preserving {} without reading or removing the guest rootfs",
                directory.display()
            )
        })?;
        let mut capture_truncated = false;
        if !sandbox {
            let native_trace = (|| -> Result<Vec<u8>> {
                let guest_trace = checked_join(&root, &format!("{RESERVED}/native.trace"))?;
                let metadata = fs::symlink_metadata(&guest_trace).map_err(|e| e.to_string())?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err("native trace must be a regular file".into());
                }
                if metadata.len() <= OUTPUT_LIMIT {
                    return read_bounded(&guest_trace, OUTPUT_LIMIT);
                }
                let mut bytes = Vec::new();
                File::open(&guest_trace)
                    .map_err(|e| e.to_string())?
                    .take(OUTPUT_LIMIT)
                    .read_to_end(&mut bytes)
                    .map_err(|e| e.to_string())?;
                capture_truncated = true;
                infrastructure_error.get_or_insert(
                    "native trace capture budget exceeded; artifact contains only a truncated prefix".into(),
                );
                Ok(bytes)
            })();
            match native_trace {
                Ok(bytes) => atomic_write(&trace_path, &bytes)?,
                Err(error) => {
                    infrastructure_error = Some(format!("native guest tracing failed: {error}"));
                    atomic_write(&trace_path, b"")?;
                }
            }
        }
        if !trace_path.exists() {
            infrastructure_error = Some("runtime emitted no guest trace".into());
            atomic_write(&trace_path, b"")?;
        }
        // A writer can cross the budget between polls. Preserve completed runs and
        // a bounded, hashable prefix rather than discarding the whole analysis.
        for path in [&stdout_path, &stderr_path, &trace_path] {
            let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err("capture artifact must be a regular file".into());
            }
            if metadata.len() > OUTPUT_LIMIT {
                fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .and_then(|file| file.set_len(OUTPUT_LIMIT))
                    .map_err(|e| e.to_string())?;
                capture_truncated = true;
                infrastructure_error.get_or_insert(
                    "capture budget exceeded; artifact contains only a truncated prefix".into(),
                );
            }
        }
        let stdout = read_bounded(&stdout_path, OUTPUT_LIMIT)?;
        let stderr = read_bounded(&stderr_path, OUTPUT_LIMIT)?;
        let trace = read_bounded(&trace_path, OUTPUT_LIMIT)?;
        let trace_kind = if sandbox {
            "runsc-guest"
        } else {
            "strace-guest"
        };
        let (events, mut trace_summary) =
            crate::trace::parse(&String::from_utf8_lossy(&trace), trace_kind);
        trace_summary.truncated |= capture_truncated;
        if trace_summary.event_count == 0 {
            infrastructure_error.get_or_insert(
                "no guest syscall events were parsed; runtime/tracer setup may have failed".into(),
            );
        }
        let observation = RunObservation {
            runtime: if sandbox {
                target.name.clone()
            } else {
                "runc".into()
            },
            runtime_version: runtime_version.into(),
            exit_code: status.code(),
            timed_out,
            duration_ms,
            stdout_sha256: sha256(&stdout),
            stderr_sha256: sha256(&stderr),
            stdout_ref: stdout_path.display().to_string(),
            stderr_ref: stderr_path.display().to_string(),
            trace_ref: trace_path.display().to_string(),
            trace_sha256: sha256(&trace),
            trace_kind: trace_kind.into(),
            trace_summary,
            events,
            infrastructure_error,
        };
        // This directory was created exclusively for this invocation. The runtime is
        // stopped and traces are copied out before removing the disposable rootfs.
        // Never follow a replacement symlink or remove outside the generated bundle.
        let resolved_root = fs::canonicalize(&root).map_err(|e| e.to_string())?;
        let resolved_bundle = fs::canonicalize(&bundle).map_err(|e| e.to_string())?;
        if resolved_root.parent() != Some(resolved_bundle.as_path())
            || fs::symlink_metadata(&root)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
        {
            return Err("refusing unsafe runtime-rootfs cleanup".into());
        }
        sentrycheck_core::image::prepare_removal(&root)?;
        fs::remove_dir_all(&root).map_err(|e| format!("temporary rootfs cleanup: {e}"))?;
        Ok(observation)
    }

    pub fn run(
        image: &Image,
        profile: &WorkloadProfile,
        target: &TargetRuntime,
        options: &Options,
    ) -> Result<DynamicAnalysis> {
        if image
            .files
            .keys()
            .any(|path| path == RESERVED || path.starts_with(&format!("{RESERVED}/")))
        {
            return Err(format!("image contains reserved analyzer path /{RESERVED}"));
        }
        let host_arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            value => value,
        };
        if image.architecture != host_arch {
            return Err(format!(
                "live execution requires matching host/image architecture: {host_arch} vs {}",
                image.architecture
            ));
        }
        let runc = executable(&options.runc)?;
        let tracer = executable(&options.strace)?;
        let native_version = version(&runc, false)?;
        let mut warnings = Vec::new();
        let sandbox = if options.native_only {
            None
        } else if target.name == "gvisor" {
            match executable(&options.runsc) {
                Ok(path) => {
                    let actual = version(&path, true)?;
                    if actual != target.version.trim_start_matches("release-") {
                        return Err(format!("installed runsc {actual} differs from target {}; pin the actual runtime or install the requested release",target.version));
                    }
                    Some((path, actual))
                }
                Err(error) => {
                    warnings.push(format!("{error}; collecting native-only evidence"));
                    None
                }
            }
        } else {
            warnings.push("Live Kata VM launch is not supported by the portable runner. Import externally collected Kata guest traces; coverage remains experimental.".into());
            None
        };
        fs::create_dir_all(&options.artifacts).map_err(|e| e.to_string())?;
        let parent = fs::canonicalize(&options.artifacts).map_err(|e| e.to_string())?;
        let run_root = parent.join(format!("scan-{}-{}", now_seconds(), std::process::id()));
        fs::create_dir(&run_root).map_err(|e| e.to_string())?;
        let mut native = Vec::new();
        let mut sandbox_runs = Vec::new();
        for index in 0..profile.repetitions {
            let directory = run_root.join(format!("native-{index}"));
            fs::create_dir(&directory).map_err(|e| e.to_string())?;
            let result = once(RunSpec {
                image,
                profile,
                target,
                binary: &runc,
                tracer: &tracer,
                runtime_version: &native_version,
                directory: &directory,
                sandbox: false,
                index,
            })?;
            let baseline_failed = result.infrastructure_error.is_some()
                || result.timed_out
                || result.exit_code != Some(profile.expected_exit_code);
            native.push(result);
            if baseline_failed {
                warnings.push("Stopping repetitions because the native baseline failed.".into());
                break;
            }
            if let Some((binary, runtime_version)) = &sandbox {
                let directory = run_root.join(format!("sandbox-{index}"));
                fs::create_dir(&directory).map_err(|e| e.to_string())?;
                sandbox_runs.push(once(RunSpec {
                    image,
                    profile,
                    target,
                    binary,
                    tracer: &tracer,
                    runtime_version,
                    directory: &directory,
                    sandbox: true,
                    index,
                })?);
                if sandbox_runs
                    .last()
                    .is_some_and(|run| run.infrastructure_error.is_some())
                {
                    warnings.push("Stopping repetitions because sandbox capture/runtime infrastructure failed.".into());
                    break;
                }
            }
        }
        let mut analysis = DynamicAnalysis {
            evidence_tier: if sandbox_runs.is_empty() {
                "dynamic-native-only"
            } else {
                "dynamic-runsc-diff"
            }
            .into(),
            provenance: "locally-executed".into(),
            profile: profile.clone(),
            profile_sha256: sha256(&serde_json::to_vec(profile).map_err(|e| e.to_string())?),
            native,
            sandbox: sandbox_runs,
            exercised_syscalls: vec![],
            fallback_observations: vec![],
            warnings,
        };
        crate::summarize(&mut analysis);
        Ok(analysis)
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cleanup_errors_cannot_be_hidden_by_absent_state_paths() {
            let directory = std::env::temp_dir().join(format!(
                "sentrycheck-cleanup-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&directory).unwrap();
            let binary = directory.join("runtime");
            for (kill_code, delete_code, accepted) in
                [(0, 0, true), (1, 0, true), (0, 1, false), (1, 1, false)]
            {
                fs::write(
                    &binary,
                    format!(
                        "#!/bin/sh\ncase \"$3\" in\nkill) exit {kill_code};;\ndelete) exit {delete_code};;\n*) exit 1;;\nesac\n"
                    ),
                )
                .unwrap();
                fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
                assert!(!directory.join("sc-test").exists());
                assert_eq!(cleanup(&binary, &directory, "sc-test").is_ok(), accepted);
            }
            fs::remove_file(&binary).unwrap();
            fs::remove_dir(&directory).unwrap();
        }
    }
}
