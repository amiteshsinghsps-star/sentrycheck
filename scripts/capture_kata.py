#!/usr/bin/env python3
"""Bounded external Kata/CRI guest-trace collector; never claims local provenance.

Requires an already configured, isolated CRI endpoint. Installs no runtime and
starts no cluster. Final evidence.json is written only after successful cleanup.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import time
import uuid

MAX_ARTIFACT = 32 * 1024 * 1024
COLLECTOR_ARTIFACT_LIMIT = 16 * 1024 * 1024
MAX_JSON = 128 * 1024 * 1024
MAX_COMMAND_OUTPUT = 4 * 1024 * 1024
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[a-f0-9]{64}\Z")
TOOLS_PATH = "/sentrycheck-collector-tools"
OUTPUT_PATH = "/sentrycheck-collector-output"
PROFILE_FIELDS = ("name", "description", "command", "env", "timeout_seconds", "repetitions", "expected_exit_code", "compare_stdout", "compare_stderr", "timing_ratio", "timing_min_native_ms", "coverage")


class CaptureError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CaptureError(message)


def now():
    return datetime.now(timezone.utc).isoformat()


def digest_bytes(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_runtime(path):
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= 512 * 1024 * 1024, "Runtime binary must be a regular file smaller than 512 MiB")
        value = hashlib.sha256()
        total = 0
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            total += len(block)
            require(total <= 512 * 1024 * 1024, "Runtime binary grew beyond the hash bound")
            value.update(block)
    return "sha256:" + value.hexdigest()


def enum_state(value, name, numeric):
    return value == name or type(value) is int and value == numeric


def read_regular(path, limit=MAX_ARTIFACT):
    """Refuse links/special files, including a raced final symlink."""
    path = Path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), f"Not a regular file: {path}")
        require(info.st_size <= limit, f"File exceeds {limit} bytes: {path}")
        data = stream.read(limit + 1)
        require(len(data) <= limit, f"File grew beyond limit: {path}")
        return data


def load_json(path, limit=MAX_JSON):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(read_regular(path, limit), object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(CaptureError(f"Invalid JSON number: {value}")))


def write_json(path, value):
    data = (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
    with open(path, "xb") as stream:
        stream.write(data)


def safe_source(root, reference):
    require(isinstance(reference, str) and "\x00" not in reference, "Invalid artifact reference")
    root = Path(root).resolve(strict=True)
    raw = Path(reference)
    candidate = raw if raw.is_absolute() else root / raw
    # Do not let resolve erase a symlink traversal before checking it.
    candidate = Path(os.path.abspath(candidate))
    require(candidate.is_relative_to(root), f"Artifact escapes the source root: {reference}")
    current = root
    for component in candidate.relative_to(root).parts:
        current = current / component
        require(not current.is_symlink(), f"Artifact traverses a symlink: {reference}")
    return candidate


def command(args, *, timeout=30, output_limit=MAX_COMMAND_OUTPUT):
    """Bound wall time and both pipes without accumulating arbitrary output."""
    import selectors
    process = subprocess.Popen([str(a) for a in args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector = selectors.DefaultSelector()
    for pipe, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ, name)
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            require(time.monotonic() < deadline, f"Command timed out: {args[0]}")
            for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                captured[key.data].extend(block)
                require(len(captured[key.data]) <= output_limit, f"Command output exceeded limit: {args[0]}")
        code = process.wait(timeout=max(.1, deadline - time.monotonic()))
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        selector.close()
        process.stdout.close()
        process.stderr.close()
    stdout, stderr = bytes(captured["stdout"]), bytes(captured["stderr"])
    require(code == 0, f"Command failed ({code}): {args[0]} {args[1:3]}: {stderr[-4096:].decode('utf-8', 'replace')}")
    return stdout


def static_elf(path, architecture):
    raw = read_regular(path)
    require(len(raw) >= 64 and raw[:4] == b"\x7fELF" and raw[4:6] == b"\x02\x01", "Trusted tools must be little-endian ELF64 binaries")
    machine = struct.unpack_from("<H", raw, 18)[0]
    require(machine == {"amd64": 62, "arm64": 183}[architecture], "Trusted tool architecture differs from the image")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    size, length = struct.unpack_from("<HH", raw, 54)
    require(size >= 56 and offset + size * length <= len(raw), "Invalid trusted-tool ELF program headers")
    for i in range(length):
        require(struct.unpack_from("<I", raw, offset + i * size)[0] != 3, "Trusted tracer and BusyBox must be static ELF binaries (no PT_INTERP)")
    return raw


def validate_native(report, image_ref):
    require(isinstance(report, dict) and report.get("schema_version") == "1.0", "Expected a SENTRYCHECK report")
    digest = report.get("image_digest")
    require(isinstance(digest, str) and DIGEST.fullmatch(digest), "Native report needs an OCI manifest digest")
    require(re.fullmatch(r"[A-Za-z0-9][^@\s]*@sha256:[0-9a-f]{64}", image_ref) and image_ref.endswith("@" + digest), "CRI image must be name@exact-native-report-manifest-digest")
    dynamic = report.get("dynamic")
    require(isinstance(dynamic, dict), "Native report has no dynamic evidence")
    profile = dynamic.get("profile")
    require(isinstance(profile, dict) and set(profile) == set(PROFILE_FIELDS), "Native report must contain the full canonical profile")
    require(isinstance(profile["repetitions"], int) and 1 <= profile["repetitions"] <= 20, "Invalid repetitions")
    require(isinstance(profile["timeout_seconds"], int) and 1 <= profile["timeout_seconds"] <= 3600, "Invalid profile timeout")
    require(isinstance(dynamic.get("profile_sha256"), str) and DIGEST.fullmatch(dynamic["profile_sha256"]), "Native report has no valid profile hash")
    runs = dynamic.get("native")
    require(isinstance(runs, list) and len(runs) == profile["repetitions"], "Native repetition count differs from profile")
    for run in runs:
        require(run.get("runtime") == "runc" and run.get("trace_kind") == "strace-guest", "Native evidence must be guest strace under runc")
        require(run.get("infrastructure_error") is None and run.get("timed_out") is False, "Native observation is incomplete")
        require(run.get("exit_code") == profile["expected_exit_code"], "The saved native profile must pass before a Kata comparison")
        summary = run.get("trace_summary", {})
        require(not summary.get("truncated") and not summary.get("discarded_guest_records") and not summary.get("unfinished_count"), "Native trace is incomplete")
    architecture = report.get("target_runtime", {}).get("architecture")
    require(architecture in ("amd64", "arm64"), "Unsupported native architecture")
    return profile, runs, architecture


def image_configuration(inspection, image_ref, architecture):
    require(isinstance(inspection, dict), "Invalid CRI image inspection")
    status, info = inspection.get("status", {}), inspection.get("info", {})
    require(image_ref in status.get("repoDigests", []), "CRI did not expose the requested immutable image digest")
    spec = info.get("imageSpec")
    require(isinstance(spec, dict) and spec.get("architecture") == architecture and spec.get("os") == "linux", "CRI imageSpec must establish linux and the expected architecture")
    config = spec.get("config")
    require(isinstance(config, dict), "CRI image configuration is unavailable")
    for key in ("Entrypoint", "Cmd", "Env"):
        value = config.get(key, [])
        require(value is None or isinstance(value, list) and all(isinstance(x, str) and "\x00" not in x for x in value), f"Invalid image {key}")
    for key in ("User", "WorkingDir"):
        require(isinstance(config.get(key, ""), str) and "\x00" not in config.get(key, ""), f"Invalid image {key}")
    cwd = config.get("WorkingDir") or "/"
    require(cwd.startswith("/"), "Image working directory must be absolute")
    require(isinstance(status.get("id"), str) and DIGEST.fullmatch(status["id"]), "CRI image config digest is unavailable")
    return config, status["id"]


def sandbox_identity(inspection, sandbox_id, runtime_type, token):
    status = inspection.get("status", {})
    require(status.get("id") == sandbox_id, "CRI sandbox inspection ID mismatch")
    require(enum_state(status.get("state"), "SANDBOX_READY", 0), "CRI sandbox is not ready")
    require(status.get("metadata", {}).get("uid") == token, "CRI sandbox UID mismatch")
    require(inspection.get("info", {}).get("runtimeType") == runtime_type, "CRI sandbox runtimeType mismatch or unavailable")


def container_identity(inspection, container_id, image_ref, image_id, token):
    status = inspection.get("status", {})
    require(status.get("id") == container_id, "CRI container inspection ID mismatch")
    require(status.get("labels", {}).get("sentrycheck.io/collector-id") == token, "CRI container label mismatch")
    require(status.get("image", {}).get("image") == image_ref, "CRI container image reference differs from pinned request")
    require(status.get("imageRef") in (image_ref, image_ref.split("@", 1)[1], image_id), "CRI resolved a different image identity")
    return status


class CRI:
    def __init__(self, executable, endpoint):
        self.base = [executable, "--runtime-endpoint", endpoint, "--image-endpoint", endpoint]

    def call(self, *args, timeout=35):
        return command(self.base + ["--timeout", f"{max(1, int(timeout))}s"] + list(args), timeout=timeout)

    def json(self, *args, timeout=35):
        return json.loads(self.call(*args, timeout=timeout))


def owned_id(raw):
    identifier = raw.decode("ascii").strip()
    require(IDENTIFIER.fullmatch(identifier), "CRI returned a noncanonical container/sandbox ID")
    return identifier


def cleanup(cri, container_id, sandbox_id):
    """Never use broad list-and-delete operations or names supplied by a guest."""
    errors = []
    def absent(verb, identifier, key):
        extra = ["--all"] if verb == "ps" else []
        result = cri.json(verb, *extra, "--id", identifier, "-o", "json", timeout=10)
        require(isinstance(result.get(key), list) and all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in result[key]), "CRI absence check returned an invalid collection")
        return not any(item.get("id") == identifier for item in result[key])
    if container_id:
        try:
            cri.call("stop", "--timeout", "5", container_id, timeout=15)
        except CaptureError as exc:
            errors.append(str(exc))
        try:
            cri.call("rm", "--force", container_id, timeout=20)
            # A stop error is harmless only if exact-ID removal succeeded.
            errors.clear()
        except CaptureError as exc:
            if absent("ps", container_id, "containers"):
                errors.clear()
            else:
                errors.append(str(exc))
    if sandbox_id:
        pod_errors = []
        try:
            cri.call("stopp", sandbox_id, timeout=20)
        except CaptureError as exc:
            pod_errors.append(str(exc))
        try:
            cri.call("rmp", "--force", sandbox_id, timeout=20)
        except CaptureError as exc:
            if not absent("pods", sandbox_id, "items"):
                pod_errors.append(str(exc))
            else:
                pod_errors.clear()
        else:
            pod_errors.clear()
        errors.extend(pod_errors)
    require(not errors, "Cleanup failed; resources preserved and no evidence bundle published: " + " | ".join(errors))


def copy_native(runs, source_root, output):
    result = []
    for index, run in enumerate(runs):
        record = {key: run[key] for key in ("runtime", "runtime_version", "exit_code", "timed_out", "duration_ms", "trace_kind")}
        for kind in ("stdout", "stderr", "trace"):
            data = read_regular(safe_source(source_root, run[kind + "_ref"]))
            require(digest_bytes(data) == run[kind + "_sha256"], f"Native {kind} hash mismatch")
            name = f"native-{index}.{kind}"
            (output / name).write_bytes(data)
            record[kind], record[kind + "_sha256"] = name, digest_bytes(data)
        result.append(record)
    return result


def env_values(config, profile):
    values = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    for item in (config.get("Env") or []) + profile["env"]:
        require("=" in item and not item.startswith("="), "Environment must contain NAME=value")
        name, value = item.split("=", 1)
        values[name] = value
    return [{"key": key, "value": value} for key, value in sorted(values.items())]


def run_once(args, cri, root, index, profile, config, image_id, runtime_type):
    token = str(uuid.uuid4())
    directory = root / f"kata-{index}"
    directory.mkdir(mode=0o700)
    output = directory / "guest-output"
    output.mkdir(mode=0o777)
    logs = directory / "cri-logs"
    logs.mkdir()
    # Three artifact files share a hard 96 MiB filesystem bound. This is
    # independent of the guest shell's file-size limit and polling latency.
    command(["mount", "-t", "tmpfs", "-o", "size=96m,mode=0777,nosuid,nodev,noexec", "sentrycheck-kata-output", output])
    sandbox_id = container_id = None
    safe_to_read = False
    inspection = None
    timed_out = False
    began = None
    try:
        pod = {"metadata": {"name": "sentrycheck-kata-" + token, "namespace": "sentrycheck-collector", "uid": token, "attempt": 0}, "logDirectory": str(logs), "linux": {"securityContext": {"privileged": False, "namespaceOptions": {"network": 0, "pid": 0, "ipc": 0}}}}
        workload = profile["command"] or (config.get("Entrypoint") or []) + (config.get("Cmd") or [])
        require(workload and workload[0], "Neither profile nor image defines a workload command")
        container = {"metadata": {"name": "workload", "attempt": 0}, "image": {"image": args.image}, "command": [TOOLS_PATH + "/busybox", "sh", TOOLS_PATH + "/launch.sh"], "args": workload, "workingDir": config.get("WorkingDir") or "/", "envs": env_values(config, profile), "labels": {"sentrycheck.io/collector-id": token}, "logPath": "launcher.log", "stdin": False, "tty": False, "mounts": [{"containerPath": TOOLS_PATH, "hostPath": str(root / "tools"), "readonly": True, "propagation": 0}, {"containerPath": OUTPUT_PATH, "hostPath": str(output), "readonly": False, "propagation": 0}], "linux": {"securityContext": {"privileged": False, "noNewPrivs": True, "capabilities": {"dropCapabilities": ["ALL"]}, "seccomp": {"profileType": 1}}}}
        write_json(directory / "pod.json", pod)
        write_json(directory / "container.json", container)
        sandbox_id = owned_id(cri.call("runp", "--runtime", args.handler, directory / "pod.json", timeout=args.startup_timeout))
        sandbox = cri.json("inspectp", "-o", "json", sandbox_id)
        write_json(directory / "sandbox-inspection.json", sandbox)
        sandbox_identity(sandbox, sandbox_id, runtime_type, token)
        container_id = owned_id(cri.call("create", sandbox_id, directory / "container.json", directory / "pod.json"))
        inspection = cri.json("inspect", "-o", "json", container_id)
        container_identity(inspection, container_id, args.image, image_id, token)
        began = time.monotonic()
        cri.call("start", container_id, timeout=min(35, profile["timeout_seconds"] + 5))
        deadline = began + profile["timeout_seconds"]
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            inspection = cri.json("inspect", "-o", "json", container_id, timeout=min(10, remaining + 1))
            status = container_identity(inspection, container_id, args.image, image_id, token)
            for kind in ("stdout", "stderr", "trace"):
                path = output / kind
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    continue
                require(stat.S_ISREG(info.st_mode) and info.st_size < COLLECTOR_ARTIFACT_LIMIT, f"Guest {kind} artifact is unsafe or reached the 16 MiB collector limit")
            require(os.statvfs(output).f_bavail > 0, "Guest output filesystem is full; instrumentation failure is not a workload verdict")
            if enum_state(status.get("state"), "CONTAINER_EXITED", 2):
                break
            require(enum_state(status.get("state"), "CONTAINER_RUNNING", 1), "Container left running state without an exit observation")
            time.sleep(min(.1, max(0, deadline - time.monotonic())))
        duration_ms = int((time.monotonic() - began) * 1000)
        write_json(directory / "container-inspection.json", inspection)
    finally:
        # A failed cleanup aborts before guest-controlled files are opened or
        # the output filesystem is unmounted. Exact IDs remain in this ledger.
        try:
            write_json(directory / "owned-resources.json", {"sandbox_id": sandbox_id, "container_id": container_id, "token": token})
        finally:
            # Disk/ledger failure must not skip stopping an already-started VM.
            cleanup(cri, container_id, sandbox_id)
            safe_to_read = True
            if began is None or sys.exc_info()[0] is not None:
                command(["umount", output])
    try:
        require(safe_to_read and inspection is not None, "No trustworthy completed observation")
        record = {"runtime": "kata", "runtime_version": args.kata_version, "exit_code": None if timed_out else inspection["status"].get("exitCode"), "timed_out": timed_out, "duration_ms": duration_ms, "trace_kind": "strace-guest"}
        require(timed_out or type(record["exit_code"]) is int and 0 <= record["exit_code"] <= 255, "CRI did not report a valid workload exit status")
        require(record["exit_code"] != 153, "SIGXFSZ/file-limit exit is instrumentation-incomplete, not Kata incompatibility")
        for kind in ("stdout", "stderr", "trace"):
            data = read_regular(output / kind)
            require(len(data) < COLLECTOR_ARTIFACT_LIMIT, "Captured output reached the collector limit")
            require(kind != "trace" or data.strip(), "Guest strace is empty; launcher failure cannot become a comparison")
            destination = root / f"kata-{index}.{kind}"
            destination.write_bytes(data)
            record[kind], record[kind + "_sha256"] = destination.name, digest_bytes(data)
        return record
    finally:
        if safe_to_read and began is not None:
            command(["umount", output])


def capture(args):
    require(sys.platform == "linux" and os.geteuid() == 0, "Collector requires a dedicated rootful Linux CRI runner and bounded tmpfs mounts")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args.handler), "Invalid CRI handler")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", args.kata_version), "Pin an explicit Kata release version")
    require(args.endpoint.startswith("unix:///") and "\x00" not in args.endpoint, "Use an explicit local Unix CRI endpoint")
    binary = Path(args.runtime_binary).resolve(strict=True)
    require(binary.name == "containerd-shim-kata-v2", "Select the actual Kata shim binary")
    # Absolute runtime_type is the auditable link from CRI identity to the
    # exact version-checked binary; named PATH resolution is not guessed.
    runtime_type = args.runtime_type or str(binary)
    require(runtime_type == str(binary), "Prototype requires an absolute runtime_type identical to --runtime-binary")
    version_output = command([binary, "--version"], output_limit=16384).decode("utf-8", "replace")
    require(re.search(r"(?<![0-9.])v?" + re.escape(args.kata_version) + r"(?![0-9A-Za-z.+-])", version_output), "Kata shim version differs from target")
    native_file = Path(args.native_report).resolve(strict=True)
    report = load_json(native_file)
    profile, native_runs, architecture = validate_native(report, args.image)
    # Delegate full model consistency, canonical Rust profile serialization,
    # and re-parsed trace/artifact validation to the existing trusted CLI.
    command([args.sentrycheck, "report", "validate", native_file, "--artifacts-root", Path(args.native_artifacts_root).resolve(strict=True), "--format", "json"], timeout=120)
    cri = CRI(args.crictl, args.endpoint)
    image = cri.json("inspecti", "-o", "json", args.image)
    config, image_id = image_configuration(image, args.image, architecture)
    tools = {"strace": static_elf(args.strace, architecture), "busybox": static_elf(args.busybox, architecture)}
    root = Path(args.output).absolute()
    require(not root.exists() and not root.is_symlink(), "Output directory must not already exist")
    require(root.parent.resolve(strict=True) == root.parent, "Output parent must be canonical and not traverse symlinks")
    root.mkdir(mode=0o700)
    ledger = {"schema_version": "1.0", "status": "running", "started_at": now(), "provenance": "external-cri-collector; imported-user-supplied", "image": args.image, "source_native_report": str(native_file), "source_native_report_sha256": digest_bytes(read_regular(native_file, MAX_JSON)), "native_scanned_at": report.get("scanned_at"), "profile_sha256": report["dynamic"]["profile_sha256"], "target_runtime": {"name": "kata", "version": args.kata_version, "architecture": architecture}, "runtime_binary": str(binary), "runtime_binary_sha256": hash_runtime(binary), "runtime_binary_version": version_output, "runtime_type": runtime_type, "handler": args.handler, "endpoint": args.endpoint, "trusted_tool_hashes": {name: digest_bytes(data) for name, data in tools.items()}, "limits": ["Saved native runs are reused, not rerun concurrently.", "CRI networking/resources may differ from the native OCI runner; use an isolated test cluster.", "Guest can modify its writable trace/output mount; this is not tamper-proof attestation.", "Kata artifacts must remain below 16 MiB each; a separate 96 MiB tmpfs bounds all guest output per observation.", "Kata release coverage in the knowledge base remains experimental/uncovered."]}
    write_json(root / "collector-start.json", ledger)
    try:
        write_json(root / "image-inspection.json", image)
        directory = root / "tools"
        directory.mkdir(mode=0o755)
        for name, data in tools.items():
            (directory / name).write_bytes(data)
            (directory / name).chmod(0o555)
        # Fixed source code; workload strings are passed as positional args.
        launcher = '#!/bin/sh\nset -eu\nulimit -f 32768\nexec ' + TOOLS_PATH + '/strace -f -qq -s 256 -o ' + OUTPUT_PATH + '/trace -- "$@" >' + OUTPUT_PATH + '/stdout 2>' + OUTPUT_PATH + '/stderr\n'
        (directory / "launch.sh").write_text(launcher)
        (directory / "launch.sh").chmod(0o444)
        native = copy_native(native_runs, args.native_artifacts_root, root)
        sandbox = [run_once(args, cri, root, index, profile, config, image_id, runtime_type) for index in range(profile["repetitions"])]
        bundle = {"schema_version": "1.0", "image_digest": report["image_digest"], "target_runtime": ledger["target_runtime"], "profile": {key: profile[key] for key in PROFILE_FIELDS}, "profile_sha256": report["dynamic"]["profile_sha256"], "native": native, "sandbox": sandbox}
        encoded = (json.dumps(bundle, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode()
        require(len(encoded) <= 1024 * 1024, "Evidence manifest exceeds importer bound")
        pending = root / "evidence.pending.json"
        with open(pending, "xb") as stream:
            stream.write(encoded)
        os.replace(pending, root / "evidence.json")
        ledger.update(status="captured", completed_at=now(), evidence_sha256=digest_bytes(read_regular(root / "evidence.json")))
        write_json(root / "collector-result.json", ledger)
        return root / "evidence.json"
    except BaseException as exc:
        ledger.update(status="failed", completed_at=now(), error=str(exc))
        write_json(root / ("collector-failure.json" if (root / "collector-result.json").exists() else "collector-result.json"), ledger)
        raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-report", required=True, help="Existing native/gVisor JSON report with passing native observations")
    parser.add_argument("--native-artifacts-root", required=True, help="Exact allowed root for existing report artifacts")
    parser.add_argument("--image", required=True, help="Already present CRI image: repository@sha256:manifest")
    parser.add_argument("--kata-version", required=True)
    parser.add_argument("--runtime-binary", required=True, help="Actual containerd-shim-kata-v2 binary")
    parser.add_argument("--runtime-type", help="Absolute CRI runtimeType; must equal the resolved runtime-binary path")
    parser.add_argument("--handler", required=True, help="Already configured Kata CRI runtime handler")
    parser.add_argument("--endpoint", required=True, help="Explicit unix:///path/to/containerd.sock")
    parser.add_argument("--crictl", default="crictl")
    parser.add_argument("--sentrycheck", default="sentrycheck")
    parser.add_argument("--strace", required=True, help="Trusted static guest strace binary")
    parser.add_argument("--busybox", required=True, help="Trusted static BusyBox used only for fixed launcher/redirection")
    parser.add_argument("--output", required=True, help="New directory; use RAM-backed scratch if host disk is constrained")
    parser.add_argument("--startup-timeout", type=int, default=120)
    args = parser.parse_args(argv)
    parser.error("startup timeout must be 1..300 seconds") if not 1 <= args.startup_timeout <= 300 else None
    return args


if __name__ == "__main__":
    try:
        print(capture(parse_args()))
    except (CaptureError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"Kata capture incomplete: {exc}", file=sys.stderr)
        sys.exit(2)
