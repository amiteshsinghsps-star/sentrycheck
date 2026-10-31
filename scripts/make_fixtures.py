"""Build tiny deterministic ELF/OCI fixtures and explicitly synthetic trace bundles.

These fixtures test analysis mechanics. They are not measurements of real runtimes.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile

def digest(data): return "sha256:" + hashlib.sha256(data).hexdigest()
def compact(value): return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()

def elf(code):
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, 0x400100, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0x400000, len(data) + len(code), len(data) + len(code), 0x1000)
    return bytes(data) + code

def layer(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.mode = 0o755 if data.startswith(b"\x7fELF") else 0o644
            info.size = len(data)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()

def oci(path, files, command=None):
    path.mkdir(parents=True, exist_ok=True)
    blobs = path / "blobs" / "sha256"
    blobs.mkdir(parents=True, exist_ok=True)
    def blob(data, media):
        identifier = digest(data)
        (blobs / identifier[7:]).write_bytes(data)
        return {"mediaType": media, "digest": identifier, "size": len(data)}
    raw = layer(files)
    compressed = gzip.compress(raw, mtime=0)
    layer_desc = blob(compressed, "application/vnd.oci.image.layer.v1.tar+gzip")
    config = {"architecture": "amd64", "os": "linux", "config": {"Entrypoint": command or ["/workload"], "Env": ["PATH=/usr/bin:/bin"], "WorkingDir": "/"}, "rootfs": {"type": "layers", "diff_ids": [digest(raw)]}}
    cfg = blob(compact(config), "application/vnd.oci.image.config.v1+json")
    manifest = blob(compact({"schemaVersion": 2, "config": cfg, "layers": [layer_desc]}), "application/vnd.oci.image.manifest.v1+json")
    manifest["platform"] = {"architecture": "amd64", "os": "linux"}
    (path / "index.json").write_bytes(compact({"schemaVersion": 2, "manifests": [manifest]}))
    (path / "oci-layout").write_bytes(compact({"imageLayoutVersion": "1.0.0"}))
    return manifest["digest"]

def profile():
    # Key order matches the Rust WorkloadProfile serialization used by profile_sha256.
    return {"name": "synthetic-io-uring", "description": "Synthetic parser/classifier fixture, never a live runtime measurement.",
            "command": ["/workload"], "env": [], "timeout_seconds": 5, "repetitions": 3, "expected_exit_code": 0,
            "compare_stdout": True, "compare_stderr": False, "timing_ratio": 2.0, "timing_min_native_ms": 100, "coverage": "representative"}

def evidence(path, image_digest, scenario):
    path.mkdir(parents=True, exist_ok=True)
    workload_profile = profile()
    bundle = {"schema_version": "1.0", "image_digest": image_digest, "target_runtime": {"name": "gvisor", "version": "20260921.0", "architecture": "amd64"}, "profile": workload_profile, "profile_sha256": digest(compact(workload_profile)), "native": [], "sandbox": []}
    for runtime in ["native", "sandbox"]:
        for index in range(3):
            sandbox = runtime == "sandbox"
            fail = sandbox and scenario == "hard-failure"
            native_trace = '1 io_uring_setup(8, {flags=0}) = 3\n1 write(1, "ok\\n", 3) = 3\n1 exit_group(0) = ?\n'
            guest_trace = 'I0926 00:00:00 strace.go:604] app X io_uring_setup(8, 0x0) = -1 errno=38 (function not implemented) (1us)\n'
            if not fail:
                guest_trace += 'I0926 00:00:00 strace.go:604] app X write(1, "ok\\n", 3) = 3 (0x3) (1us)\n'
            record = {"runtime": "gvisor" if sandbox else "runc", "runtime_version": "20260921.0" if sandbox else "runc version fixture",
                      "exit_code": 42 if fail else 0, "timed_out": False, "duration_ms": 350 if sandbox and scenario == "performance" else 100,
                      "trace_kind": "runsc-guest" if sandbox else "strace-guest"}
            streams = {"stdout": b"" if fail else b"different\n" if sandbox and scenario == "output-diff" else b"ok\n", "stderr": b"", "trace": (guest_trace if sandbox else native_trace).encode()}
            for stream, data in streams.items():
                name = f"{runtime}-{index}.{stream}"
                (path / name).write_bytes(data)
                record[stream] = name
                record[stream + "_sha256"] = digest(data)
            bundle[runtime].append(record)
    if scenario == "native-only":
        bundle["sandbox"] = []
    if scenario == "native-fails":
        for run in bundle["native"]:
            run["exit_code"] = 42
    (path / "evidence.json").write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path / "evidence.json"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("artifacts/fixtures"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    codes = {
        "io-uring": bytes.fromhex("b8a901000031ff31f60f05b83c00000031ff0f05"),
        "baseline": bytes.fromhex("b83c00000031ff0f05"),
        "embedded-opcode": bytes.fromhex("b80f050000b83c00000031ff0f05"),
        "unresolved": bytes.fromhex("4889f80f05b83c00000031ff0f05"),
        "bpf": bytes.fromhex("b84101000031ff31f631d20f05b83c00000031ff0f05"),
    }
    identities = {}
    for name, code in codes.items():
        binary = elf(code)
        (args.out / (name + ".elf")).write_bytes(binary)
        identities[name] = oci(args.out / name, {"workload": binary})
    for scenario in ["hard-failure", "fallback", "output-diff", "performance", "native-only", "native-fails"]:
        evidence(args.out / "traces" / scenario, identities["io-uring"], scenario)
    (args.out / "identities.json").write_text(json.dumps(identities, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("Created deterministic OCI/ELF and synthetic evidence fixtures in", args.out)

if __name__ == "__main__":
    main()
