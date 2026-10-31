"""Reproduce the bounded KB importer checks from the v0.3 review offline."""
from pathlib import Path
import importlib.util
import json
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sentrycheck_kb_updater", ROOT / "scripts/update_kb.py")
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)
source = (ROOT / "docs/evidence/release-amd64.txt").read_bytes()
prose = (ROOT / "docs/evidence/release-compatibility.txt").read_bytes()
constructors = (HERE / "gvisor-syscall-constructors.txt").read_bytes()
version = "20260921.0"
revision = "26f3455a4cb9a377354c33aeac049080a077c79c"


def build(table=source, docs=prose, helpers=constructors):
    return updater.build(version, revision, table, docs, "2026-09-26T00:00:00Z", helpers)


snapshot = build()
assert len(snapshot["entries"]) == 237
assert all(row["detail"] == "Fully Supported." for row in snapshot["syscall_support"] if row["status"] == "full")
cap_calls = re.findall(rb'\d+:\s*syscalls\.CapError\("(\w+)"', source)
cap_rows = [row for row in snapshot["syscall_support"] if "Granting the capability does not enable" in row["detail"]]
assert len(cap_rows) == len(cap_calls)
assert all(row["status"] == "unimplemented" and "EPERM without CAP_" in row["detail"] and "ENOSYS with" in row["detail"] for row in cap_rows)

mutations = {
    "changed_constructor_source": dict(helpers=constructors + b"\n"),
    "opposite_cgroup_claim": dict(docs=prose.replace(b"are not enforced", b"are enforced")),
    "unknown_supported_constructor": dict(table=source.replace(b"syscalls.SupportedPoint(", b"syscalls.SupportedSurprise(", 1)),
    "multiline_table_row": dict(table=source.replace(b'0:   syscalls.SupportedPoint("read"', b'0:\n            syscalls.SupportedPoint("read"', 1)),
}
rejections = {}
for name, kwargs in mutations.items():
    try:
        build(**kwargs)
    except ValueError as error:
        rejections[name] = str(error)
    else:
        raise AssertionError("unsafe importer change accepted: " + name)

result = {
    "source_revision": revision,
    "entries": len(snapshot["entries"]),
    "syscall_rows": len(snapshot["syscall_support"]),
    "capability_error_stubs": len(cap_rows),
    "full_rows": sum(row["status"] == "full" for row in snapshot["syscall_support"]),
    "rejections": rejections,
    "status": "passed",
}
(HERE / "kb-checks.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2))
