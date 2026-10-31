# Reproducing node overhead and the recorded runtime-drift demo

The existing `scripts/test-node-runtime-live.sh` still performs its real Kubernetes
checks: healthy gVisor canary, deliberately mismatched runc canary, missing runtime,
Warning event, health-label removal, strict denial, and recovery. It now has optional
resource sampling and actual-output recording hooks. Both are off by default.

This is a disposable, single-node Linux experiment. The script refuses an existing
K3s socket or its test bridge, starts its own K3s process/session, uses dedicated
service-account credentials, and retains its existing cleanup behavior. It does not
modify a public cluster. Run it in an isolated Linux environment with the already
installed K3s/gVisor binaries and built Go components. Do not run builds or other
benchmarks concurrently.

```sh
SENTRYCHECK_NODE_OUTPUT=/tmp/sentrycheck-node-evidence \
SENTRYCHECK_NODE_TEMP_BASE=/tmp/sentrycheck-node-work \
SENTRYCHECK_NODE_MEASURE=1 \
SENTRYCHECK_NODE_MEASURE_SECONDS=60 \
SENTRYCHECK_NODE_SAMPLE_SECONDS=0.2 \
SENTRYCHECK_NODE_PROBE_INTERVAL=5s \
SENTRYCHECK_NODE_RECORD=1 \
SENTRYCHECK_NODE_DEMO_PAUSE_SECONDS=5 \
bash scripts/test-node-runtime-live.sh
```

Use a **new output directory** for each experiment. The measurement and recorder
refuse existing output files/directories, so an older successful run cannot be
silently overwritten. The script's overall `summary.json` changes to running,
failed, or passed independently of the optional measurement summary.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SENTRYCHECK_NODE_OUTPUT` | `artifacts/node-runtime` | Retained logs, checks, recording, and measurement |
| `SENTRYCHECK_NODE_TEMP_BASE` | `/tmp` | Parent for the disposable K3s working directory |
| `SENTRYCHECK_NODE_MEASURE` | `0` | Set `1` to collect idle and active resource windows |
| `SENTRYCHECK_NODE_MEASURE_SECONDS` | `60` | Duration of **each** resource window |
| `SENTRYCHECK_NODE_SAMPLE_SECONDS` | `0.2` | Requested `/proc` polling interval |
| `SENTRYCHECK_NODE_PROBE_INTERVAL` | `5s` | Period of the repeated probe during measurement |
| `SENTRYCHECK_NODE_RECORD` | `0` | Set `1` to record actual output between demo markers |
| `SENTRYCHECK_NODE_DEMO_PAUSE_SECONDS` | `0` | Actual reading pause after the first three recorded phases |
| `SENTRYCHECK_NODE_K3S` / `RUNSC` / `ADMISSION` / `PROBE` | Existing project binary paths | Explicit executable overrides |

The last table row abbreviates four complete variable names:
`SENTRYCHECK_NODE_K3S`, `SENTRYCHECK_NODE_RUNSC`,
`SENTRYCHECK_NODE_ADMISSION`, and `SENTRYCHECK_NODE_PROBE`.

## Resource experiment

After the initial healthy canary and successful admission, the script invokes
`scripts/measure_node_probe.py`. That program:

1. Observes the idle dedicated K3s process tree/session for the requested duration.
2. Starts the actual periodic node probe with publication enabled.
3. Waits for a newly generated, healthy `canary-verified` report.
4. Observes K3s plus the probe and their descendants for the same duration.
5. Sends SIGTERM to the periodic probe and checks graceful exit before intentional
   runtime-mismatch testing begins.

The active window must observe at least two completed probe reports, all healthy.
An absent/partially written latest-report file is counted as unavailable at that
sample, not fabricated into a healthy or unhealthy state. A root process exiting
or a PID being reused invalidates the experiment. Interrupted or unhealthy runs
retain a failed status and their partial evidence.

Outputs live in `overhead/`: `idle.jsonl`, `active.jsonl`, `summary.json`,
`NODE-BENCHMARK.md`, the periodic probe's actual stdout/stderr, and its latest
report. The summary includes the benchmark script hash, executable hashes of the
root processes, PID/start-time identities, kernel/CPU/tick/page metadata, polling
intervals, observed probe states, raw-file hashes, and shutdown result.

CPU is the difference in each observed process's own `utime + stime` from
`/proc/PID/stat`. Parent `cutime/cstime` is excluded to avoid counting children
twice. `average_cores_observed` divides observed CPU seconds by wall seconds;
100% in `average_cpu_percent_one_core_observed` means one full CPU core, not the
entire machine. Process membership follows PPID descendants, dedicated root
sessions, and previously observed `(PID, starttime)` identities so ordinary
reparenting does not immediately erase observed children.

RSS is the **sum of per-process resident pages**, converted using the host page
size. Shared pages can be counted repeatedly. The time-weighted mean uses
trapezoidal integration between samples; the peak is only the peak among observed
samples. Neither value is unique physical memory, proportional set size, a cgroup
memory measurement, nor the node's total footprint.

These are partial observations with explicit limits:

- Children that start and exit between polls can be entirely missed. CPU between
  a child's last sample and its exit is also missed. This particularly affects
  short `crictl` invocations. Faster polling reduces this blind spot but increases
  the sampler's observer effect.
- Runtime helpers outside the dedicated process/session ancestry, kernel work,
  page cache, and unrelated services are outside the process accounting boundary.
- Active-minus-idle differences include ordinary K3s background activity,
  scheduling variation, and allocator/cache retention. Negative differences are
  retained. A single sequential pair is not a causal estimate of the probe alone.
- A five-second canary interval is an explicit stress/configuration choice; it
  must not be reported as the cost of the default sixty-second interval.
- Probe shutdown can cancel a new canary after the active window. Its resulting
  shutdown output is retained, but it is not counted as an in-window runtime
  incompatibility. A forced or unsuccessful shutdown fails the experiment.

For a stronger result, repeat multiple independent nodes/windows in counterbalanced
order, use the intended production poll interval, and add cgroup/PSS or whole-node
telemetry with an independently measured idle baseline. Do not turn these samples
into a billing estimate.

## Actual-output recording

`scripts/record_demo.py` wraps the real shell invocation and writes asciicast v2
and a timestamped JSONL stream. Cluster setup and the resource windows run before
the start marker. A **new healthy probe invocation** then starts the recorded
sequence, followed by the actual mismatch, missing-runtime denial, and recovery.
The recorder never replays a prior report to simulate a fresh command.

Files:

- `demo.cast`: playable timed terminal output, with LF converted to CRLF for display.
- `demo.events.jsonl`: original decoded output and observation timestamps.
- `demo.cast.metadata.json`: command, recorder hash, actual duration, event count,
  command exit code, completion state, and hashes of both recording files.

This captures combined stdout/stderr through a pipe; it is not a desktop screen
capture or a PTY emulator. A marker-delimited recording is valid only when the
wrapped command succeeds and the end marker is reached. Reading pauses are real
elapsed waits, recorded as such; they do not manufacture execution evidence. An
actual recording may be shorter or longer than ninety seconds. A video export
must preserve timing or clearly disclose cuts/speed changes and should retain the
original cast alongside it.

The demonstration deliberately requests a real **runc** canary while requiring a
gVisor runtime identity. It demonstrates detection of a real isolation mismatch
and runtime unavailability. It does **not** establish that standard Kubernetes
silently falls back to runc when a configured handler is missing; Kubernetes
normally reports handler/configuration failures explicitly. The observed mechanism
and the injected setup must remain clear in any poster or video description.
