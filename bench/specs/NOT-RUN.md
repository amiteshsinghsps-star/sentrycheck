# Unexecuted Suites Runbook: NOT-RUN.md

This document records benchmark suites that are registered in the SENTRYCHECK Master PRD (v2) but have no automated execution driver on this specific measurement host. Per PRD Principle 5, unexecuted suites are explicitly documented and accounted for rather than omitted.

## Summary of Deferred / Unexecuted Suites

| Suite ID | Description | Reason Deferred / Not Run | Prerequisite Environment |
|---|---|---|---|
| **BM-05** | Knowledge base correctness audit | Requires 200+ rule audit with upstream runtime test validation | Upstream source checkout, Linux host |
| **BM-06** | Fallback & tolerance behavior | Requires comparative matrix against secondary tools not installed | Linux host, multiple sandboxing tools |
| **BM-09** | Runtime overhead (native vs sandbox) | Requires bare-metal host with quiet CPU governor control (no KVM jitter) | Dedicated bare-metal hardware |
| **BM-10** | Kubernetes admission & controller | Requires live Kubernetes (k3s/kind v1.35+) cluster with mutating policies | Multi-node K8s cluster |
| **BM-11** | Viewer and report scale | Requires browser testing harness (Playwright/Puppeteer) on rendered UI | Headless Chromium / Web browser |
| **BM-12** | Human factors study | Human-subject user study requiring IRB approval and external participants | Recruited human evaluators |

## Detailed Breakdown

### BM-05: Knowledge Base Correctness
- **Objective:** Quantify false-positive/negative rules in `kb/snapshot.json` against gVisor/Kata release notes and upstream integration tests.
- **Why deferred:** Exhaustive audit of 200+ capability rules requires systematic cross-verification against upstream test suites across multiple releases.

### BM-06: Fallback and Tolerance Behavior
- **Objective:** Determine which probed syscall interfaces are non-fatal vs fatal when stubbed or denied.
- **Why deferred:** Requires multi-tool comparative harness with runtime fault injector.

### BM-09: Runtime Overhead
- **Objective:** Measure CPU, memory RSS, I/O throughput, and startup latency degradation under gVisor vs runc.
- **Why deferred:** Desktop virtualized host (WSL2) introduces scheduling and power-governor jitter violating PRD Principle 4 ("uncontrolled desktop host cannot make performance claims").

### BM-10: Kubernetes Admission Controller Latency & Correctness
- **Objective:** Measure ValidatingAdmissionPolicy / MutatingAdmissionPolicy evaluation latency and rejection accuracy under cluster load.
- **Why deferred:** Requires active Kubernetes cluster with CEL admission controller enabled.

### BM-11: Report Viewer Scale & Accessibility
- **Objective:** Validate DOM size, render time (<500ms p95), memory footprint, and WCAG 2.2 AA accessibility of the HTML report viewer.
- **Why deferred:** Requires browser automation framework and accessibility audit runner.

### BM-12: Human Factors & Usability
- **Objective:** Measure time-to-diagnosis, fix accuracy, and SUS (System Usability Scale) score among developers.
- **Why deferred:** Involves human participants and formal usability protocol.

