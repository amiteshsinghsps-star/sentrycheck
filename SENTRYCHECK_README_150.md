# SENTRYCHECK

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust: 1.82+](https://img.shields.io/badge/Rust-1.82%2B-orange.svg)](Cargo.toml)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](bench/)
[![Go: 1.23+](https://img.shields.io/badge/Go-1.23%2B-cyan.svg)](integration/)
[![Analysis Plan: Frozen](https://img.shields.io/badge/Analysis%20Plan-Frozen%20%E2%9C%93-brightgreen.svg)](bench/analysis/preregistration.json)

> **Evidence-graded container compatibility analysis and empirical pilot evaluation for gVisor and Kata Containers, with Kubernetes admission enforcement.**

SENTRYCHECK assesses application compatibility with restricted container runtimes. Rather than relying on simple static syscall lookups, SENTRYCHECK structures findings through a **claims ladder** with multi-tier evidence grading, empirical baselines, and a reproducible benchmark harness (`bench/`).

---

## 1. Pilot Evaluation: Results at a Glance

All metrics are computed by `bench analyze` under a frozen analysis plan (`bench/analysis/preregistration.json`) on an author-selected corpus ($n=9$ cases).

### Compatibility Accuracy (BM-01 Pilot Sweep)

| Classifier / Arm | Correct Cases | Point Est. | Wilson 95% CI | Discordant Pairs $(b, c)$ | Exact McNemar ($p$-value) | Holm-Adjusted $p$ | Significance ($\alpha = 0.05$) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **SENTRYCHECK (Dynamic Diff)** | **8 / 9** | **0.889** | **[0.565 .. 0.980]** | — | — | — | — |
| **B0: Naive Syscall Table** | 3 / 9 | 0.333 | [0.121 .. 0.646] | $(5, 0)$ | $p = 0.0625$ | $p = 0.1875$ | Not significant |
| **B3: Confine-Style Re-impl.** | 2 / 9 | 0.222 | [0.063 .. 0.547] | $(6, 0)$ | $p = 0.03125$ | $p = 0.1250$ | Not significant |
| **B5: Just-Run (Blind Trial)** | 3 / 9 | 0.333 | [0.121 .. 0.646] | $(5, 0)$ | $p = 0.0625$ | $p = 0.1875$ | Not significant |

### Methodological Limits
- **Sample Size ($n=9$):** Initial pilot only. Wilson score confidence intervals are broad ($0.57$ to $0.98$), and McNemar tests lack statistical power. After Holm step-down correction across the family of tests, **no baseline comparison achieves statistical significance** at $\alpha = 0.05$.
- **Corpus Tuning:** The 9 cases were curated and observed during scanner prototyping. The only held-out split case is `postgres-18-io-uring`. Reported accuracy reflects development/validation performance, not a blind third-party benchmark.
- **Baseline Implementations:** B0, B3, and B5 are author-written reference models (B3 re-implements Confine-style reachability without dynamic diffing).
- **Environment:** Executed under WSL2 (Ubuntu 24.04 on Windows 11) with an unmanaged CPU frequency governor (`null`), introducing virtualization jitter.
- **Integrity vs Correctness:** The 59 recorded runs and 1,731 hashed artifacts confirm content-addressed store reproducibility, not oracle correctness.

```bash
# Reproduce analysis tables and verify artifact integrity
python -m bench analyze
python -m bench verify --all --prereg
```

---

## 2. Benchmark Suites Summary

The 14 benchmark suites defined in the Master PRD are accounted for below:

| Suite ID | Suite Title | Focus Area | Status / Pilot Findings |
|---|---|---|---|
| **BM-01** | Compatibility Matrix | Dynamic diff vs ground truth | 8/9 accuracy (Wilson CI: 0.57..0.98) |
| **BM-02** | Static Extraction Accuracy | 11 ELF binaries / OCI layouts | Quantifies the static-dynamic gap |
| **BM-03** | Dynamic Fidelity & Perturbation | 48 mutant traces | 0 silent accepts (PID bounded $\le 4{,}194{,}304$) |
| **BM-04** | Static-versus-Dynamic Ablation | ABBA interleaving (36 runs) | Static-only produces no verdict by design (exit 2, indeterminate); dynamic 8/9 |
| **BM-07** | Adversarial Robustness | 24 malformed OCI/tar inputs | 100% fail-closed, memory strictly bounded ($<128\text{ MB}$ RSS) |
| **BM-08** | Performance & Cache Ladders | 4 targets (0MB to 58.5MB) | Cold vs warm scan speedups of 1.64x to 2.79x |
| **BM-13** | Provenance & Rebuild | Windows & WSL2 cross-rebuild | Bit-identical CSV and SVG generation across interpreters |
| **BM-14** | Replicated Scans | Duplicate live runs | 7/7 cases stable (14 runs, one host, Wilson 95% CI 0.65 to 1.00) |
| **BM-05** | KB Correctness Audit | Upstream gVisor rule audit | *Deferred* (requires 200+ rule upstream audit; see `NOT-RUN.md`) |
| **BM-06** | Fallback & Tolerance Behavior | Probed syscall tolerance | *Deferred* (requires multi-tool fault injector; see `NOT-RUN.md`) |
| **BM-09** | Runtime Overhead | Native vs sandbox benchmarks | *Deferred* (requires bare-metal host with quiet cpufreq governor) |
| **BM-10** | Kubernetes Admission Load | Controller latency & admission | *Deferred* (requires multi-node K8s cluster with CEL) |
| **BM-11** | Viewer Scale & Accessibility | HTML report DOM scaling & WCAG | *Deferred* (requires headless browser testing harness) |
| **BM-12** | Human Factors Study | Developer time-to-diagnosis | *Deferred* (requires IRB protocol and human participants) |

---

## 3. Evidence Tiers & Severity Hierarchy

Static presence indicates an **unconfirmed capability candidate**, never an automatic failure.

```
Evidence Claims Ladder:
  L0: Single observation  ──►  L1: Synthetic fixture  ──►  L2: Labeled real case (single host)
  L3: Held-out labeled set (with CIs)  ──►  L4: Multi-host replication  ──►  L5: 3rd-party replication
```

**Severity Classes (First Match Wins):**
1. `hard-failure`: Process terminated unexpectedly or returned fatal runtime error.
2. `silent-degradation`: Process exited 0, but stdout/stderr diverged from native reference.
3. `performance-regression`: Execution completed with substantial degradation ($>5\times$ slowdown).
4. `tolerated`: Probed interface denied or stubbed, but handled gracefully via fallback.
5. `compatible`: Full dynamic scan completed with matching exit codes and outputs.
6. `indeterminate`: Incomplete scan, static-only analysis, or stale knowledge base ($>30$ days).

---

## 4. Architecture & Workflows

```
┌────────────────────────────────────────────────────────────────────────┐
│                          SENTRYCHECK SYSTEM                            │
├───────────────────────────────┬────────────────────────────────────────┤
│ Rust Analyzer (sentrycheck)   │  • ELF disassembly & static scan       │
│                               │  • OCI layout extraction & diffing     │
│                               │  • Dynamic strace / runsc trace diff   │
├───────────────────────────────┼────────────────────────────────────────┤
│ Python Harness (bench)        │  • BM-01..14 execution drivers         │
│                               │  • Content-addressed artifact store    │
│                               │  • Frozen plan verification & HTML dash│
├───────────────────────────────┼────────────────────────────────────────┤
│ Go Admission & Probe          │  • Kubernetes ValidatingAdmissionPolicy│
│                               │  • Ed25519 signed CI report validation │
│                               │  • Node CRI runtime canary probe       │
└───────────────────────────────┴────────────────────────────────────────┘
```

### Quickstart & Commands
```bash
# 1. Build Rust scanner and Go admission tools
cargo build --release
cd integration && go build -o ../bin/sentrycheck-admission ./cmd/sentrycheck-admission && cd ..

# 2. Scanning (Static analysis works cross-platform; live execution requires Linux runc/runsc)
target/release/sentrycheck scan ./image-oci --profile profiles/python.toml --output report.json
target/release/sentrycheck ci-gate ./image-oci --profile profiles/node.toml --fail-on hard-failure
target/release/sentrycheck report render report.json --output report.html

# 3. Benchmark operations via CLI bridge
sentrycheck bench estimate          # Pre-flight time/disk budget
sentrycheck bench suite BM-01       # Live compatibility sweep
sentrycheck bench dashboard         # Generate standalone HTML dashboard
sentrycheck bench verify --all      # Recompute artifact hashes
```

---

## 5. Kubernetes Admission & Policy Enforcement

SENTRYCHECK admission blocks pods requesting gVisor/Kata if:
- Required Ed25519-signed CI report is missing or invalid.
- Stored report contains a `hard-failure` for the deployed image digest.
- Node canary probe (`sentrycheck-node-probe`) detects runtime health divergence.

---

## 6. Repository Hygiene & Governance

- **Artifact Storage:** Third-party container layers and heavy raw traces ($>10\text{ MB}$) are excluded from git via `.gitignore` to prevent clone bloat; cryptographic digests remain tracked in `run.json` and `index.json`.
- **Governance:** Case submissions must declare an explicit open-source license, define expected interfaces, and cannot self-assign to the frozen `test` split (`sentrycheck bench cases validate-submission --file case.json`).

---

## 7. License & Citation

Licensed under Apache-2.0 or MIT. When citing:
```bibtex
@software{sentrycheck2026,
  author = {Singh, Amitesh},
  title = {SENTRYCHECK: Evidence-Graded Container Sandbox Compatibility and Empirical Benchmarking},
  year = {2026},
  version = {0.5.0},
  url = {https://github.com/example/sentrycheck}
}
```

