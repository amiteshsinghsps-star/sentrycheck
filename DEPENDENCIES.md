# Dependency decisions

The Rust core has no ELF-parser, ptrace-wrapper, async runtime, HTTP client, database, or CLI-parser dependency. It uses safe, bounded in-tree ELF parsing and a small documented profile format.

| Dependency | Why it is retained |
| --- | --- |
| `iced-x86` | Correct instruction boundaries and register-write metadata. Grepping bytes for `0f 05` misclassifies immediates/data; a complete x86 decoder is not a sensible in-tree reinvention. Only decoder and instruction-info features are enabled. |
| `serde`, `serde_json` | Mature typed JSON handling for untrusted OCI metadata, reports, and KB snapshots. Avoids hand-written Unicode/number/escaping parsers. |
| `sha2` | Standard SHA-256 for OCI manifests, compressed/uncompressed layers, profiles, reports, and traces. |
| `tar`, `flate2` | Bounded streaming tar/gzip parsing. Archive paths are validated in-tree, never blindly unpacked onto the host. |

`Cargo.lock` pins the complete graph. Dependency updates require build, malformed-input, OCI, and classifier regression tests.

The Go runtime integration uses the **standard library only**: Ed25519, TLS, HTTP, JSON, process management, and Kubernetes REST operations. `crictl` is an external administrator-installed prerequisite for node canaries. `runc`, `runsc`, `strace`, and `skopeo` are runtime/acquisition tools, not Rust wrapper crates. Python 3's standard library handles source-KB refresh, fixture creation, deployment rendering, and evaluation tooling.

Guest tracing is delegated to established tools instead of implementing ptrace in the analyzer. Native workloads run under in-container strace; runsc workloads use runsc guest strace, never host tracing of the runtime launcher.

The optional report viewer is authored in the separate `frontend/` Astro package. Its exact JavaScript dependency graph is pinned by `frontend/package-lock.json`. Astro and its build tools are contributor dependencies; the CLI embeds the prebuilt `frontend/template.html` and never invokes Node, npm, or a server. The page uses small inline vanilla JavaScript for local file loading, navigation, filtering, and charts. It has no external fonts, analytics, CDN assets, or network data requests. See [docs/REPORT-VIEWER.md](docs/REPORT-VIEWER.md) for rebuilding and offline verification.
