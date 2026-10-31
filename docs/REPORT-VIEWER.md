# Offline report explorer

SENTRYCHECK 0.4 adds an Astro frontend for saved JSON reports and SENTRYCHECK SARIF 2.1.0 exports. It is a generated HTML file, with inline styles, scripts, report data, and optional knowledge-base data. Open it directly from disk. There is no application server, account, telemetry, CDN, or background network request.

## Generate a report

```sh
sentrycheck report render report.json --output report.html
sentrycheck report render report.json --output ./report-site
sentrycheck report render report.sarif --output sarif.html
sentrycheck report render report.json --kb ./snapshot.json --output report.html --force
```

An `.html` or `.htm` destination creates that file. A directory destination creates `index.html` inside it and preserves other files. Existing output requires `--force`. Report and KB inputs cannot be overwritten, and output symlinks are refused.

Rendering exits **0 when the HTML export succeeds**, including when the report describes a failed or incomplete scan. Invalid input, contradictory report evidence, mismatched explicit KB snapshots, and output errors exit **2**. Use `scan` or `ci-gate` for compatibility gating; successful rendering is not a clean compatibility verdict.

The native report undergoes the same semantic checks as `report validate`. Rendering does not read referenced trace artifacts, verify signatures, launch workloads, or refresh the scan timestamp. The generation time and original scan time are separate. The embedded input hash identifies the supplied file bytes; it does not authenticate the producer.

The bundled KB is attached only when its snapshot identifier, runtime release, and architecture match the report. `--kb` validates an explicit snapshot and rejects a mismatch. When no matching bundled snapshot exists, the report's citations remain available and the viewer explains why a full KB was not attached. Matching identifiers do not authenticate a KB or retroactively bind its content to an old report.

## Explore the evidence

The viewer has four local views, connected through fragment navigation so links work under `file://` without a server:

- **Overview:** scan identity, declared assessment, evidence level, observed findings, unconfirmed static candidates, profile coverage, and visible limitations.
- **Findings:** search and severity filtering, plus individual detail views containing dynamic/static evidence, source binary, trace/profile hashes, causal limitations, citations, and available source revisions.
- **Knowledge base:** searchable cited gaps with release/architecture context. Static candidates remain distinct from observed incompatibilities.
- **Trace timeline:** ordered native/sandbox observations with per-run counts for diagnostics, discarded records, unfinished calls, and parsed events. This is an observation sequence, not a timestamped event trace; the report does not store the time of each diagnostic line. Missing counters in older reports are shown as unavailable.

Evidence color identifies the collection method; it is not a substitute for severity or a claim that stronger evidence always means a worse outcome. Empty findings in an incomplete report do not mean compatibility. Node-isolation checks remain separate from workload execution evidence.

Use **Open report** or drag a local `.json`/`.sarif` file into the page. This reads the file in your browser without uploading it. Browser imports receive structural checks only, and do not inherit a prior CLI validation label. For full consistency checking, generate a fresh HTML export with the CLI. Large collections use bounded pages; raw syscall events are not all expanded into the DOM.

SARIF is a reduced view. It preserves exported findings, classification, citations, and scan metadata, but older exports may omit source revisions and all exports omit full static-site and per-run trace summaries. Missing data is labeled unavailable. The viewer never fabricates a trace timeline or compatibility verdict to fill those gaps. The CLI accepts one SENTRYCHECK SARIF run, checks its classification/status consistency, and does not claim full report validation for that reduced format.

## Develop the Astro frontend

```sh
cd frontend
npm ci
npm run dev
# Production build, including the self-contained CLI template:
npm run build
cd ..
cargo build --locked
```

Use Node 22.12 or newer compatible with the pinned Astro release; development here uses Node 24.11.0. Astro and its lockfile live in `frontend/`, separate from Rust and Go dependencies. The contributor build generates `frontend/dist/index.html` and the tracked `frontend/template.html`. Cargo embeds that template at compile time, so normal CLI builds and users do not need npm or Node.

`npm run dev` binds to localhost and enables Astro's development reload connection. The strict offline content-security policy is applied to production builds and CLI exports; it is omitted during development so Astro can reload changes.

The unpopulated frontend opens an explicitly labeled illustrative demo. CLI-generated pages use their embedded report. A malformed embedded report produces an error, never a silent switch to demo evidence. JavaScript is required for exploration and local file loading; the page contains a `noscript` explanation.

Run the CLI export tests and browser checks after rebuilding:

```sh
python -m unittest discover -s tests -p test_render.py -v
python -m pip install playwright==1.62.0
python scripts/test_viewer.py --artifacts artifacts/viewer-validation
```

The browser checks use an installed Chrome, Chromium, or Edge executable and never download a browser. Supply `--browser /path/to/browser` if it is not detected, and `--binary /path/to/sentrycheck` for a custom CLI build. The checks cover offline loading, local imports, untrusted markup, reduced SARIF evidence, filters, pagination, and desktop/mobile navigation. Their generated fixtures are synthetic UI tests, not workload compatibility measurements.

The page's content-security policy disables network connections and external resources. Untrusted text is inserted as text, data is escaped before embedding, and citation links use permitted web schemes with opener isolation. Following a citation is an explicit browser navigation. Reports can contain application paths and arguments, so choose what to share before publishing an HTML artifact.

Rendering is presentation, not signature verification. Use `sentrycheck-admission verify --report report.json` with the original bytes when trusted authorship is required. Editing an HTML page can change what it displays.
