# Reference document library

Fetched from the PRD section 14 link library by `python -m bench sources`.
Every entry records the URL that was tried, the URL it actually resolved to, the HTTP status,
the byte count and the digest of what was kept. Failures stay in the manifest as findings.

| outcome | count |
|---|---|
| blocked | 2 |
| error | 4 |
| not-found | 2 |
| ok | 53 |
| rate-limited | 1 |

## Findings

* **gVisor CI pipeline run (Buildkite)** (blocked) `https://buildkite.com/gvisor/pipeline/builds/35298` - HTTP 403
* **Docker Hub image configuration dataset (Zenodo, CCGRID 2023)** (rate-limited) `https://commons.datacite.org/doi.org/10.5281/zenodo.7602499` - HTTP 429
* **Large-scale Docker Hub data set (Lin, Nadi, Khazaei)** (not-found) `https://pacs.eecs.yorku.ca/pubs/pdf/lin2020docker.pdf` - HTTP 404
* **Large-Scale Analysis of the Docker Hub Dataset (Zhao et al.)** (error) `https://par.nsf.gov/servlets/purl/10167826` - URLError: <urlopen error [WinError 10060] A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has fai
* **fio and direct I/O explanation (secondary)** (error) `https://intel.com/content/www/us/en/developer/articles/technical/evaluate-performance-for-storage-performance-development-kit-spdk-based-nvme-ssd.html` - URLError: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1081)>
* **summary of the above (secondary)** (blocked) `https://blog.acolyer.org/2017/11/06/statistically-rigorous-java-performance-evaluation/` - HTTP 403
* **Confine PDF via NSF PAR** (error) `https://par.nsf.gov//servlets/purl/10219922` - URLError: <urlopen error [WinError 10060] A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has fai
* **Attack surface reduction thesis summary** (not-found) `https://www.cs.stonybrook.edu/node/877701` - HTTP 404
* **Validating Admission Policy (v1.30, stable)** (error) `https://v1-30.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy` - URLError: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 'v1-30.docs.kubernetes.io'. (_ssl.c:1081)>

## Named in the PRD with no verified URL (section 15)

* Hoefler and Belli primary paper (SC15) - needed for reporting rules for BM-09
* Official Sigstore documentation and in-toto specification - needed for attestation design
* Firecracker and Cloud Hypervisor official repositories - needed for possible additional runtimes
* iperf3, hackbench official pages - needed for network and scheduler overhead
* Phoronix Test Suite or UnixBench official pages - needed for optional broad overhead suites
* Zenodo or data-repository deposit guidance - needed for dataset DOI
* statistical references for Wilson interval, McNemar, Cohen's kappa, Holm correction - needed for section 4.3 citations
* WCAG 2.2 specification - needed for BM-11
* System Usability Scale reference - needed for BM-12
* Linux per-architecture syscall tables (kernel source) - needed for BM-02 validation
* Kubernetes CEL cost and limits documentation - needed for BM-10 CEL cost checks
* Kubernetes conformance or e2e testing docs - needed for BM-10 matrix design
* additional prior art on sandbox compatibility (beyond Confine) - needed for master PRD survey

## Licensing and redistribution

These files are kept locally as retrieved evidence for this study, not redistributed as part of
any published dataset. A bundle intended for publication ships the digests and URLs in
`manifest.json` and leaves the upstream documents where they live (PRD section 7.7, NF-09).
