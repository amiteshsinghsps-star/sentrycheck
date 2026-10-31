# Reviewable publication and CFP package

**Draft prepared 2026-09-26. Nothing has been submitted or published.** Authorship, affiliation, contact details, speaker availability, public repository URL and submission account belong to the human author and remain pending. The technical claims below use the checked-in validation records; planned v0.5 measurements are not treated as completed results.

## Verified target

Target: **KubeCon + CloudNativeCon Europe 2027**, Barcelona, **15–18 March 2027**. The [official current CFP](https://events.linuxfoundation.org/kubecon-cloudnativecon-europe/program/cfp/) and [linked Sessionize call](https://sessionize.com/kubecon-cloudnativecon-europe-2027/) state:

| Milestone | Published date |
| --- | --- |
| CFP closes | **11 October 2026, 23:59 CEST (UTC+2)** |
| Equivalent UTC / India time | 11 October 21:59 UTC / **12 October 03:29 IST** |
| Notifications | 7 December 2026 |
| Schedule announcement | 9 December 2026 |
| Conference | 15–18 March 2027 |

Suggested format: **Poster Session**, track **Emerging + Advanced**. The track explicitly welcomes cloud-native research and early technical work. A poster has one or two presenters, counts toward each speaker’s three-proposal limit, and is scored within its selected track. The organizers select up to ten posters. Acceptance, a talk slot and paper proceedings are not promised.

The current policy offers accepted poster presenters the same all-access pass as speakers and a Credly badge after the event. A co-presenter is recommended for staffing; authors are required to staff the poster during KubeCrawl. These benefits do not establish travel reimbursement or permission to replace an accepted speaker.

## Proposed title

**SENTRYCHECK: Evidence-Graded, Profile-Bounded Compatibility Checks for gVisor**

## Proposed abstract

An unsupported syscall does not necessarily break a container: applications can probe an interface and fall back. SENTRYCHECK combines incomplete static capability extraction, native and gVisor guest traces, and a release-specific knowledge base to distinguish candidates from observed workload failures. We present a reproducible PostgreSQL 18.0 case with explicitly selected io_uring: native query assertions passed, while gVisor 20260921.0 failed startup. A fallback-enabled fixture and bounded Python, Node.js and Go profiles completed without functional incompatibility findings. A separate Kubernetes demonstration detects runtime identity mismatch and unhealthy-handler drift using CRI canaries and admission policy. The poster exposes evidence, coverage gaps and causal limits; it does not claim universal prediction, automatic Kubernetes fallback or production-wide accuracy.

## Reviewer context and audience value

The artifact is a Rust CLI, a Go admission/probe integration and an offline report viewer. It shows why syscall presence, exercised capability, changed output and deployed runtime identity are different kinds of evidence. Attendees can inspect pinned image/profile/runtime identities, trace completeness, signed CI claims and unconfirmed candidates, then adapt a bounded profile to their own workload.

The current empirical record consists of nine selected profiles and 54 executions in v0.2, 30 fresh small-profile executions in v0.3, replay of 54 retained traces, and an actual CRI/runtime-drift demonstration. v0.4 validated report rendering and offline browser behavior; it did not refresh the application experiments. These are local artifact demonstrations, not independently labeled accuracy or controlled overhead measurements. The source-backed [case study](CASE-STUDY.md), [validation record](VALIDATION.md), and [paper source](../paper/README.md) are supporting material. Replace local paths with reviewed public URLs only after a public release exists.

Suggested audience: platform engineers, runtime maintainers and systems researchers with Kubernetes/container familiarity. Suggested prerequisites: OCI images, RuntimeClass and basic syscall tracing. The concrete contribution is an inspectable evidence pipeline and reproduced cases. A broader related-work review is still needed before asserting research novelty.

## Poster layout and demonstration

1. **Question:** how does required io_uring differ from tolerated capability probing?
2. **Method:** image digest → static candidates → paired guest observations → versioned source → graded report.
3. **Observed case:** PostgreSQL build/profile identity, native success versus sandbox startup failure, and successful fallback/baseline profiles.
4. **Deployment claim:** CRI canary mismatch → warning and protected-label revocation → admission denial → recovery.
5. **Limits:** selected profiles, trace coverage, causal attribution, runtime configuration, no Kata VM evaluation and no production accuracy claim.

The live demo should have a retained-evidence fallback clearly labeled as replay. Browser navigation or a saved trace is not a fresh workload execution. An untested new feature must be labeled planned or removed from the submitted abstract.

## Author review before submission

- Confirm names, affiliations, presenter availability, authorship contributions, public artifact location and permission to disclose all examples. No identity or institutional endorsement has been invented.
- Read the abstract in the author’s own voice; verify every technical statement against the artifacts. The CFP allows AI assistance but discourages low-quality AI-generated material and warns that repeated abuse can lead to review removal or a future-CFP ban.
- Count all proposals on which each person appears, including posters and co-located submissions where a separate call’s rules apply. The main CFP limit is three proposals regardless of format.
- Explain any significant changes from a similar talk presented at a Linux Foundation event within the preceding year. Do not assume a renamed title makes repeated content eligible.
- Recheck the current CFP and acceptance guidance immediately before committing to attendance. Attendee registration transfer is not automatic presenter substitution. Current registration refund text contains a stale-looking 2026 year; no applicable speaker-withdrawal penalty or deadline was verified.

These are concrete items for author review, not actions performed by SENTRYCHECK. No organizer, maintainer or endorser has been messaged.

## arXiv preparation

The local [LaTeX draft](../paper/main.tex) and [bibliography](../paper/references.bib) are source artifacts, not an arXiv publication. The [arXiv submission guide](https://info.arxiv.org/help/submit/index.html) requires author/account metadata and source processing; its [endorsement guidance](https://info.arxiv.org/help/endorsement.html) says endorsement is required for a first submission or a new category. An institutional affiliation is not fabricated to bypass this process.

Suggested category for author review: `cs.DC`, with `cs.CR` only if the eventual paper’s contribution and arXiv cross-listing rules warrant it. No category acceptance, moderation outcome or endorsement is assumed. Before upload, finalize authorship, artifact licensing and public availability, include supported results, build and inspect the PDF, and decide whether the incomplete related-work/independent-evaluation sections are sufficient for the intended manuscript. Uploading or contacting endorsers is a separate, explicit action.

Source excerpts, final redirect targets and hashes are recorded in [research/v2-evidence](../research/v2-evidence/sources.json); the claim-by-claim review is [v2-PRD-AUDIT.md](../research/v2-PRD-AUDIT.md).
