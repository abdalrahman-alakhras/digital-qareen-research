# Digital Qareen Research Roadmap

**Scope:** Public research direction, not an operational deployment plan.  
**Reference:** [DQ-D2-V2 / v0.1.0-research](https://github.com/abdalrahman-alakhras/digital-qareen-research/releases/tag/v0.1.0-research)

The research investigates whether an AI agent's proposed actions can remain subject to independently constrained, auditable execution authority, including when trusted assumptions fail. The public repository contains scoped metadata-integrity research artifacts, not the complete Digital Qareen framework.

## 1. Evidence status

| Workstream | Status | Evidence or remaining boundary |
| --- | --- | --- |
| Scoped public evidence release | PUBLISHED | Nine original diagnostic artifacts and three top-level files at the fixed reference commit |
| Synthetic acceptance V2 | RECORDED_SCOPED_PASS | 20 methods; six reported passing subtests |
| Targeted V2 regressions | RECORDED_SCOPED_PASS | Three methods; 19 reported passing subtests |
| Release integrity guide | AVAILABLE | Fixed-inventory offline verification; not experimental reproduction |
| Reproducibility documentation | AVAILABLE | Describes what can be examined and what remains unavailable |
| Independent full reproduction | NOT_ESTABLISHED | Requires a separately reviewed runner and missing external evidence |
| Native Windows T10 | NOT_RUN | Fourteen proposed fixture cases; native behavior not established |
| Operational enforcement and integration | OPEN | No general end-to-end guarantee established by this release |
| Adversarial breach containment and data sovereignty (ABCDS) | PLANNED_NOT_RUN | Research hypotheses, not implemented or verified guarantees |
| Independent security assessment | NOT_ESTABLISHED | External technical scrutiny invited |

## 2. Next research priorities

### R1 - Native metadata validation

Evaluate the published T10 fixture specification in an independently scoped Windows/NTFS laboratory. Establish the ABI and platform assumptions before interpreting native results. Measure same-handle behavior, early rejection, metadata coherence and residual race conditions. Missing controls or inconclusive observations must not be treated as a pass.

### R2 - Reproducibility and independent scrutiny

Prepare a separately reviewed, distributable synthetic replay runner and a documented experimental envelope. Enable reviewers to reproduce selected model results and identify the difference between historical observations and newly collected evidence. Publish new evidence with separate run identities and explicit scope, subject to disclosure and rights review.

### R3 - Execution authority and integration

Investigate independent authorization at the point of external effect, scoped identity binding, revocation, stale authority, replay resistance, failure containment and non-bypassable enforcement. Evaluate database, worker and external-provider boundaries separately. Cooperative and opaque external services may offer different guarantees; irreversible external effects cannot be assumed reversible or strictly revocable after acceptance.

### R4 - Adversarial breach containment and data sovereignty (ABCDS)

Explore the following proposed research areas using synthetic identities, data and isolated laboratory services:

| Research area | Question to investigate |
| --- | --- |
| Authentication and credential compromise | Can compromised credentials be prevented from becoming unrestricted execution authority? |
| Application and database compromise | Can data exposure and cross-tenant impact be bounded when an application-level control fails? |
| Cryptographic and authorization separation | Can sensitive keys and authorization mechanisms remain outside a compromised component's authority? |
| Compromised workloads and administrative identities | Can a failed or compromised component be prevented from bypassing an independently enforced boundary? |
| Identity providers, sessions and federated trust | Can the effects of identity and trust compromise be contained across connected systems? |
| Bulk data access and compound failures | Can unauthorized bulk access and propagation across services be detected, constrained and evidenced? |
| Audit integrity | Can tampering be detected using evidence outside the compromised trust boundary? |

These are high-level research questions, not claims of protection against every attack. The framework is not intended to replace secure application design, identity providers, endpoint protection, database hardening, network segmentation or incident response. Detailed internal test cases, private engineering history and host-specific information are intentionally outside this public roadmap.

## 3. Evidence-based progression

For each future milestone, define the threat model, assumptions, permitted scope, expected failure behavior and measurable acceptance criteria. Run only admitted tests on authorized synthetic resources. Preserve failures and uncertainty; review source and evidence integrity, and record the exact revision tested. Require a separate disclosure review before publishing new artifacts.

A static check is not a runtime result. A synthetic result is not a native result. A native component result is not an end-to-end security guarantee. A public release is not independent certification. No schedule or production readiness date is asserted here.

The sequence is dependency-driven: preparations may proceed in parallel where safe, but passing an earlier scoped test must not silently unlock a later operational stage.

## 4. Participation and rights

Critical feedback on assumptions, test coverage, integrity, and reproducibility is welcome through the repository's public review channels. Do not post sensitive data or credentials. See [REPRODUCIBILITY.md](REPRODUCIBILITY.md), [VERIFICATION.md](VERIFICATION.md), and [RIGHTS.md](RIGHTS.md). The artifacts are not released under an open-source license; availability for inspection does not itself grant unrestricted use or deployment rights.

AI Can Propose.  
Policy Must Authorize.  
Infrastructure Must Enforce.  
Evidence Must Prove.
