# Digital Qareen Research

## DQ-D2-V2: Metadata Differential - scoped research evidence

A standalone research artifact collection exploring metadata integrity as one component of deterministic AI execution governance. This is not the full Digital Qareen framework, a deployment package, or a production security product.

The collection contains nine unchanged diagnostic artifacts under [`diagnostics/dq_d2_v2/`](diagnostics/dq_d2_v2/README.md): a review-only candidate, two synthetic harnesses, a native fixture plan and schema, an acceptance crosswalk, two original verification receipts, and a scoped README.

### Recorded evidence

| Verification | Recorded result | Environment |
|---|---|---|
| Synthetic acceptance V2 | 20/20 methods; 6 reported passing subtests | Linux, CPython 3.13.5 |
| Targeted V2 regressions | 3/3 methods; 19 reported passing subtests | Linux, CPython 3.13.5 |
| Native Windows T10 | NOT_RUN | Not executed |

The two suites exercised selected AST projections using synthetic observations. They did not run the complete candidate or establish end-to-end authorization, filesystem atomicity, platform equivalence, OS containment, memory isolation, or worker/provider certification. Subtests are not independent suite runs. See the [artifact README](diagnostics/dq_d2_v2/README.md) for the precise test scope.

### Provenance and integrity

[`PROVENANCE.json`](PROVENANCE.json) records raw SHA-256, Git blob SHA-1 and byte counts for each original artifact. Those pins match the nine-file payload and the owner-reported local commit `4711472f2653ca719ab6b15602faf87806a52c4a` (tree `0fd05a70af9e91649c5f0d39c9c253cc7dbe44b8`). That local commit is not included in this standalone repository, and its history is not transferred. This repository has separate commit identities. The provenance record is a reported linkage with byte-level crosswalk, not a signature or a publicly verifiable proof of the private commit's ancestry.

To inspect integrity, hash the raw downloaded files and compare to `PROVENANCE.json`. For example, in Windows PowerShell, `Get-FileHash -Algorithm SHA256 -LiteralPath 'diagnostics/dq_d2_v2/DQ_I1B2_D2_Metadata_Differential_V2.py'` checks the candidate. Do not normalize line endings when checking raw hashes.

### Reproducibility boundaries

The historical receipts retain their original PENDING_REVIEW statuses. The full controlled runner, complete original archives and external enforcement evidence are not part of this collection. The harnesses expose synthetic suite builders; this is not a standalone reproduction of the recorded execution envelope. The candidate CLI intentionally refuses execution. Do not invoke the live diagnostic callable against a live environment on the authority of these artifacts.

### Rights and review

See [RIGHTS.md](RIGHTS.md). This collection is not released under an open-source license. The material is offered for technical inspection subject to applicable law and platform terms. No operational execution authority is conferred.

AI Can Propose.  
Policy Must Authorize.  
Infrastructure Must Enforce.  
Evidence Must Prove.
