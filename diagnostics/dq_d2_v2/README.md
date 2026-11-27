# Digital Qareen — Metadata Differential V2 (DQ-D2-V2)

## Scope

This directory is a diagnostic research artifact, not production code or an operational authorization mechanism. It is not integrated into application dispatch, workers, provider calls, or database migrations. The candidate's direct CLI refuses execution. Its `review_candidate(repo, downloads)` callable is not a security sandbox and must not be invoked against a live environment without a separately approved, independently enforced execution scope.

## Recorded synthetic verification

The exact candidate digest is `139AEE6B2140206FAACE28F2F5B30048F26E3313BD057FAFEE1B4516825024BB` (SHA-256 of raw file bytes).

| Suite | Recorded result | Runtime |
|---|---|---|
| Historical acceptance V2 | 20/20 methods, 6/6 reported subtests | Linux, CPython 3.13.5, 0.110 s |
| Targeted V2 regressions | 3/3 methods, 19/19 reported subtests | Linux, CPython 3.13.5, 0.075 s |

These are two distinct model-only runs, not an end-to-end integration test. Subtests are not independent suite runs. They cover selected early-rejection, metadata coherence and same-file-object ordering properties using synthetic observations. The historical suite projects eight top-level AST nodes and does not exercise `checked_hash`; the targeted regression suite projects nine nodes and includes selected `checked_hash` behavior.

## Evidence and reproducibility

The two JSON verification receipts are unchanged point-in-time runner outputs. Their `PENDING_REVIEW` status values were recorded before subsequent review admission; they are retained rather than rewritten. The acceptance crosswalk and T10 fixture plan are preparation records, and their `NOT_RUN` / null fields are not retroactively populated. The subsequent review dispositions are limited to the scoped synthetic results, not operational certification.

Both harnesses expose `build_suite(source_bytes)` for exact candidate bytes, with digest binding and synthetic AST projections. They are not standalone approved operational runners. Reproducing the recorded execution envelope requires the separately reviewed runner, environment and controls; the nine-file payload does not include the full runner or the complete original evidence archives. The receipts reference additional evidence held separately. No automatic live diagnostic or new execution authorization is supplied here.

## Explicit limitations

- Native Windows ABI / NTFS fixture verification (T10) is NOT_RUN; kernel share-mode behavior, path/ancestor race containment and platform-specific metadata equivalence are unverified.
- The in-memory model does not prove filesystem atomicity, absence of all concurrent mutations, or independent OS containment. Independent OS telemetry and external watchdog/writer enforcement were not verified.
- The historical `FILE_CHANGED` failure's exact triggering condition is unknown; payload mutation and executable trust are not established.
- Not all twelve acceptance contracts were exercised. The historical perimeter and native operational prerequisites are unresolved. No worker/provider dispatch or migration execution is authorized by these artifacts.

AI Can Propose.  
Policy Must Authorize.  
Infrastructure Must Enforce.  
Evidence Must Prove.
