# Reproducibility and Experimental Boundaries

**Research identifier:** DQ-D2-V2  
**Reference release:** [v0.1.0-research](https://github.com/abdalrahman-alakhras/digital-qareen-research/releases/tag/v0.1.0-research)  
**Status:** Evidence inspection available; full independent experimental reproduction not established.

This document is a post-release documentation addition. It does not amend the original evidence or authorize execution. The reference public commit is `0867c28a807a96b8e65a2900903dc213cfb91e2a`. Use that fixed revision, not a changing main branch, when comparing results.

## 1. What can be independently checked today

| Activity | Availability | What it establishes |
| --- | --- | --- |
| Archive integrity | Available | Exact inventory, byte counts, SHA-256 and Git blob identifiers against fixed public pins |
| Static source inspection | Available | Review of the published candidate, harness logic, fixtures and crosswalk |
| Historical receipt inspection | Available | What the original runners reported; not independent confirmation of the run |
| New synthetic model replay | Planned; requires a separately reviewed runner and scope | Selected projected behavior under controlled synthetic observations |
| Reproduction of the original controlled execution envelope | Not established | Original runner, complete archives and independent external controls are not all published |
| Native Windows validation | NOT_RUN | No native results are claimed |
| Operational integration or security certification | NOT_ESTABLISHED | Outside the scope of this evidence release |

## 2. Inspect the fixed release without executing the project

1. Obtain the [ZIP of the exact public commit](https://github.com/abdalrahman-alakhras/digital-qareen-research/archive/0867c28a807a96b8e65a2900903dc213cfb91e2a.zip).
2. Follow the [release integrity guide](VERIFICATION.md) and review its Python standard-library verifier before running it. This verifier reads ZIP members; it does not extract or import the research candidate.
3. Require an overall PASS for all 12 files, totaling 65,693 raw bytes. Compare the tag against the fixed commit.
4. Read the [original artifact README](https://github.com/abdalrahman-alakhras/digital-qareen-research/blob/0867c28a807a96b8e65a2900903dc213cfb91e2a/diagnostics/dq_d2_v2/README.md), the [provenance manifest](https://github.com/abdalrahman-alakhras/digital-qareen-research/blob/0867c28a807a96b8e65a2900903dc213cfb91e2a/PROVENANCE.json), and the rights notice before examining the evidence.
5. If any inventory or digest check fails, stop and investigate. Do not normalize line endings, modify files, or substitute an updated artifact to obtain a match.

A matching hash establishes consistency with the reference bytes, not author authenticity, a trusted timestamp, experimental validity or the ancestry of an unpublished private repository.

## 3. Historical experimental configuration

Both recorded suites ran on Linux using CPython 3.13.5. They are separate, single-invocation model-only records.

| Suite | Test methods | Reported passing subtests | Unittest duration | Outcome |
| --- | ---: | ---: | ---: | --- |
| Synthetic acceptance V2 | 20/20 | 6 | 0.110 s | No failures, errors, skips, expected failures or unexpected successes reported |
| Targeted V2 regressions | 3/3 | 19 | 0.075 s | No failures, errors, skips, expected failures or unexpected successes reported |

Durations describe the recorded unittest runs, not performance benchmarks. Subtests are not independent suite invocations. See the original [acceptance receipt](https://github.com/abdalrahman-alakhras/digital-qareen-research/blob/0867c28a807a96b8e65a2900903dc213cfb91e2a/diagnostics/dq_d2_v2/Verification_Receipt.json) and [regression receipt](https://github.com/abdalrahman-alakhras/digital-qareen-research/blob/0867c28a807a96b8e65a2900903dc213cfb91e2a/diagnostics/dq_d2_v2/Regression_Verification_Receipt.json).

### Source bindings

| Input | Raw SHA-256 |
| --- | --- |
| Candidate V2 | `139AEE6B2140206FAACE28F2F5B30048F26E3313BD057FAFEE1B4516825024BB` |
| Synthetic acceptance harness | `DB292473F366ED115BE554F97B991CCAA0DC70B2021DC2C864070D554B198427` |
| Targeted regression harness | `B7873FE5E594EC6EC22F0AD4B31F16906ADE5AEFEEA0AA623EBA72889A7BD72F` |

The acceptance harness projects eight top-level AST nodes: LIMIT, digest, reparse, GUARD_FIELDS, OBS_FIELDS, snapshot, differences and differential. The regression harness adds checked_hash (nine nodes). Both expose build_suite(source_bytes); neither is an admitted standalone execution runner.

The acceptance receipt reports 25 projection compilations and executions, 39 matching pre/post pins, eight verified archives and 38 matched archive members. The regression receipt reports 25 matching pre/post digests and three methods covering early rejection without content reads, cross-field inconsistency and same-descriptor/no-reopen ordering. The complete external evidence behind these historical controls is not included in this release.

## 4. Contract coverage and non-claims

The [acceptance crosswalk](https://github.com/abdalrahman-alakhras/digital-qareen-research/blob/0867c28a807a96b8e65a2900903dc213cfb91e2a/diagnostics/dq_d2_v2/Acceptance_Crosswalk_V2.json) is a preparation record, not a completed acceptance certificate. Its result fields remain null. T01 is static-only; T02-T08 have partial synthetic coverage; T09 and T11 are specification-only; T10 is native NOT_RUN; T12 has partial synthetic and static coverage.

The candidate's direct CLI deliberately refuses execution. Do not invoke review_candidate against a live environment or remove the execution locks on the authority of this guide. The historical PENDING_REVIEW fields in the two receipts are preserved as recorded, not rewritten into a new status.

No full candidate import, live native API behavior, filesystem atomicity, share-mode enforcement, OS containment, memory isolation, end-to-end authorization, or worker/provider operational certification has been established by these synthetic runs. External observer/writer/deadline enforcement and independent OS event counters were not verified or collected.

## 5. Requirements for a future independent synthetic replay

This is a proposed review checklist, not an executable procedure or admission.

- Review the exact pinned sources and the projected code and establish a fresh, explicit execution scope. Respect RIGHTS.md and obtain any required permission.
- Use a disposable offline environment with no live project repositories, production credentials, provider access or database connections. Pin and record the interpreter and runner.
- Review an external supervisor that supplies exact source bytes, admits only the intended projections, bounds resource use, observes execution and preserves failures. Local import or compile/exec restrictions alone are not OS confinement.
- Run each suite under a new attempt identifier and record method-level results, subtest results, errors, skips, elapsed time, input/output hashes, and independent control observations where available.
- Compare results against the historical receipts without overwriting them. A matching replay does not reproduce unavailable external controls or establish native behavior.
- Preserve failed or inconclusive runs. Do not silently retry under the original historical attempt identifiers.

Do not use the historical receipts as authorization for a new run. A separately reviewed, distributable runner and its evidence package would be a new deliverable.

## 6. Native validation

The [T10 fixture plan](https://github.com/abdalrahman-alakhras/digital-qareen-research/blob/0867c28a807a96b8e65a2900903dc213cfb91e2a/diagnostics/dq_d2_v2/T10_Fixture_Plan_V2.json) and schema are specifications only. All 14 fixtures remain NOT_RUN in that reference. A future native experiment requires an admitted x64 Windows/local NTFS environment, an independently checked CPython/SDK ABI oracle, isolated synthetic fixtures, and separately established observation, cleanup and deadline controls. No live repository, worker, provider or migration execution is implied.

## 7. Reporting independent observations

For a technical review, report the exact commit, file hashes, environment, review scope, expected versus observed behavior, and any missing controls. Separate static findings, new synthetic observations, native results and operational evidence. Do not include credentials, private data, or sensitive host details in a public issue.

See [ROADMAP.md](ROADMAP.md) for the high-level research directions and [RIGHTS.md](RIGHTS.md) for the publication terms. Public availability is not an open-source license, certification or operational authorization.

AI Can Propose.  
Policy Must Authorize.  
Infrastructure Must Enforce.  
Evidence Must Prove.
