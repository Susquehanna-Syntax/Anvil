# Anvil Implementation — Unified Audit Record And Store

## Overview

Every other area of Anvil — the SAST/DAST detectors, attack-surface discovery, the coding-agent consumption
pipeline, GitHub export, and the scheduler — reads or writes through the record and store this document
defines, so it is specified once, precisely, and frozen before those areas are built. It resolves two direct
research-branch conflicts (the fingerprint algorithm's exact field set and separator; the SQLite `synchronous`
pragma) and adds every field `00-SPINE.md` S6 flagged as absent from branch 18's original SARIF design. The
store collapses to one SQLite database holding the durable knowledge base, the sealed audit record, and a
`handoff` claim/lease table, plus a regenerable tmpfs packet that is never a source of truth — there is no
second durable buffer file, per spine S1. Every packet below that touches security, migrations, secrets, or an
unresolved legal question carries a mandatory cross-family critic per `00-ROUTING.md`.

## Dependency Summary

This area has no upstream dependency inside the Anvil implementation plan — it is the first area a coding
agent should build, and every packet below reads only from `research/`, `plan/00-SPINE.md`, and
`plan/00-ROUTING.md`. Downstream, every other implementation area is blocked on this area's outputs:

| Downstream area (not built here) | Blocked on |
|---|---|
| SAST/DAST detectors | R.1 (Record Field Contract), R.2 (Fingerprint Specification) |
| Attack-surface discovery / target lifecycle harness | R.1 (`anvil/target.provenance`, `anvil/dastCoverage` placement) |
| Coding-agent consumption pipeline | R.1, R.2, R.13 (three-tier read path), R.7 (handoff claim protocol) |
| GitHub Actions export | R.14 (reduced SARIF projection) |
| Scheduler / queue | R.11 (queue re-cut rule) |
| Fix verification / "verified fixed" gate | R.1 (`anvil/repro.env` sanitizer+ASLR fields) |
| Licence compliance (`plan/80-compliance.md`) | R.1 (SARIF 2.1.0 + `owenrumney/go-sarif` pins), R.4/R.5 (`modernc.org/sqlite` pin + FTS5 guard) — see Pinned Versions And Licences. The zstd pin is **unowned**; see Open Question 4. |

Treat R.1's `internal/record/contract.go`, R.2's `internal/record/fingerprint.go`, and R.4's
`internal/store/schema.sql` as a frozen interface once R.17's exit gate passes — later areas must not
redefine `anvil/*` keys already reserved here without amending this document.

## Steps

### Serial Phase 1 — The Contract And Its Fingerprint

```
Step ID:          R.1
Phase/group:      serial
Depends on:       none
Backend/model:    Claude Code subagent (opus)
Objective:        Reconcile branch 18's SARIF 2.1.0 + anvil/* extension design against 00-SPINE.md S6's list of
                   fields it lacked, and write the single frozen Record Field Contract every other area builds
                   against.
Scope and files:  READ: research/18-unified-audit-record.md (Recommendation, the annotated record example, Risks);
                   research/24-coding-agent-consumption.md (the "audit record must carry" list); 00-SPINE.md
                   (S1, S6, S7); 00-ROUTING.md.
                   WRITE: internal/record/contract.go (Go structs + anvil/* property-key constants),
                   internal/record/CONTRACT.md (human-readable field table matching this plan's Record Field
                   Contract section as ground truth), schemas/anvil-record-v1.schema.json (JSON Schema
                   extending sarif-schema-2.1.0.json with the anvil/* property bags).
Forbidden actions: Do not implement detector logic, correlation matching, masking, or coding-agent prompt
                   construction — this step defines the wire contract only. Do not invent anvil/* keys beyond
                   what 00-SPINE.md S6 and research/18/24 require without flagging the addition in Open
                   Questions. Do not weaken or duplicate a SARIF-native mechanism (correlationGuid,
                   partialFingerprints, provenance, fixes) into an anvil/* key when the native slot already
                   exists. Do not pin $schema/version to anything other than SARIF 2.1.0.
Inputs/artifact refs: The Record Field Contract table in this document (R.1's output must match it row for
                   row, or the deviation must be logged in Open Questions).
Expected output schema: contract.go compiles with one exported Go type per SARIF object Anvil extends
                   (sarifLog, run, result) plus a typed anvil/* sub-struct for each; CONTRACT.md table has one
                   row per field with producer/consumer named; the JSON Schema validates the annotated example
                   record from research/18 (comments stripped) with zero errors.
Validation/evidence required: Every field in 00-SPINE.md S6's explicit list (anvil/state, anvil/version,
                   per-half status+sealedAt, anvil/trust, dast_status/dast_coverage/target_provenance,
                   remediable_by_agent, INSUFFICIENT_CONTEXT, as_of/staleness_seconds/parse_degraded,
                   endpoint_coverage/inventory_provenance, sanitizer+ASLR state) appears in contract.go with a
                   named producer and consumer. Grep-checkable: each S6 term above has a corresponding constant.
Stop condition:    contract.go, CONTRACT.md, and the JSON Schema exist, are mutually consistent, and every S6
                   field is present with no TODOs.
Why this model:    Hardest architecture in this plan — reconciling one already-vetted SARIF mapping against
                   seven spine-mandated additions it never saw, where a wrong call here is load-bearing for
                   every downstream consumer. Per 00-ROUTING.md, opus is reserved for exactly this: "the one
                   genuinely hard parallel sub-problem," not escalated by default.
```

```
Step ID:          R.2
Phase/group:      serial
Depends on:       R.1
Backend/model:    Claude Code subagent (sonnet)
Objective:        Resolve the fingerprint-algorithm conflict between research/07 and research/18 into the single
                   `anvil-fp/v1` algorithm specified in this document's Fingerprint Specification section, and
                   ship it as code plus a fixed input corpus.
Scope and files:  READ: research/07-database-design.md (§3 "Fingerprint scheme", the matching cascade);
                   research/18-unified-audit-record.md ("Stable identity" subsection); this document's
                   Fingerprint Specification section (the resolved, authoritative spec — implement exactly this,
                   not either source verbatim).
                   WRITE: internal/record/fingerprint.go, internal/record/fingerprint_test.go,
                   testdata/fingerprint_corpus/*.json (fixed input fixtures: at minimum 2 SAST, 2 DAST, 1 SCA,
                   1 host case).
Forbidden actions: Do not change any field name already fixed by R.1's contract.go. Do not include line
                   numbers, column numbers, the literal snippet, hostnames, ports, payload strings, or
                   timestamps in any hash input. Do not truncate the SHA-256 digest. Do not use any separator
                   other than U+001F between joined fields.
Inputs/artifact refs: The exact algorithm text in this document's Fingerprint Specification section.
Expected output schema: fingerprint.go exports one function per tier (Sast, Sca, Dast, Host) each returning a
                   64-hex-char lowercase digest string; fingerprint_test.go asserts each corpus fixture
                   produces its documented digest and that changing only a line number in a fixture's input
                   does not change the output.
Validation/evidence required: `go test ./internal/record/...` passes; a mutation test confirms a line-number-only
                   change to a SAST fixture leaves the digest unchanged.
Stop condition:    All corpus fixtures produce stable digests across two consecutive runs and the mutation test
                   passes.
Why this model:    Default strong worker for a bounded, evidence-grounded implementation task: turn a named,
                   already-resolved two-branch conflict into spec-conformant code and fixtures. No open
                   architecture question remains once R.1 and this document's spec exist.
```

```
Step ID:          R.3
Phase/group:      serial
Depends on:       R.1, R.2
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Cross-family critique of the Record Field Contract (R.1) and the Fingerprint Specification
                   implementation (R.2) before either becomes a frozen interface for downstream areas.
Scope and files:  READ: internal/record/contract.go, internal/record/CONTRACT.md,
                   schemas/anvil-record-v1.schema.json, internal/record/fingerprint.go,
                   internal/record/fingerprint_test.go, testdata/fingerprint_corpus/*.json, this document's
                   Record Field Contract and Fingerprint Specification sections, 00-SPINE.md S6.
                   WRITE: internal/record/CRITIQUE-01.md (findings only — no code edits).
Forbidden actions: Do not modify contract.go, fingerprint.go, or any test file directly — this is a critique
                   pass, not a fix pass. Do not approve a fingerprint algorithm that hashes a line number,
                   column, or raw payload. Do not approve a contract missing any 00-SPINE.md S6 field.
Inputs/artifact refs: 00-ROUTING.md cross-family critique rule (Anthropic-authored output requires an
                   OpenCode/OpenRouter critic on data-integrity/security-relevant work).
Expected output schema: CRITIQUE-01.md with one PASS/FAIL verdict per S6 field, one PASS/FAIL verdict on
                   fingerprint determinism and exclusion of volatile fields, and a numbered list of any gaps.
Validation/evidence required: Every S6 field individually marked PASS or FAIL with a one-line reason; any FAIL
                   triggers a reroute of R.1 or R.2 per the rerouting rule before R.4 may start.
Stop condition:    CRITIQUE-01.md is complete and either all-PASS, or R.1/R.2 have been rerouted and re-reviewed
                   until all-PASS.
Why this model:    Mandatory per 00-ROUTING.md's cross-family critique rule — R.1/R.2 are Anthropic-authored and
                   this decision is data-integrity- and regression-matching-relevant, which the rule names
                   explicitly as requiring a critic from a different model family. gpt-5.5 is the routing
                   table's strong cross-family critic route; justified here as foundational, high-stakes
                   judgment, not default use of a paid route.
```

### Serial Phase 2 — The Store

```
Step ID:          R.4
Phase/group:      serial
Depends on:       R.3
Backend/model:    Claude Code subagent (sonnet)
Objective:        Write the collapsed SQLite store schema: research/07's knowledge-base tables, the sealed
                   `audit_record` table (S1/S6-extended, no separate buffer file), and the new `handoff` table
                   (state/lease/attempts/expiry, per S1).
Scope and files:  READ: research/07-database-design.md (§2 "Schema", the full DDL block); research/08-buffer-
                   and-handoff.md (Recommendation §1, the handoff table sketch); this document's Store Schema
                   section (authoritative — implement exactly this).
                   WRITE: internal/store/schema.sql, internal/store/ddl.go (Go wrapper exposing the DDL as an
                   embedded string for R.5's migrations).
Forbidden actions: Do not create a second durable buffer file or table outside `handoff` — 00-SPINE.md S1
                   explicitly collapses the buffer; a second durable copy is a direct spine violation. Do not
                   drop any research/07 table without logging the reason in Open Questions. Do not store raw
                   snippets, DAST request/response bodies, or any secret outside `audit_record.payload` (which
                   is itself masked per R.8 before it ever reaches this table).
Inputs/artifact refs: This document's Store Schema section.
Expected output schema: schema.sql is valid SQLite DDL; `sqlite3 :memory: < schema.sql` exits 0; every table
                   from this document's Store Schema section exists with the documented columns, indexes, and
                   CHECK constraints.
Validation/evidence required: A smoke test that creates an in-memory DB from schema.sql, inserts one row per
                   table with FK-valid references, and selects it back.
Stop condition:    schema.sql applies cleanly to an empty SQLite database with `PRAGMA foreign_keys=ON` and the
                   smoke test passes.
Why this model:    Default strong worker: this is schema translation from two already-vetted research designs
                   into the collapsed single-store shape this document specifies, not open architecture.
```

```
Step ID:          R.5
Phase/group:      serial
Depends on:       R.4
Backend/model:    Claude Code subagent (sonnet)
Objective:        Build forward-only numbered SQL migrations with a checksummed ledger, plus the two mandatory
                   startup guards: refuse a network-mounted data directory, and refuse if FTS5 is unavailable.
Scope and files:  READ: research/07-database-design.md (§7 "Migrations", the ALTER TABLE rules table, the
                   12-step rebuild); research/08-buffer-and-handoff.md (WAL/network-filesystem risk); 00-SPINE.md
                   S12 (modernc.org/sqlite, no cgo).
                   WRITE: internal/store/migrate.go, internal/store/migrations/0001_init.sql (embeds R.4's
                   schema.sql), internal/store/guards.go, internal/store/guards_test.go,
                   internal/store/migrate_test.go.
Forbidden actions: Do not use Alembic, goose, sqlx-cli, or any external migration CLI — Go-only per S12, no
                   venv or external tool for the self-hoster. Do not write a down-migration; use `VACUUM INTO`
                   pre-migration snapshotting instead, per research/07. Do not skip the FTS5 smoke test on the
                   theory that 00-SPINE.md S12 already calls modernc.org/sqlite's FTS5 support
                   "orchestrator-verified" — the guard must independently verify at every process start by
                   attempting to create a real FTS5 virtual table, not trust the spine's claim at build time.
Inputs/artifact refs: research/07's verbatim ALTER TABLE restriction table (do not write ADD COLUMN ... NOT
                   NULL DEFAULT CURRENT_TIMESTAMP, do not write ADD COLUMN ... UNIQUE, etc. — see that table).
Expected output schema: migrate.go applies migrations in numbered order inside `BEGIN...COMMIT`, bumps
                   `PRAGMA user_version` in the same transaction, and records a checksum in `schema_migration`;
                   guards.go exposes `CheckNetworkMount(path string) error` and `CheckFTS5(db *sql.DB) error`,
                   both called before any other store operation.
Validation/evidence required: migrate_test.go applies 0001_init.sql to an empty DB and asserts the resulting
                   schema matches R.4's schema.sql byte-for-byte (via `sqlite3 .schema` diff); re-running
                   migrate is a no-op; guards_test.go asserts CheckFTS5 fails loudly (not silently) against a
                   build tag that disables FTS5, and CheckNetworkMount fails against an injected fake network
                   filesystem type.
Stop condition:    Both guard tests and the migration round-trip test pass; a hand-edited migration file with a
                   mismatched checksum causes migrate.go to refuse to start.
Why this model:    Default strong worker: the ALTER TABLE rules and the 12-step rebuild are already fully
                   documented in research/07 — this is bounded implementation against a documented checklist,
                   not invention.
```

### Parallel Group 1 — Sealing, Handoff, And Secrets (all depend only on R.1 or R.4; disjoint write scope)

```
Step ID:          R.6
Phase/group:      parallel group 1
Depends on:       R.4
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement per-half sealing: independent SAST/DAST status + sealedAt tracking, a re-entrant
                   consumer read gate, and `deadline_at` anchored to scan START (never last write).
Scope and files:  READ: 00-SPINE.md S1 ("One audit identity, two independently-sealed halves, a re-entrant
                   consumer"), S6 (per-half status+sealedAt), S9 (DAST is opt-in — most DAST halves will be
                   empty); this document's Record Field Contract (anvil/state, run.properties["anvil/status"],
                   ["anvil/sealedAt"]) and Store Schema (audit_record columns) sections.
                   WRITE: internal/record/sealing.go, internal/record/sealing_test.go.
Forbidden actions: Do not conflate `anvil/sealedAt` (per-half completion) with `anvil/deadline.deadlineAt` (the
                   claim-timeout clock) — they are independent clocks with independent semantics. Do not allow
                   a consumer to read a half's results before that half's `status` field equals `sealed`. Do
                   not compute `deadline_at` from any write timestamp — it must be `scan_run.started_at +
                   claim_timeout_seconds`, computed once and never recomputed.
Inputs/artifact refs: This document's Store Schema section (audit_record.deadline_at, .sast_sealed_at,
                   .dast_sealed_at, .dast_status).
Expected output schema: sealing.go exposes `SealHalf(auditID, half string, status string) error` and
                   `ReadyForConsumption(auditID string) (sastReady, dastReady bool)`; DAST-disabled audits
                   (S9 tier S/M without DAST) reach `both_sealed` state with `dast_status='not_run'`, never
                   `NULL` and never `'completed_clean'`.
Validation/evidence required: A test asserting a DAST-disabled scan's `dast_status` is distinguishable from a
                   DAST-enabled scan that found nothing (`'completed_clean'`); a test asserting `deadline_at`
                   is unchanged by a late write to either half.
Stop condition:    Both tests pass and a consumer attempting to read an unsealed half is rejected with a typed
                   error, not a partial/zero-value result.
Why this model:    Default strong worker: this is a state machine over R.4's already-fixed schema, not open
                   architecture — the states and transition rules are fully specified by S1/S6.
```

```
Step ID:          R.7
Phase/group:      parallel group 1
Depends on:       R.4
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the handoff claim protocol: atomic write/rename of the tmpfs packet, renameat2-based
                   claiming, OFD locks for the claim duration, and a reaper that distinguishes the 15–30 minute
                   claim lease from the multi-hour claim timeout.
Scope and files:  READ: research/08-buffer-and-handoff.md (Recommendation §1 claim protocol, §4 "Is 8 hours a
                   sensible TTL", the reaper pseudocode, Risks on shred/fcntl/tmpfiles); this document's Store
                   Schema section (handoff table).
                   WRITE: internal/handoff/state_machine.go, internal/handoff/claim.go, internal/handoff/
                   reaper.go, internal/handoff/handoff_test.go.
Forbidden actions: Do not use classic `fcntl` record locks (close() drops them process-wide — use OFD locks or
                   flock). Do not claim or imply secure deletion anywhere in code, comments, or logs — no
                   `shred` call, no "securely destroyed" language. Do not conflate the 15–30 minute claim lease
                   with the multi-hour claim timeout; they are separately configured
                   (`buffer.lease` vs. `claim_timeout_seconds`) and independently renewable/expirable. Never
                   expire a live claim (a finding whose lease is still valid must be allowed to finish). At
                   claim-timeout expiry, do not delete the database row — only drop the tmpfs packet and
                   transition state.
Inputs/artifact refs: research/08's exact primitives: `renameat2(..., RENAME_NOREPLACE)` for claiming,
                   O_TMPFILE+linkat or temp-file+fsync+rename+fsync(parent) for writing.
Expected output schema: claim.go exposes `Claim(fingerprint string, workerID string) (Handle, error)` that
                   returns `ErrAlreadyClaimed` on a losing race; state_machine.go implements the
                   ready→leased→{validated|failed_*|expired} transitions from this document's Store Schema
                   `handoff.state` enum; reaper.go implements lease-expiry requeue (attempts<max→ready,
                   attempts>=max→terminal failed state) separately from claim-timeout expiry (→'expired',
                   payload dropped, row kept).
Validation/evidence required: A concurrency test spawning two goroutines racing to claim the same fingerprint —
                   exactly one succeeds; a clock-manipulation test proving lease expiry and claim-timeout
                   expiry fire independently and produce different state transitions.
Stop condition:    The concurrency test and the two independent-clock tests pass, and no code path references
                   `shred`, `rm -P`, or any claim of cryptographic erasure.
Why this model:    Default strong worker: research/08 fully specifies the primitives (renameat2, OFD locks,
                   O_TMPFILE) — this is implementation against a documented protocol, not invention.
```

```
Step ID:          R.8
Phase/group:      parallel group 1
Depends on:       R.1
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the secrets-masking pipeline that strips live session cookies and bearer tokens from
                   `webRequest`/`webResponse` headers and bodies before the record reaches the store or any
                   model context.
Scope and files:  READ: research/18-unified-audit-record.md (Risk #10, the ZAP masking precedent — 8KB
                   request/32KB response caps, Authorization header masking); this document's Record Field
                   Contract (anvil/trust field).
                   WRITE: internal/record/mask.go, internal/record/mask_test.go.
Forbidden actions: Do not log or persist an unmasked value anywhere, even transiently, before the mask step
                   runs. Do not run masking after the record is written to the DB or handed to any model
                   context — masking must be the last step of assembly, before either sink, not a post-hoc
                   scrub. Do not treat the 8-hour claim timeout as a substitute for masking — a still-valid
                   token is exploitable for the full window regardless of retention policy.
Inputs/artifact refs: The header-name denylist (Authorization, Cookie, Set-Cookie, Proxy-Authorization,
                   X-Api-Key, and any header matching `*token*`/`*secret*` case-insensitively) and the
                   8KB/32KB body caps from research/18.
Expected output schema: mask.go exposes `MaskRecord(*sarifLog) error` that redacts denylisted headers to
                   `***REDACTED***` and truncates bodies at the documented caps, spilling the remainder to a
                   Tier-2 blob reference rather than dropping it.
Validation/evidence required: A test fixture containing a live-looking bearer token and session cookie in
                   `webRequest.headers` and a stack trace containing no secrets in `webResponse.body`; after
                   masking, the serialized record contains zero occurrences of the planted token/cookie values
                   anywhere in the output, verified by a substring-absence assertion.
Stop condition:    The substring-absence assertion passes for at least three distinct secret-shaped fixtures
                   (bearer token, session cookie, API key in a query parameter).
Why this model:    Default strong worker: the masking rule and the header denylist are fully specified by
                   research/18's ZAP precedent — bounded implementation, not architecture.
```

```
Step ID:          R.9
Phase/group:      parallel group 1
Depends on:       R.1
Backend/model:    Claude Code subagent (haiku)
Objective:        Write the retention-and-deletion honesty document: transcribe research/08's already-sourced
                   findings that `shred` does not work on the filesystems Anvil will run on, and that LUKS2/
                   fscrypt (not `shred`) is the actual confidentiality control if one is required.
Scope and files:  READ: research/08-buffer-and-handoff.md (Risks: "`shred` is folklore for this use case",
                   "`systemd-tmpfiles` has a demonstrated data-loss foot-gun", "`fscrypt` protects less than
                   people assume", "Two copies is the real security risk").
                   WRITE: internal/record/SECRETS.md.
Forbidden actions: Do not claim `shred` achieves secure deletion on Btrfs, ZFS, XFS, NTFS, ext3/4 journal mode,
                   compressed filesystems, RAID, snapshotting filesystems, NFSv3 clients, or SSDs — research/08
                   already sources this negative claim; do not soften it. Do not recommend
                   `systemd-tmpfiles --purge` without a scoped config file. Do not add any new, unsourced
                   security claim — every sentence in SECRETS.md must trace to a quoted or closely paraphrased
                   finding already in research/08.
Inputs/artifact refs: research/08's exact quotes: "'overwritten' data blocks are still present in the
                   underlying device" (SSD wear-levelling); the systemd 256 `--purge` `/home`-deletion incident.
Expected output schema: A short markdown document stating plainly: (1) the tmpfs packet and the DB payload are
                   not securely erased by any code in this repository, (2) if confidentiality-at-rest is a
                   requirement, the control is a per-scan LUKS2 volume or fscrypt, not application-level
                   deletion, (3) the 8-hour/claim-timeout window is a latency bound, not a confidentiality
                   guarantee.
Validation/evidence required: Every claim in SECRETS.md is traceable to a specific quoted sentence in
                   research/08 (cite the sentence).
Stop condition:    SECRETS.md exists, contains no unsourced claims, and explicitly states the LUKS2/fscrypt
                   alternative.
Why this model:    Mechanical transcription of already-quoted, already-verified research findings into a short
                   doc — bounded, checkable against the source quotes, exactly the "docs" and "compact
                   verification" use case the routing table reserves for haiku.
```

### Serial — Critic Gate 2

```
Step ID:          R.10
Phase/group:      serial
Depends on:       R.6, R.7, R.8, R.9
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Cross-family critique of per-half sealing, the handoff claim protocol, and secrets masking —
                   the security-relevant, data-loss-relevant core of the store.
Scope and files:  READ: internal/record/sealing.go, internal/handoff/*.go, internal/record/mask.go,
                   internal/record/SECRETS.md, and their tests; 00-SPINE.md S1, S6, S7.
                   WRITE: internal/handoff/CRITIQUE-02.md.
Forbidden actions: Do not modify any of the reviewed files directly. Do not approve a design that can expire a
                   live claim, that conflates the claim lease with the claim timeout, or that leaves any code
                   path capable of persisting an unmasked secret.
Inputs/artifact refs: 00-ROUTING.md's mandatory-critic list ("security, migrations, data-loss risk, or
                   authorization decision").
Expected output schema: CRITIQUE-02.md with explicit PASS/FAIL verdicts on: (a) lease vs. claim-timeout
                   independence, (b) no secure-deletion claims present, (c) masking runs before both sinks,
                   (d) re-entrant consumer never reads an unsealed half, (e) reaper never drops a live claim.
Validation/evidence required: All five verdicts PASS, or R.6/R.7/R.8/R.9 rerouted and re-reviewed.
Stop condition:    All-PASS verdict recorded.
Why this model:    Mandatory per 00-ROUTING.md — this cluster is security-relevant, data-loss-relevant, and
                   Anthropic-authored, which the cross-family critique rule names as a hard requirement, not a
                   preference.
```

```
Step ID:          R.11
Phase/group:      serial
Depends on:       R.4, R.10
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the queue re-cut rule: re-cut the work queue on every `anvil/version` bump and
                   reserve a configurable fraction (default 50%) of remaining budget for late DAST-confirmed
                   arrivals.
Scope and files:  READ: 00-SPINE.md S6 ("re-cut the work queue on every version bump and reserve a configurable
                   fraction... otherwise incremental publication silently inverts the priority scheme");
                   research/24-coding-agent-consumption.md (step 9, "Cut the queue").
                   WRITE: internal/store/queue.go, internal/store/queue_test.go.
Forbidden actions: Do not hardcode the 50% reservation fraction — it is a config value with 50% as the
                   documented default. Do not re-cut on every write to `handoff` — only on an `audit_record.
                   audit_version` bump. Do not let the reservation apply to total budget rather than *remaining*
                   budget at re-cut time.
Inputs/artifact refs: This document's Store Schema section (`audit_record.audit_version`, `handoff.state`).
Expected output schema: queue.go exposes `RecutQueue(auditID string, remainingBudgetTokens int) error` that,
                   given a version bump, reserves `config.DastReserveFraction * remainingBudgetTokens` for
                   `evidence_class='dast_confirmed'` items arriving after the previous cut.
Validation/evidence required: A test with a controlled arrival sequence (early SAST-only findings, a late
                   version bump introducing DAST-confirmed findings) asserting the DAST-confirmed items receive
                   at least the configured reservation of *remaining*, not total, budget.
Stop condition:    The arrival-sequence test passes with the default 50% config and with an overridden 25%
                   config, proving the value is read from config, not compiled in.
Why this model:    Default strong worker: the re-cut trigger and the reservation formula are fully specified by
                   S6 — bounded implementation over R.4's schema.
```

### Parallel Group 2 — Correlation, Read Path, GitHub Projection (all depend only on R.1/R.2/R.4; disjoint write scope)

```
Step ID:          R.12
Phase/group:      parallel group 2
Depends on:       R.2, R.4
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the correlation policy: link findings, never merge them; require ≥2 independent
                   signals before emitting any link; require a stack-trace match or a pre/post-patch re-run flip
                   before `verified:true`.
Scope and files:  READ: research/18-unified-audit-record.md ("Correlation policy — link, never merge",
                   including the weighted-signals example in the annotated record); Table 2 in the same document
                   (signal costs and failure modes).
                   WRITE: internal/record/correlation.go, internal/record/correlation_test.go.
Forbidden actions: Do not merge a SAST and a DAST finding into one row under any circumstance — both must
                   survive independently in the record. Do not emit a cluster link on a CWE-only match — CWE
                   match is banned as a sole signal; require at least one additional independent signal from
                   Table 2 (route table, call-graph reachability, parameter-name match, or a stack-trace
                   string). Do not set `verified:true` on a clean SAST rescan alone — only a response
                   stack-trace naming the SAST file, or a post-patch reproduction re-run that flips from failing
                   to passing, qualifies (00-SPINE.md S7).
Inputs/artifact refs: This document's Open Questions entry on the US10043004B2 patent — this step must NOT
                   attempt to resolve that question; it implements the policy as specified and flags the patent
                   risk in a code comment pointing at this document.
Expected output schema: correlation.go exposes `Correlate(sast, dast []Result) []Cluster` where each Cluster
                   carries `signals []Signal`, `confidence float64`, `verified bool`, `merged bool` (always
                   false), matching the anvil/correlation shape in R.1's contract.
Validation/evidence required: A test asserting a CWE-only match produces zero clusters; a test asserting
                   `verified:true` requires a stack-trace-match or re-run-flip signal specifically, not
                   confidence alone.
Stop condition:    Both tests pass and `merged` is unconditionally `false` in every code path.
Why this model:    Default strong worker: the link-never-merge policy, the ≥2-signal rule, and the verified:true
                   criteria are fully specified by branch 18's Recommendation — bounded implementation.
```

```
Step ID:          R.13
Phase/group:      parallel group 2
Depends on:       R.1, R.2
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the three-tier read path for the coding agent: Tier 0 manifest (≤8KB), Tier 1 task
                   cards (≤~2,500 tokens each, derived and self-contained), Tier 2 content-addressed blobs.
Scope and files:  READ: research/18-unified-audit-record.md ("Size — the three-tier read path", the annotated
                   task-card example); research/24-coding-agent-consumption.md ("What the audit record must
                   carry", listing evidence_class, locus, group_id, fingerprints, advisory_excerpt).
                   WRITE: internal/record/readpath.go, internal/record/taskcard.go,
                   internal/record/readpath_test.go.
Forbidden actions: Do not exceed the 8KB Tier-0 manifest budget or the ~1,500–2,500 token Tier-1 card budget
                   without an explicit, logged override. Do not inline full response bodies past the 8KB
                   request/32KB response caps enforced by R.8's masking step — spill the remainder to a Tier-2
                   blob referenced by `sha256:` digest. Do not have the agent's default read order be anything
                   other than: correlated clusters first, then SAST-only by rank, then DAST-only.
Inputs/artifact refs: research/24's non-negotiable handoff fields: `finding_id`, `fingerprint.
                   primary_location_line_hash`, `fingerprint.region_sha256`, `evidence_class`, `dast.
                   reproduction`, `risk.*`, `locus.*`, `advisory_excerpt` (≤800 tokens), `group_id`.
Expected output schema: readpath.go exposes `BuildManifest(auditID string) (Manifest, error)` and
                   `BuildTaskCards(auditID string) ([]TaskCard, error)`; each TaskCard round-trips through
                   R.1's schema and stays under the documented token budget (measured via a token-count
                   approximation, not a hard requirement on an exact tokenizer).
Validation/evidence required: A test asserting every generated TaskCard is ≤2,500 tokens (approximate count) and
                   that the deterministic read order (clusters → SAST-by-rank → DAST-by-rank) is stable across
                   repeated calls on the same input.
Stop condition:    The budget test and the deterministic-order test pass on a fixture record with at least one
                   correlated cluster, several SAST-only findings, and one DAST-only finding.
Why this model:    Default strong worker: the tier boundaries, budgets, and read order are fully specified by
                   branch 18 and branch 24 — bounded implementation, not invention.
```

```
Step ID:          R.14
Phase/group:      parallel group 2
Depends on:       R.1, R.2
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the reduced-SARIF GitHub projection: a lossy view containing only results with a
                   physical code location and a populated `partialFingerprints.primaryLocationLineHash`, capped
                   under GitHub's documented limits.
Scope and files:  READ: research/18-unified-audit-record.md ("What GitHub actually accepts — hard numbers",
                   "What Anvil loses by choosing SARIF" — the reduced-SARIF design rule).
                   WRITE: internal/record/sarif_github.go, internal/record/sarif_github_test.go.
Forbidden actions: Do not upload `webRequest`, `webResponse`, `taxonomies`-as-relationships, `provenance`, or
                   any anvil/* property bag in the GitHub projection — GitHub silently ignores them, and relying
                   on silent ignoring rather than explicit stripping risks size-limit failures on large payloads
                   that GitHub would otherwise reject outright. Do not include a DAST-only result with no
                   `startLine` — GitHub requires one. Do not exceed 25,000 results/run, 10MB gzip, or 20 runs/
                   file; shard by run rather than truncate results when the cap would be exceeded.
Inputs/artifact refs: GitHub's documented limits from research/18: "10 MB gzip-compressed file; 20 runs per
                   file; 25,000 results per run (only the top 5,000 by severity are displayed)... GitHub uses
                   only partialFingerprints.primaryLocationLineHash".
Expected output schema: sarif_github.go exposes `ProjectForGitHub(*sarifLog) ([]GitHubSarifFile, error)`
                   returning one or more sharded files, each under the documented caps, each containing only
                   results with a physical location.
Validation/evidence required: A test with a fixture exceeding 25,000 results asserts the output is sharded into
                   multiple files, none exceeding the cap, and that DAST-only results (no physical location) are
                   excluded with a logged count rather than silently dropped.
Stop condition:    The sharding test and the DAST-exclusion-is-logged test both pass.
Why this model:    Default strong worker: the projection rules and caps are fully enumerated by branch 18 —
                   bounded implementation of a well-specified filter/shard transform.
```

### Serial — Critic Gate 3 And Remaining Deliverables

```
Step ID:          R.15
Phase/group:      serial
Depends on:       R.11, R.12, R.13, R.14
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Cross-family critique of the correlation implementation (flagging, not resolving, the
                   US10043004B2 patent-risk comment), the GitHub projection's cap compliance, and the queue
                   re-cut correctness.
Scope and files:  READ: internal/record/correlation.go, internal/store/queue.go, internal/record/sarif_github.go
                   and their tests; research/18-unified-audit-record.md Risk #1 (the patent); this document's
                   Open Questions entry on the same patent.
                   WRITE: internal/record/CRITIQUE-03.md.
Forbidden actions: Do not attempt to resolve the patent question — that is an owner/legal decision, out of
                   scope for any worker in this plan. Do not approve a GitHub projection that could exceed a
                   documented cap on any input size. Do not approve a queue re-cut implementation with a
                   hardcoded reservation fraction.
Inputs/artifact refs: 00-ROUTING.md's mandatory critic requirement for "a licence conclusion" (the patent
                   comment counts) and for the migration/queue-adjacent logic.
Expected output schema: CRITIQUE-03.md with PASS/FAIL verdicts on: (a) correlation.go carries a code comment
                   pointing at this document's patent Open Question without attempting to resolve it, (b)
                   sarif_github.go cannot exceed GitHub's caps on any tested input, (c) queue.go's reservation
                   fraction is config-driven.
Validation/evidence required: All three verdicts PASS or the relevant step is rerouted.
Stop condition:    All-PASS verdict recorded.
Why this model:    Mandatory per 00-ROUTING.md: this cluster touches a licence/legal conclusion (the patent) and
                   is Anthropic-authored — cross-family critique is a hard requirement, not a preference; paid
                   route justified by high-stakes, unresolved-conflict judgment.
```

```
Step ID:          R.16
Phase/group:      serial
Depends on:       R.2, R.3
Backend/model:    Claude Code subagent (sonnet)
Objective:        Ship the spine-mandated conformance test asserting identical fingerprint digests on a fixed
                   corpus, computed independently of the implementation under test, to guard against two
                   producers silently diverging.
Scope and files:  READ: 00-SPINE.md S6 ("Ship a conformance test asserting identical digests on a fixed
                   corpus"); testdata/fingerprint_corpus/*.json (from R.2); internal/record/fingerprint.go.
                   WRITE: internal/record/fingerprint_conformance_test.go,
                   testdata/fingerprint_corpus/*.golden, scripts/compute_golden_fingerprints.py (or equivalent
                   offline script — not Go, and not calling internal/record/fingerprint.go, so the oracle is
                   independent of the code it checks).
Forbidden actions: Do not compute the golden digests by calling the Go implementation under test — that is
                   circular and defeats the point of a conformance test. Do not skip any corpus fixture. Do not
                   let this test import internal/record/fingerprint.go's internals for the *oracle* generation
                   step (the test itself may call the public function to compare against the golden value, but
                   the golden value's origin must be independent).
Inputs/artifact refs: This document's Fingerprint Specification section (the exact algorithm, byte-for-byte, is
                   what the offline script must reimplement independently).
Expected output schema: A committed `.golden` file per corpus fixture containing its expected 64-hex-char
                   digest, produced by re-implementing the algorithm text (not by importing Go code); a Go test
                   that loads each fixture, computes the digest via `internal/record/fingerprint.go`, and
                   asserts byte-for-byte equality against the `.golden` file.
Validation/evidence required: `go test ./internal/record/... -run Conformance` passes; the offline script and
                   the Go implementation are demonstrably two independent code paths (different language or, at
                   minimum, no shared function).
Stop condition:    Every corpus fixture's Go-computed digest matches its independently-computed golden digest
                   exactly, and the test is wired into CI to run on every change to fingerprint.go.
Why this model:    Default strong worker: this is the specific spine-mandated safeguard against the exact
                   failure mode ("two producers emitting different digests... silently fails forever") — bounded,
                   high-stakes correctness work justifying sonnet over haiku despite its mechanical shape.
```

```
Step ID:          R.17
Phase/group:      serial
Depends on:       R.1, R.2, R.3, R.4, R.5, R.6, R.7, R.8, R.9, R.10, R.11, R.12, R.13, R.14, R.15, R.16
Backend/model:    OpenCode route (openai/gpt-5.5)
Objective:        Final integration critique and exit-criteria gate for the entire Record And Storage area:
                   verify every 00-SPINE.md S6 field appears end-to-end in a synthetic record, per-half sealing
                   is observable, the storage collapse is honored (no second durable buffer file exists
                   anywhere in the tree), migrations and guards are tested, fingerprint conformance is green, and
                   secrets are masked before storage.
Scope and files:  READ: this entire document; internal/record/*, internal/store/*, internal/handoff/*,
                   schemas/anvil-record-v1.schema.json, all CRITIQUE-*.md files from R.3/R.10/R.15.
                   WRITE: internal/record/EXIT-GATE-REPORT.md.
Forbidden actions: Do not modify any implementation file — this is synthesis and verification only. Do not mark
                   the area done if any Exit Criteria item in this document fails. Do not silently drop a
                   limitation — state it in the report.
Inputs/artifact refs: This document's Exit Criteria section, used verbatim as the checklist.
Expected output schema: EXIT-GATE-REPORT.md with one line per Exit Criteria item: PASS, FAIL (with the failing
                   command/assertion), or N/A with justification; cites the specific test or file that provides
                   the evidence for each PASS.
Validation/evidence required: Every Exit Criteria item is either PASS with cited evidence or explicitly FAIL
                   with a remediation pointer back to the owning step (R.1–R.16).
Stop condition:    EXIT-GATE-REPORT.md is complete; any FAIL is routed back to its owning step and this gate is
                   re-run until all-PASS or all remaining items are explicitly deferred with owner sign-off
                   (e.g., the patent question).
Why this model:    Required by 00-ROUTING.md's review-gates table ("Final synthesis: cites worker evidence and
                   states limitations") and the cross-family critique rule, since the entire area is
                   Anthropic-authored; gpt-5.5 justified as the final high-stakes judgment call before this
                   interface freezes for every downstream area.
```

## Record Field Contract

Every field below names its wire location, whether it is native SARIF 2.1.0 or an Anvil `anvil/*` extension,
whether it is required, who writes it, and who reads it. Fields marked **NEW** are the ones `00-SPINE.md` S6
flagged as absent from branch 18's original design.

### Audit envelope (`sarifLog.properties`)

| Field | SARIF-native or extension | Required? | Producer | Consumer |
|---|---|---|---|---|
| `$schema` / `version` | SARIF-native | required, pinned to `2.1.0` exactly | record assembler | any SARIF consumer, GitHub, DefectDojo |
| `anvil/schemaVersion` | anvil/* | required | record assembler | store, migrations, coding agent |
| `anvil/auditId` | anvil/* | required | scan controller (at scan start) | store (PK), handoff, coding agent, report |
| `anvil/state` **NEW** | anvil/* | required — enum `collecting\|sast_sealed\|dast_sealed\|both_sealed\|consumed\|expired` | scan controller | handoff consumer, store, report |
| `anvil/version` **NEW** | anvil/* | required — monotonic int, bumped on every re-scan of the same audit | scan controller | queue re-cut logic (R.11) |
| `anvil/createdAt` | anvil/* | required | scan controller | store, reaper |
| `anvil/target.{repoUrl,ref,commit,subpath,runtimeBaseUrl}` | anvil/* | required (runtimeBaseUrl only if DAST enabled) | scan controller | coding agent, correlation, report |
| `anvil/target.provenance` **NEW** (`target_provenance`) | anvil/* | required — enum `booted_clean\|boot_failed\|build_failed\|no_target_declared\|unreachable_at_scan_time` | target lifecycle harness (owned by a different area; this area only reserves the field) | coding agent, `dast_status` derivation, report |
| `anvil/trigger.*` | anvil/* | required | scan controller | report, audit trail |
| `anvil/deadline.deadlineAt` (replaces branch 18's `anvil/buffer.expiresAt`, per S1 correction) | anvil/* | required, = `scan_run.started_at + claimTimeoutSeconds`, never recomputed | scan controller, computed once at scan START | reaper, handoff, coding agent |
| `anvil/deadline.claimTimeoutSeconds` | anvil/* | required, default 28800 (8h), config-driven | config loader | reaper |
| `anvil/deadline.dastDeadlineSeconds` **NEW** (`dast_deadline`) | anvil/* | optional (null if DAST disabled), config-driven, independent clock from claimTimeoutSeconds | config loader | DAST worker, target lifecycle harness |
| `anvil/db.recordId` / `.writtenAt` | anvil/* | required after DB commit | store writer | audit trail |
| `anvil/index.*` (Tier-0 manifest: counts, readOrder, byCluster, byCwe, byPath) | anvil/* | required | record assembler | coding agent (Tier 0 read) |
| `anvil/dastStatus` **NEW** (`dast_status`, audit-level mirror of the per-run value) | anvil/* | required, never null — enum `not_run\|running\|completed_clean\|completed_findings\|target_boot_failed\|target_unreachable\|timed_out` | scan controller (derived from the DAST run's per-half status + target_provenance) | coding agent (must not treat an absent DAST half as "scanned clean"), report |

### Per-half run (`run.automationDetails`, `run.properties`)

| Field | SARIF-native or extension | Required? | Producer | Consumer |
|---|---|---|---|---|
| `run.automationDetails.correlationGuid` | SARIF-native (§3.17.5) | required, identical value in both runs | record assembler | correlation/cluster logic |
| `run.properties["anvil/half"]` | anvil/* | required — `sast` or `dast` | SAST/DAST worker | routing |
| `run.properties["anvil/status"]` **NEW** (per-half `status`) | anvil/* | required — enum `running\|sealed\|failed\|skipped` | SAST/DAST worker at seal time | re-entrant consumer, report |
| `run.properties["anvil/sealedAt"]` **NEW** (per-half `sealedAt`) | anvil/* | required once status=`sealed`, else null | SAST/DAST worker | re-entrant consumer read-gate, deadline math |
| `run.properties["anvil/dastCoverage"]` **NEW** (`dast_coverage`, consolidated with `endpoint_coverage`/`inventory_provenance` — see Open Questions #5) | anvil/* | required on the DAST run — `{probedCount, inventoryUnionCount, inventoryProvenanceMix}` (numerator + provenance mix, never a bare ratio, per research/14 critique m6) | attack-surface-discovery subsystem (different area; field reserved here) | coding agent (confidence weighting), report |
| `run.properties["anvil/routeTableDigest"]` | anvil/* | required on DAST run | DAST worker | audit trail, correlation replay |
| `run.properties["anvil/advisorySnapshot"]` | anvil/* | required on SAST run | ingestion subsystem (different area) | coding agent (staleness), report |
| `run.properties["anvil/runtimeTarget"]` | anvil/* | required on DAST run | DAST worker | correlation, repro replay |

### Per-finding result (`result.*`)

| Field | SARIF-native or extension | Required? | Producer | Consumer |
|---|---|---|---|---|
| `result.correlationGuid` | SARIF-native (§3.27.4) | required only for clustered findings | correlation engine (R.12) | consumer clustering |
| `physicalLocation.region` + `.contextRegion` + `region.snippet` | SARIF-native | required for SAST, absent for pure-DAST | detector | coding agent (Tier 1 card) |
| `logicalLocations[]` | SARIF-native | required when a symbol resolves | detector | coding agent |
| `result.taxa[]` / `run.taxonomies[]` (CWE) | SARIF-native (§3.8.2-preferred over tags) | required | detector | coding agent, report |
| `result.webRequest` / `.webResponse` | SARIF-native (§3.27.14/15) | required for DAST findings, **masked by R.8 before storage** | DAST worker → masking pipeline | coding agent, verification replay |
| `result.partialFingerprints["anvilFindingId/v1"]` | SARIF-native mechanism, Anvil-defined value | required | fingerprint engine (R.2) | store identity join, regression engine |
| `result.partialFingerprints["primaryLocationLineHash"]` | SARIF-native mechanism | required when a physical location exists | fingerprint engine | GitHub upload path only (R.14) |
| `result.provenance.*` | SARIF-native (§3.48) | required | store (on read-back) | regression history, report |
| `result.fixes[]` | SARIF-native (§3.27.30) | written only after a coding-agent proposal | coding agent (different area) | PR generator, verification |
| `result.properties["anvil/findingId"]` | anvil/* | required | record assembler | cross-reference (task cards, DB) |
| `result.properties["anvil/half"]` | anvil/* | required | detector | routing |
| `result.properties["anvil/confidence"]` | anvil/* | required | detector model | ranking, report |
| `result.properties["anvil/verdict"]` **NEW** (`INSUFFICIENT_CONTEXT` as a valid verdict) | anvil/* | required — enum `true_positive\|false_positive\|insufficient_context` | detector model / triage gate | coding agent consumption pipeline (drops `false_positive`, demotes `insufficient_context` to report-only) |
| `result.properties["anvil/remediableByAgent"]` **NEW** (`remediable_by_agent`) | anvil/* | required, boolean; **host findings are always `false`** | record assembler (derived from `detector`) | coding agent (never attempts host fixes — S7 read-only host agent) |
| `result.properties["anvil/reasoning"]` | anvil/* | required | detector model | report, coding agent context |
| `result.properties["anvil/detector"]` | anvil/* | required | detector model | audit trail, prompt-digest replay |
| `result.properties["anvil/advisory"]` (+ `.asOf`, `.stalenessSeconds`, `.parseDegraded` **NEW**) | anvil/* | required when an advisory is linked | ingestion subsystem at record-assembly time | coding agent (down-weight stale/degraded context), report |
| `result.properties["anvil/trust"]` **NEW** — on every string sourced outside Anvil | anvil/* | required — enum `untrusted\|anvil_generated\|verified` | whichever component ingests the external string (advisory text, DAST response bodies, third-party SARIF imports) | prompt builder (must never treat `untrusted` text as instructions — S7 prompt-injection containment), report |
| `result.properties["anvil/patchContext"]` | anvil/* | required | record assembler | coding agent |
| `result.properties["anvil/correlation"]` | anvil/* | required only for clustered findings | correlation engine (R.12) | coding agent (peer lookup), report |
| `result.properties["anvil/repro"]` (+ `.env.sanitizers[]`, `.env.aslrEnabled` **NEW**) | anvil/* | required on any reproducer (DAST or dynamic-analysis) | DAST worker / dynamic-analysis harness (different area; field reserved here) | verification pipeline (S7: only a DAST reproduction that now fails earns "verified fixed" — sanitizer/ASLR state qualifies that claim) |
| `result.properties["anvil/chunkRef"]` | anvil/* | required | task-card generator (R.13) | coding agent (Tier 1 pointer) |
| `result.properties["anvil/evidenceClass"]` (mirrors research/24's `evidence_class`) | anvil/* | required — enum `dast_confirmed\|sast_reachable\|sast_static_only\|sca\|host` | record assembler (derived from detector + correlation state) | ranking (R.11 queue re-cut), coding agent |
| `result.properties["anvil/locus"].proximityClass` | anvil/* | required for SAST findings | record assembler | fix-grouping (coding-agent consumption area) |
| `result.properties["anvil/groupId"]` | anvil/* | key reserved here; **assigned by the coding-agent consumption pipeline, not this area** | coding agent | coding agent (self-consumed) |

## Fingerprint Specification

**Conflict resolved.** research/07 §3 and research/18 "Stable identity" specify two different `anvil-fp/v1`
formulas under the same name. This is precisely the failure `00-SPINE.md` S6 warns about — "two producers
emitting different digests means regression matching silently fails forever" — so it is resolved once, here,
and every future producer implements exactly this.

**Resolution and why:**

- **Separator:** research/07's explicit `U+001F` (ASCII Unit Separator) wins over research/18's undefined `‖`
  glyph. A literal character can appear inside a snippet or symbol name and create a field-boundary collision;
  `U+001F` cannot appear in normalized source text.
- **Ordinal:** research/07's `ordinal` (index among identical matches in the same file) is adopted. Branch 18's
  SAST formula lacks it, which means two identical macro-expanded call sites in one file would silently hash
  to the same fingerprint and one finding would be lost on upsert.
- **`advisory_id_or_empty` in the SAST hash:** research/07 includes it; this spec **excludes** it, matching
  branch 18. Identity should track "this exact defect in this exact code." If Anvil's ingestion later attaches
  a more specific advisory to a sink that was previously linked only to a generic CWE, that reclassification
  must not fork the finding's identity.
- **Truncation:** research/07 truncates the stored hash to 32 hex characters "for storage." This spec does
  **not** truncate — SQLite's storage cost for a 64- vs. 32-character `TEXT` column is negligible, and
  truncating a cryptographic digest without a forcing constraint only adds collision risk for no benefit.
- **Normalization depth:** research/07's metavariable-abstraction approach (literals → `<STR>`/`<NUM>`,
  identifiers → positional `$1..$N`) is adopted over branch 18's shallower whitespace/comment-only
  normalization, because it is the one directly modeled on Semgrep's `match_based_id`, which is the cited,
  externally-verified mechanism for surviving reindentation and metavariable-only edits.
- **DAST evidence class:** branch 18's `evidenceClass` (how the vulnerability was observed — stack trace,
  status-code flip, timing, etc.) is a real, distinguishing signal absent from research/07's Tier D. It is
  added as an additional hashed field alongside research/07's `injection_point`/`param_name`, since the two
  concepts (where the payload went in vs. how the defect was observed) are independent.
- **Host findings:** neither source branch defines a fourth tier for host/package findings, but S1 requires
  Lane A to own "dependency and host findings" and S6 requires `remediable_by_agent=false` on all of them —
  they need a defined identity too. This spec generalizes research/07's Tier C (SCA) into one formula
  parameterized by `detector_kind ∈ {sca, host}`, rather than inventing an unrelated scheme.

**The single algorithm — `anvil-fp/v1`:**

```
SEPARATOR = U+001F  (ASCII Unit Separator, "\x1f") — joins every field below, in the listed order.
DIGEST    = lowercase hex-encoded SHA-256 of the joined byte string. Full 64 characters. Never truncated.

Tier SAST  (evidence_class ∈ {sast_reachable, sast_static_only}):
  sha256( target_id ␟ "sast" ␟ rule_id_versioned ␟ repo_relpath ␟ enclosing_symbol_path
        ␟ normalized_match ␟ ordinal )

  normalized_match := strip comments; collapse whitespace runs to a single space;
                       replace string/numeric literals with <STR>/<NUM>;
                       replace local identifiers with positional $1..$N in first-occurrence order.
  ordinal          := 0-based index of this match among all matches of the same rule_id in the same
                       repo_relpath whose normalized_match is IDENTICAL (disambiguates duplicate
                       macro-expanded or generated call sites that would otherwise collide).

  NEVER hashed: line number, column number, the literal (non-normalized) snippet text, advisory_id.

Tier SCA/HOST (evidence_class ∈ {sca, host}; detector_kind is 'sca' for repo dependencies, 'host' for
              host packages):
  sha256( target_id ␟ detector_kind ␟ advisory_id ␟ purl_base ␟ locator )

  locator := manifest_relpath (sca) | "<package_manager>:<host_identifier>" (host, e.g. "apt:openssl").
  NEVER hashed: the version string — bumping 1.2.3→1.2.4 while still inside the vulnerable range must
                not mint a new finding; resolution is proved by re-evaluating advisory_affects, not by
                identity change.

Tier DAST  (evidence_class = dast_confirmed):
  sha256( target_id ␟ "dast" ␟ rule_id_versioned ␟ http_method ␟ route_template
        ␟ injection_point ␟ param_name ␟ evidence_class_detail )

  route_template        := numeric/UUID/hash path segments replaced with a placeholder token.
  injection_point        ∈ {query, body, header, cookie, path} — WHERE the payload was injected.
  evidence_class_detail  ∈ {responseStackTrace, statusCodeFlip, dbErrorString, timingSideChannel,
                             reflectedPayload, other} — HOW the vulnerability was observed.
  NEVER hashed: host, port, scheme, the concrete payload string, any timestamp.
```

**Conformance test (R.16, spine-mandated).** A fixed corpus of at least six fixtures (≥2 SAST, 1 SCA, 1 host,
≥2 DAST) is checked into `testdata/fingerprint_corpus/*.json`. Their expected digests are computed
**independently of the Go implementation under test** — by a small offline script that re-implements the
algorithm text above from scratch, not by importing `internal/record/fingerprint.go` — and committed as
`testdata/fingerprint_corpus/*.golden`. The conformance test asserts byte-for-byte equality between the Go
implementation's output and the golden digest for every fixture. A mutation sub-test additionally asserts that
changing only a fixture's line/column number leaves its digest unchanged. This is the mechanism that would
have caught research/07 and research/18 shipping two different `/v1` algorithms under one name.

**Algorithm migration protocol** (unchanged from research/07, both sources agree): when `anvil-fp/v2` ships,
dual-write both `v1` and `v2` values into `finding_fingerprint` for one full retention cycle, match on
`v1 OR v2`, then retire `v1`. This matches SARIF's own normative convention that an unversioned string is
"considered older than any corresponding string with a version component."

## Store Schema

One SQLite database, WAL mode, single writer, per `00-SPINE.md` S1/S12. Connection pragmas (resolving a second
research-branch conflict — see below):

```sql
PRAGMA journal_mode = WAL;         -- one writer, unlimited readers
PRAGMA foreign_keys = ON;          -- off by default in SQLite; this schema depends on it
PRAGMA busy_timeout = 10000;
PRAGMA synchronous = NORMAL;       -- resolved: research/07 recommends NORMAL (the documented standard WAL
                                   -- pairing); research/08 recommends FULL without WAL-specific justification
                                   -- (its own text calls FULL "the default", not a reasoned WAL choice).
                                   -- NORMAL+WAL is crash-safe for the database file; the risk it accepts is
                                   -- losing the most recent commit(s) on power loss, not corruption — an
                                   -- acceptable trade for a tool whose durable identity lives in `finding`,
                                   -- not in any single scan's payload.
PRAGMA wal_autocheckpoint = 1000;
```

**Startup guards (R.5), both mandatory:** refuse to start if the data directory is on a network-mounted
filesystem ("WAL does not work over a network filesystem"); refuse to start if an `FTS5` smoke-test virtual
table cannot be created — do not merely trust `00-SPINE.md` S12's "orchestrator-verified" claim about
`modernc.org/sqlite`'s FTS5 support, since the research trail backing that claim (`plan/spine-c-language.md`,
citation C5–C7) itself grades its own evidence for FTS5 presence as "B — absence-of-evidence, not
evidence-of-absence." The guard is the actual safety net; the spine claim is not self-verifying.

**Carried forward unchanged from `research/07-database-design.md` §2** (full DDL there; not repeated here to
keep this document reviewable — R.4 reads that file directly): `advisory`, `advisory_alias`, `advisory_fts`,
`component`, `advisory_affects`, `target`, `trigger_policy`, `ingest_watermark`, `code_location`,
`finding_fingerprint`, `finding_state_event`, `fix_attempt`, `verification`, `suppression`, `file_state`,
`schema_migration`.

**Changed or new tables** (S1 collapse + S6 fields):

```sql
-- ============ SCAN RUN — unchanged shape from research/07 ============
CREATE TABLE scan_run (
  scan_run_id       INTEGER PRIMARY KEY,
  target_id         INTEGER NOT NULL REFERENCES target(target_id),
  policy_id         INTEGER REFERENCES trigger_policy(policy_id),
  trigger_ref       TEXT,
  commit_sha        TEXT,
  started_at        TEXT NOT NULL,          -- anvil/deadline.deadlineAt is computed from THIS, never last write
  finished_at       TEXT,
  status            TEXT NOT NULL,          -- 'running'|'ok'|'failed'|'partial'
  sast_engine_ver   TEXT,
  dast_engine_ver   TEXT,
  ruleset_version   TEXT NOT NULL,
  advisory_snapshot TEXT,
  rollup_hash       TEXT
);
CREATE INDEX idx_scan_target_time ON scan_run(target_id, started_at DESC);
CREATE INDEX idx_scan_running     ON scan_run(target_id) WHERE status = 'running';

-- ============ AUDIT RECORD — the collapsed store (S1: no second durable buffer file) ============
CREATE TABLE audit_record (
  audit_record_id       INTEGER PRIMARY KEY,
  scan_run_id            INTEGER NOT NULL UNIQUE REFERENCES scan_run(scan_run_id),
  schema_version          TEXT NOT NULL,           -- anvil/schemaVersion
  audit_version           INTEGER NOT NULL DEFAULT 1,  -- anvil/version; a bump triggers R.11's queue re-cut
  state                   TEXT NOT NULL,           -- anvil/state: collecting|sast_sealed|dast_sealed|both_sealed|consumed|expired
  sast_status             TEXT,                    -- per-half status
  sast_sealed_at          TEXT,
  dast_status             TEXT NOT NULL DEFAULT 'not_run',  -- NEW S6: never NULL, never silently 'completed_clean'
  dast_sealed_at          TEXT,
  dast_coverage_json      TEXT,                    -- NEW S6: {probedCount, inventoryUnionCount, inventoryProvenanceMix}
  target_provenance       TEXT NOT NULL,           -- NEW S6: booted_clean|boot_failed|build_failed|no_target_declared|unreachable_at_scan_time
  deadline_at             TEXT NOT NULL,           -- = scan_run.started_at + claim_timeout_seconds. NEVER recomputed.
  claim_timeout_seconds   INTEGER NOT NULL DEFAULT 28800,  -- 8h default, configurable (this is a claim timeout, not a deletion policy)
  dast_deadline_seconds   INTEGER,                 -- NEW S6: configurable, independent clock from claim_timeout_seconds
  payload                 BLOB,                    -- zstd(canonical SARIF JSON); NULLed by the reaper at deadline_at
  payload_sha256          TEXT NOT NULL,           -- survives payload deletion: proof of what was handed over
  created_at              TEXT NOT NULL,
  consumed_at             TEXT,
  purged_at               TEXT
);
CREATE INDEX idx_audit_deadline ON audit_record(deadline_at) WHERE purged_at IS NULL;
CREATE INDEX idx_audit_state    ON audit_record(state);

-- ============ FINDING — extended from research/07 with S6/S24 fields ============
CREATE TABLE finding (
  finding_id          INTEGER PRIMARY KEY,
  target_id           INTEGER NOT NULL REFERENCES target(target_id),
  fingerprint          TEXT NOT NULL,            -- anvil-fp/v1, full 64-hex SHA-256, never truncated
  fingerprint_alg      TEXT NOT NULL DEFAULT 'anvil-fp/v1',
  detector             TEXT NOT NULL,            -- 'sast'|'dast'|'sca'|'host'
  evidence_class       TEXT NOT NULL,            -- 'dast_confirmed'|'sast_reachable'|'sast_static_only'|'sca'|'host'
  rule_id              TEXT NOT NULL,
  verdict              TEXT NOT NULL DEFAULT 'true_positive',  -- NEW S6: 'true_positive'|'false_positive'|'insufficient_context'
  remediable_by_agent  INTEGER NOT NULL,         -- NEW S6: 0/1; host findings are ALWAYS 0 (S7 read-only host agent)
  advisory_id          TEXT REFERENCES advisory(advisory_id),
  component_id         INTEGER REFERENCES component(component_id),
  severity             TEXT NOT NULL,
  title                TEXT NOT NULL,
  state                TEXT NOT NULL,            -- 'open'|'resolved'|'suppressed'|'regressed'
  first_seen_scan      INTEGER NOT NULL REFERENCES scan_run(scan_run_id),
  first_seen_at        TEXT NOT NULL,
  last_seen_scan       INTEGER REFERENCES scan_run(scan_run_id),
  last_seen_at         TEXT,
  resolved_at          TEXT,
  resolved_by_fix      INTEGER,
  UNIQUE (target_id, fingerprint),
  CHECK (detector != 'host' OR remediable_by_agent = 0)
);
CREATE INDEX idx_finding_state   ON finding(target_id, state, severity);
CREATE INDEX idx_finding_evclass ON finding(target_id, evidence_class);
CREATE INDEX idx_finding_verdict ON finding(verdict) WHERE verdict != 'true_positive';
CREATE INDEX idx_finding_adv     ON finding(advisory_id) WHERE advisory_id IS NOT NULL;
CREATE INDEX idx_finding_comp    ON finding(component_id) WHERE component_id IS NOT NULL;

-- ============ FINDING OCCURRENCE — extended with advisory staleness (S6) ============
CREATE TABLE finding_occurrence (
  occurrence_id               INTEGER PRIMARY KEY,
  finding_id                   INTEGER NOT NULL REFERENCES finding(finding_id) ON DELETE CASCADE,
  scan_run_id                  INTEGER NOT NULL REFERENCES scan_run(scan_run_id) ON DELETE CASCADE,
  location_id                  INTEGER REFERENCES code_location(location_id),
  confidence                   REAL,
  message                      TEXT,             -- hashes/pointers only; oversized inserts rejected by trigger (research/07 Risk #13)
  evidence_ref                 TEXT,              -- pointer INTO the sealed payload; never the raw request/response
  advisory_as_of                TEXT,             -- NEW S6: as_of
  advisory_staleness_seconds     INTEGER,          -- NEW S6: staleness_seconds
  advisory_parse_degraded        INTEGER NOT NULL DEFAULT 0,  -- NEW S6: parse_degraded
  UNIQUE (finding_id, scan_run_id)
);
CREATE INDEX idx_occ_scan ON finding_occurrence(scan_run_id, finding_id);

-- ============ HANDOFF — the collapsed buffer replacement (S1: state/lease/attempts/expiry) ============
CREATE TABLE handoff (
  handoff_id        INTEGER PRIMARY KEY,
  finding_id         INTEGER NOT NULL REFERENCES finding(finding_id) ON DELETE CASCADE,
  audit_record_id     INTEGER NOT NULL REFERENCES audit_record(audit_record_id),
  fingerprint         TEXT NOT NULL,             -- denormalised for the reaper's WHERE clause
  group_id            TEXT,                      -- fix-group id, assigned by the coding-agent consumption pipeline
  state                TEXT NOT NULL DEFAULT 'ready',
                       -- 'ready'|'leased'|'validated'|'failed_validation'|'failed_format'
                       -- |'skipped_budget'|'false_positive'|'regression_introduced'|'expired'
  claimed_by           TEXT,                     -- worker_id
  lease_expires_at      TEXT,                     -- claim lease: 15-30 min, heartbeat-renewed. NOT the claim_timeout above.
  attempts              INTEGER NOT NULL DEFAULT 0,
  max_attempts          INTEGER NOT NULL DEFAULT 2,
  idempotency_key        TEXT UNIQUE,             -- sha256(audit_id‖finding_fingerprint‖base_commit_sha); mirrors the git trailer
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL,
  UNIQUE (finding_id, audit_record_id)
);
CREATE INDEX idx_handoff_ready ON handoff(state) WHERE state = 'ready';
CREATE INDEX idx_handoff_lease ON handoff(lease_expires_at) WHERE state = 'leased';
CREATE INDEX idx_handoff_fp    ON handoff(fingerprint);
```

**Two independent clocks, never conflated (S1):** `handoff.lease_expires_at` (15–30 min, heartbeat-renewed,
governs one coding-agent attempt) and `audit_record.claim_timeout_seconds` (default 8h, config-driven, governs
how long an *unclaimed* finding stays eligible before the reaper drops only the tmpfs packet — the DB row and
`finding`/`finding_state_event` history are never deleted at claim-timeout expiry).

**No second durable buffer file anywhere.** The "buffer" the owner originally specified is `audit_record.
payload`; the "immediate ready set" is `SELECT ... FROM handoff WHERE state='ready'`; the file the coding
agent is actually handed a path to is a regenerable tmpfs packet materialized from this table, never a source
of truth (S1).

## Exit Criteria

1. `internal/record/fingerprint_conformance_test.go` (R.16) passes with zero diffs against the independently
   computed golden corpus on every CI run.
2. A synthetic record containing one SAST finding, one DAST finding, one host finding, and one SCA finding
   validates against `schemas/anvil-record-v1.schema.json` with zero errors, and every field marked "required"
   in the Record Field Contract is present and non-null.
3. The store refuses to start against a network-mounted data directory test fixture, with a documented
   refusal message and a non-zero exit code.
4. The store refuses to start when the FTS5 smoke test (`CREATE VIRTUAL TABLE ... USING fts5(...)`) fails, with
   a documented refusal message and a non-zero exit code — this must be tested independently of the spine's
   "orchestrator-verified" claim about `modernc.org/sqlite`.
5. Applying `migrations/0001_init.sql` through the latest migration to an empty database produces a schema
   whose checksum matches the committed `schema_migration` ledger; re-running the migration set is a no-op.
6. A concurrency test proves the handoff claim protocol: two concurrent claimants racing
   `renameat2(..., RENAME_NOREPLACE)` on the same fingerprint — exactly one succeeds, the other observes a
   typed "already claimed" error.
7. A clock-manipulation test proves lease expiry and claim-timeout expiry are independent: a claimed finding
   whose lease expires with `attempts < max_attempts` returns to `ready` with `attempts+1`; a finding whose
   claim timeout expires drops only the tmpfs payload and leaves the `finding`/`handoff` rows intact.
8. No plaintext `Authorization`/`Cookie`/`Bearer` header or token value is present in any `audit_record.payload`
   blob or any `finding_occurrence` row — verified by a substring-absence test over fixtures containing planted
   secret markers.
9. GitHub SARIF projection output for a fixture exceeding 25,000 results is sharded into multiple files, none
   exceeding 25,000 results/run or 10 MB gzip, and DAST-only results without a physical location are excluded
   with a logged count, never silently dropped.
10. `audit_record.dast_status` distinguishes a DAST-disabled scan (`'not_run'`) from a DAST-enabled scan that
    found nothing (`'completed_clean'`) — both are non-null, well-defined, and never conflated.
11. `finding.remediable_by_agent = 0` is enforced by the `CHECK` constraint for every row where
    `detector = 'host'` — an attempted violating insert raises a constraint error, verified by a unit test.
12. Given a controlled arrival sequence, the queue re-cut function (R.11) reserves at least the configured
    fraction (default 50%) of *remaining* budget for `evidence_class='dast_confirmed'` findings arriving after
    a version bump — verified with both the default and an overridden fraction, proving the value is
    config-driven, not compiled in.
13. Every cross-family critic step (R.3, R.10, R.15, R.17) produced a written verdict file; any FAIL verdict
    was rerouted per `00-ROUTING.md`'s rerouting rule before this area is considered done.

## Pinned Versions And Licences

| Artifact | Version / commit pinned | Licence | Verification status |
|---|---|---|---|
| SARIF | "2.1.0 Plus Errata 01" (OASIS Standard, 2023-08-28) | OASIS specification, unrestricted implementer use | Verified in research/18 primary-source read; pin `$schema`/`version` exactly; do not track the 2.2 draft (unratified as of this research). |
| `owenrumney/go-sarif` (Go SARIF library) | Verified active, pushed 2026-07-29, targets SARIF 2.1.0 | Unlicense | Verified via `plan/spine-c-language.md` citations C18/C19 (GitHub page + API metadata read). Pin the exact module version/commit SHA at implementation time, and archive its LICENSE file body per `00-SPINE.md` S8's compliance mechanics (read the file, not GitHub's `spdx_id` metadata) — a fresh confirmation fetch immediately before pinning is cheap and should be R.1's first sub-action. |
| `modernc.org/sqlite` | v1.56.0 (2026-08-03, per `plan/spine-c-language.md` C5) | Requires reading the LICENSE file body at pin time — not independently re-verified in this pass | `00-SPINE.md` S12 states FTS5 support is "orchestrator-verified"; the research trail backing that (`plan/spine-c-language.md` C5–C7) grades its own evidence as B ("absence-of-evidence, not evidence-of-absence"). Spine-locked as the pick; R.5's startup FTS5 guard is the real safety net regardless. |
| CWE taxonomy version embedded in `run.taxonomies[].version` | Must equal whatever CWE release Lane B's detection model actually loads at record-assembly time — never hardcoded | CWE is MITRE-published; attribution duty tracked in `plan/80-compliance.md` | Owned by the detection-training area (research/03), not this area; this area only requires the field be populated dynamically, not pinned to a literal string. |
| zstd compression library for `audit_record.payload` | Not selected in this pass | — | Not researched by any of the four input documents. `klauspost/compress/zstd` (pure Go, BSD-3-Clause) is a plausible candidate but was **not verified against a primary source in this session** — treat as an Open Question, not a pin. |

## Open Questions

1. **US10043004B2 patent risk on the correlation mechanism.** research/18 Risk #1: Anvil's link-based
   correlation (route table + CWE + parameter match) is materially similar to a granted patent (priority
   2015-01-30, granted 2018-08-07, expires ≈2035, assignee Denim Group Ltd./Coalfire Systems). `00-SPINE.md`
   S8 already names this patent and explicitly declines to resolve it via the Apache-2.0 licence choice. R.12
   implements the policy and flags the risk in code; R.15's critic verifies the flag exists but does not
   resolve it. **This must be escalated to the owner before R.12's output ships in a release**, per research/18's
   explicit instruction ("Escalate to the owner; do not assume this is fine").
2. **`modernc.org/sqlite` FTS5 support.** Spine-locked as verified (S12), but the research citation trail
   backing that claim grades its own evidence as B/unconfirmed (no "fts5" string found in source, docs, or
   issue search as of the research date). Not re-litigated here per this plan's constraints — R.5's mandatory
   startup smoke test is the actual control, independent of whichever way the spine's verification turns out
   to be right.
3. **`PRAGMA synchronous` value.** research/07 recommends `NORMAL` (paired with WAL, flagged "NOT verified
   in-session" against SQLite's own docs); research/08 recommends `FULL` ("conventional... default", not
   specifically justified for WAL mode). This document resolves to `NORMAL` as the documented standard WAL
   pairing (see Store Schema section for the reasoning) — a maintainer should confirm this against SQLite's
   own WAL+synchronous documentation before the first release, since neither source branch verified the
   crash-safety text in-session.
4. **zstd library pin.** Not selected or verified in this pass (see Pinned Versions And Licences) — needs a
   dedicated verification step before `audit_record.payload` compression ships.
5. **Whether `dast_coverage` (branches 15/19/22) and `endpoint_coverage`/`inventory_provenance` (branch 22) are
   the same measurement or must stay distinct.** This document consolidates them into one
   `run.properties["anvil/dastCoverage"]` field (`{probedCount, inventoryUnionCount, inventoryProvenanceMix}`).
   The attack-surface-discovery area (research/22, out of this area's scope) should confirm no information is
   lost by this consolidation when that area's plan is written.
6. **`as_of`/`staleness_seconds`/`parse_degraded` producer contract.** These are defined by research/06
   (ingestion), which this area did not read in depth (out of scope per this area's input list). The placement
   proposed here (`finding_occurrence.advisory_*` columns) should be confirmed against research/06's actual
   producer contract when the ingestion area's plan is written.
7. **Sanitizer+ASLR reproducer fields.** Primarily relevant to the host-side dynamic-analysis reproducer
   (`00-SPINE.md` S4's ASan+UBSan test suite), owned by a different area. This document reserves the SARIF
   placement (`result.properties["anvil/repro"].env`); the producer logic itself belongs to that area's plan.
8. **`internal/record/mask.go`'s header denylist completeness.** R.8 uses a documented but not exhaustively
   researched denylist (`Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`, and a
   `*token*`/`*secret*` pattern match). A dedicated security review of real-world header names before the
   masking pipeline ships in a release is recommended but was out of scope for the four input research
   documents.

## Conflicts With Spine

None identified. Two conflicts existed **between input research branches** — the fingerprint algorithm's exact
field set/separator/truncation (research/07 vs. research/18) and the `PRAGMA synchronous` value (research/07
vs. research/08) — and both are resolved above, within this area's delegated authority under `00-SPINE.md` S6
("One fingerprint algorithm, defined once, here"). Neither rises to a conflict with the spine itself, since the
spine does not specify either decision at that level of detail; it explicitly delegates the fingerprint
decision to this area. Every other design choice in this document (per-half sealing anchored to scan start,
the collapsed single-store-plus-handoff-table, the 50%-of-remaining-budget queue re-cut reservation, SARIF
2.1.0 pinned with no 2.2 tracking, the claim-lease/claim-timeout clock separation, the honest no-secure-deletion
posture) implements a `00-SPINE.md` S1/S6/S7 requirement directly and was not found to conflict with it.
