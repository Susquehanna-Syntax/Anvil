-- Anvil store of record — complete DDL for schema version 1 (step R.4).
--
-- plan/00-SPINE.md S1 collapses the originally-specified "8-hour buffer file"
-- into ONE SQLite database plus a `handoff` table plus a regenerable tmpfs
-- packet. There is no second durable buffer file and no second durable table
-- carrying finding dispositions: plan/IMPLEMENTATION-PLAN.md §6 rulings G9 and
-- G10 make THIS FILE the only definition of `handoff` anywhere in Anvil.
-- Area 70's O.3 migration and area 60's `anvil_ledger` are both deleted and
-- folded in here.
--
-- SOURCES, in precedence order:
--   1. plan/40-record-and-storage.md, "Store Schema" — authoritative for
--      `scan_run`, `audit_record`, `finding`, `finding_occurrence`, `handoff`.
--   2. plan/IMPLEMENTATION-PLAN.md §6 (G9, G10) — supersedes (1) where they
--      disagree: `handoff.state` carries all thirteen dispositions and
--      `handoff.consumption_class` is present.
--   3. research/07-database-design.md §2 — carried forward unchanged for every
--      other table. No research/07 table is dropped.
--
-- WHAT IS DELIBERATELY NOT IN THIS FILE:
--
--   * PRAGMA statements. `PRAGMA journal_mode = WAL` cannot run inside a
--     transaction, and R.5 applies this file inside `BEGIN ... COMMIT`. The
--     connection pragmas plan/40-record-and-storage.md specifies are exposed
--     by ddl.go as ConnectionPragmas() and are applied per connection, before
--     any other store operation. `foreign_keys` in particular is per
--     connection and OFF by default; this schema depends on it being ON.
--   * `PRAGMA user_version` and the migration ledger's contents. R.5 owns
--     both; the `schema_migration` table itself is created here.
--
-- CHECK-CONSTRAINT POLICY. A CHECK constraint that names literals freezes a
-- vocabulary, and plan/IMPLEMENTATION-PLAN.md §6 documents what happens when
-- two areas freeze the same vocabulary differently: one area writes a literal
-- another area's NOT NULL column cannot accept. So enum CHECKs appear here
-- ONLY where internal/record/contract.go owns the enum, and ddl_test.go
-- asserts every such constraint agrees literal-for-literal with the Go values.
-- Columns whose comment names a vocabulary that contract.go does NOT own
-- (severity, ecosystem, suppression classification, ...) are left
-- unconstrained on purpose; constraining them here would be area 40 inventing
-- vocabulary for another area, which is the defect §6 exists to stop.
--
-- Every CHECK is NAMED. research/07 Risk #15: batch-recreate tooling silently
-- drops unnamed CHECK constraints, which on a security tool's schema is an
-- integrity regression with no error message.

-- ============ ADVISORY DOMAIN (feeds owned by area 20) ============
CREATE TABLE advisory (
  advisory_id     TEXT PRIMARY KEY,          -- 'CVE-2026-1234' | 'GHSA-xxxx-yyyy-zzzz'
  source          TEXT NOT NULL,             -- 'osv' | 'ghsa' | 'nvd' | ...
  published_at    TEXT NOT NULL,             -- ISO-8601 UTC
  modified_at     TEXT NOT NULL,
  severity        TEXT,                      -- 'critical'|'high'|'medium'|'low'|'none'
  cvss_vector     TEXT,
  cvss_score      REAL,
  summary         TEXT NOT NULL,
  details         TEXT,
  raw_json        BLOB,                      -- zstd-compressed original
  content_hash    TEXT NOT NULL,             -- sha256 of canonical form; drives delta ingest
  ingested_at     TEXT NOT NULL
);

CREATE TABLE advisory_alias (                -- CVE <-> GHSA <-> OSV
  advisory_id TEXT NOT NULL REFERENCES advisory(advisory_id) ON DELETE CASCADE,
  alias_id    TEXT NOT NULL,
  PRIMARY KEY (advisory_id, alias_id)
);
CREATE INDEX idx_alias_lookup ON advisory_alias(alias_id);

-- BM25 over advisory text. External-content table: no duplicate storage of
-- summary/details. Query:
--   ... WHERE advisory_fts MATCH ? ORDER BY bm25(advisory_fts, 4.0, 1.0, 8.0)
-- with `aliases` weighted highest so a literal 'CVE-2026-1234' beats prose.
--
-- This is also the schema's built-in FTS5 availability probe: if the driver
-- lacks FTS5, applying this file fails loudly here rather than at first query.
-- R.5's CheckFTS5 guard still runs independently at every process start.
--
-- KNOWN DEFECT, CARRIED FORWARD DELIBERATELY AND REPORTED, NOT SILENTLY
-- PATCHED. `content='advisory'` makes FTS5 read column values back from
-- `advisory`, but `advisory` has no `aliases` column — aliases are a
-- one-to-many in `advisory_alias`. So `INSERT INTO advisory_fts(advisory_fts)
-- VALUES('rebuild')`, any `SELECT <column> FROM advisory_fts`, and any
-- snippet()/highlight() call fail with:
--     SQL logic error: no such column: T.aliases
-- Verified empirically on modernc.org/sqlite v1.56.0. Writes into
-- advisory_fts and rowid-only MATCH queries work; ddl_test.go exercises
-- exactly those. R.4 does not invent a fix because the two candidate repairs
-- (point `content=` at a view that projects the aliases, or drop `aliases`
-- from the FTS columns and re-derive the bm25 weights) both change an
-- interface area 20's ingestion owns. Flagged to the orchestrator.
CREATE VIRTUAL TABLE advisory_fts USING fts5(
  summary, details, aliases,
  content='advisory', content_rowid='rowid',
  tokenize='porter unicode61'
);

-- ============ COMPONENT DOMAIN ============
CREATE TABLE component (
  component_id INTEGER PRIMARY KEY,
  ecosystem    TEXT NOT NULL,                -- 'npm'|'pypi'|'cargo'|'go'|'deb'|'rpm'|'maven'
  name         TEXT NOT NULL,
  purl_base    TEXT NOT NULL,                -- 'pkg:pypi/requests' (no version)
  UNIQUE (ecosystem, name)
);

CREATE TABLE advisory_affects (
  advisory_id  TEXT NOT NULL REFERENCES advisory(advisory_id) ON DELETE CASCADE,
  component_id INTEGER NOT NULL REFERENCES component(component_id),
  introduced   TEXT,                         -- version range endpoints, ecosystem-native
  fixed        TEXT,
  range_kind   TEXT NOT NULL,                -- 'semver'|'ecosystem'|'git'
  PRIMARY KEY (advisory_id, component_id, introduced, fixed)
);
CREATE INDEX idx_affects_component ON advisory_affects(component_id, advisory_id);

-- ============ TARGET + TRIGGER (never hard-coded) ============
CREATE TABLE target (
  target_id   INTEGER PRIMARY KEY,
  kind        TEXT NOT NULL,                 -- 'repo'|'host'
  locator     TEXT NOT NULL UNIQUE,          -- clone URL or hostname
  config_json TEXT NOT NULL DEFAULT '{}',
  CONSTRAINT ck_target_config_json CHECK (json_valid(config_json))
);

CREATE TABLE trigger_policy (                -- HARD CONSTRAINT: policy lives in data, not code
  policy_id   INTEGER PRIMARY KEY,
  target_id   INTEGER NOT NULL REFERENCES target(target_id) ON DELETE CASCADE,
  kind        TEXT NOT NULL,                 -- 'cron'|'github_action'|'webhook'|'manual'
  spec        TEXT NOT NULL,                 -- cron expr | tag glob 'v*.0.0' | event name
  scan_depth  TEXT NOT NULL,                 -- 'full'|'incremental'|'sca_only'
  enabled     INTEGER NOT NULL DEFAULT 1,
  config_json TEXT NOT NULL DEFAULT '{}',
  CONSTRAINT ck_trigger_policy_enabled_bool CHECK (enabled IN (0, 1)),
  CONSTRAINT ck_trigger_policy_config_json CHECK (json_valid(config_json))
);
CREATE INDEX idx_policy_enabled ON trigger_policy(target_id, kind) WHERE enabled = 1;

CREATE TABLE ingest_watermark (              -- delta scraping cursors (feeds = area 20)
  source          TEXT PRIMARY KEY,
  cursor          TEXT,
  etag            TEXT,
  last_success_at TEXT
);

-- ============ SCAN RUN — unchanged shape from research/07 ============
CREATE TABLE scan_run (
  scan_run_id       INTEGER PRIMARY KEY,
  target_id         INTEGER NOT NULL REFERENCES target(target_id),
  policy_id         INTEGER REFERENCES trigger_policy(policy_id),
  trigger_ref       TEXT,                    -- tag / commit / cron fire id
  commit_sha        TEXT,
  started_at        TEXT NOT NULL,           -- anvil/deadline.deadlineAt is computed from THIS, never last write
  finished_at       TEXT,
  status            TEXT NOT NULL,           -- scan_run.status, owned by internal/record
  sast_engine_ver   TEXT,
  dast_engine_ver   TEXT,
  ruleset_version   TEXT NOT NULL,
  advisory_snapshot TEXT,                    -- max(advisory.modified_at) at scan time
  rollup_hash       TEXT,                    -- sha256 over sorted finding fingerprints
  CONSTRAINT ck_scan_run_status CHECK (status IN ('running', 'ok', 'failed', 'partial'))
);
CREATE INDEX idx_scan_target_time ON scan_run(target_id, started_at DESC);
CREATE INDEX idx_scan_running     ON scan_run(target_id) WHERE status = 'running';

-- ============ AUDIT RECORD — the collapsed store (S1: no second durable buffer file) ============
CREATE TABLE audit_record (
  audit_record_id       INTEGER PRIMARY KEY,
  scan_run_id           INTEGER NOT NULL UNIQUE REFERENCES scan_run(scan_run_id),
  schema_version        TEXT NOT NULL,                   -- anvil/schemaVersion
  audit_version         INTEGER NOT NULL DEFAULT 1,      -- anvil/version; a bump triggers R.11's queue re-cut
  state                 TEXT NOT NULL,                   -- anvil/state
  sast_status           TEXT,                            -- per-half status (anvil/status)
  sast_sealed_at        TEXT,
  dast_status           TEXT NOT NULL DEFAULT 'not_run', -- S6: never NULL, never silently 'completed_clean'
  dast_sealed_at        TEXT,
  dast_coverage_json    TEXT,                            -- S6: {probedCount, inventoryUnionCount, inventoryProvenanceMix}
  target_provenance     TEXT NOT NULL,                   -- S6: a target that failed to boot must be distinguishable from scanned clean
  deadline_at           TEXT NOT NULL,                   -- = scan_run.started_at + claim_timeout_seconds. NEVER recomputed.
  claim_timeout_seconds INTEGER NOT NULL DEFAULT 28800,  -- 8h default, configurable. A CLAIM timeout, not a deletion policy.
  dast_deadline_seconds INTEGER,                         -- S6: configurable, independent clock from claim_timeout_seconds
  payload               BLOB,                            -- zstd(canonical SARIF JSON); NULLed by the reaper at deadline_at
  payload_sha256        TEXT NOT NULL,                   -- survives payload deletion: proof of what was handed over
  created_at            TEXT NOT NULL,
  consumed_at           TEXT,
  purged_at             TEXT,
  CONSTRAINT ck_audit_record_state CHECK (
    state IN ('collecting', 'sast_sealed', 'dast_sealed', 'both_sealed', 'consumed', 'expired')),
  CONSTRAINT ck_audit_record_sast_status CHECK (
    sast_status IS NULL OR sast_status IN ('running', 'sealed', 'failed', 'timed_out', 'skipped')),
  CONSTRAINT ck_audit_record_dast_status CHECK (
    dast_status IN ('not_run', 'skipped_no_manifest', 'running', 'completed_clean',
                    'completed_findings', 'completed_partial', 'completed_failed', 'target_boot_failed',
                    'target_unreachable', 'timed_out')),
  CONSTRAINT ck_audit_record_target_provenance CHECK (
    target_provenance IN ('booted_clean', 'boot_failed', 'build_failed',
                          'no_target_declared', 'unreachable_at_scan_time')),
  CONSTRAINT ck_audit_record_payload_sha256_hex CHECK (
    length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
  CONSTRAINT ck_audit_record_claim_timeout_positive CHECK (claim_timeout_seconds > 0),
  CONSTRAINT ck_audit_record_dast_deadline_positive CHECK (
    dast_deadline_seconds IS NULL OR dast_deadline_seconds > 0),
  CONSTRAINT ck_audit_record_audit_version_positive CHECK (audit_version >= 1),
  CONSTRAINT ck_audit_record_dast_coverage_json CHECK (
    dast_coverage_json IS NULL OR json_valid(dast_coverage_json))
);
CREATE INDEX idx_audit_deadline ON audit_record(deadline_at) WHERE purged_at IS NULL;
CREATE INDEX idx_audit_state    ON audit_record(state);

-- ============ CODE LOCATION ============
CREATE TABLE code_location (
  location_id  INTEGER PRIMARY KEY,
  repo_relpath TEXT NOT NULL,                -- POSIX separators, repo-root-relative, never absolute
  start_line   INTEGER,
  end_line     INTEGER,
  start_col    INTEGER,
  end_col      INTEGER,
  symbol       TEXT,                         -- 'pkg/mod.py::ClassA.method_b'
  symbol_kind  TEXT,                         -- 'function'|'method'|'class'|'module'
  blob_sha     TEXT,                         -- git blob hash of the file at scan time
  snippet_hash TEXT                          -- sha256 of NORMALISED snippet; never the raw snippet
);
CREATE INDEX idx_loc_path ON code_location(repo_relpath, start_line);

-- ============ FINDING: the stable identity ============
-- Extended from research/07 with the S6/S24 fields (evidence_class, verdict,
-- remediable_by_agent). `finding_id` is the permanent key; `fingerprint` is a
-- lookup key that may be re-derived, because no vendor guarantees fingerprint
-- stability (research/07 Risk #1).
CREATE TABLE finding (
  finding_id          INTEGER PRIMARY KEY,
  target_id           INTEGER NOT NULL REFERENCES target(target_id),
  fingerprint         TEXT NOT NULL,          -- anvil-fp/v1, full 64-hex SHA-256, never truncated
  fingerprint_alg     TEXT NOT NULL DEFAULT 'anvil-fp/v1',
  detector            TEXT NOT NULL,          -- finding.detector
  evidence_class      TEXT NOT NULL,          -- anvil/evidenceClass
  rule_id             TEXT NOT NULL,          -- versioned: 'anvil.py.sqli/v3'
  verdict             TEXT NOT NULL DEFAULT 'true_positive',  -- S6: anvil/verdict
  remediable_by_agent INTEGER NOT NULL,       -- S6: 0/1; host findings are ALWAYS 0 (S7 read-only host agent)
  advisory_id         TEXT REFERENCES advisory(advisory_id),
  component_id        INTEGER REFERENCES component(component_id),
  severity            TEXT NOT NULL,
  title               TEXT NOT NULL,
  state               TEXT NOT NULL,          -- finding.state
  first_seen_scan     INTEGER NOT NULL REFERENCES scan_run(scan_run_id),
  first_seen_at       TEXT NOT NULL,
  last_seen_scan      INTEGER REFERENCES scan_run(scan_run_id),
  last_seen_at        TEXT,
  resolved_at         TEXT,
  resolved_by_fix     INTEGER,                -- -> fix_attempt(fix_attempt_id); intentionally not an FK, see note below
  UNIQUE (target_id, fingerprint),            -- THE regression-check index
  CONSTRAINT ck_finding_detector CHECK (detector IN ('sast', 'dast', 'sca', 'host')),
  CONSTRAINT ck_finding_evidence_class CHECK (
    evidence_class IN ('dast_confirmed', 'sast_reachable', 'sast_static_only', 'sca', 'host')),
  CONSTRAINT ck_finding_verdict CHECK (
    verdict IN ('true_positive', 'false_positive', 'insufficient_context')),
  CONSTRAINT ck_finding_state CHECK (state IN ('open', 'resolved', 'suppressed', 'regressed')),
  CONSTRAINT ck_finding_remediable_bool CHECK (remediable_by_agent IN (0, 1)),
  CONSTRAINT ck_finding_host_not_remediable CHECK (detector != 'host' OR remediable_by_agent = 0),
  CONSTRAINT ck_finding_fingerprint_hex CHECK (
    length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*')
);
CREATE INDEX idx_finding_state   ON finding(target_id, state, severity);
CREATE INDEX idx_finding_evclass ON finding(target_id, evidence_class);
CREATE INDEX idx_finding_verdict ON finding(verdict) WHERE verdict != 'true_positive';
CREATE INDEX idx_finding_adv     ON finding(advisory_id) WHERE advisory_id IS NOT NULL;
CREATE INDEX idx_finding_comp    ON finding(component_id) WHERE component_id IS NOT NULL;
-- NOTE on `resolved_by_fix`: research/07 §2 and plan/40's Store Schema both
-- declare it a bare INTEGER, not a REFERENCES clause, because `fix_attempt`
-- also references `finding` and a mutual FK pair cannot be satisfied by either
-- insert order without deferred constraints. Carried forward as specified.

-- Multi-fingerprint side table -> fuzzy fallback + algorithm migration
-- without data loss.
CREATE TABLE finding_fingerprint (
  finding_id INTEGER NOT NULL REFERENCES finding(finding_id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,                  -- 'primary'|'line_hash'|'symbol_hash'|'purl_advisory'|'dast_route'
  alg        TEXT NOT NULL,                  -- 'anvil-fp/v1' | 'lineHash/v1' | ...
  value      TEXT NOT NULL,
  PRIMARY KEY (finding_id, kind, alg)
);
CREATE INDEX idx_fp_lookup ON finding_fingerprint(kind, value);

-- ============ OCCURRENCE: one row per (finding, scan) ============
-- Extended with the S6 advisory-staleness fields.
CREATE TABLE finding_occurrence (
  occurrence_id               INTEGER PRIMARY KEY,
  finding_id                  INTEGER NOT NULL REFERENCES finding(finding_id) ON DELETE CASCADE,
  scan_run_id                 INTEGER NOT NULL REFERENCES scan_run(scan_run_id) ON DELETE CASCADE,
  location_id                 INTEGER REFERENCES code_location(location_id),
  confidence                  REAL,
  message                     TEXT,          -- hashes/pointers only; oversized inserts rejected by trigger
  evidence_ref                TEXT,          -- pointer INTO the sealed payload; never the raw request/response
  advisory_as_of              TEXT,          -- S6: as_of
  advisory_staleness_seconds  INTEGER,       -- S6: staleness_seconds
  advisory_parse_degraded     INTEGER NOT NULL DEFAULT 0,  -- S6: parse_degraded
  UNIQUE (finding_id, scan_run_id),
  CONSTRAINT ck_occurrence_parse_degraded_bool CHECK (advisory_parse_degraded IN (0, 1))
);
CREATE INDEX idx_occ_scan ON finding_occurrence(scan_run_id, finding_id);  -- drives the delta query

-- research/07 Risk #13, verbatim: "The 8-hour rule is defeatable by careless
-- denormalisation. If raw snippets or DAST request/response bodies get copied
-- into finding_occurrence.message, they outlive the purge forever." These two
-- triggers are that risk's named mitigation. The cap is deliberately far below
-- internal/record's smallest inline body cap (8 KiB) so that no request or
-- response body can be smuggled into a durable column even at its minimum
-- size, while remaining ample for a rule title plus a pointer.
CREATE TRIGGER trg_occurrence_durable_text_cap_insert
BEFORE INSERT ON finding_occurrence
FOR EACH ROW WHEN
  length(CAST(COALESCE(NEW.message, '') AS BLOB)) > 2048
  OR length(CAST(COALESCE(NEW.evidence_ref, '') AS BLOB)) > 2048
BEGIN
  SELECT RAISE(ABORT,
    'finding_occurrence: message/evidence_ref exceed the durable-text cap; durable tables store hashes and pointers only (research/07 Risk #13)');
END;

CREATE TRIGGER trg_occurrence_durable_text_cap_update
BEFORE UPDATE ON finding_occurrence
FOR EACH ROW WHEN
  length(CAST(COALESCE(NEW.message, '') AS BLOB)) > 2048
  OR length(CAST(COALESCE(NEW.evidence_ref, '') AS BLOB)) > 2048
BEGIN
  SELECT RAISE(ABORT,
    'finding_occurrence: message/evidence_ref exceed the durable-text cap; durable tables store hashes and pointers only (research/07 Risk #13)');
END;

-- ============ APPEND-ONLY STATE HISTORY ============
CREATE TABLE finding_state_event (
  event_id    INTEGER PRIMARY KEY,
  finding_id  INTEGER NOT NULL REFERENCES finding(finding_id) ON DELETE CASCADE,
  scan_run_id INTEGER REFERENCES scan_run(scan_run_id),
  from_state  TEXT,
  to_state    TEXT NOT NULL,
  cause       TEXT NOT NULL,                 -- 'first_seen'|'absent_in_scan'|'fix_verified'|'regression'|'suppressed'|'expired'
  at          TEXT NOT NULL
);
CREATE INDEX idx_state_hist ON finding_state_event(finding_id, at DESC);

-- ============ FIX + VERIFICATION ============
CREATE TABLE fix_attempt (
  fix_attempt_id  INTEGER PRIMARY KEY,
  finding_id      INTEGER NOT NULL REFERENCES finding(finding_id),
  audit_record_id INTEGER REFERENCES audit_record(audit_record_id),
  agent_model_id  TEXT NOT NULL,
  started_at      TEXT NOT NULL,
  finished_at     TEXT,
  status          TEXT NOT NULL,             -- 'proposed'|'applied'|'rejected'|'failed'
  patch_ref       TEXT,                      -- git ref / blob sha, not the diff text
  branch_name     TEXT,
  pr_url          TEXT
);
CREATE INDEX idx_fix_finding ON fix_attempt(finding_id, started_at DESC);

CREATE TABLE verification (
  verification_id INTEGER PRIMARY KEY,
  fix_attempt_id  INTEGER NOT NULL REFERENCES fix_attempt(fix_attempt_id) ON DELETE CASCADE,
  kind            TEXT NOT NULL,             -- 'rescan_sast'|'rescan_dast'|'build'|'unit_tests'
  scan_run_id     INTEGER REFERENCES scan_run(scan_run_id),
  result          TEXT NOT NULL,             -- 'pass'|'fail'|'inconclusive'
  details_json    TEXT,
  verified_at     TEXT NOT NULL,
  CONSTRAINT ck_verification_details_json CHECK (details_json IS NULL OR json_valid(details_json))
);
CREATE INDEX idx_verif_fix ON verification(fix_attempt_id);

-- ============ SUPPRESSION / FALSE POSITIVE ============
CREATE TABLE suppression (
  suppression_id INTEGER PRIMARY KEY,
  target_id      INTEGER NOT NULL REFERENCES target(target_id) ON DELETE CASCADE,
  match_kind     TEXT NOT NULL,              -- 'fingerprint'|'rule'|'path_glob'|'advisory'|'component'
  match_value    TEXT NOT NULL,
  classification TEXT NOT NULL,              -- 'false_positive'|'accepted_risk'|'not_exploitable'|'wont_fix'
  justification  TEXT NOT NULL,
  created_by     TEXT NOT NULL,
  created_at     TEXT NOT NULL,
  expires_at     TEXT,                       -- expiring suppressions prevent permanent blindness
  active         INTEGER NOT NULL DEFAULT 1,
  CONSTRAINT ck_suppression_active_bool CHECK (active IN (0, 1))
);
CREATE INDEX idx_supp_match ON suppression(target_id, match_kind, match_value) WHERE active = 1;

-- ============ INCREMENTAL-SCAN CACHE (this is where compute is actually saved) ============
CREATE TABLE file_state (
  target_id       INTEGER NOT NULL REFERENCES target(target_id) ON DELETE CASCADE,
  repo_relpath    TEXT NOT NULL,
  blob_sha        TEXT NOT NULL,
  ruleset_version TEXT NOT NULL,
  last_scan_id    INTEGER NOT NULL REFERENCES scan_run(scan_run_id),
  PRIMARY KEY (target_id, repo_relpath)
);

-- ============ HANDOFF — the collapsed buffer replacement (S1: state/lease/attempts/expiry) ============
--
-- ONE TABLE, ONE STATE COLUMN. plan/IMPLEMENTATION-PLAN.md §6 G10 traced the
-- concrete bug that a second table produces: area X wrote `skipped_budget` to
-- its own `anvil_ledger` while area 40's ready-set index still saw the finding
-- as 'ready', so the finding was re-leased forever. `anvil_ledger` is deleted;
-- its four extra dispositions (fixed_incidentally, split_required, withdrawn,
-- superseded) are values of `state` here.
--
-- `consumption_class` arrives from area 70's O.3 (§6 G9). Nothing else in this
-- schema can express the gate research/21 §5 requires: `static_only` findings
-- are claimable once the SAST half is sealed, `requires_dynamic_confirmation`
-- findings must wait on the DAST half. It is NOT NULL with NO DEFAULT on
-- purpose — a default would silently grant every row the permissive value, and
-- plan/00-SPINE.md S7 says only a DAST reproduction earns "verified fixed".
--
-- TWO INDEPENDENT CLOCKS, NEVER CONFLATED (S1):
--   handoff.lease_expires_at          15-30 min, heartbeat-renewed, governs ONE
--                                     coding-agent attempt.
--   audit_record.claim_timeout_seconds default 8h, governs how long an
--                                     UNCLAIMED finding stays eligible. At its
--                                     expiry the reaper drops only the tmpfs
--                                     packet and NULLs audit_record.payload;
--                                     this row, `finding`, and
--                                     `finding_state_event` are never deleted.
CREATE TABLE handoff (
  handoff_id        INTEGER PRIMARY KEY,
  finding_id        INTEGER NOT NULL REFERENCES finding(finding_id) ON DELETE CASCADE,
  audit_record_id   INTEGER NOT NULL REFERENCES audit_record(audit_record_id),
  fingerprint       TEXT NOT NULL,           -- denormalised for the reaper's WHERE clause
  group_id          TEXT,                    -- fix-group id, assigned by the coding-agent consumption pipeline
  state             TEXT NOT NULL DEFAULT 'ready',
  consumption_class TEXT NOT NULL,           -- from O.3 per §6 G9; no default, see note above
  claimed_by        TEXT,                    -- worker_id (O.3's lease_owner)
  lease_expires_at  TEXT,                    -- claim lease. NOT audit_record.claim_timeout_seconds.
  attempts          INTEGER NOT NULL DEFAULT 0,
  max_attempts      INTEGER NOT NULL DEFAULT 2,
  idempotency_key   TEXT UNIQUE,             -- sha256(audit_id || finding_fingerprint || base_commit_sha); mirrors the git trailer
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  UNIQUE (finding_id, audit_record_id),
  CONSTRAINT ck_handoff_state CHECK (
    state IN ('ready', 'leased', 'validated', 'failed_validation', 'failed_format',
              'skipped_budget', 'false_positive', 'regression_introduced',
              'fixed_incidentally', 'split_required', 'withdrawn', 'superseded',
              'expired')),
  CONSTRAINT ck_handoff_consumption_class CHECK (
    consumption_class IN ('static_only', 'requires_dynamic_confirmation')),
  CONSTRAINT ck_handoff_fingerprint_hex CHECK (
    length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*'),
  CONSTRAINT ck_handoff_attempts_nonneg CHECK (attempts >= 0 AND max_attempts >= 0),
  CONSTRAINT ck_handoff_lease_requires_holder CHECK (
    state != 'leased' OR (claimed_by IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE INDEX idx_handoff_ready ON handoff(state) WHERE state = 'ready';
CREATE INDEX idx_handoff_lease ON handoff(lease_expires_at) WHERE state = 'leased';
CREATE INDEX idx_handoff_fp    ON handoff(fingerprint);

-- ============ MIGRATIONS ============
-- Rows are written by R.5's migrate.go, in the same transaction that applies
-- the migration and bumps PRAGMA user_version.
CREATE TABLE schema_migration (
  version    INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  checksum   TEXT NOT NULL,
  applied_at TEXT NOT NULL
);
