-- 0003_remediation — the remediation tier's durable statements (Phase 7, 2026-10-04).
--
-- Record v1 is frozen, so everything here is additive and nothing in
-- schema.sql changes. Four things, each with one producer:
--
-- 1. audit_record.audit_id. `anvil/auditId` is the audit's identity and the
--    first component of handoff.idempotency_key, which the coding agent writes
--    into a git trailer. Until now the store had no column for it, so the key
--    could only be recomputed by whoever still held the record (the gap
--    internal/handoff's EnqueueRequest names). The scan writer fills it; rows
--    written before this migration keep NULL, which the partial unique index
--    allows.
--
-- 2. triage_verdict. The triage gate's own judgement of an `unconfirmed`
--    finding (CONTRACT.md §1.6). It is a SEPARATE STATEMENT with its own
--    producer, never written over the record's anvil/verdict and never over
--    finding.verdict: Lane B's evidence stays exactly as Lane B wrote it, and a
--    triage verdict is never shown as evidence that a finding is real (plan
--    node triage). It is keyed by the fingerprint and a digest of the inputs
--    the gate saw, so a finding that persists unchanged across scans is not
--    re-triaged, and one whose code changed is.
--
-- 3. remediation_log. The audit log: every disposition the consumption
--    controller writes, with its reason. A triage false positive is "dropped
--    into the audit log" here, never deleted. `detail` is capped like
--    finding_occurrence.message and for the same reason: durable tables hold
--    reasons and pointers, never target source or response bodies.
--
-- 4. fix_pr. One draft pull request per validated fix group, with the label
--    it earned and how it ended. The label `verified_fixed` is set by exactly
--    one code path (the exploit oracle, internal/remediation); this CHECK only
--    keeps the vocabulary closed.

ALTER TABLE audit_record ADD COLUMN audit_id TEXT;
CREATE UNIQUE INDEX idx_audit_record_audit_id ON audit_record(audit_id) WHERE audit_id IS NOT NULL;

CREATE TABLE triage_verdict (
  triage_id       INTEGER PRIMARY KEY,
  target_id       INTEGER NOT NULL REFERENCES target(target_id),
  fingerprint     TEXT NOT NULL,
  input_digest    TEXT NOT NULL,           -- sha256 over the fenced inputs the gate was shown
  audit_record_id INTEGER REFERENCES audit_record(audit_record_id),
  verdict         TEXT NOT NULL,
  model           TEXT NOT NULL,           -- the endpoint's model name, as configured
  prompt_digest   TEXT NOT NULL,           -- sha256 of the exact prompt sent
  reason          TEXT NOT NULL,           -- the gate's one-line reason; model output about untrusted input
  decided_at      TEXT NOT NULL,
  UNIQUE (target_id, fingerprint, input_digest),
  CONSTRAINT ck_triage_verdict CHECK (
    verdict IN ('true_positive', 'false_positive', 'insufficient_context')),
  CONSTRAINT ck_triage_fingerprint_hex CHECK (
    length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*'),
  CONSTRAINT ck_triage_input_digest_hex CHECK (
    length(input_digest) = 64 AND input_digest NOT GLOB '*[^0-9a-f]*'),
  CONSTRAINT ck_triage_reason_cap CHECK (length(CAST(reason AS BLOB)) <= 512)
);

CREATE TABLE remediation_log (
  log_id      INTEGER PRIMARY KEY,
  handoff_id  INTEGER REFERENCES handoff(handoff_id),
  fingerprint TEXT NOT NULL,
  state       TEXT NOT NULL,               -- the handoff.state written, or 'note'
  detail      TEXT NOT NULL,
  at          TEXT NOT NULL,
  CONSTRAINT ck_remediation_log_state CHECK (
    state IN ('ready', 'leased', 'validated', 'failed_validation', 'failed_format',
              'skipped_budget', 'false_positive', 'regression_introduced',
              'fixed_incidentally', 'split_required', 'withdrawn', 'superseded',
              'expired', 'note')),
  CONSTRAINT ck_remediation_log_detail_cap CHECK (length(CAST(detail AS BLOB)) <= 2048)
);
CREATE INDEX idx_remediation_log_fp ON remediation_log(fingerprint, at);

CREATE TABLE fix_pr (
  fix_pr_id      INTEGER PRIMARY KEY,
  fix_attempt_id INTEGER NOT NULL REFERENCES fix_attempt(fix_attempt_id),
  repository     TEXT NOT NULL,            -- owner/name of the upstream
  branch         TEXT NOT NULL,
  number         INTEGER,
  url            TEXT,
  label          TEXT NOT NULL,
  state          TEXT NOT NULL,
  cwe            TEXT,
  reason         TEXT,                     -- a maintainer's rejection reason, or why it closed
  superseded_by  INTEGER REFERENCES fix_pr(fix_pr_id),
  opened_at      TEXT NOT NULL,
  closed_at      TEXT,
  CONSTRAINT ck_fix_pr_label CHECK (label IN ('verified_fixed', 'unverified_security')),
  CONSTRAINT ck_fix_pr_state CHECK (
    state IN ('draft', 'merged', 'rejected', 'stale_closed', 'superseded')),
  CONSTRAINT ck_fix_pr_reason_cap CHECK (reason IS NULL OR length(CAST(reason AS BLOB)) <= 2048)
);
CREATE INDEX idx_fix_pr_repo_state ON fix_pr(repository, state);
