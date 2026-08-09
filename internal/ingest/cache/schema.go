// Package cache owns the Lane A ingestion cache: a SECOND SQLite file,
// `anvil-cache.sqlite`, holding advisory feed content (step A.2 of
// plan/20-lane-a-ingestion-sca.md).
//
// # This is not the store of record
//
// internal/store is Anvil's audit store of record and it is a frozen
// interface. This package must never be confused with it and never imported
// into it. The two databases differ in kind, not just in content:
//
//   - internal/store holds sealed audit records. Losing it loses evidence, so
//     R.5 gates every upgrade behind a `VACUUM INTO` snapshot and refuses to
//     migrate a populated database without one.
//   - THIS cache holds a rederivable projection of public advisory feeds. It
//     is regenerable from A.8's bootstrap in bounded time, so there is no
//     snapshot gate here (see migrate.go). Deleting the file is a legal, if
//     expensive, recovery step. Deleting the store of record is not.
//
// Nothing in this package imports internal/store, and no table declared here
// exists in schema.sql.
//
// # Why SQLite and why FTS5
//
// research/06-ingestion-and-scraping.md Recommendation §5: "one SQLite file,
// WAL mode, with FTS5 — pre-parsed rows plus a raw-JSON column". A packed KV
// store (BoltDB, as Trivy uses) gives O(1) key lookup but no text search,
// which is the one access pattern Lane B's retrieval actually needs; raw JSON
// files mean 300,000+ inodes and a directory walk per query. The decisive
// property is the third one: FTS5 accepts incremental INSERT/DELETE, so an
// hourly delta touching 200 records costs 200 row upserts and NOT a rebuild.
// That is why no code path in Anvil may DROP or rebuild `advisory_fts`, and
// why cache_test.go traces the SQL that reaches the driver to prove it.
//
// plan/00-SPINE.md S12 mandates modernc.org/sqlite, which translates the
// SQLite C source to Go and needs no cgo, and forbids mattn/go-sqlite3, which
// needs a C toolchain and would break both the single static binary and the
// cross-compilation matrix.
//
// # The primary key is (source, source_id), never the CVE ID
//
// research/06 Risk #2 is explicit: do not let CVE IDs be the primary key of
// the cache. A cvelistV5 outage must be survivable by swapping to EUVD, OSV
// or GHSA without touching detector code, and those sources disagree about
// which CVE a record carries — GHSA advisories often have none at all.
// `advisory.cve_id` is a nullable alias with an index, and `cve_alias` carries
// the one-to-many.
//
// # What this package deliberately does NOT do
//
//   - It does not sanitize. A.3 owns Sanitize(); every writer must run
//     external text through it before binding a parameter to any statement
//     below. A SQL string cannot sanitize its own arguments, so the
//     statement constants here are documentation of the write shape, not a
//     safe write path on their own.
//   - It does not resolve a licence. A.4's Gate() decides tiers and output
//     directories by reading checked-in LICENSE file bodies. This schema only
//     RECORDS the outcome, and refuses a row that records nothing at all.
//   - It does not fetch. A.7 polls and A.8 bootstraps.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Trust vocabulary — consumed from internal/record, never redeclared here
// ---------------------------------------------------------------------------

// plan/IMPLEMENTATION-PLAN.md §6: "area 40 owns every shared enum, because it
// owns the record contract, and no other area may declare one." `anvil/trust`
// is one of those enums. The two constants below are aliases for the record's
// own values so that a Lane A caller writing a trust value writes a Go
// constant from internal/record and never a bare string; cache_test.go proves
// the SQL DEFAULT clauses and CHECK constraint literals in Schema() still
// agree with record.TrustValues().
const (
	// AdvisoryTrustDefault is the `anvil_trust` value stamped on every
	// `advisory` row that does not name one. plan/00-SPINE.md S6 requires
	// the field "on every string originating outside Anvil", and an
	// advisory row is nothing but strings originating outside Anvil.
	//
	// The DDL's CHECK deliberately admits only the two values
	// record.Trust.LegalForExternalString reports as legal — `verified` is
	// reachable for a signature-checked snapshot, `anvil_generated` is not
	// reachable at all. That is the mislabelling internal/record documents
	// area B committing: the question the field answers is "who wrote these
	// bytes", never "who assigned this field".
	AdvisoryTrustDefault = record.TrustUntrusted

	// FindingTrustDefault is the `anvil_trust` value stamped on a `finding`
	// row. A finding is Anvil's own conclusion — the output of A.17's
	// version comparator — so `anvil_generated` is correct here for exactly
	// the reason it is wrong on `advisory`.
	FindingTrustDefault = record.TrustAnvilGenerated
)

// Collector values for `finding.collector`. These are Lane-A-local vocabulary
// with no counterpart in the record contract's six frozen enums, so declaring
// them here does not violate §6's single-owner rule; they exist so that A.9
// and A.10 write a constant rather than a literal.
const (
	// CollectorHost is A.9's read-only host package collector.
	// plan/00-SPINE.md S6 and exit criterion 21 make every row it produces
	// `remediable_by_agent = 0`, and the DDL enforces that with a CHECK so
	// that no flag, config key or future code path can override it.
	CollectorHost = "host"

	// CollectorRepoSCA is A.10's repository SBOM/SCA collector, whose
	// findings an agent may legitimately be asked to remediate.
	CollectorRepoSCA = "repo-sca"
)

// Advisory lifecycle states for `advisory.state`. Exit criterion 22 requires
// withdrawn and REJECTED advisories to be TOMBSTONED, never deleted, so that
// dependent findings become invalidated rather than silently vanishing; the
// DDL pairs a non-published state with a non-null `tombstoned_at`.
const (
	// AdvisoryPublished is a live advisory.
	AdvisoryPublished = "published"
	// AdvisoryWithdrawn is an advisory the publisher retracted.
	AdvisoryWithdrawn = "withdrawn"
	// AdvisoryRejected is a CVE record in the REJECTED state.
	AdvisoryRejected = "rejected"
)

// ---------------------------------------------------------------------------
// The DDL
// ---------------------------------------------------------------------------

// schemaSQL is the complete DDL for cache schema version 1.
//
// It is a Go string rather than an embedded .sql file because A.2's scope
// names three .go files and no SQL file; migrate.go checksums this text, so
// the constant is as frozen in practice as a committed file would be.
//
// It contains no PRAGMA statement. `PRAGMA journal_mode = WAL` cannot run
// inside a transaction and migrate.go applies this text inside
// BEGIN ... COMMIT; the connection pragmas live in the DSN instead (see
// migrate.go's DSN).
//
// TWO DELIBERATE DEVIATIONS FROM THE DDL SKETCH IN
// plan/20-lane-a-ingestion-sca.md "Cache Schema", both reported rather than
// silently applied:
//
//  1. `advisory_fts` carries `contentless_delete=1`. The plan's sketch says
//     `content=”` and its upsert contract says "writers issue row-scoped
//     INSERT OR REPLACE for exactly the (source, source_id) rows touched by
//     the current sync batch". Those two are incompatible. Verified
//     empirically on modernc.org/sqlite v1.56.0 (SQLite 3.53.3): against a
//     plain `content=”` table, `DELETE` fails with "cannot DELETE from
//     contentless fts5 table", and `INSERT OR REPLACE` SUCCEEDS WITHOUT AN
//     ERROR while leaving the old row's terms in the index forever — after
//     replacing 'hello' with 'goodbye' at rowid 1, both still MATCH. A delta
//     pipeline built on that contract accumulates phantom hits with nothing
//     to surface them, which is the same silent-drift failure mode S6's
//     one-fingerprint rule exists to prevent. `contentless_delete=1`
//     (SQLite 3.43+) makes the plan's stated contract actually hold.
//     cache_test.go carries the regression test.
//
//  2. Every CHECK constraint is NAMED. research/07-database-design.md Risk
//     #15 records that batch-recreate tooling silently drops UNNAMED check
//     constraints — on a security tool's schema that is an integrity
//     regression with no error message. Naming them also makes each one
//     addressable from a test, which is how cache_test.go proves the
//     `anvil_trust` literals have not drifted from internal/record.
//
// Three CHECK constraints encode plan exit criteria that would otherwise be
// enforceable only by convention. Each is called out at its definition.
const schemaSQL = `
-- Anvil Lane A ingestion cache — complete DDL for cache schema version 1
-- (step A.2 of plan/20-lane-a-ingestion-sca.md).
--
-- This is NOT internal/store/schema.sql. That file is the store of record and
-- is frozen; no table here exists there, and no table there is referenced
-- here. The two databases are separate files opened by separate packages.

-- ============ FEED POLLING STATE ============
--
-- One row per feed, keyed by internal/ingest/config's FeedConfig.ID. This is
-- what makes conditional GET work: A.7's poller reads etag/last_modified to
-- build If-None-Match/If-Modified-Since, and writes back whatever the response
-- carried. research/06 Risk #8 is the reason the poller must still
-- authenticate a request that produces a 304 — an unauthenticated 304 costs
-- the same 60/hour GitHub budget as a 200.
--
-- The CADENCE IS NOT HERE and must never be added. research/06 Recommendation
-- item 4 puts every interval in feeds.yaml so an operator can dial the whole
-- pipeline down to daily on a constrained host; a cadence column here would be
-- a second, drifting source of truth for the same fact.
CREATE TABLE feed_state (
  feed_id              TEXT PRIMARY KEY,
  etag                 TEXT,                  -- verbatim ETag header value, quotes and W/ prefix included
  last_modified        TEXT,                  -- verbatim Last-Modified header value
  watermark            TEXT,                  -- feed-specific cursor: lastModStartDate, delta filename, git ref
  last_ok_at           TEXT,                  -- ISO8601 UTC; the only column a 304 is allowed to move
  consecutive_failures INTEGER NOT NULL DEFAULT 0
    CONSTRAINT feed_state_failures_nonneg CHECK (consecutive_failures >= 0),
  license_tier         INTEGER NOT NULL
    CONSTRAINT feed_state_license_tier CHECK (license_tier IN (0, 1, 2, 3))
);

-- ============ ADVISORY ============
--
-- One row per (source, source_id). NEVER keyed on CVE ID (research/06 Risk
-- #2): a cvelistV5 outage must be survivable by swapping to EUVD/OSV/GHSA
-- without touching detector code, and GHSA advisories frequently carry no CVE
-- at all. cve_id is a nullable, indexed alias.
--
-- rowid is load-bearing here: it is the join key into advisory_fts, which is
-- contentless and therefore addressable only by rowid. Writers MUST upsert
-- with ON CONFLICT ... DO UPDATE (see UpsertAdvisorySQL) and MUST NOT use
-- INSERT OR REPLACE on this table: REPLACE deletes and re-inserts the row,
-- assigning a NEW rowid and orphaning its FTS entry with no error.
CREATE TABLE advisory (
  source               TEXT NOT NULL,         -- 'cvelistv5' | 'ghsa' | 'osv' | 'redhat-csaf' | 'ubuntu' | 'alpine' | ...
  source_id            TEXT NOT NULL,         -- native ID within that source
  cve_id               TEXT,                  -- nullable alias, never the primary key
  published            TEXT,
  modified             TEXT,
  state                TEXT NOT NULL DEFAULT 'published'
    CONSTRAINT advisory_state CHECK (state IN ('published', 'withdrawn', 'rejected')),
  tombstoned_at        TEXT,
  severity             TEXT,
  cvss_vector          TEXT,
  cvss_score           REAL,
  epss_score           REAL,
  epss_as_of           TEXT,
  kev                  INTEGER NOT NULL DEFAULT 0
    CONSTRAINT advisory_kev_bool CHECK (kev IN (0, 1)),
  -- spine S8. license_spdx is the SPDX id where a LICENSE file BODY states
  -- one; license_manual_note is the manual-override field carrying the quoted
  -- operative sentence when SPDX is null, NOASSERTION, or simply wrong.
  license_spdx         TEXT,
  license_manual_note  TEXT,
  license_tier         INTEGER NOT NULL
    CONSTRAINT advisory_license_tier CHECK (license_tier IN (0, 1, 2, 3)),
  -- spine S6. See AdvisoryTrustDefault: 'anvil_generated' is deliberately
  -- absent, because every byte in this table originated outside Anvil.
  anvil_trust          TEXT NOT NULL DEFAULT 'untrusted'
    CONSTRAINT advisory_anvil_trust CHECK (anvil_trust IN ('untrusted', 'verified')),
  as_of                TEXT NOT NULL,
  staleness_seconds    INTEGER NOT NULL DEFAULT 0
    CONSTRAINT advisory_staleness_nonneg CHECK (staleness_seconds >= 0),
  -- spine S6 / exit criterion 23: an unknown CVE dataVersion is PERSISTED
  -- with parse_degraded = 1, never dropped.
  parse_degraded       INTEGER NOT NULL DEFAULT 0
    CONSTRAINT advisory_parse_degraded_bool CHECK (parse_degraded IN (0, 1)),
  data_version         TEXT,                  -- e.g. CVE record dataVersion 5.0/5.1/5.2
  raw_json             BLOB NOT NULL,
  PRIMARY KEY (source, source_id),
  -- Exit criterion 11, enforced rather than documented: "Every advisory row
  -- carries license_spdx or a non-empty license_manual_note. No row has both
  -- null." A row that records neither is a row Anvil cannot lawfully
  -- redistribute and cannot prove it may use.
  CONSTRAINT advisory_license_declared CHECK (
    (license_spdx IS NOT NULL AND length(trim(license_spdx)) > 0)
    OR (license_manual_note IS NOT NULL AND length(trim(license_manual_note)) > 0)
  ),
  -- Exit criterion 22, enforced rather than documented: withdrawn/REJECTED
  -- advisories are TOMBSTONED, never deleted. A non-published state without a
  -- tombstone timestamp loses the "when" that A.16 needs to invalidate the
  -- findings that depended on it.
  CONSTRAINT advisory_tombstone_paired CHECK (
    (state = 'published' AND tombstoned_at IS NULL)
    OR (state <> 'published' AND tombstoned_at IS NOT NULL)
  )
);
CREATE INDEX idx_advisory_cve_id ON advisory(cve_id);

-- The one-to-many CVE alias table Risk #2 asks for: one CVE may be described
-- by a cvelistV5 record, a GHSA advisory, an OSV entry and a distro advisory
-- at once, and the comparator wants all four.
CREATE TABLE cve_alias (
  cve_id    TEXT NOT NULL,
  source    TEXT NOT NULL,
  source_id TEXT NOT NULL,
  PRIMARY KEY (cve_id, source, source_id),
  FOREIGN KEY (source, source_id) REFERENCES advisory(source, source_id)
);

-- ============ AFFECTED VERSION RANGES ============
--
-- The rows A.17's version comparator reads. Lane A is deterministic and
-- zero-inference (plan/00-SPINE.md S1): CVE/OSV/GHSA describe vulnerable
-- PACKAGE VERSIONS, and a comparator answers that exactly and for free.
CREATE TABLE affected (
  id              INTEGER PRIMARY KEY,
  source          TEXT NOT NULL,
  source_id       TEXT NOT NULL,
  ecosystem       TEXT NOT NULL,              -- 'deb' | 'rpm' | 'apk' | 'npm' | 'pypi' | 'go' | ...
  package         TEXT NOT NULL,
  purl            TEXT,                       -- pkg:deb/debian/openssl@... (purl-spec)
  introduced      TEXT,
  fixed           TEXT,
  -- True when the range came from a vendor/distro advisory rather than
  -- upstream. This column is what defeats the CVE-2023-32681 /
  -- RHSA-2023:4520 backport false-positive class (research/12 §3): a distro
  -- backports the fix without bumping the upstream version, so an upstream
  -- range says "vulnerable" about a package that is not.
  distro_backport INTEGER NOT NULL DEFAULT 0
    CONSTRAINT affected_distro_backport_bool CHECK (distro_backport IN (0, 1)),
  FOREIGN KEY (source, source_id) REFERENCES advisory(source, source_id)
);
CREATE INDEX idx_affected_pkg ON affected(ecosystem, package);

-- ============ FULL-TEXT INDEX ============
--
-- Contentless FTS5 over advisory text: the prose is not duplicated into a
-- shadow copy of raw_json, and the index accepts incremental INSERT/DELETE so
-- a 200-record delta costs 200 row upserts rather than a rebuild
-- (research/06 Recommendation §5).
--
-- rowid == advisory.rowid. There is no content table, so nothing else can
-- address a row.
--
-- UPSERT CONTRACT, and the only legal way to touch this table:
--   INSERT OR REPLACE INTO advisory_fts (rowid, description, references_text)
--   DELETE FROM advisory_fts WHERE rowid = ?
-- NO code path may DROP this table, CREATE it outside this migration, or run
-- the 'rebuild' command. cache_test.go traces every statement reaching the
-- driver and fails if one does.
--
-- contentless_delete=1 is a deliberate, reported addition to the plan's
-- sketch; see the Go doc comment on schemaSQL for the empirical result that
-- forced it.
CREATE VIRTUAL TABLE advisory_fts USING fts5(
  description, references_text,
  content='', contentless_delete=1,
  tokenize='porter unicode61'
);

-- ============ LICENCE DIRECTORY MANIFEST ============
--
-- Backs the segregated on-disk mirror layout spine S8 requires, not just a DB
-- row: "Share-alike sources live in segregated directories with their own
-- LICENSE files." A.4's Gate() is the only writer, and license_file names a
-- LICENSE file PHYSICALLY CHECKED INTO that directory — never a URL and never
-- an API response, because S8's whole point is that seven artifacts return
-- NOASSERTION over a real licence and one hides a restrictive one.
CREATE TABLE license_dir_manifest (
  directory    TEXT PRIMARY KEY,              -- e.g. 'mirror/tier2/ubuntu'
  tier         INTEGER NOT NULL
    CONSTRAINT license_dir_manifest_tier CHECK (tier IN (0, 1, 2, 3)),
  license_file TEXT NOT NULL,                 -- path to the checked-in LICENSE file
  spdx_id      TEXT
);

-- ============ LANE A FINDINGS ============
--
-- Lane A's own output, pre-canonical-record-schema. The canonical fingerprint
-- is anvil-fp/v1 and is owned by internal/record (FINGERPRINT-SPEC.md); id
-- here is a LANE-LOCAL identifier and must never be presented as, derived
-- into, or compared against a canonical fingerprint. Two producers emitting
-- different digests under one name is the named cross-area failure S6 forbids.
CREATE TABLE finding (
  id                   TEXT PRIMARY KEY,      -- Lane A local id, NOT a canonical fingerprint
  collector            TEXT NOT NULL
    CONSTRAINT finding_collector CHECK (collector IN ('host', 'repo-sca')),
  source               TEXT NOT NULL,
  source_id            TEXT NOT NULL,
  package              TEXT NOT NULL,
  installed_version    TEXT NOT NULL,
  ecosystem            TEXT NOT NULL,
  remediable_by_agent  INTEGER NOT NULL
    CONSTRAINT finding_remediable_bool CHECK (remediable_by_agent IN (0, 1)),
  as_of                TEXT NOT NULL,
  staleness_seconds    INTEGER NOT NULL DEFAULT 0
    CONSTRAINT finding_staleness_nonneg CHECK (staleness_seconds >= 0),
  anvil_trust          TEXT NOT NULL DEFAULT 'anvil_generated'
    CONSTRAINT finding_anvil_trust CHECK (anvil_trust IN ('untrusted', 'anvil_generated', 'verified')),
  detected_at          TEXT NOT NULL,
  -- Exit criterion 21, enforced rather than documented: remediable_by_agent
  -- is false for 100% of host-collector rows "with no code path, flag, or
  -- config key capable of overriding it". A CHECK is the only place that
  -- claim can be made true rather than asserted — spine S7's "enforce in
  -- code, not documentation" applied to the host agent's read-only rule.
  CONSTRAINT finding_host_not_remediable CHECK (
    collector <> 'host' OR remediable_by_agent = 0
  ),
  FOREIGN KEY (source, source_id) REFERENCES advisory(source, source_id)
);
CREATE INDEX idx_finding_source ON finding(source, source_id);
`

// Schema returns the complete DDL for cache schema version 1, exactly as
// committed above.
func Schema() string { return schemaSQL }

// SchemaSHA256 returns the lowercase hex SHA-256 of the DDL over its exact
// bytes with no normalisation. migrate.go records this in the ledger, so a
// changed comment changes the checksum — which is the intended sensitivity
// for a schema a running database was built from.
func SchemaSHA256() string {
	sum := sha256.Sum256([]byte(schemaSQL))
	return hex.EncodeToString(sum[:])
}

var tableRE = regexp.MustCompile(`(?m)^CREATE\s+(?:VIRTUAL\s+)?TABLE\s+([A-Za-z_][A-Za-z0-9_]*)`)

// Tables returns every table the DDL creates, ordinary and virtual alike, in
// file order. It is a parse of the DDL rather than a hand-kept list, so a
// table added without a corresponding test goes unexercised loudly instead of
// quietly.
func Tables() []string {
	matches := tableRE.FindAllStringSubmatch(schemaSQL, -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	return names
}

// CheckConstraint returns the text of the named CHECK constraint's expression,
// without the enclosing parentheses.
//
// Every CHECK in this schema is named (research/07 Risk #15), which is what
// makes them addressable from a test at all.
func CheckConstraint(name string) (string, error) {
	anchor := regexp.MustCompile(`CONSTRAINT\s+` + regexp.QuoteMeta(name) + `\s+CHECK\s*\(`)
	loc := anchor.FindStringIndex(schemaSQL)
	if loc == nil {
		return "", fmt.Errorf("cache: no CHECK constraint named %q in the schema", name)
	}
	// loc[1] is the index just past the opening parenthesis. Scan forward to
	// its match, tracking nesting and single-quoted literals so a parenthesis
	// inside a string literal cannot end the scan early.
	depth := 1
	inLiteral := false
	for i := loc[1]; i < len(schemaSQL); i++ {
		switch c := schemaSQL[i]; {
		case c == '\'':
			// Doubled '' inside a literal is an escaped quote; toggling
			// twice leaves the state correct, so no special case is needed.
			inLiteral = !inLiteral
		case inLiteral:
			// Parentheses inside a literal are data, not structure.
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return schemaSQL[loc[1]:i], nil
			}
		}
	}
	return "", fmt.Errorf("cache: CHECK constraint %q has an unbalanced expression", name)
}

var literalRE = regexp.MustCompile(`'((?:[^']|'')*)'`)

// CheckLiterals returns the single-quoted string literals inside the named
// CHECK constraint, in order, with SQL's doubled-quote escape undone.
//
// This exists for exactly one purpose: cache_test.go compares the literals in
// `advisory_anvil_trust` and `finding_anvil_trust` against
// internal/record's TrustValues(), so that adding a trust value in the record
// contract without widening this schema turns a silent produce/consume break
// into a red test. plan/IMPLEMENTATION-PLAN.md §6 exists because eight agents
// each defined the shared vocabulary from their own side and nothing
// reconciled them.
func CheckLiterals(name string) ([]string, error) {
	expr, err := CheckConstraint(name)
	if err != nil {
		return nil, err
	}
	matches := literalRE.FindAllStringSubmatch(expr, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, strings.ReplaceAll(m[1], "''", "'"))
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// The write shapes every later Lane A step must use
// ---------------------------------------------------------------------------
//
// These are statement TEXTS, not a write path. They cannot sanitize their own
// arguments: A.3's Sanitize() must have run on every externally-sourced string
// before it is bound, and A.4's Gate() must have chosen the tier and directory
// before a licence column is bound. They live here because the alternative —
// each of A.7, A.8, A.14, A.15 and A.16 composing its own upsert — is how a
// second, subtly different write shape enters a schema and breaks the FTS
// linkage or the tombstone invariant with no error message.

// UpsertAdvisorySQL inserts or updates one advisory row and RETURNS ITS ROWID,
// which is the key the caller must then use against advisory_fts.
//
// It is ON CONFLICT ... DO UPDATE and not INSERT OR REPLACE on purpose:
// REPLACE deletes the conflicting row and inserts a new one, which assigns a
// new rowid and silently orphans the row's FTS entry. Parameter order matches
// the column list.
const UpsertAdvisorySQL = `
INSERT INTO advisory (
  source, source_id, cve_id, published, modified, state, tombstoned_at,
  severity, cvss_vector, cvss_score, epss_score, epss_as_of, kev,
  license_spdx, license_manual_note, license_tier, anvil_trust,
  as_of, staleness_seconds, parse_degraded, data_version, raw_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (source, source_id) DO UPDATE SET
  cve_id = excluded.cve_id,
  published = excluded.published,
  modified = excluded.modified,
  state = excluded.state,
  tombstoned_at = excluded.tombstoned_at,
  severity = excluded.severity,
  cvss_vector = excluded.cvss_vector,
  cvss_score = excluded.cvss_score,
  epss_score = excluded.epss_score,
  epss_as_of = excluded.epss_as_of,
  kev = excluded.kev,
  license_spdx = excluded.license_spdx,
  license_manual_note = excluded.license_manual_note,
  license_tier = excluded.license_tier,
  anvil_trust = excluded.anvil_trust,
  as_of = excluded.as_of,
  staleness_seconds = excluded.staleness_seconds,
  parse_degraded = excluded.parse_degraded,
  data_version = excluded.data_version,
  raw_json = excluded.raw_json
RETURNING rowid`

// UpsertAdvisoryFTSSQL indexes one advisory's text. Parameters are
// (rowid, description, references_text), where rowid is the value
// UpsertAdvisorySQL returned for the same advisory.
//
// This is the row-scoped INSERT the plan's upsert contract names. With
// `contentless_delete=1` it genuinely replaces the previous terms; without it
// the old terms would survive (see schemaSQL's doc comment).
const UpsertAdvisoryFTSSQL = `
INSERT OR REPLACE INTO advisory_fts (rowid, description, references_text)
VALUES (?, ?, ?)`

// DeleteAdvisoryFTSSQL removes one advisory's text from the index by rowid.
// A.16 uses it when an advisory is tombstoned; the `advisory` row itself is
// never deleted (exit criterion 22).
const DeleteAdvisoryFTSSQL = `DELETE FROM advisory_fts WHERE rowid = ?`

// SelectFeedStateSQL reads one feed's polling state. Parameter is the
// feed_id, which is internal/ingest/config's FeedConfig.ID.
//
// A.7 calls this before every poll to build its conditional-GET headers, and
// must treat "no row" as "never polled" rather than as an error.
const SelectFeedStateSQL = `
SELECT etag, last_modified, watermark, last_ok_at, consecutive_failures, license_tier
FROM feed_state WHERE feed_id = ?`

// UpsertFeedStateSQL writes one feed's polling state. Parameters are
// (feed_id, etag, last_modified, watermark, last_ok_at, consecutive_failures,
// license_tier).
//
// A 304 must reach this statement with the PREVIOUS etag/last_modified/
// watermark values and only last_ok_at advanced: exit criterion 3 requires a
// 304 to leave advisory/affected/advisory_fts byte-identical and move nothing
// but last_ok_at.
const UpsertFeedStateSQL = `
INSERT INTO feed_state (
  feed_id, etag, last_modified, watermark, last_ok_at, consecutive_failures, license_tier
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (feed_id) DO UPDATE SET
  etag = excluded.etag,
  last_modified = excluded.last_modified,
  watermark = excluded.watermark,
  last_ok_at = excluded.last_ok_at,
  consecutive_failures = excluded.consecutive_failures,
  license_tier = excluded.license_tier`
