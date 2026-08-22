// Package decode turns a publisher's advisory document into the row shape
// internal/ingest/cache stores. It is the ONE implementation of every wire
// format Lane A reads.
//
// ===========================================================================
// WHY THIS PACKAGE EXISTS — ORCHESTRATOR RULING G11
// ===========================================================================
//
// It did not exist until A.21. internal/ingest/bootstrap's decoders were
// unexported, so internal/ingest/delta RE-DERIVED CVE 5.x, OSV and KEV
// decoding, and the cache had two producers writing one table from one wire
// format.
//
// That is worse than ordinary duplication. If the two drifted, A.15's weekly
// self-heal would RESTORE THE SAME ROWS FOREVER and nothing would surface it:
// the baseline importer would rewrite what the delta importer wrote, each
// convinced the other was wrong, and the cache would settle on whichever ran
// last. A self-healing system healing toward the wrong answer is quieter than
// one that breaks.
//
// A.14 guarded the duplication with a conformance test that ran both importers
// over identical fixtures — the right move available to it — but two
// implementations agreeing today is a smoke alarm, not a fix. This package is
// the fix. There is now one decodeOSV, one decodeCVE5, one KEV entry mapping,
// one distro-ecosystem list and one known-dataVersion set, and a divergence
// between the two importers is no longer expressible.
//
// ===========================================================================
// WHAT THIS PACKAGE DOES NOT OWN — THE SEAM IS DELIBERATE
// ===========================================================================
//
// DISPATCH IS NOT SHARED, because the two callers legitimately disagree about
// what an unrecognised document MEANS, and collapsing that disagreement would
// be a second bug wearing the first one's clothes:
//
//   - A.8's bulk importer walks 300,000 archive members written by strangers.
//     A member it does not recognise is a README, a directory entry or a CWE
//     catalog, and it is SKIPPED — one bad member must not cost the other
//     299,999.
//   - A.14's delta path fetched a document BECAUSE SOMETHING SAID IT CHANGED.
//     A document it does not recognise means a change was dropped, so it is an
//     ERROR that routes the feed to a path that does understand it.
//
// Each caller therefore keeps its own dispatch and its own size bounds (a
// streamed archive member and a body already read into memory are bounded by
// different numbers for different reasons), and calls in here for the format
// itself. What a record IS, is shared; what a caller does about a record it
// cannot read, is not.
//
// SIZE BOUNDS ARE PARAMETERS, never constants of this package. A limit stated
// twice is a limit that can diverge, which is the exact failure this package
// was created to end.
//
// ===========================================================================
// SANITISATION
// ===========================================================================
//
// Every string this package binds into a Record goes through Decoder.s, which
// is internal/ingest/sanitize applied field by field with the removal counts
// accumulated (A.3 forbids dropping characters without a count; spine S7 puts
// prompt-injection defence at ingest, not at prompt time). Record.Raw is the
// one exception and it is deliberate: `advisory.raw_json` stores the
// PUBLISHER'S BYTES VERBATIM, because CVE-TOU requires records be stored
// unedited, and because two importers that re-render a document store two
// different digests of the same advisory.
//
// The callers re-prove it at the write site with sanitize.AssertAllSanitized
// on the exact values about to be bound. This package's guarantee is not
// trusted there; it is checked.
package decode

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// ErrElementTooLarge is returned by StreamArrayField when one element of a
// streamed array exceeds the caller's bound.
//
// It is the only error this package originates that is not simply a JSON parse
// failure handed back. Callers wrap it in their own refusal vocabulary — the
// bound is theirs, so the sentence about it is theirs too.
var ErrElementTooLarge = errorString("decode: an array element exceeds the caller's size bound")

type errorString string

func (e errorString) Error() string { return string(e) }

// ---------------------------------------------------------------------------
// The record model
// ---------------------------------------------------------------------------

// AffectedRange is one row of the cache's `affected` table: a package, an
// ecosystem, and the version window a comparator answers against.
//
// plan/00-SPINE.md S1 is why these rows are the point of Lane A at all:
// "CVE/OSV/GHSA describe vulnerable PACKAGE VERSIONS, and a version comparator
// answers that exactly and for free."
type AffectedRange struct {
	Ecosystem string
	Package   string
	PURL      string

	// Introduced and Fixed bound the vulnerable window. Either may be empty:
	// an OSV entry with a `last_affected` event and no `fixed` has no fixed
	// version, and that is a fact about the advisory, not a parse failure.
	Introduced string
	Fixed      string

	// DistroBackport marks a range that came from a vendor or distro advisory
	// rather than from upstream. research/12 §3: a distro backports a fix
	// without moving the upstream version, so an upstream range calls a
	// patched package vulnerable. This column is what A.17 needs to not do
	// that.
	DistroBackport bool
}

// Record is one decoded advisory, already sanitized, ready to bind.
//
// Both importers write THIS type. internal/ingest/delta.Record and
// internal/ingest/bootstrap's advisoryRecord are Go type ALIASES for it, so
// there is one field set, one meaning per field, and no conversion function
// anywhere that could quietly drop one.
type Record struct {
	// Source is the feed id and SourceID the native id within it. Together
	// they are the primary key, and it is NEVER the CVE id: research/06 Risk
	// #2 requires a cvelistV5 outage to be survivable by swapping sources,
	// and GHSA advisories frequently carry no CVE at all.
	Source   string
	SourceID string

	// CVEID is the nullable, indexed alias. Aliases carries the one-to-many.
	CVEID   string
	Aliases []string

	Published string
	Modified  string

	// State is one of cache.AdvisoryPublished / AdvisoryWithdrawn /
	// AdvisoryRejected. A non-published state MUST carry TombstonedAt, and
	// the schema's advisory_tombstone_paired CHECK refuses the row otherwise
	// — withdrawn advisories are tombstoned, never deleted, so that findings
	// that depended on them become invalidated rather than vanishing.
	State        string
	TombstonedAt string

	Severity   string
	CVSSVector string

	// CVSSScore and EPSSScore are `any` so that "no score" is SQL NULL rather
	// than 0.0. A zero CVSS base score is a real value, and a comparator that
	// cannot tell it from "absent" ranks an unscored advisory as harmless.
	CVSSScore any
	EPSSScore any
	EPSSAsOf  string

	KEV bool

	Description string
	References  []string

	Affected []AffectedRange

	// DataVersion is the record schema version the document declared, and
	// ParseDegraded is spine S6's field for "this was persisted anyway".
	// A.2 exit criterion 23: an unknown CVE dataVersion is PERSISTED with
	// parse_degraded = 1, never dropped, because silently discarding a record
	// from a newer schema is how a vulnerability disappears from a security
	// tool with no error anywhere.
	DataVersion   string
	ParseDegraded bool

	// StalenessSeconds overrides the batch-wide value when the record carries
	// its own age. Zero means "use the batch's".
	StalenessSeconds int

	// Raw is the document verbatim, stored in advisory.raw_json. It is never
	// sanitized: the column is the publisher's bytes, and CVE-TOU requires
	// records be stored byte-verbatim (research/06 §"License").
	Raw []byte
}

// ReferencesText is the `references_text` column of advisory_fts: the
// references as one newline-separated string, each element already sanitized.
func (r Record) ReferencesText() string { return strings.Join(r.References, "\n") }

// ---------------------------------------------------------------------------
// The decoder
// ---------------------------------------------------------------------------

// Decoder is the per-import decoding context: which feed the rows belong to,
// and the running report of everything A.3 removed.
//
// The stats exist so the sanitizer's findings are not thrown away. A feed that
// ships zero-width joiners, bidi overrides or HTML comments inside an advisory
// description is not a curiosity — spine S7 puts prompt injection at ingest,
// and the counts are the only place the fact is visible after the bytes are
// clean.
type Decoder struct {
	feedID string
	stats  sanitize.SanitizeStats
}

// New returns a decoder that stamps feedID into every record's Source.
func New(feedID string) *Decoder { return &Decoder{feedID: feedID} }

// FeedID is the feed every record from this decoder is attributed to.
func (dc *Decoder) FeedID() string { return dc.feedID }

// Stats is everything the sanitizer removed across every field decoded so far.
func (dc *Decoder) Stats() sanitize.SanitizeStats { return dc.stats }

// s is A.3 applied to one field, accumulating what it removed.
//
// It is a named method rather than an inline call at every site so that
// internal/ingest/sanitize's writer guard — which resolves the package-local
// call graph by NAME — sees the decoders reaching the sanitizer, and so that
// there is exactly one place where a field could be bound without passing
// through it (there is none).
func (dc *Decoder) s(raw string) string {
	clean, st := sanitize.Sanitize(raw)
	dc.stats.Merge(st)
	return clean
}

// ---------------------------------------------------------------------------
// Streaming helper
// ---------------------------------------------------------------------------

// StreamArrayField walks a top-level JSON object and hands every element of the
// named array to fn, ONE AT A TIME.
//
// This is the function that makes "never loads the whole archive into memory"
// true for the multi-record feeds. CISA KEV is a single JSON document holding
// every known-exploited vulnerability; json.Unmarshal of it would allocate the
// entire file plus its object graph, which for the merged OSV export would be
// gigabytes. json.Decoder buffers one VALUE.
//
// maxElement bounds ONE element and is the caller's number: an archive member
// and a body already read into memory are bounded differently, for different
// reasons, and a constant here would be a third bound nobody owns. A zero or
// negative maxElement means unbounded, which is only correct when the caller
// has already bounded the whole document.
//
// A MALFORMED DOCUMENT ENDS THE WALK AND IS NOT AN ERROR. That is this
// function's contract and the callers depend on it: a bulk archive member that
// is not the shape it looked like is a skip, and the caller counts the skip.
// Only the size refusal and fn's own error propagate.
func StreamArrayField(r io.Reader, field string, maxElement int, fn func(json.RawMessage) error) error {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil
		}
		key, _ := keyTok.(string)
		if key != field {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil
			}
			continue
		}
		open, err := dec.Token()
		if err != nil {
			return nil
		}
		if d, ok := open.(json.Delim); !ok || d != '[' {
			return nil
		}
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return nil
			}
			if maxElement > 0 && len(raw) > maxElement {
				return ErrElementTooLarge
			}
			if err := fn(raw); err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

// IsCVEID is the ALLOWLIST that decides whether a string from a feed may be
// treated as a CVE identifier.
//
// It is not only a parsing convenience: the deltaLog route in
// internal/ingest/delta uses it as the ONLY thing that may cross from feed
// content into a fetch, so its strictness is a security property and not a
// nicety.
//
// The shape is CVE-<4+ digits>-<1+ digits> and nothing else. It is an allowlist
// of characters and structure, not a denylist of dangerous ones: this project
// has lost three guards to a symbol, a verb or a wording nobody listed, and
// `CVE-2024-0001/../../etc/passwd` is precisely the string a denylist misses.
func IsCVEID(s string) bool {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "CVE-") || len(t) < 8 {
		return false
	}
	rest := t[4:]
	dash := strings.Index(rest, "-")
	if dash < 4 {
		return false
	}
	for _, r := range rest[:dash] {
		if r < '0' || r > '9' {
			return false
		}
	}
	tail := rest[dash+1:]
	if tail == "" {
		return false
	}
	for _, r := range tail {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// distroEcosystemPrefixes are the ecosystems whose advisories carry BACKPORTED
// fixes. research/12 §3, the CVE-2023-32681 / RHSA-2023:4520 class: a distro
// patches without moving the upstream version, so an upstream range calls a
// fixed package vulnerable.
//
// THIS LIST EXISTS ONCE. It used to exist twice — identically, and guarded by a
// conformance test — and a divergence would have changed
// `affected.distro_backport` for the same bytes depending on which importer
// ran, which is the column A.17's vendor-first precedence rests on.
var distroEcosystemPrefixes = []string{
	"ubuntu", "debian", "alpine", "red hat", "redhat", "rocky", "almalinux",
	"suse", "photon", "chainguard", "wolfi", "mageia",
}

// IsDistroEcosystem reports whether an OSV ecosystem string names a
// distribution, and therefore whether its ranges are backported.
func IsDistroEcosystem(eco string) bool {
	lower := strings.ToLower(eco)
	for _, p := range distroEcosystemPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// knownCVEDataVersions are the record schema versions these decoders were
// written against. An UNKNOWN one is PERSISTED with parse_degraded = 1 and
// never dropped (Lane A exit criterion 23, spine S6): silently discarding a
// record from a newer schema is how a vulnerability disappears from a security
// tool with no error anywhere.
var knownCVEDataVersions = map[string]bool{"5.0": true, "5.1": true, "5.2": true}

// KnownCVEDataVersion reports whether a CVE record's declared dataVersion is
// one these decoders understand.
func KnownCVEDataVersion(v string) bool { return knownCVEDataVersions[strings.TrimSpace(v)] }

// KnownCVEDataVersions is the sorted set, for a caller that has to report it.
func KnownCVEDataVersions() []string {
	out := make([]string, 0, len(knownCVEDataVersions))
	for v := range knownCVEDataVersions {
		out = append(out, v)
	}
	// Three fixed values; an insertion sort keeps the dependency count at zero
	// and the order stable for a report.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// AppendUnique appends v to list when it is neither empty nor already present.
func AppendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

// FirstNonEmpty returns the first value that is not blank after trimming.
func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
