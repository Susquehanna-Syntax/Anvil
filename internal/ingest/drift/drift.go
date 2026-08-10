// Package drift is A.16: what Anvil does when a feed changes shape underneath
// it, and what it does when a publisher takes an advisory back.
//
// ===========================================================================
// THE ONE RULE THIS PACKAGE EXISTS TO KEEP
// ===========================================================================
//
// A RECORD IS NEVER DROPPED FOR BEING UNFAMILIAR, AND NEVER EMITTED AS THOUGH
// IT WERE WHOLE WHEN IT IS NOT.
//
// Those are the same rule seen from two sides. research/06 Risk #3 states the
// first half — "on an unknown minor version, ingest raw and set
// parse_degraded=1 rather than dropping the record" — and plan/00-SPINE.md S6
// states the second by making `parse_degraded` a REQUIRED field of the record
// rather than an optional diagnostic. A parser that skips a field it does not
// recognise and emits the record anyway produces a finding that looks complete
// and is not, and a finding that looks complete is one nobody re-checks.
//
// The failure this guards against is not hypothetical and does not announce
// itself. research/06's worked example is the deltaLog.json retention window
// being cut from 30 days to 15 in February 2026 with no announcement: the feed
// did not break, it did not error, it simply started meaning something
// slightly different. A version bump is the polite form of the same event.
//
// ===========================================================================
// WHAT "BRANCH ON dataVersion" MEANS HERE, AND WHAT IT DOES NOT MEAN
// ===========================================================================
//
// It does NOT mean a second CVE decoder. internal/ingest/delta already has one
// and internal/ingest/bootstrap has another, and delta's own package comment
// records that the second one is a real cross-area hazard which its
// conformance test exists to contain. A THIRD would be the same defect with a
// third name on it, so this package extracts NOTHING itself: it decides which
// parse profile a document's `dataVersion` selects, delegates the extraction
// to delta.Decode, and adds the one thing delta cannot express — WHICH FIELDS
// WERE NOT UNDERSTOOD.
//
// For the same reason drift.Record is a Go type ALIAS for delta.Record and not
// a struct of its own. A parallel record type would be a parallel write path a
// week later.
//
// THE FIELD CHECK IS AN ALLOWLIST. Three guards on this project were defeated
// by a symbol, a verb or a wording nobody thought to list, and a denylist of
// "fields we know are dangerous" cannot be written at all for a schema whose
// next version has not been published. Each profile enumerates the paths this
// parser HAS been written against — including the ones it deliberately does
// not extract, because "I know that field exists and I do not use it" is a
// decision, while "I have never heard of that field" is drift. Anything not on
// the list is reported by path.
//
// ===========================================================================
// DEGRADED IS LOUD; REPORTED IS NOT THE SAME AS DEGRADED
// ===========================================================================
//
// Two outcomes, deliberately distinguished, because a report nobody can act on
// is a report nobody reads:
//
//   - An UNKNOWN dataVersion is degraded, always. The document may mean
//     something this parser cannot see, anywhere in it.
//   - A KNOWN dataVersion carrying an unrecognised field is degraded ONLY when
//     that field sits in a LOAD-BEARING path: `/cveMetadata`, which decides
//     identity and retraction, or an `affected` subtree, which is the version
//     range Lane A's whole reason for existing is answered from
//     (plan/00-SPINE.md S1). An unrecognised field in prose, credits or
//     taxonomy mappings is REPORTED, and does not by itself make the version
//     comparator's answer wrong.
//
// Both lists ride on the Report. Only the first sets `parse_degraded` on the
// row, and Report.Degraded and Record.ParseDegraded are asserted equal on
// every path — the one thing worse than a degraded record is a record whose
// flag and whose report disagree about whether it is degraded.
//
// ===========================================================================
// WHAT THIS PACKAGE DOES NOT DO
// ===========================================================================
//
//   - It does not fetch, and it holds no clock of its own. A.7 polls, A.14
//     syncs, and Tombstoner takes its clock as a field so a test does not have
//     to sleep.
//   - It does not sanitize on the parse path. delta.Decode does that field by
//     field; this package sanitizes only the strings it originates itself (the
//     fallback record's identifiers, and the values it reads back out of the
//     cache on the tombstone path).
//   - It does not compute a fingerprint, derive one, or compare against one.
//     anvil-fp/v1 is internal/record's and is the only one (S6).
package drift

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/delta"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrDrift is satisfied by every error this package originates, so a
	// caller can tell "A.16 declined" from "the database failed" without
	// listing every sentinel below.
	ErrDrift = errors.New("drift")

	// ErrDriftRefused is satisfied by every refusal: a decision Anvil made, as
	// opposed to something that went wrong.
	ErrDriftRefused = fmt.Errorf("%w: refused", ErrDrift)

	// ErrDocumentTooLarge bounds one document. The bound is on what ARRIVED,
	// never on what a header claimed, and it is delta.MaxDocumentBytes rather
	// than a second number, because two caps for one document is how a
	// document becomes acceptable to one half of the pipeline and not the
	// other.
	ErrDocumentTooLarge = fmt.Errorf("%w: document too large", ErrDriftRefused)

	// ErrNotAnObject is a document that is not a single JSON object. An array
	// of advisories is a legitimate feed shape and delta.Decode handles it;
	// this entry point answers about ONE record and says so rather than
	// silently taking the first element.
	ErrNotAnObject = fmt.Errorf("%w: document is not a single JSON object", ErrDriftRefused)

	// ErrNoPrimaryKey is a document from which no (source, source_id) can be
	// formed even by the fallback. It is the ONLY case in this package where a
	// document does not become a persistable record, and it is an error rather
	// than a silent drop for exactly that reason: the cache is keyed on
	// (source, source_id) and a row without one cannot be written, re-found or
	// re-opened.
	ErrNoPrimaryKey = fmt.Errorf("%w: no primary key in the document", ErrDriftRefused)
)

// refuse builds a refusal: a decision Anvil made.
func refuse(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, args...))
}

// ---------------------------------------------------------------------------
// The record model, aliased and not redefined
// ---------------------------------------------------------------------------

// Record is internal/ingest/delta's Record, ALIASED.
//
// It is `=` and not a new struct on purpose. A.14 owns the decoded-advisory
// shape and the only sanctioned write path for it (delta.Apply); a struct
// declared here would be convertible, plausible, and one refactor away from
// being written to the cache by a second route with a subtly different set of
// invariants. The alias means a drift-parsed record IS a delta record, so
// there is exactly one write path and no conversion in which a field can be
// dropped.
type Record = delta.Record

// ---------------------------------------------------------------------------
// Versions and branches
// ---------------------------------------------------------------------------

// Branch names the parse profile a document's `dataVersion` selects.
//
// It is Lane-A-local vocabulary with no counterpart among the record
// contract's six frozen enums, so declaring it here does not violate
// plan/IMPLEMENTATION-PLAN.md §6's single-owner rule. It exists so that a
// caller switches on a constant rather than comparing version strings it
// re-derived.
type Branch string

const (
	// BranchCVE50, BranchCVE51 and BranchCVE52 are the CVE Record Format
	// versions this parser has been written against. A.16's packet names
	// exactly these three as known.
	BranchCVE50 Branch = "cve-5.0"
	BranchCVE51 Branch = "cve-5.1"
	BranchCVE52 Branch = "cve-5.2"

	// BranchUnknown is every other value, INCLUDING an absent one. It is not
	// an error and it is not a drop: it is the loud degraded state this
	// package exists to produce.
	BranchUnknown Branch = "unknown"
)

// branchByVersion is the ALLOWLIST of understood `dataVersion` values.
//
// It must agree with internal/ingest/delta's own knownCVEDataVersions, which
// is unexported and therefore cannot be compared to this map directly.
// drift_test.go compares them BEHAVIOURALLY instead — it runs delta.Decode
// over a synthetic record at each version and asserts the decoder's own
// parse_degraded matches this table — so the two cannot drift apart without a
// red test in this package. A third copy of this list is in
// internal/ingest/bootstrap; the same behavioural comparison is the only tool
// available for it, and delta's conformance test already binds bootstrap to
// delta.
var branchByVersion = map[string]Branch{
	"5.0": BranchCVE50,
	"5.1": BranchCVE51,
	"5.2": BranchCVE52,
}

// KnownVersions returns the understood `dataVersion` values in ascending
// order. It exists so a caller (or an operator-facing status page) can print
// what this build understands without reaching into the table.
//
// The order is NUMERIC PER COMPONENT and not lexical. Lexically, "5.10" sorts
// before "5.2", which would make newestBranch pick the wrong profile the first
// time CVE reaches a two-digit minor — a latent, silent, off-by-one-schema
// defect that would surface as a partial parse and nothing else.
func KnownVersions() []string {
	out := make([]string, 0, len(branchByVersion))
	for v := range branchByVersion {
		out = append(out, v)
	}
	return sortVersions(out)
}

// sortVersions orders dotted numeric versions ascending, in place, and returns
// the slice.
//
// It is a named function rather than a sort.Slice call inside KnownVersions so
// that it can be tested against a list this build's table does not contain.
// With only 5.0, 5.1 and 5.2 known, a lexical sort and a numeric one give the
// same answer, so a test that could only look at KnownVersions() would pass
// against the wrong implementation — which is the "a guard that has never
// failed has not been tested" shape, arrived at by accident.
func sortVersions(versions []string) []string {
	sort.Slice(versions, func(i, j int) bool { return compareVersions(versions[i], versions[j]) < 0 })
	return versions
}

// compareVersions orders dotted numeric versions component by component. A
// non-numeric component compares as -1, below every real one, so a malformed
// entry can never become "newest".
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := versionComponent(as, i), versionComponent(bs, i)
		switch {
		case av < bv:
			return -1
		case av > bv:
			return 1
		}
	}
	return strings.Compare(a, b)
}

func versionComponent(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	n := 0
	for _, c := range parts[i] {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// BranchFor maps a declared `dataVersion` to its parse profile.
//
// The comparison is on the TRIMMED value and nothing else: no prefix match, no
// "5.x means 5.anything", no major-version fallback. A prefix rule is how "5.3
// looks close enough to 5.2" becomes a silently partial parse, which is the
// entire failure this package was written to prevent.
func BranchFor(dataVersion string) Branch {
	if b, ok := branchByVersion[strings.TrimSpace(dataVersion)]; ok {
		return b
	}
	return BranchUnknown
}

// Known reports whether b is a profile this parser implements.
func (b Branch) Known() bool { return b != BranchUnknown && b != "" }

// ---------------------------------------------------------------------------
// Report codes
// ---------------------------------------------------------------------------

// Code is one reason a document was reported on. Codes are stable strings so
// an operator can grep a log for one, and they are constants so a producer
// cannot invent a fourth spelling of "unknown version".
type Code string

const (
	// CodeUnknownDataVersion is the packet's central case: a `dataVersion`
	// this parser has no profile for. ALWAYS degrading.
	CodeUnknownDataVersion Code = "unknown-data-version"

	// CodeMissingDataVersion is a CVE record that declares no version at all.
	// It is treated exactly as an unknown one — a document that will not say
	// what it is has not earned the benefit of the doubt.
	CodeMissingDataVersion Code = "missing-data-version"

	// CodeUnknownField is a path outside the selected profile's allowlist,
	// sitting outside every load-bearing subtree. Reported, not degrading.
	CodeUnknownField Code = "unknown-field"

	// CodeUnknownFieldLoadBearing is a path outside the allowlist INSIDE
	// `/cveMetadata` or an `affected` subtree. Degrading: identity, retraction
	// and version ranges are what Lane A's answers are made of.
	CodeUnknownFieldLoadBearing Code = "unknown-field-in-load-bearing-path"

	// CodeUndecodable is a document delta.Decode refused. The record is
	// preserved by the fallback — raw bytes and primary key only — and is
	// degraded, because a record with no parsed content is the most incomplete
	// a record can be.
	CodeUndecodable Code = "undecodable-document"

	// CodeDecoderDegraded is delta.Decode reporting parse_degraded when this
	// package's own rules did not. It exists so the two can never disagree
	// silently: if the decoder degrades a record, the report says why it is
	// degraded rather than claiming everything was understood.
	CodeDecoderDegraded Code = "decoder-reported-degraded"

	// CodeFieldsTruncated means the walk hit its node or field cap and the
	// field lists are incomplete. It is degrading on its own: an incomplete
	// answer about whether anything was missed is not an answer.
	CodeFieldsTruncated Code = "field-scan-truncated"
)

// codeIsDegrading is the ALLOWLIST of codes that set parse_degraded.
//
// A codes-that-are-harmless denylist would have the wrong default: a code
// added later and forgotten would silently NOT degrade. This way a new code
// degrades until somebody says otherwise on purpose.
var codeIsDegrading = map[Code]bool{
	CodeUnknownDataVersion:      true,
	CodeMissingDataVersion:      true,
	CodeUnknownFieldLoadBearing: true,
	CodeUndecodable:             true,
	CodeDecoderDegraded:         true,
	CodeFieldsTruncated:         true,
	CodeUnknownField:            false,
}

// Degrading reports whether this code sets parse_degraded on the row.
//
// A code that is not in the table degrades. That default is the whole reason
// the table is written as "which codes are harmless" rather than "which codes
// are dangerous": the entry somebody forgets to add then fails loudly, and the
// alternative fails silently.
func (c Code) Degrading() bool {
	deg, known := codeIsDegrading[c]
	return deg || !known
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

// MaxReportedFields bounds each field list. A document is attacker-adjacent
// input and a report is a log line: an advisory carrying fifty thousand
// unrecognised keys must not be able to turn one log line into fifty thousand.
// Hitting the cap sets Truncated, which is itself degrading.
const MaxReportedFields = 64

// maxWalkNodes bounds the structural walk for the same reason. It is generous
// enough for the largest real CVE record (a few thousand nodes) and small
// enough that a hostile document cannot make the walk the expensive part of an
// ingest.
const maxWalkNodes = 20000

// Report is what the parser understood about one document and what it did not.
//
// It is the "carrying which fields were not understood" half of A.16. A bare
// degraded bool would say a record is incomplete without saying in what way,
// which is a status nobody can act on and therefore a status everybody learns
// to ignore.
type Report struct {
	// DataVersion is the value the document declared, sanitized, verbatim
	// otherwise. Empty means the document declared none.
	DataVersion string

	// Branch is the profile DataVersion selected, and KnownVersion is
	// Branch.Known() recorded at the time of the parse.
	Branch       Branch
	KnownVersion bool

	// Degraded is the value written to `advisory.parse_degraded`. It equals
	// "any code on Codes is degrading", and Parse refuses to return a Record
	// whose ParseDegraded disagrees with it.
	Degraded bool

	// Codes are the reasons, deduplicated, in a stable order.
	Codes []Code

	// UnknownFields are the JSON paths outside the profile's allowlist, as
	// "/containers/cna/affected[]/versions[]/lessThan" — array subscripts are
	// collapsed to "[]" so a thousand affected entries with the same new key
	// report it once. Sorted, deduplicated, capped at MaxReportedFields.
	UnknownFields []string

	// DegradingFields is the subset of UnknownFields inside a load-bearing
	// path. It is the list an operator acts on first.
	DegradingFields []string

	// Truncated is set when the walk hit maxWalkNodes or MaxReportedFields, so
	// a short list is never mistaken for a clean one.
	Truncated bool

	// DecodeError is delta.Decode's refusal, when the fallback record was used
	// instead. Empty otherwise.
	DecodeError string
}

// Clean reports whether the document raised nothing at all.
func (r Report) Clean() bool { return len(r.Codes) == 0 && !r.Degraded }

// Has reports whether the report carries the given code.
func (r Report) Has(c Code) bool {
	for _, got := range r.Codes {
		if got == c {
			return true
		}
	}
	return false
}

// maxRenderedVersion clips the declared version in rendered output. The COLUMN
// stores what the publisher sent; a log line does not have to.
const maxRenderedVersion = 48

// String renders the report as one operator-readable line.
func (r Report) String() string {
	var b strings.Builder
	state := "ok"
	if r.Degraded {
		state = "DEGRADED"
	}
	version := r.DataVersion
	if version == "" {
		version = "(absent)"
	}
	if len(version) > maxRenderedVersion {
		version = version[:maxRenderedVersion] + "..."
	}
	fmt.Fprintf(&b, "drift: %s dataVersion=%q branch=%s", state, version, r.Branch)
	if len(r.Codes) > 0 {
		codes := make([]string, 0, len(r.Codes))
		for _, c := range r.Codes {
			codes = append(codes, string(c))
		}
		fmt.Fprintf(&b, " codes=[%s]", strings.Join(codes, " "))
	}
	if len(r.DegradingFields) > 0 {
		fmt.Fprintf(&b, " not-understood-in-load-bearing-path=[%s]", strings.Join(r.DegradingFields, " "))
	}
	if n := len(r.UnknownFields) - len(r.DegradingFields); n > 0 {
		fmt.Fprintf(&b, " other-fields-not-understood=%d", n)
	}
	if r.Truncated {
		b.WriteString(" (field scan truncated)")
	}
	if r.DecodeError != "" {
		fmt.Fprintf(&b, " decode-error=%q", r.DecodeError)
	}
	return b.String()
}

// add records a code once.
func (r *Report) add(c Code) {
	if !r.Has(c) {
		r.Codes = append(r.Codes, c)
	}
	if c.Degrading() {
		r.Degraded = true
	}
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

// ParseVersioned is the narrow entry point A.16's packet names: bytes in, one
// record and the degraded flag out.
//
// It cannot report WHICH fields it did not understand and it cannot report an
// error, so it is a convenience over Parse and not the primary API. Use Parse
// when either matters, which on an ingest path is always.
//
// TWO THINGS THE RETURNED RECORD DOES NOT HAVE, both by construction:
//
//   - NO Source. Bytes do not know which feed delivered them, and the cache is
//     keyed on (source, source_id). A caller writing the record must stamp
//     rec.Source with the feed id — or call Parse(feedID, raw), which does it.
//     delta.Apply refuses a record with no Source (ErrBadRecord); it does not
//     invent one.
//   - NO parsed content, when the document could not be decoded at all. The
//     record still carries Raw verbatim and ParseDegraded true, because
//     persisting the publisher's bytes under a degraded flag keeps the record
//     re-parseable by a later build, and dropping it does not.
//
// The returned bool is Record.ParseDegraded, which Parse guarantees equals
// Report.Degraded.
func ParseVersioned(raw []byte) (Record, bool) {
	rec, rep, err := Parse("", raw)
	if err != nil {
		// The error cannot be returned through this signature, so the record
		// carries the only two facts that survive it: the publisher's bytes,
		// and "this is degraded". Such a record has no primary key, and
		// delta.Apply refuses it by name rather than writing a keyless row.
		return Record{Raw: raw, ParseDegraded: true}, true
	}
	return rec, rep.Degraded
}

// Parse decodes one advisory document, branching on its declared dataVersion,
// and reports what it did not understand.
//
// THE EXTRACTION IS delta.Decode's, NOT THIS PACKAGE'S. See the package
// comment: a third CVE decoder in this tree would be the cross-area drift the
// second one already has a conformance test to contain.
//
// feedID becomes Record.Source and is the feed's config id. It may be empty,
// in which case the caller must stamp it before writing.
func Parse(feedID string, raw []byte) (Record, Report, error) {
	var rep Report

	if len(raw) > delta.MaxDocumentBytes {
		return Record{}, rep, refuse(ErrDocumentTooLarge,
			"feed %q: a %d-byte document exceeds the %d-byte cap",
			feedID, len(raw), delta.MaxDocumentBytes)
	}

	doc, err := decodeObject(raw)
	if err != nil {
		return Record{}, rep, refuse(ErrNotAnObject, "feed %q: %v", feedID, err)
	}

	// --- branch on dataVersion, explicitly and without a prefix rule ---
	declared, _ := sanitize.Sanitize(stringField(doc, "dataVersion"))
	rep.DataVersion = declared
	rep.Branch = BranchFor(declared)
	rep.KnownVersion = rep.Branch.Known()
	switch {
	case strings.TrimSpace(declared) == "":
		rep.add(CodeMissingDataVersion)
	case !rep.KnownVersion:
		rep.add(CodeUnknownDataVersion)
	}

	// --- what, in this document, is outside the profile ---
	scanBranch := rep.Branch
	if !rep.KnownVersion {
		// An unknown version is scanned against the NEWEST profile this build
		// has, because that is the profile whose extraction actually ran. The
		// resulting field list answers the question an operator has — "what is
		// in this document that our newest parser has never seen?" — rather
		// than the one nobody asked.
		scanBranch = newestBranch()
	}
	w := newWalker(scanBranch)
	w.walk("", doc)
	rep.UnknownFields = w.unknownFields()
	rep.DegradingFields = w.degradingFields()
	rep.Truncated = w.truncated
	if rep.Truncated {
		rep.add(CodeFieldsTruncated)
	}
	if len(rep.DegradingFields) > 0 {
		rep.add(CodeUnknownFieldLoadBearing)
	}
	if len(rep.UnknownFields) > len(rep.DegradingFields) {
		rep.add(CodeUnknownField)
	}

	// --- extraction, delegated ---
	rec, decodeErr := decodeOne(feedID, raw)
	if decodeErr != nil {
		rep.add(CodeUndecodable)
		rep.DecodeError = decodeErr.Error()
		fallback, err := fallbackRecord(feedID, doc, declared, raw)
		if err != nil {
			return Record{}, rep, err
		}
		rec = fallback
	}
	if rec.ParseDegraded && !rep.Degraded {
		// delta's own table said degraded and ours did not. That is a
		// divergence between two lists that must agree, and the conformance
		// test in drift_test.go exists to catch it before a feed does; here it
		// is resolved in the only safe direction.
		rep.add(CodeDecoderDegraded)
	}

	// THE ROW'S FLAG IS THE REPORT'S CONCLUSION, never the other way round,
	// and this single assignment is what makes the two unable to disagree.
	//
	// There is deliberately no `if rec.ParseDegraded != rep.Degraded { ... }`
	// after it. A check on the line below its own assignment can never fire,
	// and a guard that can never fire is worse than none: it reads as
	// verification. The invariant is asserted where it can actually be
	// observed — drift_test.go runs every fixture class through this function
	// and compares the two fields.
	rec.ParseDegraded = rep.Degraded
	return rec, rep, nil
}

// decodeOne runs delta.Decode and insists on exactly one record.
func decodeOne(feedID string, raw []byte) (Record, error) {
	recs, _, err := delta.Decode(feedID, raw)
	if err != nil {
		return Record{}, err
	}
	switch len(recs) {
	case 1:
		return recs[0], nil
	case 0:
		return Record{}, refuse(ErrNotAnObject, "the document decoded to no records at all")
	default:
		return Record{}, refuse(ErrNotAnObject,
			"the document decoded to %d records; this entry point answers about one", len(recs))
	}
}

// fallbackRecord is the never-drop path: delta.Decode refused the document, so
// the record is reduced to the two things that can still be persisted — a
// primary key and the publisher's bytes.
//
// It is deliberately minimal. Reconstructing severity or version ranges here
// would be the third decoder the package comment refuses to write, and a
// half-reconstructed record is exactly the "looks complete and is not" outcome
// A.16 exists to prevent. What survives is enough for the record to be found
// again and re-parsed by a later build that understands the shape.
func fallbackRecord(feedID string, doc map[string]any, dataVersion string, raw []byte) (Record, error) {
	meta, _ := doc["cveMetadata"].(map[string]any)
	id := ""
	if meta != nil {
		id = stringField(meta, "cveId")
	}
	if strings.TrimSpace(id) == "" {
		id = stringField(doc, "id") // OSV-shaped documents key their id at the root.
	}
	clean, _ := sanitize.Sanitize(strings.TrimSpace(id))
	if clean == "" {
		return Record{}, refuse(ErrNoPrimaryKey,
			"feed %q: the document could not be decoded and carries no cveMetadata.cveId or id, "+
				"so no (source, source_id) exists to store it under. The bytes are NOT discarded by "+
				"this package; they are returned to the caller, which must route them to a path that "+
				"can name them.", feedID)
	}
	rec := Record{
		Source:        feedID,
		SourceID:      clean,
		DataVersion:   dataVersion,
		ParseDegraded: true,
		Raw:           raw,
	}
	if delta.IsCVEID(clean) {
		rec.CVEID = clean
		rec.Aliases = []string{clean}
	}
	return rec, nil
}

// decodeObject parses the document as one JSON object.
func decodeObject(raw []byte) (map[string]any, error) {
	// The UTF-8 BOM is written as an ESCAPE and never as a literal. A literal
	// BOM in a Go source file is exactly the kind of invisible character
	// internal/ingest/invisible exists to keep out of this tree, and
	// internal/ingest/delta writes it the same way for the same reason.
	trimmed := strings.TrimLeft(string(raw), " \t\r\n\ufeff")
	if strings.TrimSpace(trimmed) == "" {
		return nil, errors.New("the document is empty")
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("the document does not parse as JSON: %w", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("the document is a %T at its root, not a JSON object", v)
	}
	// Trailing content after the object is refused rather than ignored. Two
	// concatenated advisories parse as "the first one" to a streaming decoder,
	// and "the first one" is a dropped record wearing a successful parse.
	if dec.More() {
		return nil, errors.New("the document carries content after its first JSON object; " +
			"a second advisory would be silently dropped")
	}
	return obj, nil
}

// stringField reads a string-valued key, or "" for anything else. A key whose
// value is not a string is not silently coerced: the walk reports the type
// change as drift, which is the loud half of the same observation.
func stringField(doc map[string]any, key string) string {
	s, _ := doc[key].(string)
	return s
}

// ---------------------------------------------------------------------------
// The structural walk
// ---------------------------------------------------------------------------

// walker compares a document's structure against one profile's allowlist.
type walker struct {
	profile   map[string]bool
	opaque    map[string]bool
	unknown   map[string]bool
	degrading map[string]bool
	nodes     int
	truncated bool
}

func newWalker(b Branch) *walker {
	return &walker{
		profile:   profileFor(b),
		opaque:    opaquePaths(),
		unknown:   map[string]bool{},
		degrading: map[string]bool{},
	}
}

// walk descends one value. path is the profile path of the value itself: "" at
// the root, and already carrying "[]" for an array-valued key, so that array
// ELEMENTS do not each add a segment and a thousand `affected` entries report
// one path rather than a thousand.
func (w *walker) walk(path string, v any) {
	if w.truncated {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			w.nodes++
			if w.nodes > maxWalkNodes {
				w.truncated = true
				return
			}
			child := path + "/" + k
			if _, isArray := t[k].([]any); isArray {
				child += "[]"
			}
			if !w.profile[child] {
				// The children of a field nobody recognises are not separately
				// reported: one unknown subtree is one finding, not a hundred.
				w.note(child)
				continue
			}
			if w.opaque[child] {
				continue
			}
			w.walk(child, t[k])
		}
	case []any:
		for _, e := range t {
			w.nodes++
			if w.nodes > maxWalkNodes {
				w.truncated = true
				return
			}
			w.walk(path, e)
		}
	}
}

func (w *walker) note(path string) {
	if len(w.unknown) >= MaxReportedFields && !w.unknown[path] {
		w.truncated = true
		return
	}
	w.unknown[path] = true
	if isLoadBearing(path) {
		w.degrading[path] = true
	}
}

func (w *walker) unknownFields() []string { return sortedKeys(w.unknown) }

func (w *walker) degradingFields() []string { return sortedKeys(w.degrading) }

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// loadBearingPrefixes are the subtrees whose contents Lane A's answers are
// made of.
//
//   - /cveMetadata decides WHICH advisory this is and whether it has been
//     retracted. A field nobody understands there can change the identity or
//     the state of the row.
//   - the `affected` subtrees are the version ranges. plan/00-SPINE.md S1:
//     "CVE/OSV/GHSA describe vulnerable PACKAGE VERSIONS, and a version
//     comparator answers that exactly and for free." An unrecognised key there
//     is a range that may not mean what the comparator read.
//
// Prose, credits, taxonomy mappings and provider metadata are deliberately NOT
// here. Degrading every record that carries a new prose field would make
// `parse_degraded` mean "this is a CVE record", and a flag that is always set
// is a flag nobody reads.
var loadBearingPrefixes = []string{
	"/cveMetadata",
	"/containers/cna/affected[]",
	"/containers/adp[]/affected[]",
}

// isLoadBearing reports whether a path lies in or names a load-bearing
// subtree.
//
// The prefix match is SEGMENT-AWARE. A plain strings.HasPrefix would make
// "/cveMetadataExtra" load-bearing because it starts with "/cveMetadata",
// which is the same class of near-miss that has defeated three guards on this
// project.
func isLoadBearing(path string) bool {
	for _, p := range loadBearingPrefixes {
		if path == p {
			return true
		}
		// The array form of a load-bearing key is the same key.
		if path == strings.TrimSuffix(p, "[]") || path == p+"[]" {
			return true
		}
		for _, base := range []string{p, strings.TrimSuffix(p, "[]")} {
			if strings.HasPrefix(path, base+"/") || strings.HasPrefix(path, base+"[]/") {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The profiles: what each version's parser has been written against
// ---------------------------------------------------------------------------
//
// EACH ENTRY IS A CLAIM THAT SOMEBODY LOOKED AT THAT FIELD, not that Anvil
// extracts it. delta.Decode reads a handful of these; the rest are here
// because "this parser knows the field exists and does not use it" is a
// decision that can be reviewed, while "this parser has never heard of that
// field" is drift that cannot.
//
// HONESTY ABOUT WHERE THESE COME FROM, because a list presented as a
// transcription and assembled from memory is the worse of the two: this is the
// CVE Record Format as this parser was written against it, not a mechanical
// export of the published JSON Schema. Two consequences, both chosen because
// they fail loudly rather than silently:
//
//   - A field that really belongs to 5.0 but is listed only under 5.1 costs a
//     REPORT LINE on a 5.0 document. It never costs a dropped record, and
//     outside a load-bearing subtree it never even sets parse_degraded.
//   - 5.2's additive set is EMPTY. This parser was written against 5.1's key
//     set and accepts 5.2 as a known version on A.16's packet's authority; a
//     key that exists only in 5.2 is therefore reported as unrecognised. That
//     is the loud outcome and it is the intended one — the alternative,
//     accepting an unenumerated key set for a version nobody enumerated, is
//     the silent one.

// mediaPaths enumerates a `supportingMedia` array. prefix names the array key.
func mediaPaths(prefix string) []string {
	return []string{prefix, prefix + "/type", prefix + "/base64", prefix + "/value"}
}

// prosePaths enumerates an array of {lang, value, supportingMedia[]} objects,
// which is the shape CVE 5.x reuses for descriptions, workarounds, solutions,
// exploits, configurations and rejected reasons.
func prosePaths(prefix string) []string {
	out := []string{prefix, prefix + "/lang", prefix + "/value"}
	return append(out, mediaPaths(prefix+"/supportingMedia[]")...)
}

// referencePaths enumerates a `references` array.
func referencePaths(prefix string) []string {
	return []string{prefix, prefix + "/url", prefix + "/name", prefix + "/tags[]"}
}

// affectedPaths enumerates the `affected` array: THE load-bearing subtree.
func affectedPaths(prefix string) []string {
	return []string{
		prefix,
		prefix + "/vendor",
		prefix + "/product",
		prefix + "/collectionURL",
		prefix + "/packageName",
		prefix + "/repo",
		prefix + "/defaultStatus",
		prefix + "/cpes[]",
		prefix + "/modules[]",
		prefix + "/platforms[]",
		prefix + "/programFiles[]",
		prefix + "/programRoutines[]",
		prefix + "/programRoutines[]/name",
		prefix + "/versions[]",
		prefix + "/versions[]/version",
		prefix + "/versions[]/status",
		prefix + "/versions[]/versionType",
		prefix + "/versions[]/lessThan",
		prefix + "/versions[]/lessThanOrEqual",
		prefix + "/versions[]/changes[]",
		prefix + "/versions[]/changes[]/at",
		prefix + "/versions[]/changes[]/status",
	}
}

// containerPaths enumerates one container (`cna`, or one element of `adp`).
// Both share a schema, so they share this list rather than two copies of it.
func containerPaths(prefix string, withCPEApplicability bool) []string {
	out := []string{
		prefix,
		prefix + "/providerMetadata",
		prefix + "/dateAssigned",
		prefix + "/datePublic",
		prefix + "/title",
		prefix + "/source",
		prefix + "/tags[]",
		prefix + "/taxonomyMappings[]",
		prefix + "/replacedBy[]",
		prefix + "/problemTypes[]",
		prefix + "/problemTypes[]/descriptions[]",
		prefix + "/problemTypes[]/descriptions[]/type",
		prefix + "/problemTypes[]/descriptions[]/lang",
		prefix + "/problemTypes[]/descriptions[]/description",
		prefix + "/problemTypes[]/descriptions[]/cweId",
		prefix + "/impacts[]",
		prefix + "/impacts[]/capecId",
		prefix + "/metrics[]",
		prefix + "/metrics[]/format",
		prefix + "/metrics[]/cvssV2_0",
		prefix + "/metrics[]/cvssV3_0",
		prefix + "/metrics[]/cvssV3_1",
		prefix + "/metrics[]/cvssV4_0",
		prefix + "/metrics[]/other",
		prefix + "/timeline[]",
		prefix + "/timeline[]/time",
		prefix + "/timeline[]/lang",
		prefix + "/timeline[]/value",
		prefix + "/credits[]",
		prefix + "/credits[]/lang",
		prefix + "/credits[]/value",
		prefix + "/credits[]/type",
		prefix + "/credits[]/user",
	}
	out = append(out, referencePaths(prefix+"/references[]")...)
	out = append(out, referencePaths(prefix+"/problemTypes[]/descriptions[]/references[]")...)
	out = append(out, prosePaths(prefix+"/descriptions[]")...)
	out = append(out, prosePaths(prefix+"/impacts[]/descriptions[]")...)
	out = append(out, prosePaths(prefix+"/metrics[]/scenarios[]")...)
	out = append(out, prosePaths(prefix+"/workarounds[]")...)
	out = append(out, prosePaths(prefix+"/solutions[]")...)
	out = append(out, prosePaths(prefix+"/exploits[]")...)
	out = append(out, prosePaths(prefix+"/configurations[]")...)
	out = append(out, prosePaths(prefix+"/rejectedReasons[]")...)
	out = append(out, affectedPaths(prefix+"/affected[]")...)
	if withCPEApplicability {
		out = append(out, prefix+"/cpeApplicability[]")
	}
	return out
}

// basePaths is the CVE 5.0 profile.
func basePaths(withCPEApplicability bool) []string {
	out := []string{
		"/dataType",
		"/dataVersion",
		"/cveMetadata",
		"/cveMetadata/cveId",
		"/cveMetadata/assignerOrgId",
		"/cveMetadata/assignerShortName",
		"/cveMetadata/requesterUserId",
		"/cveMetadata/serial",
		"/cveMetadata/state",
		"/cveMetadata/dateReserved",
		"/cveMetadata/datePublished",
		"/cveMetadata/dateUpdated",
		"/cveMetadata/dateRejected",
		"/containers",
		"/containers/adp[]",
	}
	out = append(out, containerPaths("/containers/cna", withCPEApplicability)...)
	out = append(out, containerPaths("/containers/adp[]", withCPEApplicability)...)
	return out
}

// opaquePaths are the subtrees the walk does NOT descend into.
//
// Each is a nested schema of its own — CVSS vectors, CPE applicability node
// trees, taxonomy mappings, provider and source metadata — whose internals are
// not what Lane A matches on. Enumerating three CVSS schemas here would import
// their revision history into this file and would report a new CVSS field as
// CVE drift, which is a false alarm about the wrong feed. The node is on the
// allowlist, so its PRESENCE is understood; only its contents go unexamined,
// and that is a decision recorded here rather than an omission.
func opaquePaths() map[string]bool {
	out := map[string]bool{}
	for _, prefix := range []string{"/containers/cna", "/containers/adp[]"} {
		for _, p := range []string{
			"/providerMetadata",
			"/source",
			"/taxonomyMappings[]",
			"/cpeApplicability[]",
			"/metrics[]/cvssV2_0",
			"/metrics[]/cvssV3_0",
			"/metrics[]/cvssV3_1",
			"/metrics[]/cvssV4_0",
			"/metrics[]/other",
		} {
			out[prefix+p] = true
		}
	}
	return out
}

// profiles is the per-branch allowlist, built once.
var profiles = map[Branch]map[string]bool{
	BranchCVE50: pathSet(basePaths(false)),
	BranchCVE51: pathSet(basePaths(true)),
	BranchCVE52: pathSet(basePaths(true)),
}

func pathSet(paths []string) map[string]bool {
	out := make(map[string]bool, len(paths))
	for _, p := range paths {
		out[p] = true
	}
	return out
}

// profileFor returns the allowlist for a branch. An unknown branch is scanned
// against the newest profile; see Parse.
func profileFor(b Branch) map[string]bool {
	if p, ok := profiles[b]; ok {
		return p
	}
	return profiles[newestBranch()]
}

// newestBranch is the highest known version's branch. It is derived from
// branchByVersion rather than written twice, so adding a version cannot leave a
// stale "newest" behind.
func newestBranch() Branch {
	versions := KnownVersions()
	if len(versions) == 0 {
		return BranchUnknown
	}
	return branchByVersion[versions[len(versions)-1]]
}
