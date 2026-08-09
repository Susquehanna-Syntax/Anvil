// engine.go is step O.6: the POLICY ENGINE over the schema O.5 froze at
// schemas/policy.schema.json.
//
// The owner's hard constraint (plan/00-SPINE.md S1, restated by
// plan/70-orchestration-ci.md) is that trigger policy is DATA. If a trigger
// decision can only be changed by editing Go, this file has failed no matter
// how clean it reads. So the evaluator below is generic over whatever
// `scanRules` the parsed document contains: it never branches on a particular
// event name, ref glob, path glob, bump kind or cadence. The only closed
// vocabularies it knows are the ones the SCHEMA itself closes -- `depth`,
// `matchSemverBump`, `version` -- plus area 40's `detector` enum, and it knows
// them for VALIDATION at load time, never as a match condition. Grep this file
// for a string literal used to decide whether a rule fires and you will find
// none; the tests in engine_test.go assert that with invented vocabulary.
//
// ---------------------------------------------------------------------------
// THE EVALUATION ORDER, STATED ONCE, NORMATIVELY
// ---------------------------------------------------------------------------
//
// Renovate's `packageRules` convention (research/09 Recommendation 2), which
// schemas/policy.schema.json documents in its `scanRules` description and this
// file implements:
//
//  1. Start from `defaults` (absent `defaults` means every field starts unset;
//     the engine has no built-in fallback values of its own).
//  2. Walk `scanRules` in ARRAY ORDER, index 0 upward. Evaluation does NOT
//     short-circuit on the first match.
//  3. A rule whose match* keys ALL match contributes its settings.
//  4. A contributing rule overrides earlier layers FIELD BY FIELD. It does not
//     replace the whole resolved rule, and a field it leaves unset keeps
//     whatever the previous layer put there.
//
// Precedence is therefore, for every leaf field independently:
//
//	last matching rule that sets it  >  earlier matching rule  >  defaults
//
// "Which rule won" is not an emergent property here: ResolvedRule.Source
// records, per leaf field, the exact layer that set it, and Evaluate never
// ranges over a Go map while resolving. (Ranging a map without sorting keys is
// how the fingerprint work shipped a determinism bug; this file has one map
// range, over the unknown-key set in the decoder, and it sorts.)
//
// ---------------------------------------------------------------------------
// WHAT `failOn` DELIBERATELY IS NOT
// ---------------------------------------------------------------------------
//
// schemas/policy.schema.json flags an OPEN CROSS-AREA ITEM: research/09 writes
// `failOn: high`, while area 40's severity vocabulary is SARIF's
// none|note|warning|error, and the mapping between them "needs one named owner
// before O.6 ships". O.6 does NOT claim that ownership and does not invent the
// mapping. `FailOn` is carried through this engine as an OPAQUE token: merged
// field-by-field like any other setting, never compared, never ordered, never
// mapped. Whoever is named owner of the mapping applies it downstream of the
// resolved rule. Inventing it here would have created exactly the second
// definition that plan/IMPLEMENTATION-PLAN.md section 6 closed ten instances
// of.

package policy

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrUnsupportedVersion reports a policy document whose `version` is not
	// SchemaVersion. The schema pins `version` to a const so an old daemon
	// fails loudly on a new file instead of misreading it; Evaluate enforces
	// the same thing on a Policy value that never went through FromDocument.
	ErrUnsupportedVersion = errors.New("policy: unsupported policy version")

	// ErrBadPattern reports a glob that cannot be compiled. It is returned,
	// never swallowed: a malformed pattern that silently matched nothing
	// would be a rule that never fires and never errors -- the failure mode
	// the schema's strictness exists to convert into a load-time error.
	ErrBadPattern = errors.New("policy: malformed glob pattern")

	// ErrPatternTooComplex reports a glob that exceeds MaxGlobPatternBytes or
	// MaxGlobPatternSegments. It is a REFUSAL, not a truncation or a silent
	// non-match, and every error carrying it also satisfies errors.Is(err,
	// ErrBadPattern) so that callers written before the cap existed still
	// branch correctly.
	//
	// WHY A POLICY FILE HAS A COMPLEXITY CAP AT ALL. `.anvil/policy.yml` is
	// read FROM THE REPOSITORY UNDER SCAN, and Anvil scans untrusted
	// repositories by design, so the pattern is attacker-controlled input
	// reaching a matcher. The matcher below is bounded (see MatchGlob's
	// COST section), and this cap bounds its one remaining free variable --
	// the size of the pattern itself. A refused policy is a diagnosable
	// outcome; a scanner that spins is research/09 Risk #4's failure mode,
	// where a reviewer reads no signal as no problem.
	ErrPatternTooComplex = errors.New("policy: glob pattern exceeds the complexity cap")

	// ErrPolicyTooLarge reports a policy, or a policy-plus-context pair, that
	// exceeds one of the AGGREGATE bounds: MaxScanRules, MaxListItems,
	// MaxChangedPaths or MaxEvaluationMatchOps. Like ErrPatternTooComplex it is
	// a REFUSAL, never a truncation and never a partial evaluation.
	//
	// WHY IT EXISTS SEPARATELY FROM ErrPatternTooComplex. That cap bounds ONE
	// pattern. It says nothing about how many patterns there are, and the
	// denial of service CRITIQUE O.4 found by recursion is reachable again by
	// MULTIPLICATION: ten thousand cheap rules cost the same outage as one
	// expensive one, and `.anvil/policy.yml` comes from the repository under
	// scan either way. A per-item cap with no aggregate cap is a bounded unit
	// price on an unbounded quantity.
	//
	// The refusals that describe the DOCUMENT — too many rules, too many items
	// in a list — also satisfy errors.Is(err, ErrInvalidDocument), because a
	// document past a maxItems the schema declares is an invalid document. The
	// refusals that describe an EVALUATION — too many changed paths, too much
	// total matching work — do not, because the document may be perfectly legal
	// and the context is what is out of range.
	ErrPolicyTooLarge = errors.New("policy: exceeds an aggregate bound")

	// ErrInvalidDocument reports a document that does not conform to
	// schemas/policy.schema.json. FromDocument wraps it with the JSON-pointer
	// -ish path of the offending node.
	ErrInvalidDocument = errors.New("policy: invalid policy document")
)

// SchemaVersion is the only `version` value that exists. It is the POLICY FILE
// schema version, not an Anvil release version. A future 2 must be added as a
// new value rather than reinterpreting 1.
const SchemaVersion = 1

// ---------------------------------------------------------------------------
// The two enums the policy schema OWNS, as Go values
// ---------------------------------------------------------------------------

// Depth is how much of the tree a scan covers.
//
// schemas/policy.schema.json#/$defs/depth owns this enum ("This enum IS owned
// here, by O.5, because no other area declares it; O.6 and O.8 consume these
// two tokens rather than declaring a third"). The schema is a JSON document
// and cannot be imported, so THIS is its one Go image: consumers use these
// constants and do not declare a third spelling. The engine never branches on
// a particular depth -- these exist so the loader can reject a typo, and so
// callers naming a depth in Go name it once.
type Depth string

const (
	DepthDelta Depth = "delta"
	DepthFull  Depth = "full"
)

// DepthValues returns every legal `depth` token, in schema order.
func DepthValues() []Depth { return []Depth{DepthDelta, DepthFull} }

// Valid reports whether d is a legal `depth` token.
func (d Depth) Valid() bool { return slices.Contains(DepthValues(), d) }

// BumpKind is a kind of semantic-version bump a tag may represent.
//
// schemas/policy.schema.json#/$defs/semverBump owns this enum and names its
// computer: internal/policy/semver.go (O.7), whose `ComputeSemverBump(repoPath,
// newTag string) (BumpKind, error)` returns THIS type. O.7 must not declare a
// second one -- that is the defect class section 6 of the implementation plan
// closed ten instances of.
//
// The bump is COMPUTED by Anvil (`git describe --tags --abbrev=0 <tag>^`),
// never read from a GitHub event payload, which carries no previous tag.
type BumpKind string

const (
	BumpMajor      BumpKind = "major"
	BumpMinor      BumpKind = "minor"
	BumpPatch      BumpKind = "patch"
	BumpPrerelease BumpKind = "prerelease"
)

// BumpNone is the zero BumpKind and means "this trigger context carries no
// bump" -- the ref is not a tag, or the bump has not been computed yet. It is
// NOT a fifth bump kind and never appears in a policy file: a rule that lists
// matchSemverBump cannot match a context carrying BumpNone.
const BumpNone BumpKind = ""

// BumpKindValues returns every legal `matchSemverBump` token, in schema order.
// BumpNone is not among them.
func BumpKindValues() []BumpKind {
	return []BumpKind{BumpMajor, BumpMinor, BumpPatch, BumpPrerelease}
}

// Valid reports whether b is a legal `matchSemverBump` token. BumpNone is not.
func (b BumpKind) Valid() bool { return slices.Contains(BumpKindValues(), b) }

// ---------------------------------------------------------------------------
// The document shape
// ---------------------------------------------------------------------------

// Policy is a parsed .anvil/policy.yml. Field for field it is
// schemas/policy.schema.json; that file is the definition and this struct is
// its Go projection, kept honest by TestDecoderKeySetsMatchSchema.
type Policy struct {
	Version   int        `json:"version"`
	Defaults  *Settings  `json:"defaults,omitempty"`
	ScanRules []ScanRule `json:"scanRules,omitempty"`
}

// Settings is the overridable settings block, reachable from `defaults` and
// embedded in every scanRule -- one definition per field, exactly as the
// schema arranges it.
//
// UNSET vs SET is the whole game in a field-by-field merge, so every field
// encodes it: a nil slice, an empty Depth/FailOn, and a nil pointer all mean
// "this layer does not speak to this field". The schema forbids empty arrays
// (minItems: 1) precisely so that "absent" and "constrained to nothing" cannot
// be confused.
type Settings struct {
	Detectors []record.DetectorKind `json:"detectors,omitempty"`
	Depth     Depth                 `json:"depth,omitempty"`
	Timeout   *time.Duration        `json:"timeout,omitempty"`
	FailOn    string                `json:"failOn,omitempty"`
	Publish   []string              `json:"publish,omitempty"`
	Dast      *DastOverrides        `json:"dast,omitempty"`
}

// DastOverrides is the DAST-half settings block. Area D EXTENDS the schema's
// $defs/dastOverrides in place; when it does, a field is added here too. Both
// fields are pointers/empty-able for the same set-vs-unset reason as Settings.
type DastOverrides struct {
	Profile     string         `json:"profile,omitempty"`
	MaxDuration *time.Duration `json:"maxDuration,omitempty"`
}

// Schedule is the cadence block of a rule that matches a scheduled event. The
// daemon-side systemd clock is authoritative; GitHub's `schedule:` is a mirror
// only. OnCalendar is passed through VERBATIM -- Anvil neither parses nor
// normalises a calendar expression, because that string is the whole cadence
// definition and re-encoding it in Go would make the cadence code.
type Schedule struct {
	OnCalendar      string         `json:"onCalendar,omitempty"`
	Persistent      *bool          `json:"persistent,omitempty"`
	RandomizedDelay *time.Duration `json:"randomizedDelay,omitempty"`
}

// ScanRule is one match/apply rule.
//
// The match* keys are ANDed: every match* key PRESENT must match. A rule with
// no match* keys matches everything, which is the idiomatic way to write a
// broad baseline that later rules narrow.
//
// Inclusion keys (matchEvents, matchRefs, matchPaths, matchSemverBump) and
// exclusion keys (matchRefsIgnore, matchPathsIgnore) behave asymmetrically
// when the trigger context is silent on that dimension, and the asymmetry is
// deliberate -- see Matches.
type ScanRule struct {
	Name string `json:"name"`

	MatchEvents      []string   `json:"matchEvents,omitempty"`
	MatchRefs        []string   `json:"matchRefs,omitempty"`
	MatchRefsIgnore  []string   `json:"matchRefsIgnore,omitempty"`
	MatchPaths       []string   `json:"matchPaths,omitempty"`
	MatchPathsIgnore []string   `json:"matchPathsIgnore,omitempty"`
	MatchSemverBump  []BumpKind `json:"matchSemverBump,omitempty"`

	Schedule *Schedule `json:"schedule,omitempty"`

	Settings
}

// ---------------------------------------------------------------------------
// The trigger context
// ---------------------------------------------------------------------------

// TriggerContext is what happened, expressed in the platform's own vocabulary.
// Every field is opaque to this engine: Event is compared for equality against
// whatever tokens the file lists, Ref and ChangedPaths are matched against
// whatever globs the file lists, and SemverBump is compared against whatever
// bump kinds the file lists.
//
// Ref is the FULLY-QUALIFIED ref (refs/heads/main, refs/tags/v2.0.0), because
// that is what the file's globs are written against.
//
// ChangedPaths are repository-relative and SLASH-SEPARATED, on every host
// including Windows. The engine does not translate separators: `\` is a legal
// character in a POSIX filename, so silently rewriting it would corrupt a real
// path to paper over a caller's bug. A caller holding host paths converts with
// filepath.ToSlash before filling this in.
//
// SemverBump is BumpNone unless O.7 computed one for this ref.
type TriggerContext struct {
	Event        string
	Ref          string
	ChangedPaths []string
	SemverBump   BumpKind
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

// RuleRef identifies a rule by ARRAY INDEX first and name second. The index is
// what makes provenance unambiguous even in a hand-built Policy with duplicate
// names; FromDocument rejects duplicate names, but Evaluate does not require
// uniqueness to stay well-defined.
type RuleRef struct {
	Index int
	Name  string
}

// FieldSource says which layer set one leaf field of the resolved rule.
type FieldSource struct {
	// Set is false when no layer set the field at all.
	Set bool
	// FromDefaults is true when the winning layer was `defaults`.
	FromDefaults bool
	// Rule is the winning rule when FromDefaults is false.
	Rule RuleRef
}

// Label renders a FieldSource for diagnostics.
func (s FieldSource) Label() string {
	switch {
	case !s.Set:
		return "(unset)"
	case s.FromDefaults:
		return "defaults"
	default:
		return fmt.Sprintf("scanRules[%d] %q", s.Rule.Index, s.Rule.Name)
	}
}

// FieldSources is per-leaf-field provenance for a ResolvedRule. It is a STRUCT
// and not a map on purpose: a map would have to be iterated to be reported,
// and an unsorted iteration is the determinism bug this project has already
// shipped once.
type FieldSources struct {
	Detectors FieldSource
	Depth     FieldSource
	Timeout   FieldSource
	FailOn    FieldSource
	Publish   FieldSource

	DastProfile     FieldSource
	DastMaxDuration FieldSource

	ScheduleOnCalendar      FieldSource
	SchedulePersistent      FieldSource
	ScheduleRandomizedDelay FieldSource
}

// ---------------------------------------------------------------------------
// The resolved rule
// ---------------------------------------------------------------------------

// ResolvedRule is what a TriggerContext resolves to: `defaults` overlaid by
// every matching rule in array order, field by field.
//
// Matched is empty when NO rule matched. That is not the same as "do not
// scan": the settings still carry whatever `defaults` said. Deciding that an
// unmatched context means no scan is the caller's policy call (the Action and
// the daemon make it), and it is deliberately not made here -- baking it in
// would be this engine overriding the user's data.
type ResolvedRule struct {
	Detectors []record.DetectorKind
	Depth     Depth
	Timeout   *time.Duration
	FailOn    string
	Publish   []string
	Dast      *DastOverrides
	Schedule  *Schedule

	// Matched lists the rules that matched, in array order. Last is the
	// highest-precedence rule.
	Matched []RuleRef

	// Source is per-field provenance: which layer set each leaf field.
	Source FieldSources

	// Warnings are non-fatal diagnostics, in a fixed order. The schema
	// requires one of them by name: dast overrides on a rule whose resolved
	// detectors do not include the dast tier are warned about rather than
	// silently ignored.
	Warnings []string
}

// HasDetector reports whether the resolved detector set contains kind.
func (r ResolvedRule) HasDetector(kind record.DetectorKind) bool {
	return slices.Contains(r.Detectors, kind)
}

// MatchedNames returns the matched rule names in array order, for diagnostics.
func (r ResolvedRule) MatchedNames() []string {
	out := make([]string, len(r.Matched))
	for i, m := range r.Matched {
		out[i] = m.Name
	}
	return out
}

// ---------------------------------------------------------------------------
// AGGREGATE BOUNDS — the cost of a policy as a whole, not of one pattern
// ---------------------------------------------------------------------------
//
// MaxGlobPatternBytes and MaxGlobPatternSegments bound ONE pattern. They were
// the answer to CRITIQUE O.4 finding O4-M4, which measured a single pathological
// pattern at 8.51 seconds. They are not an answer to the same denial of service
// reached by MULTIPLICATION, and until these four constants existed there was
// nothing bounding the number of rules, the number of patterns in a rule, or the
// number of changed paths one evaluation would walk. Ten thousand cheap rules
// are the same outage as one expensive one, and the input is attacker-controlled
// in both cases: `.anvil/policy.yml` is read FROM THE REPOSITORY UNDER SCAN, and
// Anvil scans untrusted repositories by design.
//
// # The arithmetic these numbers are chosen against
//
// The matcher is bounded (see MatchGlob's COST section), so the free variable is
// how many times it is CALLED. For one Evaluate:
//
//	calls = SUM over rules of
//	          |matchRefs| + |matchRefsIgnore|                    (once, vs the ref)
//	        + (|matchPaths| + |matchPathsIgnore|) x |changedPaths|
//
// The path term is the one that multiplies, and it multiplies THREE ways at
// once, which is why three independent caps do not close this on their own:
//
//	MaxScanRules x 2 x MaxListItems x MaxChangedPaths
//	  = 256 x 2 x 64 x 4096
//	  = 134,217,728 calls
//
// Measured on this repository's development machine, one MatchGlob call costs
// ~0.17us for a short pattern, ~1us for a typical one, and ~4us for the worst
// shape the per-pattern caps still admit (a 64-segment `**` pattern against a
// 100-segment path). 134 million of those is between 23 SECONDS and 9 MINUTES,
// per event, on a scanner the attacker triggered by committing a file. The three
// structural caps alone are therefore not a fix: they are three generous limits
// whose PRODUCT is an outage. That is the whole shape of this residual — the
// per-pattern cap bounded the unit price and left the quantity open.
//
// So there are FOUR bounds, and the fourth is the one that actually closes the
// multiplication: MaxEvaluationMatchOps caps the SUM above. It is computed from
// the shape in O(number of rules) arithmetic BEFORE the first path.Match call, so
// an over-budget policy is refused without doing any of the work it asked for.
//
// # Why these particular numbers
//
// MaxScanRules = 256. Renovate's `packageRules`, the convention this schema
// borrows, runs to a few dozen entries in large monorepos; the owner's own
// fixture has four. 256 is roughly sixty times the fixture and beyond any
// hand-maintained trigger policy — a file with 257 rules is not a document
// anybody reads, and refusing it costs a real user nothing.
//
// MaxListItems = 64, per list-valued key: every globList and every tokenList,
// so matchPaths, matchRefs, matchEvents, detectors and publish alike. It is
// deliberately the same 64 as MaxGlobPatternSegments and for the same reason —
// deeper or wider than a human writes. CodeQL's path filters, which matchPaths
// borrows its naming from, run to a dozen or two. At the cap one key already
// carries up to 64 KiB of pattern text.
//
// MaxChangedPaths = 4096. This one is NOT policy data — it is the trigger
// context, i.e. a git diff — so it bounds what a huge commit can cost rather
// than what a crafted file can. Large refactors and generated-code sweeps reach
// the low thousands; past 4096 the delta pass has stopped being a delta, and the
// honest answer is `depth: full`, not a per-path glob walk over the whole tree.
// Refusing tells the operator exactly that.
//
// MaxEvaluationMatchOps = 250,000. At the measured ~4us worst-case call this is
// about one second of matcher work; TestAggregateBoundsAcceptTheCapAndRefuseOneOver
// evaluates a policy sitting exactly on this budget with ordinary patterns and
// logs ~40ms, so the ceiling is a bound and not a cost anyone pays. Real shapes
// fit with room to spare: 50 rules x 10 path patterns x 400 changed paths is
// 200,000. Crafted shapes do not: the 134-million product above is refused after
// 256 additions. A policy that legitimately wants more than this is a policy
// asking for a second of matching per event, and the fix is fewer path globs or
// `depth: full` — not a larger budget.
//
// # Refusal, never truncation
//
// Every bound produces an error naming WHICH bound was exceeded, the observed
// value, and the limit. None of them silently drops a rule, a pattern or a path.
// A refused policy is a diagnosable outcome an operator can act on; a TRUNCATED
// policy is the worst outcome available, because the operator believes rules are
// in force that are not, and Anvil reports a scan that never applied them.
//
// # Enforced in the engine, not only in the schema
//
// schemas/policy.schema.json carries `maxItems` for the two bounds JSON Schema
// can express, and TestPolicySchemaAggregateBoundsMatchTheEngineCaps fails if
// they drift from these constants. That is not sufficient on its own: a Policy
// can reach Evaluate without ever passing through schema validation (a hand-built
// value, a TOML decoding, a caller that skipped the loader), so FromDocument,
// Evaluate and ScanRule.Matches each enforce the bounds themselves.
const (
	MaxScanRules          = 256
	MaxListItems          = 64
	MaxChangedPaths       = 4096
	MaxEvaluationMatchOps = 250_000
)

// namedLen pairs a list-valued key with its length. Lengths are all the bounds
// need, and collecting them in a FIXED order keeps a refusal deterministic:
// a document breaking two bounds must name the same one on every run and on
// every host.
type namedLen struct {
	key string
	n   int
}

// listLengths returns the settings block's list-valued keys, in schema order.
func (s Settings) listLengths() []namedLen {
	return []namedLen{
		{"detectors", len(s.Detectors)},
		{"publish", len(s.Publish)},
	}
}

// listLengths returns every list-valued key on the rule, in schema order.
func (r ScanRule) listLengths() []namedLen {
	return append([]namedLen{
		{"matchEvents", len(r.MatchEvents)},
		{"matchRefs", len(r.MatchRefs)},
		{"matchRefsIgnore", len(r.MatchRefsIgnore)},
		{"matchPaths", len(r.MatchPaths)},
		{"matchPathsIgnore", len(r.MatchPathsIgnore)},
		{"matchSemverBump", len(r.MatchSemverBump)},
	}, r.Settings.listLengths()...)
}

// matchOps is the WORST-CASE number of MatchGlob calls evaluating this rule can
// make against a context carrying changedPaths paths. It is an upper bound, not
// a prediction: Matches short-circuits, so the real count is usually far lower.
// Bounding the worst case is the point — an attacker picks the input that does
// not short-circuit.
func (r ScanRule) matchOps(changedPaths int) int {
	perRef := len(r.MatchRefs) + len(r.MatchRefsIgnore)
	perPath := len(r.MatchPaths) + len(r.MatchPathsIgnore)
	return perRef + perPath*changedPaths
}

// tooLargeDocument builds a refusal that describes the DOCUMENT, so it matches
// both ErrInvalidDocument and ErrPolicyTooLarge.
func tooLargeDocument(format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrInvalidDocument, ErrPolicyTooLarge, fmt.Sprintf(format, args...))
}

// tooLargeEvaluation builds a refusal that describes an EVALUATION — the
// document may be entirely legal and the CONTEXT out of range — so it matches
// ErrPolicyTooLarge alone.
func tooLargeEvaluation(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrPolicyTooLarge, fmt.Sprintf(format, args...))
}

// checkScanRuleCount refuses a policy with more rules than MaxScanRules.
//
// It takes the count rather than the policy so FromDocument can refuse a crafted
// file BEFORE decoding a hundred thousand rules into memory.
func checkScanRuleCount(n int, at string) error {
	if n <= MaxScanRules {
		return nil
	}
	return tooLargeDocument(
		"%s has %d rules, which exceeds the %d-rule cap (policy.MaxScanRules); "+
			"the policy file is read from the repository under scan, so the NUMBER of rules is "+
			"bounded as well as the cost of each one. Nothing has been evaluated and no rule has "+
			"been dropped: this policy is refused, not truncated",
		at, n, MaxScanRules)
}

// checkListBound refuses one over-long list-valued key.
func checkListBound(at string, l namedLen) error {
	if l.n <= MaxListItems {
		return nil
	}
	where := l.key
	if at != "" {
		where = at + "/" + l.key
	}
	return tooLargeDocument(
		"%s has %d items, which exceeds the %d-item cap (policy.MaxListItems); "+
			"the policy file is read from the repository under scan, so the number of patterns in "+
			"a key is bounded as well as the length of each one. This key is refused whole, never "+
			"trimmed to the first %d",
		where, l.n, MaxListItems, MaxListItems)
}

// checkDocumentBounds enforces the two SHAPE bounds — MaxScanRules and
// MaxListItems — on a Policy however it was obtained. It is O(rules).
func checkDocumentBounds(p Policy) error {
	if err := checkScanRuleCount(len(p.ScanRules), "/scanRules"); err != nil {
		return err
	}
	if p.Defaults != nil {
		for _, l := range p.Defaults.listLengths() {
			if err := checkListBound("/defaults", l); err != nil {
				return err
			}
		}
	}
	for i := range p.ScanRules {
		at := fmt.Sprintf("/scanRules/%d", i)
		for _, l := range p.ScanRules[i].listLengths() {
			if err := checkListBound(at, l); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkEvaluationBounds is the whole aggregate check, run BEFORE any matching.
//
// ORDER MATTERS AND IS NOT COSMETIC. The shape bounds run first, so by the time
// the work budget multiplies anything, every factor is already known to be at
// most (MaxScanRules, MaxListItems, MaxChangedPaths). The product cannot
// overflow and the sum cannot run long: the budget check is O(rules) additions
// over a slice whose length was bounded two lines earlier.
func checkEvaluationBounds(p Policy, ctx TriggerContext) error {
	if err := checkDocumentBounds(p); err != nil {
		return err
	}
	if n := len(ctx.ChangedPaths); n > MaxChangedPaths {
		return tooLargeEvaluation(
			"the trigger context carries %d changed paths, which exceeds the %d-path cap "+
				"(policy.MaxChangedPaths); a change set this large is no longer a delta, and the "+
				"answer is depth=%q rather than a per-path glob walk. No path has been ignored: "+
				"the evaluation is refused",
			n, MaxChangedPaths, DepthFull)
	}

	ops := 0
	for i := range p.ScanRules {
		ops += p.ScanRules[i].matchOps(len(ctx.ChangedPaths))
	}
	if ops > MaxEvaluationMatchOps {
		return tooLargeEvaluation(
			"evaluating %d rules against %d changed paths would perform up to %d pattern matches, "+
				"which exceeds the %d-match budget (policy.MaxEvaluationMatchOps); per-pattern caps "+
				"bound the price of one match and this bounds the quantity, which is the same denial "+
				"of service reached by multiplication instead of by recursion. Reduce the path globs "+
				"or use depth=%q; nothing has been matched and nothing has been dropped",
			len(p.ScanRules), len(ctx.ChangedPaths), ops, MaxEvaluationMatchOps, DepthFull)
	}
	return nil
}

// checkBounds is the per-rule half of the aggregate check, for the callers that
// reach ScanRule.Matches directly instead of going through Evaluate. Matches is
// exported, so it is an entry point in its own right, and an entry point that
// enforced nothing would be the bypass this section exists to close.
func (r ScanRule) checkBounds(changedPaths int) error {
	for _, l := range r.listLengths() {
		if err := checkListBound("", l); err != nil {
			return err
		}
	}
	if changedPaths > MaxChangedPaths {
		return tooLargeEvaluation(
			"the trigger context carries %d changed paths, which exceeds the %d-path cap "+
				"(policy.MaxChangedPaths)", changedPaths, MaxChangedPaths)
	}
	if ops := r.matchOps(changedPaths); ops > MaxEvaluationMatchOps {
		return tooLargeEvaluation(
			"matching this rule against %d changed paths would perform up to %d pattern matches, "+
				"which exceeds the %d-match budget (policy.MaxEvaluationMatchOps)",
			changedPaths, ops, MaxEvaluationMatchOps)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Evaluate
// ---------------------------------------------------------------------------

// Evaluate resolves ctx against p.
//
// It applies `defaults`, then every matching rule in array order, merging
// field by field with later-overrides-earlier precedence (see the file header
// for the normative statement). It does not short-circuit on the first match.
//
// Every rule's globs are compiled BEFORE that rule's match keys are evaluated,
// so a malformed pattern is an error whatever the context is. A typo'd glob
// that errored only for the contexts that happened to reach it would be a
// latent, context-dependent failure in the one file that decides whether a
// security scan happens.
//
// The returned ResolvedRule shares no memory with p: slices are copied and
// pointers are freshly allocated, so a caller mutating the result cannot
// change the policy every later evaluation reads.
func Evaluate(p Policy, ctx TriggerContext) (ResolvedRule, error) {
	if p.Version != SchemaVersion {
		return ResolvedRule{}, fmt.Errorf("%w: have %d, want %d",
			ErrUnsupportedVersion, p.Version, SchemaVersion)
	}

	// The aggregate bounds, BEFORE any matching. A Policy can reach here
	// without passing through FromDocument or through schema validation, so
	// this is where the bounds have to hold if they are to hold at all. It is
	// O(rules) arithmetic, so an over-budget policy is refused in microseconds
	// rather than after the work it asked for. See AGGREGATE BOUNDS above.
	if err := checkEvaluationBounds(p, ctx); err != nil {
		return ResolvedRule{}, err
	}

	var out ResolvedRule
	out.applySettings(p.Defaults, FieldSource{Set: true, FromDefaults: true})

	for i := range p.ScanRules {
		rule := p.ScanRules[i]

		ok, err := rule.Matches(ctx)
		if err != nil {
			return ResolvedRule{}, fmt.Errorf("scanRules[%d] %q: %w", i, rule.Name, err)
		}
		if !ok {
			continue
		}

		ref := RuleRef{Index: i, Name: rule.Name}
		src := FieldSource{Set: true, Rule: ref}

		out.Matched = append(out.Matched, ref)
		out.applySettings(&rule.Settings, src)
		out.applySchedule(rule.Schedule, src)
	}

	out.Warnings = out.warnings()
	return out, nil
}

// applySettings overlays one layer onto the resolved rule. A field the layer
// leaves unset is not touched, which is what "field by field, later overrides
// earlier" means operationally.
//
// List-valued fields (detectors, publish) are REPLACED wholesale, not unioned.
// A list is one field, and a rule that narrows `detectors` back to the static
// tier must be able to do so; a union would make de-escalation inexpressible.
func (r *ResolvedRule) applySettings(s *Settings, src FieldSource) {
	if s == nil {
		return
	}

	if len(s.Detectors) > 0 {
		r.Detectors = slices.Clone(s.Detectors)
		r.Source.Detectors = src
	}
	if s.Depth != "" {
		r.Depth = s.Depth
		r.Source.Depth = src
	}
	if s.Timeout != nil {
		d := *s.Timeout
		r.Timeout = &d
		r.Source.Timeout = src
	}
	if s.FailOn != "" {
		r.FailOn = s.FailOn
		r.Source.FailOn = src
	}
	if len(s.Publish) > 0 {
		r.Publish = slices.Clone(s.Publish)
		r.Source.Publish = src
	}

	if s.Dast != nil {
		// Nested objects merge per LEAF field, the same way the top level
		// does. A rule setting only `dast.profile` therefore keeps an
		// earlier layer's `dast.maxDuration` rather than erasing it: "field
		// by field" is a statement about leaves, and dast.profile and
		// dast.maxDuration are two independent knobs.
		if r.Dast == nil {
			r.Dast = &DastOverrides{}
		}
		if s.Dast.Profile != "" {
			r.Dast.Profile = s.Dast.Profile
			r.Source.DastProfile = src
		}
		if s.Dast.MaxDuration != nil {
			d := *s.Dast.MaxDuration
			r.Dast.MaxDuration = &d
			r.Source.DastMaxDuration = src
		}
	}
}

// applySchedule overlays a rule's cadence block. Schedule lives on the rule,
// not in Settings, so `defaults` cannot set a cadence -- that is the schema's
// arrangement, not a choice made here. Leaves merge exactly like dast's.
func (r *ResolvedRule) applySchedule(s *Schedule, src FieldSource) {
	if s == nil {
		return
	}
	if r.Schedule == nil {
		r.Schedule = &Schedule{}
	}
	if s.OnCalendar != "" {
		r.Schedule.OnCalendar = s.OnCalendar
		r.Source.ScheduleOnCalendar = src
	}
	if s.Persistent != nil {
		b := *s.Persistent
		r.Schedule.Persistent = &b
		r.Source.SchedulePersistent = src
	}
	if s.RandomizedDelay != nil {
		d := *s.RandomizedDelay
		r.Schedule.RandomizedDelay = &d
		r.Source.ScheduleRandomizedDelay = src
	}
}

// warnings produces the non-fatal diagnostics, in a fixed order.
//
// The one the schema requires by name: "$defs/dastOverrides ... Only
// meaningful when this rule's resolved `detectors` includes the dast token;
// the engine warns rather than silently ignoring it otherwise." The dast token
// here is area 40's constant, not a literal, and this check changes NOTHING
// about which detectors run -- it emits text. It is a diagnostic, not a
// trigger decision.
func (r ResolvedRule) warnings() []string {
	if r.Dast == nil || r.HasDetector(record.DetectorKindDast) {
		return nil
	}

	var setters []string
	for _, s := range []FieldSource{r.Source.DastProfile, r.Source.DastMaxDuration} {
		if s.Set && !slices.Contains(setters, s.Label()) {
			setters = append(setters, s.Label())
		}
	}

	have := make([]string, len(r.Detectors))
	for i, d := range r.Detectors {
		have[i] = string(d)
	}

	return []string{fmt.Sprintf(
		"policy: dast overrides set by %s have no effect: resolved detectors [%s] do not include %q",
		strings.Join(setters, ", "), strings.Join(have, " "), record.DetectorKindDast)}
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

// Matches reports whether r applies to ctx.
//
// Every match* key present must match (they are ANDed). A rule with no match*
// keys matches everything.
//
// INCLUSION keys (matchEvents, matchRefs, matchPaths, matchSemverBump) name a
// dimension the context must satisfy. A context that is SILENT on that
// dimension -- no event, no ref, no changed paths, BumpNone -- cannot satisfy
// it, so the rule does not match. This is what makes `matchSemverBump` mean
// "tags only" without any tag-detection logic in Go: a branch push carries no
// bump, so a bump-gated rule cannot fire on it.
//
// EXCLUSION keys (matchRefsIgnore, matchPathsIgnore) name a dimension that can
// only take a match AWAY. A context silent on that dimension cannot trigger an
// exclusion. The asymmetry is intentional: an absent changed-path list must not
// silently exclude a tag push from a rule carrying a docs ignore list.
//
// matchPathsIgnore is applied PER PATH, per the schema: a change set is
// excluded only when EVERY changed path matches an ignore pattern, so a commit
// touching both docs/ and source still triggers the rule.
//
// All of the rule's globs are compiled first, so a malformed pattern errors
// regardless of which key would otherwise have decided the outcome.
func (r ScanRule) Matches(ctx TriggerContext) (bool, error) {
	if err := r.checkBounds(len(ctx.ChangedPaths)); err != nil {
		return false, err
	}
	if err := r.validateGlobs(); err != nil {
		return false, err
	}

	if len(r.MatchEvents) > 0 {
		if ctx.Event == "" || !slices.Contains(r.MatchEvents, ctx.Event) {
			return false, nil
		}
	}

	if len(r.MatchRefs) > 0 {
		if ctx.Ref == "" {
			return false, nil // an inclusion key a silent context cannot satisfy
		}
		ok, err := anyGlobMatches(r.MatchRefs, ctx.Ref)
		if err != nil || !ok {
			return false, err
		}
	}
	if len(r.MatchRefsIgnore) > 0 && ctx.Ref != "" {
		ok, err := anyGlobMatches(r.MatchRefsIgnore, ctx.Ref)
		if err != nil {
			return false, err
		}
		if ok {
			return false, nil
		}
	}

	if len(r.MatchPaths) > 0 {
		matched := false
		for _, p := range ctx.ChangedPaths {
			ok, err := anyGlobMatches(r.MatchPaths, p)
			if err != nil {
				return false, err
			}
			if ok {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	if len(r.MatchPathsIgnore) > 0 && len(ctx.ChangedPaths) > 0 {
		all := true
		for _, p := range ctx.ChangedPaths {
			ok, err := anyGlobMatches(r.MatchPathsIgnore, p)
			if err != nil {
				return false, err
			}
			if !ok {
				all = false
				break
			}
		}
		if all {
			return false, nil
		}
	}

	if len(r.MatchSemverBump) > 0 {
		if ctx.SemverBump == BumpNone || !slices.Contains(r.MatchSemverBump, ctx.SemverBump) {
			return false, nil
		}
	}

	return true, nil
}

// validateGlobs compiles every glob the rule carries, in a fixed key order so
// the error a broken rule produces is the same on every run and on every host.
func (r ScanRule) validateGlobs() error {
	for _, group := range []struct {
		key      string
		patterns []string
	}{
		{"matchRefs", r.MatchRefs},
		{"matchRefsIgnore", r.MatchRefsIgnore},
		{"matchPaths", r.MatchPaths},
		{"matchPathsIgnore", r.MatchPathsIgnore},
	} {
		for i, pattern := range group.patterns {
			if err := validateGlob(pattern); err != nil {
				return fmt.Errorf("%s[%d]: %w", group.key, i, err)
			}
		}
	}
	return nil
}

// anyGlobMatches reports whether any pattern matches name.
func anyGlobMatches(patterns []string, name string) (bool, error) {
	for _, pattern := range patterns {
		ok, err := MatchGlob(pattern, name)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// Globs
// ---------------------------------------------------------------------------

// doubleStar is the one pattern segment with cross-segment meaning. It is not
// a policy VALUE -- it is syntax, the same way `*` is, and it is named once
// here rather than being spelled inline three times.
const doubleStar = "**"

// MaxGlobPatternBytes and MaxGlobPatternSegments are the complexity cap on ONE
// glob pattern. They are the only thing standing between a crafted
// `.anvil/policy.yml` and unbounded work inside Evaluate, so they are stated as
// arithmetic rather than as taste:
//
//	total work for one MatchGlob call
//	  <= O(len(pattern) x len(name))                       (see the COST note)
//	  <= O(MaxGlobPatternBytes x len(name))
//
// 1 KiB is roughly forty typical patterns' worth of characters in ONE pattern
// and sixty-four segments is deeper than any ref or repository-relative path a
// human writes; a pattern past either bound is a mistake or an attack, and both
// are better answered with an error naming the bound than with a scan that
// never starts.
//
// The same bound appears in schemas/policy.schema.json as `maxLength` on
// #/$defs/glob, and TestPolicySchemaGlobBoundMatchesTheEngineCap fails if the
// two drift.
const (
	MaxGlobPatternBytes    = 1024
	MaxGlobPatternSegments = 64
)

// MatchGlob reports whether name matches pattern.
//
// It is exported because a glob predicate re-derived per caller is precisely
// how this repository has been bitten before -- five authors independently
// re-implemented one predicate and all five got it wrong. There is one glob
// implementation for policy matching and this is it.
//
// The dialect, stated so it is a contract rather than an accident:
//
//   - `/` is the separator. Pattern and name are split on it and matched
//     segment by segment. This is path.Match's dialect (NOT filepath.Match --
//     the separator is `/` on every host, because refs and repository-relative
//     paths use `/` on every host).
//   - `**` as a COMPLETE segment matches zero or more segments. Zero is
//     load-bearing: `**` + `/*.md` is how `**/*.md` matches a top-level
//     README.md, and `docs/**` matching `docs` itself follows from the same
//     rule.
//   - `*` matches any run of characters WITHIN one segment, never across `/`.
//   - `?` matches one non-`/` character; `[a-z]` and `[^a-z]` are character
//     classes; `\` escapes. These are path.Match's, unchanged -- note that its
//     negation character is `^`, NOT the shell's `!`, so `[!ab]` is a class
//     containing `!`, `a` and `b`. That is the standard library's dialect and
//     it is documented here rather than "fixed", because a second glob dialect
//     that differs from Go's in one character is worse than one that differs
//     in none.
//   - `**` that is not a whole segment (`a**b`) is just two `*` to path.Match,
//     i.e. within-segment. That is a degenerate spelling, not a feature.
//
// A malformed pattern is ErrBadPattern, never a silent false. A pattern past
// MaxGlobPatternBytes or MaxGlobPatternSegments is ErrPatternTooComplex (which
// also satisfies errors.Is(err, ErrBadPattern)), never a truncated match.
//
// # COST — this is a security property, not a performance note
//
// The policy file is read from the repository under scan, so `pattern` is
// attacker-controlled on the public-repo path. The segment walk below is a
// bottom-up dynamic program over (pattern suffix, name suffix), so `**` costs
// nothing beyond a table cell:
//
//	path.Match calls   <= (pattern segments) x (name segments)
//	work per call      <= O(len(pattern segment) x len(name segment))
//	total              <= O(len(pattern) x len(name))
//
// The last line follows because the sum of the pattern's segment lengths is
// len(pattern) and likewise for the name, so the double sum factorises. With
// len(pattern) capped at MaxGlobPatternBytes the whole call is linear in the
// path being matched.
//
// It replaces a recursion that tried every split point for every `**` with no
// memoisation, which CRITIQUE O.4 (O4-M4) measured at 8.5s for ten `**`
// segments against a thirty-segment path and unbounded past eleven. That was
// not a slow path, it was a denial of service against the scanner reachable by
// committing a file. TestPathologicalGlobPatternsTerminateFast is the
// regression.
func MatchGlob(pattern, name string) (bool, error) {
	if err := validateGlob(pattern); err != nil {
		return false, err
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

// matchSegments is the `**`-aware segment walk, as a bottom-up dynamic program
// over suffixes. Non-`**` segments are handed to path.Match so the
// within-segment dialect is the standard library's and not a second, subtly
// different one written here.
//
// dp[i][j] is "pat[i:] matches seg[j:]". Only two rows are ever live, so the
// table is O(len(seg)) memory and each cell is computed exactly once:
//
//	i == len(pat)     dp = (j == len(seg))
//	pat[i] == "**"    dp[i][j] = dp[i+1][j] || dp[i][j+1]     (zero or more)
//	otherwise         dp[i][j] = match(pat[i], seg[j]) && dp[i+1][j+1]
//
// The `**` row is where the old recursion blew up: "zero or more segments"
// there meant re-deriving every suffix once per split point, and k independent
// `**` segments multiplied that k times over. Here the same fact is one OR of
// two already-computed cells.
//
// path.Match itself is the standard library's single-backtrack-point matcher,
// which is O(len(pattern) x len(name)) and not exponential, so nothing under
// this function reintroduces the cost the table removes.
func matchSegments(pat, seg []string) (bool, error) {
	np, ns := len(pat), len(seg)

	// prev is dp[i+1][*]; cur is dp[i][*]. dp[np][j] is true only for the
	// empty name suffix, which is the "pattern exhausted, name exhausted"
	// base case.
	prev := make([]bool, ns+1)
	cur := make([]bool, ns+1)
	prev[ns] = true

	for i := np - 1; i >= 0; i-- {
		if pat[i] == doubleStar {
			cur[ns] = prev[ns]
			for j := ns - 1; j >= 0; j-- {
				cur[j] = prev[j] || cur[j+1]
			}
		} else {
			cur[ns] = false // a pattern segment cannot match a name that ended
			for j := ns - 1; j >= 0; j-- {
				ok, err := path.Match(pat[i], seg[j])
				if err != nil {
					return false, fmt.Errorf("%w %q: %v", ErrBadPattern, pat[i], err)
				}
				cur[j] = ok && prev[j+1]
			}
		}
		prev, cur = cur, prev
	}
	return prev[0], nil
}

// validateGlob rejects a pattern path.Match would call ErrBadPattern, and a
// pattern past the complexity cap.
//
// It exists because path.Match only reports a malformed pattern when its scan
// REACHES the malformed part: `path.Match("x[", "y")` is (false, nil), because
// matching failed before the bad class. Relying on that would make a typo'd
// pattern an error for some inputs and a silent non-match for others. This
// walks the whole pattern unconditionally, so the rule that carries it fails
// the same way every time.
//
// The cap is checked HERE rather than in MatchGlob because this is the one
// function both entry points share: MatchGlob calls it, and ScanRule.Matches
// calls it through validateGlobs for every pattern on the rule BEFORE any
// matching starts. A rule carrying one over-cap pattern therefore fails to
// evaluate at all, rather than failing only on whichever changed path happens
// to reach it.
func validateGlob(pattern string) error {
	bad := func(reason string) error {
		return fmt.Errorf("%w %q: %s", ErrBadPattern, pattern, reason)
	}
	tooComplex := func(reason string) error {
		return fmt.Errorf("%w: %w %q: %s", ErrBadPattern, ErrPatternTooComplex, pattern, reason)
	}

	if len(pattern) > MaxGlobPatternBytes {
		return tooComplex(fmt.Sprintf("%d bytes exceeds the %d-byte cap; the policy file is read from the repository under scan and its patterns are bounded",
			len(pattern), MaxGlobPatternBytes))
	}
	if n := strings.Count(pattern, "/") + 1; n > MaxGlobPatternSegments {
		return tooComplex(fmt.Sprintf("%d segments exceeds the %d-segment cap; the policy file is read from the repository under scan and its patterns are bounded",
			n, MaxGlobPatternSegments))
	}

	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			if i+1 >= len(pattern) {
				return bad("trailing backslash")
			}
			i++
		case '[':
			j := i + 1
			// path.Match's negation character is '^' and only '^'.
			if j < len(pattern) && pattern[j] == '^' {
				j++
			}
			if j < len(pattern) && pattern[j] == ']' { // a literal ] first
				j++
			}
			for ; j < len(pattern) && pattern[j] != ']'; j++ {
				if pattern[j] == '\\' {
					j++
				}
			}
			if j >= len(pattern) {
				return bad("unterminated character class")
			}
			i = j
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// FromDocument: the schema's shape, in Go, once
// ---------------------------------------------------------------------------
//
// Anvil's module graph carries exactly one dependency and a YAML library is
// not on the table, so decoding a policy file is a two-stage job: some decoder
// turns the bytes into a generic document (map[string]any / []any / string /
// bool / integer), and FromDocument turns THAT into a Policy. Splitting it
// this way means the same function validates a .yml, a .yaml and a .toml, and
// means the strictness the schema promises is enforced in exactly one place.
//
// The accepted key sets below are the schema's `properties` lists. They are
// package-level data, not literals scattered through the decoder, so
// TestDecoderKeySetsMatchSchema can read schemas/policy.schema.json and assert
// they are a faithful projection of it. Adding a key to the schema without
// teaching this decoder fails that test; adding one here that the schema does
// not have fails it too.

// keyDast is the schema's `dast` KEY name. It is a named constant, and the
// only key name that is, because it collides spelling-with area 40's `dast`
// DETECTOR token -- two unrelated vocabularies that happen to share a word.
// Naming it once keeps the collision visible and lets
// TestFrozenEnumsAreNotForked reject a stray detector literal in this file
// without having to guess which of the two a bare "dast" meant.
const keyDast = "dast"

var (
	keysPolicy   = []string{"version", "defaults", "scanRules"}
	keysSettings = []string{"detectors", "depth", "timeout", "failOn", "publish", "dast"}
	keysScanRule = []string{
		"name",
		"matchEvents", "matchRefs", "matchRefsIgnore",
		"matchPaths", "matchPathsIgnore", "matchSemverBump",
		"schedule",
		"detectors", "depth", "timeout", "failOn", "publish", "dast",
	}
	keysDast     = []string{"profile", "maxDuration"}
	keysSchedule = []string{"onCalendar", "persistent", "randomizedDelay"}
)

// FromDocument converts a generically-decoded policy document into a Policy,
// enforcing the parts of schemas/policy.schema.json that decide whether a rule
// can ever fire:
//
//   - `version` is present and is SchemaVersion;
//   - no unknown keys anywhere (additionalProperties: false). A `matchEvent:`
//     typo would otherwise parse cleanly and match nothing, forever, silently
//     -- the schema's own stated reason for being strict;
//   - list-valued keys are non-empty and duplicate-free (minItems/uniqueItems)
//     -- absent means "unconstrained", empty would mean "matches nothing",
//     which is always an authoring mistake;
//   - `detectors` tokens are area 40's DetectorKind, validated through
//     record.ValidateDetectorKind. This file does not re-enumerate them;
//   - `depth` and `matchSemverBump` tokens are the schema's own enums;
//   - durations parse as Go durations and are not negative;
//   - `name` is present and unique across scanRules (the schema says the
//     loader enforces this because JSON Schema cannot).
//
// Traversal is deterministic: keys are visited in the fixed order above, never
// by ranging the decoded map. The one map range is the unknown-key scan, whose
// result is sorted before it is reported, so a document with two typos always
// produces the same message.
//
// Explicit null is treated as absent for optional keys, because `defaults:`
// with nothing under it is a normal thing to write.
func FromDocument(doc any) (Policy, error) {
	top, err := asMapping(doc, "")
	if err != nil {
		return Policy{}, err
	}
	if err := checkKeys(top, keysPolicy, ""); err != nil {
		return Policy{}, err
	}

	var p Policy

	raw, ok := top["version"]
	if !ok || raw == nil {
		return Policy{}, fmt.Errorf("%w: /version is required", ErrInvalidDocument)
	}
	v, err := asInt(raw, "/version")
	if err != nil {
		return Policy{}, err
	}
	if v != SchemaVersion {
		return Policy{}, fmt.Errorf("%w: /version: have %d, want %d",
			ErrUnsupportedVersion, v, SchemaVersion)
	}
	p.Version = v

	if raw, ok := top["defaults"]; ok && raw != nil {
		m, err := asMapping(raw, "/defaults")
		if err != nil {
			return Policy{}, err
		}
		if err := checkKeys(m, keysSettings, "/defaults"); err != nil {
			return Policy{}, err
		}
		s, err := settingsFromMapping(m, "/defaults")
		if err != nil {
			return Policy{}, err
		}
		p.Defaults = &s
	}

	if raw, ok := top["scanRules"]; ok && raw != nil {
		items, err := asSequence(raw, "/scanRules")
		if err != nil {
			return Policy{}, err
		}
		// Counted BEFORE the decode loop, so a crafted file is refused without
		// first being decoded rule by rule into memory.
		if err := checkScanRuleCount(len(items), "/scanRules"); err != nil {
			return Policy{}, err
		}
		seen := map[string]int{}
		for i, item := range items {
			at := fmt.Sprintf("/scanRules/%d", i)
			rule, err := scanRuleFromDocument(item, at)
			if err != nil {
				return Policy{}, err
			}
			if prev, dup := seen[rule.Name]; dup {
				return Policy{}, fmt.Errorf(
					"%w: %s: rule name %q is already used by /scanRules/%d; names must be unique",
					ErrInvalidDocument, at, rule.Name, prev)
			}
			seen[rule.Name] = i
			p.ScanRules = append(p.ScanRules, rule)
		}
	}

	return p, nil
}

func scanRuleFromDocument(doc any, at string) (ScanRule, error) {
	m, err := asMapping(doc, at)
	if err != nil {
		return ScanRule{}, err
	}
	if err := checkKeys(m, keysScanRule, at); err != nil {
		return ScanRule{}, err
	}

	var r ScanRule

	name, ok, err := stringField(m, "name", at)
	if err != nil {
		return ScanRule{}, err
	}
	if !ok {
		return ScanRule{}, fmt.Errorf("%w: %s/name is required", ErrInvalidDocument, at)
	}
	r.Name = name

	for _, f := range []struct {
		key string
		dst *[]string
	}{
		{"matchEvents", &r.MatchEvents},
		{"matchRefs", &r.MatchRefs},
		{"matchRefsIgnore", &r.MatchRefsIgnore},
		{"matchPaths", &r.MatchPaths},
		{"matchPathsIgnore", &r.MatchPathsIgnore},
	} {
		list, _, err := tokenListField(m, f.key, at)
		if err != nil {
			return ScanRule{}, err
		}
		*f.dst = list
	}

	if list, ok, err := tokenListField(m, "matchSemverBump", at); err != nil {
		return ScanRule{}, err
	} else if ok {
		for i, tok := range list {
			b := BumpKind(tok)
			if !b.Valid() {
				return ScanRule{}, fmt.Errorf("%w: %s/matchSemverBump/%d: %q is not one of %v",
					ErrInvalidDocument, at, i, tok, BumpKindValues())
			}
			r.MatchSemverBump = append(r.MatchSemverBump, b)
		}
	}

	if raw, ok := m["schedule"]; ok && raw != nil {
		sm, err := asMapping(raw, at+"/schedule")
		if err != nil {
			return ScanRule{}, err
		}
		if err := checkKeys(sm, keysSchedule, at+"/schedule"); err != nil {
			return ScanRule{}, err
		}
		var s Schedule
		if v, ok, err := stringField(sm, "onCalendar", at+"/schedule"); err != nil {
			return ScanRule{}, err
		} else if ok {
			s.OnCalendar = v
		}
		if v, ok, err := boolField(sm, "persistent", at+"/schedule"); err != nil {
			return ScanRule{}, err
		} else if ok {
			s.Persistent = &v
		}
		if v, ok, err := durationField(sm, "randomizedDelay", at+"/schedule"); err != nil {
			return ScanRule{}, err
		} else if ok {
			s.RandomizedDelay = &v
		}
		r.Schedule = &s
	}

	settings, err := settingsFromMapping(m, at)
	if err != nil {
		return ScanRule{}, err
	}
	r.Settings = settings

	return r, nil
}

// settingsFromMapping reads the settings keys out of a mapping that may also
// carry match keys (a scanRule) or nothing else (defaults). Unknown-key
// checking is the caller's, because the two callers allow different key sets.
func settingsFromMapping(m map[string]any, at string) (Settings, error) {
	var s Settings

	if list, ok, err := tokenListField(m, "detectors", at); err != nil {
		return Settings{}, err
	} else if ok {
		for i, tok := range list {
			// Area 40 owns this vocabulary. It is validated through
			// record's own validator, not re-enumerated here.
			if err := record.ValidateDetectorKind(tok); err != nil {
				return Settings{}, fmt.Errorf("%w: %s/detectors/%d: %v",
					ErrInvalidDocument, at, i, err)
			}
			s.Detectors = append(s.Detectors, record.DetectorKind(tok))
		}
	}

	if v, ok, err := stringField(m, "depth", at); err != nil {
		return Settings{}, err
	} else if ok {
		d := Depth(v)
		if !d.Valid() {
			return Settings{}, fmt.Errorf("%w: %s/depth: %q is not one of %v",
				ErrInvalidDocument, at, v, DepthValues())
		}
		s.Depth = d
	}

	if v, ok, err := durationField(m, "timeout", at); err != nil {
		return Settings{}, err
	} else if ok {
		s.Timeout = &v
	}

	if v, ok, err := stringField(m, "failOn", at); err != nil {
		return Settings{}, err
	} else if ok {
		// Opaque on purpose -- see this file's header.
		s.FailOn = v
	}

	if list, ok, err := tokenListField(m, "publish", at); err != nil {
		return Settings{}, err
	} else if ok {
		s.Publish = list
	}

	if raw, ok := m[keyDast]; ok && raw != nil {
		at := at + "/" + keyDast
		dm, err := asMapping(raw, at)
		if err != nil {
			return Settings{}, err
		}
		if err := checkKeys(dm, keysDast, at); err != nil {
			return Settings{}, err
		}
		var d DastOverrides
		if v, ok, err := stringField(dm, "profile", at); err != nil {
			return Settings{}, err
		} else if ok {
			d.Profile = v
		}
		if v, ok, err := durationField(dm, "maxDuration", at); err != nil {
			return Settings{}, err
		} else if ok {
			d.MaxDuration = &v
		}
		s.Dast = &d
	}

	return s, nil
}

// ---------------------------------------------------------------------------
// Decoding primitives
// ---------------------------------------------------------------------------

func asMapping(v any, at string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s must be a mapping, got %s", ErrInvalidDocument, atOrRoot(at), typeName(v))
	}
	return m, nil
}

func asSequence(v any, at string) ([]any, error) {
	s, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s must be a sequence, got %s", ErrInvalidDocument, atOrRoot(at), typeName(v))
	}
	return s, nil
}

func asInt(v any, at string) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		if n == float64(int64(n)) {
			return int(n), nil
		}
	}
	return 0, fmt.Errorf("%w: %s must be an integer, got %s", ErrInvalidDocument, atOrRoot(at), typeName(v))
}

// checkKeys enforces additionalProperties:false. Unknown keys are collected
// and SORTED before reporting: ranging a map and reporting the first hit would
// make the error text depend on Go's map iteration order, which is exactly the
// determinism defect class this project has already shipped once.
func checkKeys(m map[string]any, allowed []string, at string) error {
	var unknown []string
	for k := range m {
		if !slices.Contains(allowed, k) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	slices.Sort(unknown)
	return fmt.Errorf("%w: %s: unknown key(s) %v; allowed keys are %v",
		ErrInvalidDocument, atOrRoot(at), unknown, allowed)
}

func stringField(m map[string]any, key, at string) (string, bool, error) {
	raw, ok := m[key]
	if !ok || raw == nil {
		return "", false, nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", false, fmt.Errorf("%w: %s/%s must be a string, got %s",
			ErrInvalidDocument, atOrRoot(at), key, typeName(raw))
	}
	if s == "" {
		return "", false, fmt.Errorf("%w: %s/%s must not be empty", ErrInvalidDocument, atOrRoot(at), key)
	}
	return s, true, nil
}

func boolField(m map[string]any, key, at string) (bool, bool, error) {
	raw, ok := m[key]
	if !ok || raw == nil {
		return false, false, nil
	}
	b, ok := raw.(bool)
	if !ok {
		return false, false, fmt.Errorf("%w: %s/%s must be a boolean, got %s",
			ErrInvalidDocument, atOrRoot(at), key, typeName(raw))
	}
	return b, true, nil
}

// durationField parses a Go duration string. Negative and signed forms are
// rejected: schemas/policy.schema.json#/$defs/duration's pattern has no sign,
// and a negative timeout is a scan that is over before it starts.
func durationField(m map[string]any, key, at string) (time.Duration, bool, error) {
	s, ok, err := stringField(m, key, at)
	if err != nil || !ok {
		return 0, false, err
	}
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") {
		return 0, false, fmt.Errorf("%w: %s/%s: %q must not be signed",
			ErrInvalidDocument, atOrRoot(at), key, s)
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %s/%s: %q is not a duration: %v",
			ErrInvalidDocument, atOrRoot(at), key, s, err)
	}
	return d, true, nil
}

// tokenListField reads a non-empty, duplicate-free list of non-empty strings.
// It backs both $defs/tokenList and $defs/globList, which have the same shape
// and differ only in what the values mean.
func tokenListField(m map[string]any, key, at string) ([]string, bool, error) {
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil, false, nil
	}
	items, err := asSequence(raw, atOrRoot(at)+"/"+key)
	if err != nil {
		return nil, false, err
	}
	if len(items) == 0 {
		return nil, false, fmt.Errorf(
			"%w: %s/%s must not be empty; omit the key to leave the dimension unconstrained",
			ErrInvalidDocument, atOrRoot(at), key)
	}
	// MaxListItems, enforced HERE because this is the one function every
	// list-valued key is decoded through -- globList and tokenList alike.
	//
	// It is checked before the loop below for a second reason worth stating:
	// that loop's duplicate check is a linear scan per item, so it is QUADRATIC
	// in the list length. An unbounded list would therefore be a denial of
	// service in the decoder as well as in the matcher, reachable without a
	// single glob being compiled.
	if err := checkListBound(atOrRoot(at), namedLen{key: key, n: len(items)}); err != nil {
		return nil, false, err
	}

	out := make([]string, 0, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, false, fmt.Errorf("%w: %s/%s/%d must be a string, got %s",
				ErrInvalidDocument, atOrRoot(at), key, i, typeName(item))
		}
		if s == "" {
			return nil, false, fmt.Errorf("%w: %s/%s/%d must not be empty",
				ErrInvalidDocument, atOrRoot(at), key, i)
		}
		if slices.Contains(out, s) {
			return nil, false, fmt.Errorf("%w: %s/%s/%d: %q is a duplicate",
				ErrInvalidDocument, atOrRoot(at), key, i, s)
		}
		out = append(out, s)
	}
	return out, true, nil
}

func atOrRoot(at string) string {
	if at == "" {
		return "(document root)"
	}
	return at
}

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case int, int64, float64:
		return "a number"
	case []any:
		return "a sequence"
	case map[string]any:
		return "a mapping"
	default:
		return fmt.Sprintf("%T", v)
	}
}
