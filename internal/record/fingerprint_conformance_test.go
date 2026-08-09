package record

// fingerprint_conformance_test.go — R.16, the spine-mandated conformance gate.
//
// ===========================================================================
// WHAT THIS FILE IS FOR
// ===========================================================================
//
// plan/00-SPINE.md S6: "Ship a conformance test asserting identical digests on
// a fixed corpus." It exists because research/07-database-design.md and
// research/18-unified-audit-record.md shipped two DIFFERENT algorithms under
// the one name `anvil-fp/v1`, and nothing in the tree surfaced it. S6 states
// the consequence: "two producers emitting different hashes means regression
// matching silently fails forever." Every stored finding loses its identity on
// the next scan, `first_seen_at` resets, every fingerprint-keyed suppression
// stops applying, every `handoff` row keyed on the old digest is orphaned —
// and not one error is logged.
//
// The distinction that makes this file worth having, and the one that is easy
// to lose in a later edit:
//
//	fingerprint_test.go asserts the Go implementation still produces the
//	values the CORPUS commits. That is a lock against drift.
//
//	THIS file asserts the Go implementation produces the values a SECOND,
//	INDEPENDENT implementation produced from the written specification alone.
//	That is a lock against the specification and the code meaning two
//	different things.
//
// A conformance oracle that read internal/record/fingerprint.go would prove
// only that the Go equals itself, which is exactly the check that failed to
// catch research/07 versus research/18.
//
// ===========================================================================
// WHERE THE GOLDEN VALUES COME FROM
// ===========================================================================
//
// scripts/compute_golden_fingerprints.py is the oracle: a from-scratch Python
// implementation of internal/record/FINGERPRINT-SPEC.md, written without
// reading fingerprint.go, that parses the reserved-word list and the algorithm
// constants OUT OF THE SPECIFICATION DOCUMENT rather than transcribing them.
// It emits testdata/fingerprint_corpus/**/*.golden. This test never runs it —
// there is no Python dependency in the Go build, and no `go generate` hook that
// could quietly re-seal a golden mid-test. It reads the committed files.
//
// The independence is two-sided by construction:
//
//   - each fixture's `hashed_fields` list was derived BY HAND from the
//     specification text and is compared field by field against what the Go
//     field builders produce, so a wrong field ORDER — which yields a perfectly
//     valid-looking 64-hex digest that is silently incompatible — is caught as
//     a field-list diff and not merely as an opaque digest mismatch;
//   - each `.golden` digest was computed by the Python oracle from that
//     algorithm, and is compared against what Go's Digest produces.
//
// IF A DIGEST EVER DISAGREES, STOP. Do not regenerate the goldens; do not edit
// a fixture. A changed digest is an `anvil-fp/v2` event with a dual-write
// migration (FINGERPRINT-SPEC.md section 0). A conformance harness that
// re-seals its own goldens is the exact failure this file exists to prevent,
// and it fails green.
//
// ===========================================================================
// THE DERIVED CORPUS — FINGERPRINT-SPEC.md APPENDIX Z
// ===========================================================================
//
// Appendix Z records six places where the specification's prose admits more
// than one reading and the main corpus happens not to distinguish them. Z4 was
// the worst: `ordinal` was NOT EXERCISED AT ALL, because every SAST fixture in
// the main corpus supplies a pre-computed ordinal in its input. An independent
// implementation could get section 4's grouping key wrong — omit `target_id`,
// group on the raw rather than the canonicalised path, sort unstably — and
// still reproduce all eight committed digests.
//
// testdata/fingerprint_corpus/derived/ closes that. Its fixtures supply
// candidates WITHOUT ordinals and require them to be derived, and its DAST
// fixture pins both sides of every section 6.3 threshold. Each derived fixture
// names the Appendix Z entries it resolves in a `resolves` key, and
// TestConformanceDerivedCorpusClosesAppendixZ4 fails if the Z4 fixture is ever
// removed or gutted.
//
// Sources: plan/00-SPINE.md S6; plan/40-record-and-storage.md R.16;
// internal/record/FINGERPRINT-SPEC.md (the algorithm, and Appendix Z);
// internal/record/CRITIQUE-01.md finding 1 (why the specification had to be
// written down completely before this test could exist at all).

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	// derivedCorpusDir is a SUBdirectory of corpusDir on purpose: loadCorpus
	// globs "*.json" non-recursively, so the derived fixtures — which have a
	// different shape and are driven by this file alone — cannot be picked up
	// by R.2's tests and cannot perturb the eight committed tier fixtures.
	derivedCorpusDir = corpusDir + "/derived"

	// oracleScriptPath is the offline, non-Go oracle. This test reads it only
	// to assert its independence structurally; it never executes it.
	oracleScriptPath = "../../scripts/compute_golden_fingerprints.py"

	goldenKindDigest  = "digest"
	goldenKindOrdinal = "ordinal"
)

// ---------------------------------------------------------------------------
// Golden files
// ---------------------------------------------------------------------------

// goldenRow is one line of a .golden file: "kind <TAB> label <TAB> value".
// The format is deliberately trivial so that neither this parser nor the
// oracle's can be the interesting part of the comparison.
type goldenRow struct {
	Kind  string
	Label string
	Value string
}

// goldenFile indexes a .golden by (kind, label) and tracks which entries a
// test has consumed, so "the golden has a row nothing checks" and "a fixture
// case has no golden row" are both hard failures rather than silent gaps.
// A conformance test that skips a case reports green while proving nothing.
type goldenFile struct {
	path   string
	values map[string]string // kind + "\x00" + label -> value
	seen   map[string]bool
}

func goldenKey(kind, label string) string { return kind + "\x00" + label }

func loadGoldenFile(t *testing.T, path string) *goldenFile {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening golden %s: %v\n"+
			"Every corpus fixture must have a committed golden produced by "+
			"scripts/compute_golden_fingerprints.py. A missing golden means this "+
			"fixture is unguarded.", path, err)
	}
	defer func() { _ = f.Close() }()

	g := &goldenFile{path: path, values: map[string]string{}, seen: map[string]bool{}}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if strings.TrimSpace(text) == "" || strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		parts := strings.Split(text, "\t")
		if len(parts) != 3 {
			t.Fatalf("%s:%d: malformed golden row %q (want kind<TAB>label<TAB>value)", path, line, text)
		}
		key := goldenKey(parts[0], parts[1])
		if _, dup := g.values[key]; dup {
			t.Fatalf("%s:%d: duplicate golden row for %s/%s", path, line, parts[0], parts[1])
		}
		g.values[key] = parts[2]
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading golden %s: %v", path, err)
	}
	if len(g.values) == 0 {
		t.Fatalf("%s: golden has no rows; an empty golden asserts nothing", path)
	}
	return g
}

// digest returns the golden digest for label, validating its shape. A golden
// carrying a truncated or uppercase digest would silently weaken the gate,
// so it is rejected here rather than compared.
func (g *goldenFile) digest(t *testing.T, label string) string {
	t.Helper()
	v, ok := g.values[goldenKey(goldenKindDigest, label)]
	if !ok {
		t.Fatalf("%s: no golden digest for %q; this case is unguarded", g.path, label)
	}
	g.seen[goldenKey(goldenKindDigest, label)] = true
	if err := ValidateDigest(v); err != nil {
		t.Fatalf("%s: golden digest for %q is malformed: %v", g.path, label, err)
	}
	return v
}

func (g *goldenFile) ordinal(t *testing.T, label string) int {
	t.Helper()
	v, ok := g.values[goldenKey(goldenKindOrdinal, label)]
	if !ok {
		t.Fatalf("%s: no golden ordinal for %q", g.path, label)
	}
	g.seen[goldenKey(goldenKindOrdinal, label)] = true
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		t.Fatalf("%s: golden ordinal for %q is %q, want a non-negative base-10 integer", g.path, label, v)
	}
	return n
}

// assertFullyConsumed is the other half of the coverage guarantee: it fails if
// the golden holds a row no assertion touched, which is what would happen if a
// fixture case were deleted while its golden row stayed behind.
func (g *goldenFile) assertFullyConsumed(t *testing.T) {
	t.Helper()
	var unused []string
	for key := range g.values {
		if !g.seen[key] {
			parts := strings.SplitN(key, "\x00", 2)
			unused = append(unused, parts[0]+"/"+parts[1])
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		t.Errorf("%s: %d golden row(s) were never checked: %v\n"+
			"Either a fixture case was removed without removing its golden row, or "+
			"this test is skipping cases.", g.path, len(unused), unused)
	}
}

func goldenPathFor(fixturePath string) string {
	return strings.TrimSuffix(fixturePath, filepath.Ext(fixturePath)) + ".golden"
}

// ---------------------------------------------------------------------------
// The main corpus: eight tier fixtures and every mutation
// ---------------------------------------------------------------------------

// TestConformanceMainCorpusMatchesIndependentGoldens is R.16's stop condition:
// every corpus fixture's Go-computed digest equals its independently computed
// golden, exactly, with no fixture skipped.
func TestConformanceMainCorpusMatchesIndependentGoldens(t *testing.T) {
	fixtures := loadCorpus(t)
	if len(fixtures) == 0 {
		t.Fatal("no fixtures loaded; the fixed corpus is mandatory (plan/00-SPINE.md S6)")
	}

	for _, f := range fixtures {
		t.Run(f.ID, func(t *testing.T) {
			g := loadGoldenFile(t, goldenPathFor(f.path))

			// The field list first. A wrong field ORDER produces a valid-looking
			// 64-hex digest that is silently incompatible; comparing the list
			// says WHICH field moved instead of only that something did.
			fields, err := fieldsFor(f.Tier, f.Input)
			if err != nil {
				t.Fatalf("building fields: %v", err)
			}
			if !reflect.DeepEqual(fields, f.HashedFields) {
				t.Fatalf("hashed field list drifted from the hand-derived fixture.\n  go:      %q\n  fixture: %q",
					fields, f.HashedFields)
			}

			got, err := Digest(fields...)
			if err != nil {
				t.Fatalf("hashing: %v", err)
			}
			want := g.digest(t, "base")
			if got != want {
				t.Errorf("CONFORMANCE FAILURE: Go and the independent oracle disagree.\n"+
					"  go:     %s\n  oracle: %s\n"+
					"Two producers emitting different digests breaks regression matching "+
					"silently and forever (plan/00-SPINE.md S6). Do NOT re-seal the golden: "+
					"a changed digest is an anvil-fp/v2 event with a dual-write migration "+
					"(FINGERPRINT-SPEC.md section 0).", got, want)
			}

			// The fixture's own expected_digest and the oracle's golden were
			// derived by two different routes and must agree. If they ever
			// diverge, one of the two derivations is wrong and neither can be
			// trusted as the reference.
			if f.ExpectedDigest != want {
				t.Errorf("the fixture's expected_digest and the oracle's golden disagree.\n"+
					"  fixture expected_digest: %s\n  oracle golden:           %s",
					f.ExpectedDigest, want)
			}

			for _, m := range f.Mutations {
				label := "mutation:" + m.Name
				md, err := digestFor(f.Tier, m.Input)
				if err != nil {
					t.Fatalf("mutation %q: %v", m.Name, err)
				}
				if mw := g.digest(t, label); md != mw {
					t.Errorf("mutation %q: Go %s, oracle %s\n%s", m.Name, md, mw, m.Description)
				}
			}

			g.assertFullyConsumed(t)
		})
	}
}

// ---------------------------------------------------------------------------
// The derived corpus: values an implementation must COMPUTE, not be given
// ---------------------------------------------------------------------------

// jsonSastCandidateInput is deliberately NOT jsonSastInput: it has no `ordinal`
// field, and it is decoded with DisallowUnknownFields. A derived fixture that
// tried to supply a pre-computed ordinal therefore fails to decode, which is
// the whole point of the Appendix Z4 corpus.
type jsonSastCandidateInput struct {
	TargetID            string `json:"target_id"`
	RuleIDVersioned     string `json:"rule_id_versioned"`
	RepoRelPath         string `json:"repo_rel_path"`
	EnclosingSymbolPath string `json:"enclosing_symbol_path"`
	Snippet             string `json:"snippet"`
}

type derivedCandidate struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Line        int             `json:"line,omitempty"`
	Column      int             `json:"column,omitempty"`
	Input       json.RawMessage `json:"input"`

	// ExpectedOrdinal is the ordinal the fixture author derived by hand from
	// FINGERPRINT-SPEC.md section 4. It is a pointer so that "0" and "absent"
	// are distinguishable — a missing ordinal on a SAST candidate must fail,
	// not silently assert 0.
	ExpectedOrdinal *int `json:"expected_ordinal,omitempty"`

	// CanonicalRoute is the derived route the fixture expects, stated in the
	// clear so a failure reads "segment X templated when it should not have"
	// rather than "the digest moved".
	CanonicalRoute string `json:"canonical_route,omitempty"`

	HashedFields []string `json:"hashed_fields"`
}

type derivedFixture struct {
	ID          string             `json:"id"`
	Kind        string             `json:"kind"`
	Resolves    []string           `json:"resolves"`
	Description string             `json:"description"`
	Notes       []string           `json:"notes,omitempty"`
	Candidates  []derivedCandidate `json:"candidates"`

	path string
}

const (
	derivedKindSastOrdinalBatch = "sast_ordinal_batch"
	derivedKindDastCases        = "dast_cases"
)

func loadDerivedCorpus(t *testing.T) []derivedFixture {
	t.Helper()

	paths, err := filepath.Glob(filepath.Join(derivedCorpusDir, "*.json"))
	if err != nil {
		t.Fatalf("globbing %s: %v", derivedCorpusDir, err)
	}
	if len(paths) == 0 {
		t.Fatalf("no fixtures in %s; FINGERPRINT-SPEC.md Appendix Z4 is then re-opened — "+
			"the ordinal grouping key would be exercised by nothing at all", derivedCorpusDir)
	}
	sort.Strings(paths)

	out := make([]derivedFixture, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("reading %s: %v", p, err)
		}
		var f derivedFixture
		if err := strictUnmarshal(b, &f); err != nil {
			t.Fatalf("decoding %s: %v", p, err)
		}
		if f.ID == "" || f.Kind == "" || len(f.Candidates) == 0 || len(f.Resolves) == 0 {
			t.Fatalf("%s: a derived fixture must declare id, kind, resolves and at least one candidate", p)
		}
		f.path = p
		out = append(out, f)
	}
	return out
}

// TestConformanceDerivedCorpusMatchesIndependentGoldens drives the derived
// corpus through the SAME two-sided comparison as the main one, but on values
// the fixture withholds: the SAST ordinals are computed by AssignSastOrdinals
// from a shuffled batch, and the DAST routes by CanonicalRouteTemplate from
// concrete input.
func TestConformanceDerivedCorpusMatchesIndependentGoldens(t *testing.T) {
	for _, f := range loadDerivedCorpus(t) {
		t.Run(f.ID, func(t *testing.T) {
			g := loadGoldenFile(t, goldenPathFor(f.path))
			switch f.Kind {
			case derivedKindSastOrdinalBatch:
				checkSastOrdinalBatch(t, f, g)
			case derivedKindDastCases:
				checkDastCases(t, f, g)
			default:
				t.Fatalf("%s: unknown derived fixture kind %q", f.path, f.Kind)
			}
			g.assertFullyConsumed(t)
		})
	}
}

func checkSastOrdinalBatch(t *testing.T, f derivedFixture, g *goldenFile) {
	t.Helper()

	cands := make([]SastCandidate, 0, len(f.Candidates))
	for _, c := range f.Candidates {
		var in jsonSastCandidateInput
		if err := strictUnmarshal(c.Input, &in); err != nil {
			t.Fatalf("%s: candidate %q: %v\n"+
				"(A candidate that supplies a pre-computed `ordinal` fails here on purpose: "+
				"FINGERPRINT-SPEC.md Appendix Z4 exists because every main-corpus SAST fixture "+
				"does exactly that, leaving section 4 untested.)", f.path, c.Name, err)
		}
		if c.ExpectedOrdinal == nil {
			t.Fatalf("%s: candidate %q has no expected_ordinal", f.path, c.Name)
		}
		cands = append(cands, SastCandidate{
			Input: SastInput{
				TargetID:            in.TargetID,
				RuleIDVersioned:     in.RuleIDVersioned,
				RepoRelPath:         in.RepoRelPath,
				EnclosingSymbolPath: in.EnclosingSymbolPath,
				Snippet:             in.Snippet,
			},
			Line:   c.Line,
			Column: c.Column,
		})
	}

	// THE ordinal is derived here, from the batch, exactly as a producer must.
	assigned, err := AssignSastOrdinals(cands)
	if err != nil {
		t.Fatalf("%s: AssignSastOrdinals: %v", f.path, err)
	}
	if len(assigned) != len(f.Candidates) {
		t.Fatalf("%s: AssignSastOrdinals returned %d inputs for %d candidates",
			f.path, len(assigned), len(f.Candidates))
	}

	for i, c := range f.Candidates {
		label := "candidate:" + c.Name
		got := assigned[i]

		if got.Ordinal != *c.ExpectedOrdinal {
			t.Errorf("%s: candidate %q: derived ordinal %d, fixture says %d\n%s",
				f.path, c.Name, got.Ordinal, *c.ExpectedOrdinal, c.Description)
		}
		if wantOrd := g.ordinal(t, label); got.Ordinal != wantOrd {
			t.Errorf("%s: candidate %q: Go derived ordinal %d, the independent oracle derived %d.\n"+
				"The section 4 grouping key or its ordering rule is being read two different ways.",
				f.path, c.Name, got.Ordinal, wantOrd)
		}

		fields, err := SastFields(got)
		if err != nil {
			t.Fatalf("%s: candidate %q: SastFields: %v", f.path, c.Name, err)
		}
		if !reflect.DeepEqual(fields, c.HashedFields) {
			t.Fatalf("%s: candidate %q: hashed field list drifted from the hand-derived fixture.\n"+
				"  go:      %q\n  fixture: %q", f.path, c.Name, fields, c.HashedFields)
		}

		d, err := Digest(fields...)
		if err != nil {
			t.Fatalf("%s: candidate %q: hashing: %v", f.path, c.Name, err)
		}
		if want := g.digest(t, label); d != want {
			t.Errorf("%s: candidate %q: CONFORMANCE FAILURE.\n  go:     %s\n  oracle: %s",
				f.path, c.Name, d, want)
		}
	}
}

func checkDastCases(t *testing.T, f derivedFixture, g *goldenFile) {
	t.Helper()

	for _, c := range f.Candidates {
		label := "case:" + c.Name
		var in jsonDastInput
		if err := strictUnmarshal(c.Input, &in); err != nil {
			t.Fatalf("%s: case %q: %v", f.path, c.Name, err)
		}

		if got := CanonicalRouteTemplate(in.RouteTemplate); got != c.CanonicalRoute {
			t.Errorf("%s: case %q: CanonicalRouteTemplate(%q) = %q, fixture says %q\n%s",
				f.path, c.Name, in.RouteTemplate, got, c.CanonicalRoute, c.Description)
		}

		fields, err := DastFields(DastInput{
			TargetID:        in.TargetID,
			RuleIDVersioned: in.RuleIDVersioned,
			HTTPMethod:      in.HTTPMethod,
			RouteTemplate:   in.RouteTemplate,
			InjectionPoint:  InjectionPoint(in.InjectionPoint),
			ParamName:       in.ParamName,
			EvidenceSignal:  EvidenceSignal(in.EvidenceSignal),
		})
		if err != nil {
			t.Fatalf("%s: case %q: DastFields: %v", f.path, c.Name, err)
		}
		if !reflect.DeepEqual(fields, c.HashedFields) {
			t.Fatalf("%s: case %q: hashed field list drifted from the hand-derived fixture.\n"+
				"  go:      %q\n  fixture: %q", f.path, c.Name, fields, c.HashedFields)
		}

		d, err := Digest(fields...)
		if err != nil {
			t.Fatalf("%s: case %q: hashing: %v", f.path, c.Name, err)
		}
		if want := g.digest(t, label); d != want {
			t.Errorf("%s: case %q: CONFORMANCE FAILURE.\n  go:     %s\n  oracle: %s",
				f.path, c.Name, d, want)
		}
	}
}

// ---------------------------------------------------------------------------
// The gate on the gate
// ---------------------------------------------------------------------------

// TestConformanceEveryFixtureHasAGolden is separate from the comparison tests
// on purpose. Those tests iterate fixtures and would simply not run for a
// fixture nobody added a golden for if the lookup were ever made lenient; this
// one asserts the file exists, so "the corpus grew and the gate did not" is a
// failure rather than an omission.
func TestConformanceEveryFixtureHasAGolden(t *testing.T) {
	var fixturePaths []string
	for _, f := range loadCorpus(t) {
		fixturePaths = append(fixturePaths, f.path)
	}
	for _, f := range loadDerivedCorpus(t) {
		fixturePaths = append(fixturePaths, f.path)
	}

	for _, p := range fixturePaths {
		gp := goldenPathFor(p)
		if _, err := os.Stat(gp); err != nil {
			t.Errorf("%s has no committed golden at %s: %v\n"+
				"Run `python scripts/compute_golden_fingerprints.py --write` and review the "+
				"result BY HAND against FINGERPRINT-SPEC.md before committing it.", p, gp, err)
		}
	}

	goldens, err := filepath.Glob(filepath.Join(corpusDir, "*.golden"))
	if err != nil {
		t.Fatalf("globbing goldens: %v", err)
	}
	derivedGoldens, err := filepath.Glob(filepath.Join(derivedCorpusDir, "*.golden"))
	if err != nil {
		t.Fatalf("globbing derived goldens: %v", err)
	}
	if got, want := len(goldens)+len(derivedGoldens), len(fixturePaths); got != want {
		t.Errorf("found %d golden files for %d fixtures; an orphaned golden guards nothing "+
			"and a missing one leaves a fixture unguarded", got, want)
	}
}

// TestConformanceDerivedCorpusClosesAppendixZ4 fails if the Appendix Z4 gap is
// ever re-opened by deleting or gutting the ordinal batch. Z4 is the entry
// Appendix Z itself calls "the one that matters most": the grouping key is what
// keeps a finding's identity stable when an unrelated edit moves it, and before
// this corpus existed it was exercised by nothing.
func TestConformanceDerivedCorpusClosesAppendixZ4(t *testing.T) {
	var batches int
	for _, f := range loadDerivedCorpus(t) {
		if f.Kind != derivedKindSastOrdinalBatch {
			continue
		}
		batches++

		var resolvesZ4 bool
		for _, z := range f.Resolves {
			if z == "Z4" {
				resolvesZ4 = true
			}
		}
		if !resolvesZ4 {
			t.Errorf("%s: a %s fixture must declare that it resolves Z4", f.path, f.Kind)
		}

		// The properties that make this fixture actually exercise section 4,
		// rather than being a batch of ten singleton groups that would pass
		// with any grouping key at all.
		var maxOrdinal, nonZero int
		targets, rules, paths := map[string]bool{}, map[string]bool{}, map[string]bool{}
		var shuffled bool
		prevLine := -1
		for _, c := range f.Candidates {
			if c.ExpectedOrdinal == nil {
				t.Fatalf("%s: candidate %q has no expected_ordinal", f.path, c.Name)
			}
			if *c.ExpectedOrdinal > maxOrdinal {
				maxOrdinal = *c.ExpectedOrdinal
			}
			if *c.ExpectedOrdinal > 0 {
				nonZero++
			}
			var in jsonSastCandidateInput
			if err := strictUnmarshal(c.Input, &in); err != nil {
				t.Fatalf("%s: candidate %q: %v", f.path, c.Name, err)
			}
			targets[in.TargetID] = true
			rules[in.RuleIDVersioned] = true
			paths[CanonicalRepoRelPath(in.RepoRelPath)] = true
			if prevLine >= 0 && c.Line < prevLine {
				shuffled = true
			}
			prevLine = c.Line
		}

		if maxOrdinal < 2 {
			t.Errorf("%s: highest derived ordinal is %d; a group of at least three is needed "+
				"before the ordering rule's line/column/batch-index tiers can all be distinguished",
				f.path, maxOrdinal)
		}
		if nonZero < 2 {
			t.Errorf("%s: only %d candidate(s) derive a non-zero ordinal; the batch is not "+
				"exercising grouping", f.path, nonZero)
		}
		if len(targets) < 2 || len(rules) < 2 || len(paths) < 2 {
			t.Errorf("%s: the batch varies %d target_id(s), %d rule(s) and %d canonical path(s); "+
				"each component of the section 4 grouping key must be varied or a wrong key "+
				"still passes", f.path, len(targets), len(rules), len(paths))
		}
		if !shuffled {
			t.Errorf("%s: the batch is in ascending line order, so a producer that ignored the "+
				"ordering rule entirely and numbered candidates in batch order would still pass",
				f.path)
		}
	}
	if batches == 0 {
		t.Fatalf("no %s fixture in %s: FINGERPRINT-SPEC.md Appendix Z4 is re-opened",
			derivedKindSastOrdinalBatch, derivedCorpusDir)
	}
}

// TestConformanceOracleIsAnIndependentOfflineImplementation is the structural
// half of R.16's "demonstrably two independent code paths" requirement. The
// substantive half is that the oracle is a different LANGUAGE implementing a
// specification document; what a test can check mechanically is that it has no
// route back to the Go it gates.
//
// The check is deliberately narrow and honest about it: it enumerates the
// script's imports and requires them to be a subset of an allowlist of pure
// standard-library modules. `subprocess`, `ctypes`, `importlib` and anything
// else that could invoke or load the implementation under test are therefore
// excluded by construction rather than by grepping for banned words, which a
// docstring mentioning them would trip.
func TestConformanceOracleIsAnIndependentOfflineImplementation(t *testing.T) {
	b, err := os.ReadFile(oracleScriptPath)
	if err != nil {
		t.Fatalf("reading the oracle at %s: %v\n"+
			"R.16 requires the golden values to come from an offline re-implementation of "+
			"FINGERPRINT-SPEC.md that is not this package. Without it the goldens have no "+
			"provenance and the conformance gate is circular.", oracleScriptPath, err)
	}
	src := string(b)

	if ext := filepath.Ext(oracleScriptPath); ext == ".go" {
		t.Fatalf("the oracle must not be Go: %s", oracleScriptPath)
	}
	if !strings.Contains(src, "FINGERPRINT-SPEC.md") {
		t.Errorf("%s never mentions FINGERPRINT-SPEC.md; the oracle must implement the "+
			"specification document, not the summary in plan/40-record-and-storage.md, which "+
			"CRITIQUE-01 finding 1 proved insufficient to reproduce the SAST goldens",
			oracleScriptPath)
	}

	allowed := map[string]bool{
		"__future__": true, "argparse": true, "hashlib": true, "json": true,
		"re": true, "sys": true, "unicodedata": true, "pathlib": true,
	}
	// Matched against whole lines that are syntactically import statements, so
	// prose in the module docstring ("... from its written specification ...")
	// is not mistaken for one.
	importRes := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^import\s+([A-Za-z_][A-Za-z0-9_.]*)\s*$`),
		regexp.MustCompile(`(?m)^from\s+([A-Za-z_][A-Za-z0-9_.]*)\s+import\s`),
	}
	found := map[string]bool{}
	for _, re := range importRes {
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			mod := strings.SplitN(m[1], ".", 2)[0]
			found[mod] = true
			if !allowed[mod] {
				t.Errorf("%s imports %q, which is not on the oracle's allowlist. The oracle must "+
					"not be able to execute, load or read the implementation it gates — that is "+
					"what makes the goldens independent evidence rather than a restatement of the Go.",
					oracleScriptPath, mod)
			}
		}
	}
	if !found["hashlib"] {
		t.Errorf("%s does not import hashlib; it cannot be computing SHA-256 itself", oracleScriptPath)
	}

	// A Go filename literal would mean the oracle opens Go source.
	for _, bad := range []string{`.go"`, `.go'`} {
		if strings.Contains(src, bad) {
			t.Errorf("%s contains a Go filename literal (%s); the oracle must not read Go source",
				oracleScriptPath, bad)
		}
	}
}

// TestConformanceGoldensAreNotDerivableFromThisPackage records, as an
// executable note, that nothing in this package can regenerate a golden.
// R.2's fingerprint_test.go carries the same prohibition in prose; this makes
// the absence checkable, because the cheapest way to make a failing digest
// green is always to re-seal, and the change that was supposed to be caught
// then ships silently.
func TestConformanceGoldensAreNotDerivableFromThisPackage(t *testing.T) {
	// Scoped to the two files that touch the corpus and the goldens. It does
	// NOT police the rest of the package: another test may have a legitimate
	// reason to write a temporary file, and a gate that fires on unrelated work
	// gets deleted rather than obeyed.
	owners := []string{"fingerprint_test.go", "fingerprint_conformance_test.go"}
	banned := regexp.MustCompile(`os\.(WriteFile|Create)\s*\(`)
	for _, p := range owners {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("reading %s: %v", p, err)
		}
		if loc := banned.FindString(string(b)); loc != "" {
			t.Errorf("%s contains %q: neither the corpus lock nor the conformance gate may "+
				"write a file. A golden this package can "+
				"regenerate proves nothing — the cheapest way to make a changed digest green "+
				"would be to re-seal, and the change this gate exists to catch would ship "+
				"silently.", p, loc)
		}
	}
}

// TestConformanceCorpusCoverageIsMeaningful pins the total number of compared
// values, so that a change which quietly reduces coverage — deleting a
// mutation, dropping a fixture — has to be an explicit edit to this number
// rather than an invisible loss of assertions.
func TestConformanceCorpusCoverageIsMeaningful(t *testing.T) {
	var digests, ordinals int
	count := func(path string) {
		g := loadGoldenFile(t, path)
		for key := range g.values {
			if strings.HasPrefix(key, goldenKindDigest+"\x00") {
				digests++
			} else if strings.HasPrefix(key, goldenKindOrdinal+"\x00") {
				ordinals++
			}
		}
	}
	for _, f := range loadCorpus(t) {
		count(goldenPathFor(f.path))
	}
	for _, f := range loadDerivedCorpus(t) {
		count(goldenPathFor(f.path))
	}

	const (
		minDigests  = 81 // 8 base + 49 mutations + 10 batch candidates + 14 route cases
		minOrdinals = 10 // one per Appendix Z4 batch candidate
	)
	if digests < minDigests {
		t.Errorf("only %d digests are compared against the independent oracle, want at least %d; "+
			"coverage went down", digests, minDigests)
	}
	if ordinals < minOrdinals {
		t.Errorf("only %d derived ordinals are compared, want at least %d; FINGERPRINT-SPEC.md "+
			"Appendix Z4 coverage went down", ordinals, minOrdinals)
	}
	t.Logf("anvil-fp/v1 conformance: %d digests and %d derived ordinals compared against "+
		"%s", digests, ordinals, oracleScriptPath)
}
