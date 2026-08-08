package record

// fingerprint_spec_test.go — the test that keeps FINGERPRINT-SPEC.md honest.
//
// R.3's CRITIQUE-01.md, blocker 1: `normalized_match` was defined only in Go.
// The critic re-implemented plan/40-record-and-storage.md's four-clause spec
// text in Python and got 55e27b07… where the committed golden for sast-01 is
// 13c60ccf…. The orchestrator ruled that the implementation is right and the
// specification incomplete, and that the fix is to write the specification
// down completely and IN TREE — plan/ is gitignored, and a second producer
// working from a clone must be able to read it.
//
// internal/record/FINGERPRINT-SPEC.md is that document. This file is the
// second half of the ruling: "add a test that keeps the spec honest … A spec
// that can drift from the code silently is the same defect one level up."
//
// What is checkable mechanically is checked here:
//
//   - the reserved-word list in the document is EXACTLY the one in
//     fingerprint.go — same set, no extra, no missing, sorted, no duplicates,
//     and the count the prose claims;
//   - every algorithm constant the document prints equals the constant in the
//     code;
//   - the document still carries the anvil-fp/v2 rule, which is the sentence
//     that stops someone treating any of the above as a maintenance edit.
//
// What is NOT checkable mechanically — the prose describing the scan order,
// the identifier-disposition clauses and their reasons — is guarded instead by
// the corpus lock in fingerprint_test.go and, eventually, by R.16's
// independent oracle re-implemented FROM THIS DOCUMENT.

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const fingerprintSpecPath = "FINGERPRINT-SPEC.md"

// specBlock returns the lines between "<!-- name: BEGIN -->" and
// "<!-- name: END -->", with markdown code fences removed. The markers are
// HTML comments so they are invisible when the document is rendered but
// unambiguous to parse.
func specBlock(t *testing.T, doc, name string) []string {
	t.Helper()

	begin := "<!-- " + name + ": BEGIN -->"
	end := "<!-- " + name + ": END -->"

	i := strings.Index(doc, begin)
	if i < 0 {
		t.Fatalf("%s: missing marker %q; the machine-checked %s block is how this "+
			"document is kept from drifting away from fingerprint.go",
			fingerprintSpecPath, begin, name)
	}
	rest := doc[i+len(begin):]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("%s: marker %q has no matching %q", fingerprintSpecPath, begin, end)
	}

	var out []string
	for _, line := range strings.Split(rest[:j], "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		t.Fatalf("%s: block %s is empty", fingerprintSpecPath, name)
	}
	return out
}

func readFingerprintSpec(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(fingerprintSpecPath)
	if err != nil {
		t.Fatalf("reading %s: %v\nThis document is the authoritative definition of anvil-fp/v1 "+
			"and must be in tree: plan/ is gitignored, so a second producer working from a clone "+
			"has nothing else to implement from.", fingerprintSpecPath, err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// TestSpecReservedWordListMatchesTheCode is the ruling's named test. The
// reserved-word list is the single largest undocumented input to
// normalized_match — ~200 entries, every one of which changes the digest of
// any snippet containing it — and it is the reason the critic's from-the-text
// re-implementation diverged.
func TestSpecReservedWordListMatchesTheCode(t *testing.T) {
	doc := readFingerprintSpec(t)
	lines := specBlock(t, doc, "ANVIL-FP-RESERVED-WORDS")

	var documented []string
	for _, line := range lines {
		documented = append(documented, strings.Fields(line)...)
	}

	// No duplicates. A duplicate is invisible in a set comparison but means
	// the human-readable count is wrong and the list has been edited carelessly.
	seen := map[string]bool{}
	for _, w := range documented {
		if seen[w] {
			t.Errorf("%s: reserved word %q is listed twice", fingerprintSpecPath, w)
		}
		seen[w] = true
	}

	// Sorted in byte order. Not a correctness property of the algorithm, but it
	// makes an added or removed entry a one-line diff instead of a hunt.
	if !sort.StringsAreSorted(documented) {
		t.Errorf("%s: the reserved-word block is not sorted in byte order; "+
			"sort it so that adding or removing an entry is a readable diff", fingerprintSpecPath)
	}

	// The set must be EXACTLY fingerprint.go's.
	inCode := make(map[string]bool, len(fingerprintReservedWords))
	for w, v := range fingerprintReservedWords {
		if !v {
			t.Fatalf("fingerprintReservedWords[%q] is false; every entry must be true", w)
		}
		inCode[w] = true
	}

	var missing, extra []string
	for w := range inCode {
		if !seen[w] {
			missing = append(missing, w)
		}
	}
	for w := range seen {
		if !inCode[w] {
			extra = append(extra, w)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)

	if len(missing) > 0 {
		t.Errorf("%s: %d reserved word(s) are in fingerprint.go but NOT documented: %q\n"+
			"A second producer implementing from this document would abstract them to $N and "+
			"emit a different digest for unchanged code.",
			fingerprintSpecPath, len(missing), missing)
	}
	if len(extra) > 0 {
		t.Errorf("%s: %d reserved word(s) are documented but NOT in fingerprint.go: %q\n"+
			"A second producer would preserve them verbatim where this implementation "+
			"abstracts them.",
			fingerprintSpecPath, len(extra), extra)
	}

	// The count the prose claims must be the real one.
	countRe := regexp.MustCompile(`\*\*(\d+) entries\*\*`)
	m := countRe.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("%s: the reserved-word section must state the entry count as \"**N entries**\"",
			fingerprintSpecPath)
	}
	claimed, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("%s: unparseable entry count %q", fingerprintSpecPath, m[1])
	}
	if claimed != len(inCode) {
		t.Errorf("%s: claims %d reserved words, fingerprint.go has %d",
			fingerprintSpecPath, claimed, len(inCode))
	}
	if len(documented) != len(inCode) {
		t.Errorf("%s: block lists %d words, fingerprint.go has %d",
			fingerprintSpecPath, len(documented), len(inCode))
	}
}

// TestSpecConstantsMatchTheCode covers every named value a re-implementation
// must reproduce byte for byte: the separator, the digest length, the four
// normalization tokens, and the two route-templating thresholds. A wrong
// threshold is the subtlest of these — it produces a perfectly valid digest
// that merges or splits routes differently from every other producer.
func TestSpecConstantsMatchTheCode(t *testing.T) {
	doc := readFingerprintSpec(t)
	lines := specBlock(t, doc, "ANVIL-FP-CONSTANTS")

	documented := map[string]string{}
	for _, line := range lines {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: constants block line %q is not \"name = value\"", fingerprintSpecPath, line)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, dup := documented[k]; dup {
			t.Errorf("%s: constant %q is listed twice", fingerprintSpecPath, k)
		}
		documented[k] = v
	}

	// "U+001F" rather than a literal control character: the separator cannot be
	// written literally into a text document without becoming invisible, and an
	// invisible separator in the one document that defines it is how the
	// research/07-vs-research/18 conflict happened in the first place.
	inCode := map[string]string{
		"FingerprintAlgV1":            FingerprintAlgV1,
		"FingerprintFieldSeparator":   "U+001F",
		"FingerprintDigestHexLen":     strconv.Itoa(FingerprintDigestHexLen),
		"NormalizedStringToken":       NormalizedStringToken,
		"NormalizedNumberToken":       NormalizedNumberToken,
		"NormalizedMetavarPrefix":     NormalizedMetavarPrefix,
		"NormalizedRouteSegmentToken": NormalizedRouteSegmentToken,
		"routeHexSegmentMinLen":       strconv.Itoa(routeHexSegmentMinLen),
		"routeOpaqueSegmentMinLen":    strconv.Itoa(routeOpaqueSegmentMinLen),
	}

	for name, want := range inCode {
		got, ok := documented[name]
		if !ok {
			t.Errorf("%s: constant %s is not documented; a re-implementation cannot reproduce it",
				fingerprintSpecPath, name)
			continue
		}
		if got != want {
			t.Errorf("%s: documents %s = %q, the code has %q", fingerprintSpecPath, name, got, want)
		}
	}
	for name := range documented {
		if _, ok := inCode[name]; !ok {
			t.Errorf("%s: documents constant %s, which does not exist in the code",
				fingerprintSpecPath, name)
		}
	}

	// The separator spelling must actually denote U+001F, not merely agree with
	// a string in this test.
	if FingerprintFieldSeparator != "\x1f" {
		t.Fatalf("FingerprintFieldSeparator = %q, want U+001F", FingerprintFieldSeparator)
	}
}

// TestSpecCarriesTheVersioningRule. fingerprint.go's fingerprintReservedWords
// comment already says that adding or removing an entry "CHANGES EVERY SAST
// FINGERPRINT and is therefore an anvil-fp/v2 event, not a maintenance edit".
// The ruling requires the document to agree, because the document is what a
// second producer reads, and someone editing a word list in a markdown file
// feels far more casual than someone editing a hash function.
func TestSpecCarriesTheVersioningRule(t *testing.T) {
	doc := readFingerprintSpec(t)
	required := []string{
		"Any change to this document's algorithm is an `anvil-fp/v2` event, never a `v1` edit.",
		"anvil-fp/v1",
	}
	for _, s := range required {
		if !strings.Contains(doc, s) {
			t.Errorf("%s must contain %q", fingerprintSpecPath, s)
		}
	}
}

// TestSpecDocumentsEveryExportedAlgorithmSurface is a cheap guard against the
// failure mode this whole document exists to prevent: a new normalization step
// or tier helper is added to fingerprint.go and nobody writes it down, so the
// spec silently stops being the definition. It names the surfaces a
// re-implementation must know about and asserts each appears in the text.
func TestSpecDocumentsEveryExportedAlgorithmSurface(t *testing.T) {
	doc := readFingerprintSpec(t)
	surfaces := []string{
		"NormalizeMatch",
		"CanonicalRepoRelPath",
		"CanonicalRouteTemplate",
		"PurlBase",
		"ordinal",
		"normalized_match",
		"route_template",
		"rule_id_versioned",
		"enclosing_symbol_path",
		"injection_point",
		"evidence_class_detail",
		"purl_base",
		"locator",
		"http_method",
		"target_id",
		"detector_kind",
		"advisory_id",
		"repo_relpath",
		"param_name",
	}
	for _, s := range surfaces {
		if !strings.Contains(doc, s) {
			t.Errorf("%s does not mention %q; a re-implementation would not know it exists",
				fingerprintSpecPath, s)
		}
	}
}

// TestSpecWorkedRouteExamplesHold re-runs the §6.5 "Whole routes" examples
// against the implementation. They are transcribed here rather than parsed out
// of the markdown table, so the assertion is on the BEHAVIOUR the document
// promises; if the document's table is edited without the code changing (or
// vice versa) this test and TestCanonicalRouteTemplate disagree with each
// other, which is the signal.
func TestSpecWorkedRouteExamplesHold(t *testing.T) {
	examples := [][2]string{
		{"/api/v1/users/12345/orders", "/api/v1/users/<VAR>/orders"},
		{"/api/v1/users/{id}/orders", "/api/v1/users/<VAR>/orders"},
		{"/api/v1/users/:userId/orders", "/api/v1/users/<VAR>/orders"},
		{"api//v1/users/12345//orders/?debug=1", "/api/v1/users/<VAR>/orders"},
		{"/12345/orders/6789", "/<VAR>/orders/<VAR>"},
		{"/api/v1/users/me/orders", "/api/v1/users/me/orders"},
		{"/", "/"},
	}
	for _, ex := range examples {
		if got := CanonicalRouteTemplate(ex[0]); got != ex[1] {
			t.Errorf("%s section 6.5 promises CanonicalRouteTemplate(%q) = %q, got %q",
				fingerprintSpecPath, ex[0], ex[1], got)
		}
	}

	// And the §3.7 normalization examples, same reasoning.
	norms := [][2]string{
		{`rows, err := db.Query("SELECT * FROM users WHERE name = '" + name + "'")`,
			`$1, $2 := $3.Query(<STR> + $4 + <STR>)`},
		{`os.system("rm -rf " + path)`, `$1.system(<STR> + $2)`},
		{`a = b + a + b`, `$1 = $2 + $1 + $2`},
		{`for i := range items { return nil }`, `for $1 := range $2 { return nil }`},
		{`a = 0xFF + 1_000 + 3.14f + 1e-9`, `$1 = <NUM> + <NUM> + <NUM> + <NUM>`},
		{`p->Field = Ns::Helper(v)`, `$1->Field = Ns::Helper($2)`},
		{`std::vector<int> v = Foo::Bar::make(x)`, `std::vector<int> $1 = Foo::Bar::make($2)`},
		{`Ns::Helper(v)`, `Ns::Helper($1)`},
		{`Other::Helper(v)`, `Other::Helper($1)`},
		{`totalCount := len(itemsList)`, `$1 := len($2)`},
	}
	for _, ex := range norms {
		if got := NormalizeMatch(ex[0]); got != ex[1] {
			t.Errorf("%s section 3.7 promises NormalizeMatch(%q) = %q, got %q",
				fingerprintSpecPath, ex[0], ex[1], got)
		}
	}

	// Sanity: the two examples the document uses to argue rule 6(c) must not
	// collide, or the argument in the document is false.
	if NormalizeMatch("Ns::Helper(v)") == NormalizeMatch("Other::Helper(v)") {
		t.Fatal("Ns::Helper and Other::Helper normalise identically; " +
			fmt.Sprintf("%s clause (c)'s stated reason does not hold", fingerprintSpecPath))
	}
}
