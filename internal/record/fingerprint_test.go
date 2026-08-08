package record

// fingerprint_test.go — R.2's own tests.
//
// These are NOT the conformance test. R.16 owns that
// (internal/record/fingerprint_conformance_test.go plus
// testdata/fingerprint_corpus/*.golden), and its oracle must be an offline
// re-implementation of internal/record/FINGERPRINT-SPEC.md that never imports
// this package. What is here is:
//
//   - a corpus lock: every fixture's committed hashed_fields and
//     expected_digest must still be what the implementation produces;
//   - determinism across two consecutive runs (R.2's stop condition) AND
//     across two separate OS processes, which is the form that can actually
//     detect a per-process source of nondeterminism such as map iteration
//     order;
//   - the mutation tests that prove the forbidden inputs are not hashed:
//     line/column numbers for SAST, the version string for SCA and host,
//     host/port/payload for DAST;
//   - a frozen-shape test on the four input structs, so a later edit cannot
//     quietly add a field that reintroduces a volatile input.
//
// THE COMMITTED GOLDENS WERE NOT PRODUCED BY THIS PACKAGE. Each fixture's
// `hashed_fields` list was derived by hand from the algorithm text — now
// internal/record/FINGERPRINT-SPEC.md, which is the authoritative and COMPLETE
// definition; plan/40-record-and-storage.md's four-clause summary was proved
// insufficient by CRITIQUE-01 — and its `expected_digest` was computed from
// that list by an offline script that only joins with U+001F and SHA-256s.
// The lock below is therefore a genuine two-sided check, and there is
// deliberately no test here that can regenerate it — see the note further
// down.
//
// TWO DAST GOLDENS WERE RE-DERIVED ON 2026-08-08 under the R.3 blocker-2
// ruling, when CanonicalRouteTemplate began deriving `route_template` as the
// specification always said it should:
//
//	dast-01  ca801b8d… → 199c3b5f…   route_template "/api/v1/users/{id}/orders"
//	                                 → "/api/v1/users/<VAR>/orders"
//	dast-03  84fe311d… → 5fc15c55…   route_template "/files/{path}"
//	                                 → "/files/<VAR>"
//
// dast-02 ("/search") was unaffected, and its untouched golden reproducing
// exactly under the same offline script is the control that shows the script
// was not quietly rewritten to agree with the Go code. No SAST, SCA or host
// digest moved. Nothing had been stored under the old digests — anvil-fp/v1
// has not shipped — so this was a correction of an unimplemented spec clause,
// not an anvil-fp/v2 event.
//
// R.16: do NOT derive the .golden files from `expected_digest` either. Even
// though it is independent of the Go code, copying it would make the
// conformance gate a transcription check rather than a re-derivation.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const corpusDir = "../../testdata/fingerprint_corpus"

// ---------------------------------------------------------------------------
// Corpus loading
// ---------------------------------------------------------------------------

type corpusMutation struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Input       json.RawMessage `json:"input"`
	NotHashed   json.RawMessage `json:"not_hashed,omitempty"`
}

type corpusFixture struct {
	ID             string           `json:"id"`
	Tier           string           `json:"tier"`
	Description    string           `json:"description"`
	Input          json.RawMessage  `json:"input"`
	NotHashed      json.RawMessage  `json:"not_hashed,omitempty"`
	HashedFields   []string         `json:"hashed_fields"`
	ExpectedDigest string           `json:"expected_digest"`
	Mutations      []corpusMutation `json:"mutations,omitempty"`
	Notes          []string         `json:"notes,omitempty"`

	path string
}

type jsonSastInput struct {
	TargetID            string `json:"target_id"`
	RuleIDVersioned     string `json:"rule_id_versioned"`
	RepoRelPath         string `json:"repo_rel_path"`
	EnclosingSymbolPath string `json:"enclosing_symbol_path"`
	Snippet             string `json:"snippet"`
	Ordinal             int    `json:"ordinal"`
}

type jsonScaInput struct {
	TargetID        string `json:"target_id"`
	AdvisoryID      string `json:"advisory_id"`
	Purl            string `json:"purl"`
	ManifestRelPath string `json:"manifest_rel_path"`
}

type jsonHostInput struct {
	TargetID       string `json:"target_id"`
	AdvisoryID     string `json:"advisory_id"`
	Purl           string `json:"purl"`
	PackageManager string `json:"package_manager"`
	HostIdentifier string `json:"host_identifier"`
}

type jsonDastInput struct {
	TargetID        string `json:"target_id"`
	RuleIDVersioned string `json:"rule_id_versioned"`
	HTTPMethod      string `json:"http_method"`
	RouteTemplate   string `json:"route_template"`
	InjectionPoint  string `json:"injection_point"`
	ParamName       string `json:"param_name"`
	EvidenceSignal  string `json:"evidence_signal"`
}

// strictUnmarshal rejects unknown keys, so a misspelled fixture key fails the
// test instead of silently defaulting a hashed field to the empty string and
// locking in a wrong digest.
func strictUnmarshal(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// fieldsFor decodes a fixture input for the named tier and returns the exact
// ordered field list that tier hashes.
func fieldsFor(tier string, raw json.RawMessage) ([]string, error) {
	switch tier {
	case "sast":
		var in jsonSastInput
		if err := strictUnmarshal(raw, &in); err != nil {
			return nil, err
		}
		return SastFields(SastInput{
			TargetID:            in.TargetID,
			RuleIDVersioned:     in.RuleIDVersioned,
			RepoRelPath:         in.RepoRelPath,
			EnclosingSymbolPath: in.EnclosingSymbolPath,
			Snippet:             in.Snippet,
			Ordinal:             in.Ordinal,
		})
	case "sca":
		var in jsonScaInput
		if err := strictUnmarshal(raw, &in); err != nil {
			return nil, err
		}
		return ScaFields(ScaInput{
			TargetID:        in.TargetID,
			AdvisoryID:      in.AdvisoryID,
			Purl:            in.Purl,
			ManifestRelPath: in.ManifestRelPath,
		})
	case "host":
		var in jsonHostInput
		if err := strictUnmarshal(raw, &in); err != nil {
			return nil, err
		}
		return HostFields(HostInput{
			TargetID:       in.TargetID,
			AdvisoryID:     in.AdvisoryID,
			Purl:           in.Purl,
			PackageManager: in.PackageManager,
			HostIdentifier: in.HostIdentifier,
		})
	case "dast":
		var in jsonDastInput
		if err := strictUnmarshal(raw, &in); err != nil {
			return nil, err
		}
		return DastFields(DastInput{
			TargetID:        in.TargetID,
			RuleIDVersioned: in.RuleIDVersioned,
			HTTPMethod:      in.HTTPMethod,
			RouteTemplate:   in.RouteTemplate,
			InjectionPoint:  InjectionPoint(in.InjectionPoint),
			ParamName:       in.ParamName,
			EvidenceSignal:  EvidenceSignal(in.EvidenceSignal),
		})
	default:
		return nil, &FingerprintError{Field: "tier", Msg: "unknown tier " + tier}
	}
}

// digestFor is the tier-dispatching equivalent of the exported Sast/Sca/
// Host/Dast entry points, used so a fixture can be driven by its declared
// tier. The public entry points are exercised directly in
// TestExportedTierEntryPointsAgreeWithFieldBuilders.
func digestFor(tier string, raw json.RawMessage) (string, error) {
	fields, err := fieldsFor(tier, raw)
	if err != nil {
		return "", err
	}
	return Digest(fields...)
}

func loadCorpus(t *testing.T) []corpusFixture {
	t.Helper()

	paths, err := filepath.Glob(filepath.Join(corpusDir, "*.json"))
	if err != nil {
		t.Fatalf("globbing corpus: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("no fixtures found in %s; the fixed corpus is mandatory (plan/00-SPINE.md S6)", corpusDir)
	}
	sort.Strings(paths)

	out := make([]corpusFixture, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("reading %s: %v", p, err)
		}
		var f corpusFixture
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			t.Fatalf("decoding %s: %v", p, err)
		}
		f.path = p
		if f.ID == "" || f.Tier == "" {
			t.Fatalf("%s: fixture must declare id and tier", p)
		}
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------------
// The corpus lock
// ---------------------------------------------------------------------------

func TestCorpusCoverage(t *testing.T) {
	// plan/40-record-and-storage.md R.2: "at minimum 2 SAST, 2 DAST, 1 SCA,
	// 1 host". A tier with no fixture is a tier nothing guards.
	want := map[string]int{"sast": 2, "dast": 2, "sca": 1, "host": 1}
	got := map[string]int{}
	for _, f := range loadCorpus(t) {
		got[f.Tier]++
	}
	for tier, min := range want {
		if got[tier] < min {
			t.Errorf("tier %q: corpus has %d fixtures, the specification requires at least %d",
				tier, got[tier], min)
		}
	}
}

func TestCorpusFixturesProduceTheirDocumentedDigest(t *testing.T) {
	for _, f := range loadCorpus(t) {
		t.Run(f.ID, func(t *testing.T) {
			if f.ExpectedDigest == "" {
				t.Fatalf("%s: expected_digest is empty; every fixture must carry a golden "+
					"derived independently of this implementation", f.path)
			}
			if err := ValidateDigest(f.ExpectedDigest); err != nil {
				t.Fatalf("%s: committed expected_digest is malformed: %v", f.path, err)
			}

			fields, err := fieldsFor(f.Tier, f.Input)
			if err != nil {
				t.Fatalf("%s: building fields: %v", f.path, err)
			}
			if !reflect.DeepEqual(fields, f.HashedFields) {
				t.Errorf("%s: hashed field list drifted.\n  got:  %q\n  want: %q",
					f.path, fields, f.HashedFields)
			}

			got, err := Digest(fields...)
			if err != nil {
				t.Fatalf("%s: hashing: %v", f.path, err)
			}
			if got != f.ExpectedDigest {
				t.Errorf("%s: digest changed.\n  got:  %s\n  want: %s\n"+
					"A changed digest means every stored finding for this tier loses its identity; "+
					"this is an anvil-fp/v2 event, not a fixture update.",
					f.path, got, f.ExpectedDigest)
			}
			if err := ValidateDigest(got); err != nil {
				t.Errorf("%s: computed digest is malformed: %v", f.path, err)
			}
		})
	}
}

// TestCorpusDigestsAreStableAcrossTwoConsecutiveRuns is R.2's stop condition
// verbatim. It catches map-iteration order or any other nondeterminism
// leaking into the digest — NormalizeMatch uses a map for metavariable
// assignment, and if that assignment ever became iteration-ordered this test
// would fail.
func TestCorpusDigestsAreStableAcrossTwoConsecutiveRuns(t *testing.T) {
	for _, f := range loadCorpus(t) {
		first, err := digestFor(f.Tier, f.Input)
		if err != nil {
			t.Fatalf("%s: run 1: %v", f.path, err)
		}
		for run := 2; run <= 8; run++ {
			next, err := digestFor(f.Tier, f.Input)
			if err != nil {
				t.Fatalf("%s: run %d: %v", f.path, run, err)
			}
			if next != first {
				t.Fatalf("%s: digest is not deterministic: run 1 = %s, run %d = %s",
					f.path, first, run, next)
			}
		}
	}
}

// crossProcessEnv puts this test binary into "child" mode: it prints one
// crossProcessMarker line per fixture and exits, so the parent can compare a
// digest computed in a DIFFERENT OS process against its own.
const (
	crossProcessEnv    = "ANVIL_FINGERPRINT_CROSS_PROCESS_CHILD"
	crossProcessMarker = "ANVIL-FP-DIGEST\t"
)

// TestCorpusDigestsAreStableAcrossProcesses is the stronger form of the stop
// condition. Repeating a computation inside ONE process cannot detect the
// failure that actually matters here, because the things that would break
// cross-process stability are all per-process constants: Go's map iteration
// seed (re-randomised per process, so an unsorted range over a map returns a
// stable-but-wrong order within a run and a different one in the next),
// pointer addresses, and any address-space or locale state. Two producers
// emitting different digests is exactly the failure 00-SPINE.md S6 says fails
// silently forever, and the two producers are two processes.
//
// The child is this same test binary re-executed with crossProcessEnv set,
// which needs no build step and no new dependency.
func TestCorpusDigestsAreStableAcrossProcesses(t *testing.T) {
	fixtures := loadCorpus(t)

	if os.Getenv(crossProcessEnv) == "1" {
		for _, f := range fixtures {
			d, err := digestFor(f.Tier, f.Input)
			if err != nil {
				fmt.Printf("%s%s\tERROR: %v\n", crossProcessMarker, f.ID, err)
				continue
			}
			fmt.Printf("%s%s\t%s\n", crossProcessMarker, f.ID, d)
		}
		return
	}

	want := make(map[string]string, len(fixtures))
	for _, f := range fixtures {
		d, err := digestFor(f.Tier, f.Input)
		if err != nil {
			t.Fatalf("%s: parent process: %v", f.path, err)
		}
		want[f.ID] = d
	}

	cmd := exec.Command(os.Args[0],
		"-test.run=^TestCorpusDigestsAreStableAcrossProcesses$",
		"-test.count=1")
	cmd.Env = append(os.Environ(), crossProcessEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("re-executing the test binary as a child process failed: %v\n%s", err, out)
	}

	got := make(map[string]string, len(fixtures))
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, strings.TrimSpace(crossProcessMarker)) {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			t.Fatalf("malformed child output line %q", line)
		}
		got[parts[1]] = parts[2]
	}

	if len(got) != len(want) {
		t.Fatalf("child reported %d digests, parent computed %d\nchild output:\n%s",
			len(got), len(want), out)
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("fixture %s: digest differs between processes.\n  parent: %s\n  child:  %s\n"+
				"anvil-fp/v1 must be a pure function of its hashed fields; two producers "+
				"emitting different digests breaks regression matching silently and forever.",
				id, w, got[id])
		}
	}
}

// TestCorpusMutationsDoNotChangeTheDigest is the mutation test R.2's
// validation requirement names. Every fixture's `mutations` array holds inputs
// that differ ONLY in fields the specification forbids hashing — line and
// column numbers, indentation, comments, the dependency version string, the
// HTTP method's case, a query string on a route template. Each must produce
// the fixture's digest unchanged.
func TestCorpusMutationsDoNotChangeTheDigest(t *testing.T) {
	total := 0
	for _, f := range loadCorpus(t) {
		for _, m := range f.Mutations {
			total++
			t.Run(f.ID+"/"+m.Name, func(t *testing.T) {
				got, err := digestFor(f.Tier, m.Input)
				if err != nil {
					t.Fatalf("%s mutation %q: %v", f.path, m.Name, err)
				}
				if got != f.ExpectedDigest {
					t.Errorf("%s mutation %q (%s) changed the digest.\n  got:  %s\n  want: %s",
						f.path, m.Name, m.Description, got, f.ExpectedDigest)
				}
			})
		}
	}
	if total == 0 {
		t.Fatal("no mutations in the corpus; the volatile-field exclusions are then untested")
	}
}

// TestCorpusFixturesHaveDistinctDigests guards the failure that motivates the
// ordinal field: two fixtures that ought to be different findings must not
// share an identity.
func TestCorpusFixturesHaveDistinctDigests(t *testing.T) {
	seen := map[string]string{}
	for _, f := range loadCorpus(t) {
		d, err := digestFor(f.Tier, f.Input)
		if err != nil {
			t.Fatalf("%s: %v", f.path, err)
		}
		if prev, ok := seen[d]; ok {
			t.Errorf("fixtures %q and %q collide on digest %s", prev, f.ID, d)
		}
		seen[d] = f.ID
	}
}

// THERE IS DELIBERATELY NO "UPDATE THE GOLDENS" TEST HERE, AND ONE MUST NOT BE
// ADDED.
//
// A golden that the implementation under test can regenerate proves nothing:
// the next time a digest changes, the cheapest way to make this package green
// is to re-seal the fixtures, and the change that was supposed to be caught
// ships silently. That is not a hypothetical — research/07 and research/18
// shipped two different algorithms under one `anvil-fp/v1` name and nothing
// surfaced it, which is why this corpus exists at all.
//
// The committed `hashed_fields` lists were derived BY HAND from the algorithm
// text in plan/40-record-and-storage.md, and each `expected_digest` was then
// computed from that list by an offline script that joins with U+001F and
// SHA-256s — no Go code involved. To change a fixture, redo that derivation.
// To change a digest, ship anvil-fp/v2 and follow the dual-write migration
// protocol; do not edit the golden.

// ---------------------------------------------------------------------------
// The exclusions, tested directly rather than only through fixtures
// ---------------------------------------------------------------------------

// TestSastDigestIgnoresPositionAndFormatting is the specific mutation
// assertion R.2 requires: "a line-number-only change to a SAST fixture leaves
// the digest unchanged". SastInput has no line field at all, so the strongest
// form of the test is to change everything a line-number change implies —
// leading blank lines, indentation, line breaks, and a comment naming the old
// line — and show the digest holds.
func TestSastDigestIgnoresPositionAndFormatting(t *testing.T) {
	base := SastInput{
		TargetID:            "t-0001",
		RuleIDVersioned:     "opengrep.go.sqli@2026.07.1",
		RepoRelPath:         "internal/api/store.go",
		EnclosingSymbolPath: "internal/api/store.go::Store.Find",
		Snippet:             "q := \"SELECT * FROM u WHERE n = '\" + name + \"'\"\nrows, err := db.Query(q)",
		Ordinal:             0,
	}
	want, err := Sast(base)
	if err != nil {
		t.Fatalf("base: %v", err)
	}

	cases := []struct {
		name    string
		snippet string
	}{
		{
			name:    "shifted down by 40 lines",
			snippet: strings.Repeat("\n", 40) + base.Snippet,
		},
		{
			name:    "reindented from tabs to eight spaces",
			snippet: "        q := \"SELECT * FROM u WHERE n = '\" + name + \"'\"\n        rows, err := db.Query(q)",
		},
		{
			name:    "CRLF line endings",
			snippet: strings.ReplaceAll(base.Snippet, "\n", "\r\n"),
		},
		{
			name:    "a comment naming the old line number added",
			snippet: "// was line 128, now line 173\n" + base.Snippet + " // moved",
		},
		{
			name:    "collapsed onto one line",
			snippet: strings.ReplaceAll(base.Snippet, "\n", " "),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := base
			m.Snippet = tc.snippet
			got, err := Sast(m)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if got != want {
				t.Errorf("digest changed under a position/formatting-only edit\n  got:  %s\n  want: %s\n  normalized: %q vs %q",
					got, want, NormalizeMatch(tc.snippet), NormalizeMatch(base.Snippet))
			}
		})
	}
}

// TestSastDigestChangesWhenTheCodeChanges is the counterpart: normalization
// must not be so aggressive that a genuinely different sink hashes the same.
func TestSastDigestChangesWhenTheCodeChanges(t *testing.T) {
	base := SastInput{
		TargetID:            "t-0001",
		RuleIDVersioned:     "opengrep.go.sqli@2026.07.1",
		RepoRelPath:         "internal/api/store.go",
		EnclosingSymbolPath: "internal/api/store.go::Store.Find",
		Snippet:             "rows, err := db.Query(q)",
	}
	baseDigest, err := Sast(base)
	if err != nil {
		t.Fatalf("%v", err)
	}

	variants := map[string]func(*SastInput){
		"different callee":         func(in *SastInput) { in.Snippet = "rows, err := db.Exec(q)" },
		"different receiver field": func(in *SastInput) { in.Snippet = "rows, err := db.conn.Query(q)" },
		"different rule version":   func(in *SastInput) { in.RuleIDVersioned = "opengrep.go.sqli@2026.08.1" },
		"different file":           func(in *SastInput) { in.RepoRelPath = "internal/api/other.go" },
		"different symbol":         func(in *SastInput) { in.EnclosingSymbolPath = "internal/api/store.go::Store.List" },
		"different target":         func(in *SastInput) { in.TargetID = "t-0002" },
		"different ordinal":        func(in *SastInput) { in.Ordinal = 1 },
	}
	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			m := base
			mutate(&m)
			got, err := Sast(m)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if got == baseDigest {
				t.Errorf("%s did not change the digest; two distinct findings would share one identity", name)
			}
		})
	}
}

// TestPackageDigestIgnoresTheVersionString is the rule the specification
// calls out most emphatically: "bumping 1.2.3 to 1.2.4 while still inside the
// vulnerable range must not mint a new finding".
func TestPackageDigestIgnoresTheVersionString(t *testing.T) {
	sca := ScaInput{
		TargetID:        "t-0001",
		AdvisoryID:      "CVE-2021-44228",
		Purl:            "pkg:maven/org.apache.logging.log4j/log4j-core",
		ManifestRelPath: "services/api/pom.xml",
	}
	want, err := Sca(sca)
	if err != nil {
		t.Fatalf("%v", err)
	}

	for _, purl := range []string{
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar#sub/path",
		"PKG:MAVEN/org.apache.logging.log4j/log4j-core@2.14.1",
	} {
		m := sca
		m.Purl = purl
		got, err := Sca(m)
		if err != nil {
			t.Fatalf("%s: %v", purl, err)
		}
		if got != want {
			t.Errorf("purl %q changed the SCA digest; the version string must never be hashed\n  got:  %s\n  want: %s",
				purl, got, want)
		}
	}

	host := HostInput{
		TargetID:       "t-0001",
		AdvisoryID:     "CVE-2022-0778",
		Purl:           "pkg:deb/debian/openssl",
		PackageManager: "apt",
		HostIdentifier: "openssl",
	}
	hostWant, err := Host(host)
	if err != nil {
		t.Fatalf("%v", err)
	}
	for _, purl := range []string{
		"pkg:deb/debian/openssl@1.1.1n-0+deb11u3",
		"pkg:deb/debian/openssl@1.1.1n-0+deb11u4",
		"pkg:deb/debian/openssl@1.1.1w-0+deb11u1?arch=amd64",
	} {
		m := host
		m.Purl = purl
		got, err := Host(m)
		if err != nil {
			t.Fatalf("%s: %v", purl, err)
		}
		if got != hostWant {
			t.Errorf("purl %q changed the host digest; the version string must never be hashed", purl)
		}
	}
}

// TestScaAndHostTiersDoNotCollide: the two tiers share one formula, so the
// detector-kind field is the only thing keeping a repo dependency and a host
// package with the same advisory apart. If it were dropped, a host finding
// (remediable_by_agent=false, plan/00-SPINE.md S7) could upsert over an
// agent-remediable dependency finding.
func TestScaAndHostTiersDoNotCollide(t *testing.T) {
	scaDigest, err := Sca(ScaInput{
		TargetID:        "t-1",
		AdvisoryID:      "CVE-2022-0778",
		Purl:            "pkg:deb/debian/openssl",
		ManifestRelPath: "apt:openssl",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	hostDigest, err := Host(HostInput{
		TargetID:       "t-1",
		AdvisoryID:     "CVE-2022-0778",
		Purl:           "pkg:deb/debian/openssl",
		PackageManager: "apt",
		HostIdentifier: "openssl",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if scaDigest == hostDigest {
		t.Fatal("sca and host tiers collided on identical locators; detector_kind is not being hashed")
	}
}

// TestDastDigestIgnoresVolatileTransportDetail. Host, port, scheme and the
// concrete payload are absent from DastInput by construction; what remains
// testable is that the canonicalisation drops the volatile parts a producer
// might still smuggle in through the route template, and that method case
// does not fork identity.
func TestDastDigestIgnoresVolatileTransportDetail(t *testing.T) {
	base := DastInput{
		TargetID:        "t-0001",
		RuleIDVersioned: "nuclei:sqli-error-based@a1b2c3d",
		HTTPMethod:      "POST",
		RouteTemplate:   "/api/v1/users/{id}/orders",
		InjectionPoint:  InjectionPointBody,
		ParamName:       "sortBy",
		EvidenceSignal:  EvidenceSignalDBErrorString,
	}
	want, err := Dast(base)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cases := map[string]func(*DastInput){
		"lowercase method":        func(in *DastInput) { in.HTTPMethod = "post" },
		"method with whitespace":  func(in *DastInput) { in.HTTPMethod = " POST " },
		"route with query string": func(in *DastInput) { in.RouteTemplate = "/api/v1/users/{id}/orders?debug=1&payload=%27" },
		"route with fragment":     func(in *DastInput) { in.RouteTemplate = "/api/v1/users/{id}/orders#frag" },
		"route with trailing slash": func(in *DastInput) {
			in.RouteTemplate = "/api/v1/users/{id}/orders/"
		},
		"route with duplicate slashes": func(in *DastInput) {
			in.RouteTemplate = "//api//v1/users/{id}/orders"
		},
		"route without leading slash": func(in *DastInput) { in.RouteTemplate = "api/v1/users/{id}/orders" },

		// The blocker-2 cases: the concrete route the scanner actually
		// requested, and the two other syntaxes a second producer would use
		// for the same route. All four are one finding.
		"route with a concrete numeric id":  func(in *DastInput) { in.RouteTemplate = "/api/v1/users/12345/orders" },
		"route with a different numeric id": func(in *DastInput) { in.RouteTemplate = "/api/v1/users/4192/orders" },
		"route with a concrete uuid": func(in *DastInput) {
			in.RouteTemplate = "/api/v1/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301/orders"
		},
		"route with a concrete sha1 object id": func(in *DastInput) {
			in.RouteTemplate = "/api/v1/users/da39a3ee5e6b4b0d3255bfef95601890afd80709/orders"
		},
		"route in express placeholder syntax": func(in *DastInput) { in.RouteTemplate = "/api/v1/users/:id/orders" },
		"route in flask placeholder syntax": func(in *DastInput) {
			in.RouteTemplate = "/api/v1/users/<int:id>/orders"
		},
		"route already carrying the canonical token": func(in *DastInput) {
			in.RouteTemplate = "/api/v1/users/" + NormalizedRouteSegmentToken + "/orders"
		},
		"route with a differently NAMED placeholder": func(in *DastInput) {
			in.RouteTemplate = "/api/v1/users/{userId}/orders"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := base
			mutate(&m)
			got, err := Dast(m)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if got != want {
				t.Errorf("%s changed the DAST digest\n  got:  %s\n  want: %s", name, got, want)
			}
		})
	}
}

// TestDastRouteTemplatingKeepsDistinctRoutesDistinct is the counterpart to the
// blocker-2 cases above. Route templating exists to merge one defect's
// instances; it must not merge two defects. Losing a finding on upsert against
// UNIQUE (target_id, fingerprint) is worse than churning one, and it is silent.
func TestDastRouteTemplatingKeepsDistinctRoutesDistinct(t *testing.T) {
	base := DastInput{
		TargetID:        "t-0001",
		RuleIDVersioned: "nuclei:idor@a1b2c3d",
		HTTPMethod:      "GET",
		RouteTemplate:   "/api/v1/users/12345/orders",
		InjectionPoint:  InjectionPointPath,
		EvidenceSignal:  EvidenceSignalStatusCodeFlip,
	}

	routes := []string{
		"/api/v1/users/12345/orders",
		"/api/v1/users/me/orders",      // "me" is a sentinel, not an id
		"/api/v1/users/12345/invoices", // a different collection
		"/api/v2/users/12345/orders",   // a different API version
		"/api/v1/users/12345",          // a shorter route
		"/api/v1/admins/12345/orders",  // a different resource
	}
	seen := map[string]string{}
	for _, r := range routes {
		m := base
		m.RouteTemplate = r
		d, err := Dast(m)
		if err != nil {
			t.Fatalf("%s: %v", r, err)
		}
		if prev, ok := seen[d]; ok {
			t.Errorf("routes %q and %q share digest %s; one of the two findings is lost on upsert",
				prev, r, d)
		}
		seen[d] = r
	}
}

// TestDastInjectionPointAndEvidenceSignalAreIndependent. The whole reason
// research/18's evidenceClass was merged into research/07's Tier D is that
// WHERE the payload went in and HOW the defect was observed are different
// facts. Each must move the digest on its own.
func TestDastInjectionPointAndEvidenceSignalAreIndependent(t *testing.T) {
	base := DastInput{
		TargetID:        "t-0001",
		RuleIDVersioned: "nuclei:sqli@a1b2c3d",
		HTTPMethod:      "GET",
		RouteTemplate:   "/search",
		InjectionPoint:  InjectionPointQuery,
		ParamName:       "q",
		EvidenceSignal:  EvidenceSignalDBErrorString,
	}
	baseDigest, err := Dast(base)
	if err != nil {
		t.Fatalf("%v", err)
	}

	byPoint := base
	byPoint.InjectionPoint = InjectionPointHeader
	d1, err := Dast(byPoint)
	if err != nil {
		t.Fatalf("%v", err)
	}
	bySignal := base
	bySignal.EvidenceSignal = EvidenceSignalTimingSideChannel
	d2, err := Dast(bySignal)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if d1 == baseDigest {
		t.Error("changing injection_point alone did not change the digest")
	}
	if d2 == baseDigest {
		t.Error("changing evidence_class_detail alone did not change the digest")
	}
	if d1 == d2 {
		t.Error("injection_point and evidence_class_detail are not independent fields")
	}
}

// TestInputStructsHaveTheirFrozenShape pins the exact field set of each tier
// input struct. Adding a field is how a volatile input (a line number, a
// version, a host) gets reintroduced, and it would silently change every
// digest that field participates in. If this test fails, the change is an
// anvil-fp/v2 event and an amendment to plan/40-record-and-storage.md, not a
// local edit.
func TestInputStructsHaveTheirFrozenShape(t *testing.T) {
	cases := []struct {
		name      string
		typ       reflect.Type
		fields    []string
		forbidden []string
	}{
		{
			name: "SastInput",
			typ:  reflect.TypeOf(SastInput{}),
			fields: []string{"TargetID", "RuleIDVersioned", "RepoRelPath",
				"EnclosingSymbolPath", "Snippet", "Ordinal"},
			// "version" is absent from this list on purpose: the RULE
			// version is deliberately hashed. Line, column, advisory and
			// evidence class are not.
			forbidden: []string{"line", "column", "advisory", "evidence", "timestamp", "region"},
		},
		{
			name:      "ScaInput",
			typ:       reflect.TypeOf(ScaInput{}),
			fields:    []string{"TargetID", "AdvisoryID", "Purl", "ManifestRelPath"},
			forbidden: []string{"version", "line", "timestamp"},
		},
		{
			name:      "HostInput",
			typ:       reflect.TypeOf(HostInput{}),
			fields:    []string{"TargetID", "AdvisoryID", "Purl", "PackageManager", "HostIdentifier"},
			forbidden: []string{"version", "line", "timestamp"},
		},
		{
			name: "DastInput",
			typ:  reflect.TypeOf(DastInput{}),
			fields: []string{"TargetID", "RuleIDVersioned", "HTTPMethod", "RouteTemplate",
				"InjectionPoint", "ParamName", "EvidenceSignal"},
			forbidden: []string{"host", "port", "scheme", "payload", "token", "cookieval", "timestamp", "line"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for i := 0; i < tc.typ.NumField(); i++ {
				got = append(got, tc.typ.Field(i).Name)
			}
			if !reflect.DeepEqual(got, tc.fields) {
				t.Fatalf("field set changed.\n  got:  %v\n  want: %v\n"+
					"Adding or removing a hashed input is an anvil-fp/v2 event.", got, tc.fields)
			}
			for _, f := range got {
				lower := strings.ToLower(f)
				for _, bad := range tc.forbidden {
					if strings.Contains(lower, bad) {
						t.Errorf("field %s contains forbidden substring %q; "+
							"the specification forbids hashing it", f, bad)
					}
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Primitive, canonicalisation and normalization behaviour
// ---------------------------------------------------------------------------

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestDigestShapeAndSeparator(t *testing.T) {
	d, err := Digest("a", "b", "c")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !hexDigest.MatchString(d) {
		t.Errorf("digest %q is not 64 lowercase hex characters", d)
	}
	if len(d) != FingerprintDigestHexLen {
		t.Errorf("digest length %d, want %d (never truncated)", len(d), FingerprintDigestHexLen)
	}

	// The separator, not concatenation: ("ab","c") and ("a","bc") must differ.
	d1, _ := Digest("ab", "c")
	d2, _ := Digest("a", "bc")
	if d1 == d2 {
		t.Error("fields are being concatenated without a separator")
	}

	if _, err := Digest("ok", "bad\x1ffield"); err == nil {
		t.Error("a field containing U+001F must be rejected: it moves a field boundary")
	}
	if _, err := Digest("ok", "bad\nfield"); err == nil {
		t.Error("a field containing a control character must be rejected")
	}
	if _, err := Digest(); err == nil {
		t.Error("an empty field list must be rejected")
	}
}

func TestValidateDigest(t *testing.T) {
	good, err := Digest("x")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := ValidateDigest(good); err != nil {
		t.Errorf("a freshly computed digest failed validation: %v", err)
	}
	bad := map[string]string{
		"truncated to 32":   good[:32],
		"uppercase hex":     strings.ToUpper(good),
		"empty":             "",
		"non-hex at end":    good[:63] + "g",
		"one char too long": good + "0",
	}
	for name, v := range bad {
		if err := ValidateDigest(v); err == nil {
			t.Errorf("%s: expected rejection, got none", name)
		}
	}
}

func TestCanonicalRepoRelPath(t *testing.T) {
	cases := map[string]string{
		"internal/api/store.go":    "internal/api/store.go",
		`internal\api\store.go`:    "internal/api/store.go",
		"./internal/api/store.go":  "internal/api/store.go",
		"/internal/api/store.go":   "internal/api/store.go",
		"internal//api///store.go": "internal/api/store.go",
		".//internal/api/store.go": "internal/api/store.go",
		"internal/api/":            "internal/api",
		`.\services\api\pom.xml`:   "services/api/pom.xml",
		"Internal/API/Store.go":    "Internal/API/Store.go", // case preserved
	}
	for in, want := range cases {
		if got := CanonicalRepoRelPath(in); got != want {
			t.Errorf("CanonicalRepoRelPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalRouteTemplate(t *testing.T) {
	const tok = NormalizedRouteSegmentToken

	cases := map[string]string{
		// Structural canonicalisation.
		"/api/v1/users/{id}":      "/api/v1/users/" + tok,
		"api/v1/users/{id}":       "/api/v1/users/" + tok,
		"/api/v1/users/{id}/":     "/api/v1/users/" + tok,
		"//api//v1/users/{id}":    "/api/v1/users/" + tok,
		"/api/v1/users/{id}?a=1":  "/api/v1/users/" + tok,
		"/api/v1/users/{id}#frag": "/api/v1/users/" + tok,
		"/":                       "/",
		"/Search":                 "/Search", // case preserved

		// Templating: the four volatile-segment classes.
		"/api/v1/users/12345/orders":              "/api/v1/users/" + tok + "/orders",
		"/orders/0":                               "/orders/" + tok,
		"/u/3f2504e0-4f89-11d3-9a0c-0305e82c3301": "/u/" + tok,
		"/u/3F2504E0-4F89-11D3-9A0C-0305E82C3301": "/u/" + tok,
		"/blob/e3b0c44298fc1c14":                  "/blob/" + tok, // 16 hex, the threshold exactly
		"/blob/3f2504e04f8911d39a0c0305e82c3301":  "/blob/" + tok, // dash-free UUID
		"/s/dXNlcjEyMzQ1Njc4OTAxMg":               "/s/" + tok,    // 22-char alnum with digits

		// Templating: the three producer placeholder syntaxes, all onto one token.
		"/api/users/{userId}/orders":      "/api/users/" + tok + "/orders",
		"/api/users/:userId/orders":       "/api/users/" + tok + "/orders",
		"/api/users/<int:user_id>/orders": "/api/users/" + tok + "/orders",

		// Idempotence: the canonical token is itself an already-templated segment.
		"/api/users/" + tok + "/orders": "/api/users/" + tok + "/orders",

		// Every segment is examined, not only the last.
		"/12345/orders/6789": "/" + tok + "/orders/" + tok,
	}
	for in, want := range cases {
		if got := CanonicalRouteTemplate(in); got != want {
			t.Errorf("CanonicalRouteTemplate(%q) = %q, want %q", in, got, want)
		}
	}

	// Idempotence as a property, not only on the one case above: a record read
	// out of the store and re-fingerprinted must not fork its own identity.
	for in := range cases {
		once := CanonicalRouteTemplate(in)
		if twice := CanonicalRouteTemplate(once); twice != once {
			t.Errorf("CanonicalRouteTemplate is not idempotent on %q: %q then %q", in, once, twice)
		}
	}
}

// TestCanonicalRouteTemplateDoesNotOverTemplate is the other half of the
// blocker-2 ruling and the more important half. Over-templating merges two
// genuinely distinct routes onto one digest, and one of the two findings is
// then LOST on upsert against UNIQUE (target_id, fingerprint) — silently.
// Under-templating only leaves a volatile route un-merged, which the DAST
// producer can still repair by emitting "{id}" itself.
//
// Every segment below must survive canonicalisation untouched.
func TestCanonicalRouteTemplateDoesNotOverTemplate(t *testing.T) {
	preserved := []string{
		"v1",                    // a version segment: has a digit, but is 2 chars
		"v2",                    //
		"me",                    // the sentinel that is NOT an id
		"users",                 //
		"oauth2",                // digit-bearing but short
		"utf8",                  //
		"api",                   //
		"latest",                //
		"internationalization",  // 20 letters, no digit — the long-word case
		"recommendations",       //
		"release-notes-2026-08", // 21 chars with a digit, but hyphenated: a slug
		"user_profile_settings", // 21 chars, underscored: a slug
		"deadbeef",              // 8 hex — below the 16-char hex threshold
		"a1b2c3d",               // a short git object id, 7 chars
		"cafebabecafebab",       // 15 hex — one short of the threshold
		"report.pdf",            // a filename
		"2026-08-08",            // an ISO date: hyphenated, so not opaque
		"Search",                //
	}
	for _, seg := range preserved {
		in := "/api/" + seg + "/x"
		want := "/api/" + seg + "/x"
		if got := CanonicalRouteTemplate(in); got != want {
			t.Errorf("segment %q was templated but must be preserved: CanonicalRouteTemplate(%q) = %q",
				seg, in, got)
		}
	}

	// And the routes that must stay distinct from each other end to end.
	distinct := []string{
		"/api/v1/users/12345/orders",
		"/api/v1/users/me/orders",
		"/api/v1/users/12345/invoices",
		"/api/v2/users/12345/orders",
		"/api/v1/users/12345/orders/12345",
	}
	seen := map[string]string{}
	for _, r := range distinct {
		c := CanonicalRouteTemplate(r)
		if prev, ok := seen[c]; ok {
			t.Errorf("routes %q and %q both canonicalise to %q; two distinct routes would share one identity",
				prev, r, c)
		}
		seen[c] = r
	}
}

func TestPurlBase(t *testing.T) {
	ok := map[string]string{
		"pkg:npm/lodash":                     "pkg:npm/lodash",
		"pkg:npm/lodash@4.17.20":             "pkg:npm/lodash",
		"pkg:NPM/lodash@4.17.20":             "pkg:npm/lodash",
		"pkg:npm/%40angular/core@13.0.0":     "pkg:npm/%40angular/core",
		"pkg:deb/debian/openssl@1.1.1n?a=b":  "pkg:deb/debian/openssl",
		"pkg:golang/golang.org/x/net@v0.0.1": "pkg:golang/golang.org/x/net",
		"PKG:maven/org.example/lib@1.0#s":    "pkg:maven/org.example/lib",
		" pkg:pypi/django@3.2.4 ":            "pkg:pypi/django",
	}
	for in, want := range ok {
		got, err := PurlBase(in)
		if err != nil {
			t.Errorf("PurlBase(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("PurlBase(%q) = %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{"", "   ", "npm/lodash", "pkg:", "pkg:npm", "pkg:@1.0"} {
		if got, err := PurlBase(bad); err == nil {
			t.Errorf("PurlBase(%q) = %q, want an error", bad, got)
		}
	}
}

func TestNormalizeMatch(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "comments stripped, whitespace collapsed, literals abstracted",
			in:   "// lookup\nq := \"SELECT \" + name + \"'\"   /* inline */  + 42\n",
			want: "$1 := <STR> + $2 + <STR> + <NUM>",
		},
		{
			name: "same identifier maps to the same metavariable",
			in:   "a = b + a + b",
			want: "$1 = $2 + $1 + $2",
		},
		{
			name: "callee and member names are preserved",
			in:   "rows := db.Query(userInput)",
			want: "$1 := $2.Query($3)",
		},
		{
			name: "keywords are preserved",
			in:   "for i := range items { return nil }",
			want: "for $1 := range $2 { return nil }",
		},
		{
			name: "hash line comments are stripped",
			in:   "value = compute(x)  # trailing note",
			want: "$1 = compute($2)",
		},
		{
			name: "numeric literal forms collapse to one token",
			in:   "a = 0xFF + 1_000 + 3.14f + 1e-9",
			want: "$1 = <NUM> + <NUM> + <NUM> + <NUM>",
		},
		{
			name: "escaped quotes do not terminate a string",
			in:   `s = "a \" b" + t`,
			want: "$1 = <STR> + $2",
		},
		{
			// The receiver `p` is a local and is abstracted; `Field` is a
			// member and `Ns`/`Helper` are the qualifier and callee of a
			// scope-resolved call, which are API surface, not churn.
			name: "arrow and scope selectors preserve member names",
			in:   "p->Field = Ns::Helper(v)",
			want: "$1->Field = Ns::Helper($2)",
		},
		{
			name: "a scope-resolution chain is preserved end to end",
			in:   "std::vector<int> v = Foo::Bar::make(x)",
			want: "std::vector<int> $1 = Foo::Bar::make($2)",
		},
		{
			// These two cases exist as a pair: calls into two different
			// namespaces must NOT normalise to the same string, which is what
			// abstracting the left operand of "::" would do.
			name: "namespace qualifier Ns is preserved",
			in:   "Ns::Helper(v)",
			want: "Ns::Helper($1)",
		},
		{
			name: "namespace qualifier Other is preserved and differs from Ns",
			in:   "Other::Helper(v)",
			want: "Other::Helper($1)",
		},
		{
			name: "renaming a local does not change the shape",
			in:   "totalCount := len(itemsList)",
			want: "$1 := len($2)",
		},
		{
			name: "renaming the same local differently yields the same shape",
			in:   "n := len(xs)",
			want: "$1 := len($2)",
		},
		{
			name: "block comment spanning lines is dropped",
			in:   "a\n/* one\n   two */\nb",
			want: "$1 $2",
		},
		{
			name: "only comments and whitespace normalises to empty",
			in:   "  // nothing here \n\n",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeMatch(tc.in); got != tc.want {
				t.Errorf("NormalizeMatch(%q)\n  got:  %q\n  want: %q", tc.in, got, tc.want)
			}
		})
	}

	// The normalized form must never contain the separator or a control
	// character, or Digest would reject it.
	for _, tc := range cases {
		if strings.ContainsAny(NormalizeMatch(tc.in), "\x00\x1f\n\r\t") {
			t.Errorf("normalized output of %q contains a control character", tc.name)
		}
	}
}

func TestNormalizeMatchIsDeterministic(t *testing.T) {
	src := "handler := func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.URL.Query().Get(\"q\")) }"
	first := NormalizeMatch(src)
	for i := 0; i < 200; i++ {
		if got := NormalizeMatch(src); got != first {
			t.Fatalf("NormalizeMatch is not deterministic: %q vs %q", got, first)
		}
	}
	if first == "" {
		t.Fatal("normalization produced an empty result for a real snippet")
	}
}

// ---------------------------------------------------------------------------
// Ordinal assignment
// ---------------------------------------------------------------------------

func TestAssignSastOrdinals(t *testing.T) {
	mk := func(path, snippet string, line int) SastCandidate {
		return SastCandidate{
			Input: SastInput{
				TargetID:            "t-1",
				RuleIDVersioned:     "r@1",
				RepoRelPath:         path,
				EnclosingSymbolPath: "sym",
				Snippet:             snippet,
			},
			Line: line,
		}
	}

	// Five matches, given out of source order, spanning two files.
	//
	// THE GROUPING KEY IS THE NORMALIZED MATCH, NOT THE RAW SNIPPET. The
	// specification defines ordinal as "the 0-based index of this match among
	// all matches of the same rule_id in the same repo_relpath whose
	// NORMALIZED_MATCH is IDENTICAL", and "exec(cmd)" and "exec(other)" both
	// normalise to `exec($1)` — `exec` is a callee name so it is preserved,
	// and the argument is a local so it becomes $1. All four a.go candidates
	// are therefore ONE group; only b.go is separate.
	cands := []SastCandidate{
		mk("a.go", "exec(cmd)", 90),
		mk("a.go", "exec(cmd)", 10),
		mk("b.go", "exec(cmd)", 5),
		mk("a.go", "exec(other)", 50),
		mk("a.go", "exec(cmd)", 50),
	}

	got, err := AssignSastOrdinals(cands)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(got) != len(cands) {
		t.Fatalf("got %d inputs, want %d", len(got), len(cands))
	}

	// Within the a.go group, ordinals follow ascending (line, column, original
	// index): line 10 -> 0, line 50 (index 3) -> 1, line 50 (index 4) -> 2,
	// line 90 -> 3. The single b.go candidate is a group of one -> 0. The
	// returned slice keeps the caller's original order, so the expectation is
	// stated in that order.
	want := []int{3, 0, 0, 1, 2}
	for i := range want {
		if got[i].Ordinal != want[i] {
			t.Errorf("candidate %d (line %d): ordinal %d, want %d",
				i, cands[i].Line, got[i].Ordinal, want[i])
		}
	}

	// The collapse of "exec(cmd)" and "exec(other)" onto one normalized match
	// is precisely the collision ordinal exists to break: without it the four
	// a.go candidates would share one digest and three findings would be lost
	// on upsert against UNIQUE (target_id, fingerprint). Assert the resulting
	// digests are all distinct.
	seen := map[string]int{}
	for i, in := range got {
		d, err := Sast(in)
		if err != nil {
			t.Fatalf("candidate %d: %v", i, err)
		}
		if prev, ok := seen[d]; ok {
			t.Errorf("candidates %d and %d collide on digest %s", prev, i, d)
		}
		seen[d] = i
	}

	// A run over the same candidates must produce the same ordinals.
	again, err := AssignSastOrdinals(cands)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !reflect.DeepEqual(got, again) {
		t.Error("AssignSastOrdinals is not deterministic")
	}

	if _, err := AssignSastOrdinals([]SastCandidate{{Input: SastInput{}}}); err == nil {
		t.Error("an unfingerprintable candidate must be rejected, not given ordinal 0")
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func TestTierValidationRejectsIncompleteInput(t *testing.T) {
	if _, err := Sast(SastInput{RuleIDVersioned: "r", RepoRelPath: "a.go", Snippet: "x"}); err == nil {
		t.Error("sast: empty target_id must be rejected")
	}
	if _, err := Sast(SastInput{TargetID: "t", RepoRelPath: "a.go", Snippet: "x"}); err == nil {
		t.Error("sast: empty rule_id_versioned must be rejected")
	}
	if _, err := Sast(SastInput{TargetID: "t", RuleIDVersioned: "r", Snippet: "x"}); err == nil {
		t.Error("sast: empty repo_relpath must be rejected")
	}
	if _, err := Sast(SastInput{TargetID: "t", RuleIDVersioned: "r", RepoRelPath: "a.go", Snippet: "// only a comment"}); err == nil {
		t.Error("sast: a snippet that normalises to nothing must be rejected")
	}
	if _, err := Sast(SastInput{TargetID: "t", RuleIDVersioned: "r", RepoRelPath: "a.go", Snippet: "x", Ordinal: -1}); err == nil {
		t.Error("sast: a negative ordinal must be rejected")
	}
	// An empty enclosing symbol is legal: top-level code and config files
	// have none, and rejecting them would make them unfingerprintable.
	if _, err := Sast(SastInput{TargetID: "t", RuleIDVersioned: "r", RepoRelPath: "a.go", Snippet: "exec(x)"}); err != nil {
		t.Errorf("sast: an empty enclosing_symbol_path must be accepted, got %v", err)
	}

	if _, err := Sca(ScaInput{TargetID: "t", Purl: "pkg:npm/a", ManifestRelPath: "p.json"}); err == nil {
		t.Error("sca: empty advisory_id must be rejected")
	}
	if _, err := Sca(ScaInput{TargetID: "t", AdvisoryID: "CVE-1", ManifestRelPath: "p.json"}); err == nil {
		t.Error("sca: empty purl must be rejected")
	}
	if _, err := Sca(ScaInput{TargetID: "t", AdvisoryID: "CVE-1", Purl: "pkg:npm/a"}); err == nil {
		t.Error("sca: empty manifest_relpath must be rejected")
	}

	if _, err := Host(HostInput{TargetID: "t", AdvisoryID: "CVE-1", Purl: "pkg:deb/d/o", HostIdentifier: "o"}); err == nil {
		t.Error("host: empty package_manager must be rejected")
	}
	if _, err := Host(HostInput{TargetID: "t", AdvisoryID: "CVE-1", Purl: "pkg:deb/d/o", PackageManager: "a:b", HostIdentifier: "o"}); err == nil {
		t.Error("host: a package_manager containing ':' must be rejected")
	}

	badDast := DastInput{
		TargetID: "t", RuleIDVersioned: "r", HTTPMethod: "GET", RouteTemplate: "/x",
		InjectionPoint: InjectionPoint("QUERY"), EvidenceSignal: EvidenceSignalOther,
	}
	if _, err := Dast(badDast); err == nil {
		t.Error("dast: a SCREAMING_CASE injection point must be rejected; the record's convention is lowercase")
	}
	badDast.InjectionPoint = InjectionPointQuery
	badDast.EvidenceSignal = EvidenceSignal("db_error_string")
	if _, err := Dast(badDast); err == nil {
		t.Error("dast: an unfrozen evidence signal literal must be rejected")
	}
	badDast.EvidenceSignal = EvidenceSignalDBErrorString
	badDast.HTTPMethod = ""
	if _, err := Dast(badDast); err == nil {
		t.Error("dast: empty http_method must be rejected")
	}
	// An empty param name is legal: a whole-body or raw-request injection has
	// no single named parameter.
	badDast.HTTPMethod = "POST"
	badDast.ParamName = ""
	if _, err := Dast(badDast); err != nil {
		t.Errorf("dast: an empty param_name must be accepted, got %v", err)
	}
}

// TestExportedTierEntryPointsAgreeWithFieldBuilders keeps the two exported
// surfaces from drifting: Sast must be exactly Digest(SastFields(...)), and so
// on for each tier.
func TestExportedTierEntryPointsAgreeWithFieldBuilders(t *testing.T) {
	sastIn := SastInput{TargetID: "t", RuleIDVersioned: "r@1", RepoRelPath: "a.go", Snippet: "exec(x)"}
	scaIn := ScaInput{TargetID: "t", AdvisoryID: "CVE-1", Purl: "pkg:npm/a@1.0", ManifestRelPath: "p.json"}
	hostIn := HostInput{TargetID: "t", AdvisoryID: "CVE-1", Purl: "pkg:deb/d/o@1", PackageManager: "apt", HostIdentifier: "o"}
	dastIn := DastInput{TargetID: "t", RuleIDVersioned: "r@1", HTTPMethod: "GET", RouteTemplate: "/x",
		InjectionPoint: InjectionPointQuery, ParamName: "q", EvidenceSignal: EvidenceSignalReflectedPayload}

	pairs := []struct {
		name   string
		fields func() ([]string, error)
		digest func() (string, error)
		want   int
	}{
		{"sast", func() ([]string, error) { return SastFields(sastIn) }, func() (string, error) { return Sast(sastIn) }, 7},
		{"sca", func() ([]string, error) { return ScaFields(scaIn) }, func() (string, error) { return Sca(scaIn) }, 5},
		{"host", func() ([]string, error) { return HostFields(hostIn) }, func() (string, error) { return Host(hostIn) }, 5},
		{"dast", func() ([]string, error) { return DastFields(dastIn) }, func() (string, error) { return Dast(dastIn) }, 8},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			fields, err := p.fields()
			if err != nil {
				t.Fatalf("%v", err)
			}
			if len(fields) != p.want {
				t.Errorf("tier %s hashes %d fields, the specification lists %d", p.name, len(fields), p.want)
			}
			viaFields, err := Digest(fields...)
			if err != nil {
				t.Fatalf("%v", err)
			}
			direct, err := p.digest()
			if err != nil {
				t.Fatalf("%v", err)
			}
			if viaFields != direct {
				t.Errorf("tier %s: Digest(Fields(in)) = %s but the entry point returned %s",
					p.name, viaFields, direct)
			}
		})
	}
}

// TestTiersUseTheirSpecifiedDiscriminator asserts the literal tier token in
// field position 2, because a swapped discriminator is invisible in a digest
// but makes every producer incompatible.
func TestTiersUseTheirSpecifiedDiscriminator(t *testing.T) {
	sastFields, err := SastFields(SastInput{TargetID: "t", RuleIDVersioned: "r", RepoRelPath: "a.go", Snippet: "exec(x)"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if sastFields[1] != "sast" {
		t.Errorf("sast tier discriminator = %q, want \"sast\"", sastFields[1])
	}
	dastFields, err := DastFields(DastInput{TargetID: "t", RuleIDVersioned: "r", HTTPMethod: "GET",
		RouteTemplate: "/x", InjectionPoint: InjectionPointQuery, EvidenceSignal: EvidenceSignalOther})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if dastFields[1] != "dast" {
		t.Errorf("dast tier discriminator = %q, want \"dast\"", dastFields[1])
	}
	scaFields, err := ScaFields(ScaInput{TargetID: "t", AdvisoryID: "C", Purl: "pkg:npm/a", ManifestRelPath: "p"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if scaFields[1] != string(DetectorKindSCA) {
		t.Errorf("sca tier discriminator = %q, want %q", scaFields[1], DetectorKindSCA)
	}
	hostFields, err := HostFields(HostInput{TargetID: "t", AdvisoryID: "C", Purl: "pkg:deb/d/o",
		PackageManager: "apt", HostIdentifier: "o"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if hostFields[1] != string(DetectorKindHost) {
		t.Errorf("host tier discriminator = %q, want %q", hostFields[1], DetectorKindHost)
	}
	if hostFields[4] != "apt:openssl" && hostFields[4] != "apt:o" {
		t.Errorf("host locator = %q, want \"<package_manager>:<host_identifier>\"", hostFields[4])
	}
}

// TestSeparatorConstantIsUnitSeparator is a belt-and-braces check on the one
// byte the whole scheme depends on. contract.go owns the constant; if it ever
// changed, every stored fingerprint would be orphaned silently.
func TestSeparatorConstantIsUnitSeparator(t *testing.T) {
	if FingerprintFieldSeparator != "\x1f" {
		t.Fatalf("FingerprintFieldSeparator = %q, want U+001F", FingerprintFieldSeparator)
	}
	if FingerprintDigestHexLen != 64 {
		t.Fatalf("FingerprintDigestHexLen = %d, want 64 (never truncated)", FingerprintDigestHexLen)
	}
	if FingerprintAlgV1 != "anvil-fp/v1" {
		t.Fatalf("FingerprintAlgV1 = %q, want \"anvil-fp/v1\"", FingerprintAlgV1)
	}
}
