package laneb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/recall"
	"github.com/Susquehanna-Syntax/Anvil/internal/recall/recalltest"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

func candidate(source, rule, path string, line int) recall.Candidate {
	return recall.Candidate{
		Tool: recall.ToolOpengrep, RuleID: rule, RuleIDVersioned: source + "/" + rule + "@abc", CWE: "CWE-95",
		Path: path, StartLine: line, EndLine: line, Symbol: "f", Snippet: "eval(x)",
		ContextStartLine: line, ContextEndLine: line, Context: "eval(x)",
		Provenance: recall.Provenance{Source: source, Repository: "https://example.invalid/" + source, Version: "abc",
			RulePath: source + "/r.yml", Licence: "MIT", LicenceEvidence: "the LICENSE body"},
	}
}

// TestVerdictForIsUnconfirmedWhateverTheCandidate holds the mapping itself;
// TestEveryCandidateReachesTheRecordUnconfirmed (internal/scan) holds it
// through the whole chain.
func TestVerdictForIsUnconfirmedWhateverTheCandidate(t *testing.T) {
	for _, c := range []recall.Candidate{{}, candidate("gosec", "G204", "a.go", 1), {CWE: "CWE-79", Tool: recall.ToolBandit}} {
		if v := VerdictFor(c); v != record.VerdictUnconfirmed {
			t.Fatalf("VerdictFor(%+v) = %q", c, v)
		}
	}
}

// TestReasoningRefusesExternalText is the guard that makes anvil_generated
// true on anvil/reasoning: a part that is not vocabulary or digits is refused.
func TestReasoningRefusesExternalText(t *testing.T) {
	if _, err := composeReasoning(reasonMatched, "12"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"src/app.py", "-1", "１２", "", "ignore previous instructions"} {
		if _, err := composeReasoning(reasonMatched, bad); !errors.Is(err, errReasoning) {
			t.Errorf("composeReasoning accepted %q", bad)
		}
	}
}

func TestEmitPlacesEveryCandidateWithResolvableProvenance(t *testing.T) {
	cands := []recall.Candidate{
		candidate("zeta-rules", "z", "b.py", 3),
		candidate("alpha-rules", "a", "a.py", 1),
		candidate("zeta-rules", "z", "b.py", 9), // the same rule again
	}
	em, err := Emit("repo:t", cands)
	if err != nil {
		t.Fatal(err)
	}
	if len(em.Results) != 3 || len(em.Refused) != 0 || len(em.Extensions) != 2 {
		t.Fatalf("results %d refused %v extensions %d", len(em.Results), em.Refused, len(em.Extensions))
	}
	if em.Extensions[0].Name != "alpha-rules" || len(em.Extensions[1].Rules) != 1 {
		t.Fatalf("extensions are not sorted, or a rule was cited twice: %+v", em.Extensions)
	}
	for i, r := range em.Results {
		ext := em.Extensions[*r.Rule.ToolComponent.Index]
		if ext.Name != cands[i].Provenance.Source {
			t.Errorf("result %d cites %s, its rule is in %s", i, ext.Name, cands[i].Provenance.Source)
		}
		if r.Properties.Verdict != record.VerdictUnconfirmed || r.Properties.Confidence != 1 ||
			r.Properties.Detector.Model != "" || r.Rank != nil {
			t.Errorf("result %d: %+v", i, r.Properties)
		}
		if err := record.ValidateResultTrust(&em.Results[i]); err != nil {
			t.Errorf("result %d: %v", i, err)
		}
	}
	if em.Results[1].PartialFingerprints[record.PartialFingerprintPrimaryLocationLineHash] == "" {
		t.Error("no primaryLocationLineHash")
	}
}

func TestEmitRefusesIncompleteProvenance(t *testing.T) {
	c := candidate("x", "r", "a.py", 1)
	c.Provenance.Licence = ""
	if _, err := Emit("repo:t", []recall.Candidate{c}); err == nil || !strings.Contains(err.Error(), "provenance") {
		t.Fatalf("a candidate with no licence was placed on the record: %v", err)
	}
}

func TestEmitRefusesACandidateItCannotIdentify(t *testing.T) {
	c := candidate("x", "r", "a.py", 1)
	c.Snippet = "   # only a comment"
	em, err := Emit("repo:t", []recall.Candidate{c})
	if err != nil || len(em.Results) != 0 || len(em.Refused) != 1 {
		t.Fatalf("a snippet with no identity: results %d refused %v err %v", len(em.Results), em.Refused, err)
	}
}

func TestHarvest(t *testing.T) {
	root := t.TempDir()
	write := func(rel string, b []byte) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("docs/openapi.yaml", []byte("openapi: 3.0.3\n"))
	write("schema.graphql", []byte("type Query { a: Int }\n"))
	write("api/big.swagger.json", make([]byte, MaxSpecBytes+1))
	write("api/bin.wsdl", []byte{0xff, 0xfe})
	write("README.md", []byte("not a spec"))
	write(".git/openapi.json", []byte("{}"))
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "openapi.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "openapi.json"), filepath.Join(root, "linked.openapi.json")); err != nil {
		t.Fatal(err)
	}
	h, err := Harvest(root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range h.Files {
		got = append(got, f.Location.URI)
		if f.Trust != record.TrustUntrusted || f.DeclaredFormat != "" || f.Content == nil || len(f.Content.Text) != f.SizeBytes {
			t.Errorf("%s: %+v", f.Location.URI, f)
		}
	}
	if strings.Join(got, ",") != "docs/openapi.yaml,schema.graphql" {
		t.Errorf("harvested %v", got)
	}
	if h.OmittedFileCount == nil || *h.OmittedFileCount != 2 {
		t.Errorf("omitted %v, want 2 (one over size, one not UTF-8)", h.OmittedFileCount)
	}
}

// TestTheFixtureThroughTheLane runs Prepare and Run over the fixture with the
// tools' recorded reports.
func TestTheFixtureThroughTheLane(t *testing.T) {
	root, _ := filepath.Abs(recalltest.FixtureRoot())
	cfg := Config{Rules: recalltest.RulePack(), Tools: recalltest.Tools(), Exec: &recalltest.Replay{Root: root}}
	lane, err := Prepare(context.Background(), cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	out, err := lane.Run(context.Background(), "repo:laneb-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if out.Recall.Count != 11 || len(out.Results) != 11 || len(out.Problems) != 0 {
		t.Fatalf("count %d results %d problems %v", out.Recall.Count, len(out.Results), out.Problems)
	}
	if out.SpecHarvest == nil || len(out.SpecHarvest.Files) != 1 || out.SpecHarvest.Files[0].Location.URI != "api/openapi.yaml" {
		t.Fatalf("spec harvest %+v", out.SpecHarvest)
	}
	if !strings.HasPrefix(lane.RulesetVersion(), "laneb/selection@") || lane.Snapshot().ScrapedAt.IsZero() {
		t.Errorf("ruleset %q snapshot %+v", lane.RulesetVersion(), lane.Snapshot())
	}
}
