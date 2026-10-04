package remediation

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

func fp(i int) string { return fmt.Sprintf("%064x", i) }

// TestTheCVELessCaseIsFullyOrdered is the remediation exit gate's row "the
// CVE-less case is fully ordered": findings with no CVE, no EPSS, no KEV and
// no CVSS, and identical primary terms, still come out in one strict order,
// the same for every input order.
func TestTheCVELessCaseIsFullyOrdered(t *testing.T) {
	var items []Item
	for i := 0; i < 40; i++ {
		items = append(items, Item{Fingerprint: fp(1000 - i), Path: "a.go", Evidence: record.EvidenceClassSastStaticOnly, CWE: "CWE-78"})
	}
	want := Rank(items, Priors{})
	for i := 1; i < len(want); i++ {
		if want[i-1].Fingerprint >= want[i].Fingerprint {
			t.Fatalf("not a strict order at %d", i)
		}
	}
	r := rand.New(rand.NewSource(20261004))
	for trial := 0; trial < 50; trial++ {
		shuffled := append([]Item(nil), items...)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got := Rank(shuffled, Priors{})
		for i := range got {
			if got[i].Fingerprint != want[i].Fingerprint {
				t.Fatalf("trial %d: order depends on input order at %d", trial, i)
			}
		}
	}
}

func f64(f float64) *float64 { return &f }

// TestBonusTermsOnlyBreakTies: KEV, EPSS and CVSS never lift a finding over a
// better primary key; they order findings whose primary keys are equal.
func TestBonusTermsOnlyBreakTies(t *testing.T) {
	kev := &record.Risk{KevMember: true, EpssScore: f64(0.97), CvssV4Base: f64(10)}
	items := []Item{
		{Fingerprint: fp(1), Evidence: record.EvidenceClassSastStaticOnly, Risk: kev},
		{Fingerprint: fp(2), Evidence: record.EvidenceClassSastReachable},
		{Fingerprint: fp(3), Evidence: record.EvidenceClassDastConfirmed},
		{Fingerprint: fp(4), Evidence: record.EvidenceClassSastStaticOnly, Risk: &record.Risk{EpssScore: f64(0.1)}},
		{Fingerprint: fp(5), Evidence: record.EvidenceClassSastStaticOnly},
	}
	got := Rank(items, Priors{})
	order := []string{fp(3), fp(2), fp(1), fp(4), fp(5)}
	for i, w := range order {
		if got[i].Fingerprint != w {
			t.Fatalf("position %d: got %s, want %s", i, got[i].Fingerprint[60:], w[60:])
		}
	}
	// A regressed finding outranks everything.
	items = append(items, Item{Fingerprint: fp(9), Evidence: record.EvidenceClassSastStaticOnly, Regressed: true})
	if got := Rank(items, Priors{}); got[0].Fingerprint != fp(9) {
		t.Fatal("a regressed finding is not at the top of the queue")
	}
	// The CWE prior is a primary term: it outranks proximity and every bonus.
	p := Priors{Default: 0.5, ByCWE: map[string]float64{"CWE-89": 0.9}}
	two := []Item{
		{Fingerprint: fp(1), Evidence: record.EvidenceClassSastStaticOnly, CWE: "CWE-78", Proximity: "changed_lines", Risk: kev},
		{Fingerprint: fp(2), Evidence: record.EvidenceClassSastStaticOnly, CWE: "CWE-89"},
	}
	if got := Rank(two, p); got[0].Fingerprint != fp(2) {
		t.Fatal("a bonus term outranked the CWE prior")
	}
}

func TestGroupsAreCoLocatedAndCapped(t *testing.T) {
	var items []Item
	for i := 0; i < 7; i++ {
		items = append(items, Item{Fingerprint: fp(i), Path: "x.py", Symbol: "f"})
	}
	items = append(items, Item{Fingerprint: fp(20), Path: "x.py", Symbol: "g"}, Item{Fingerprint: fp(21), Path: "y.py", Symbol: "f"}, Item{Fingerprint: fp(22)}, Item{Fingerprint: fp(23)})
	gs := Groups("audit", items, Priors{})
	sizes := map[int]int{}
	for _, g := range gs {
		sizes[len(g.Members)]++
		for _, m := range g.Members[1:] {
			if m.Path != g.Members[0].Path || m.Symbol != g.Members[0].Symbol || m.Path == "" {
				t.Fatalf("group %s mixes locations", g.ID)
			}
		}
	}
	if sizes[MaxGroup] != 1 || sizes[2] != 1 || sizes[1] != 4 || len(gs) != 6 {
		t.Fatalf("group sizes %v over %d groups", sizes, len(gs))
	}
	again := Groups("audit", items, Priors{})
	for i := range gs {
		if gs[i].ID != again[i].ID {
			t.Fatal("group ids are not deterministic")
		}
	}
}
