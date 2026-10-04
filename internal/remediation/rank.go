package remediation

// Ranking and fix groups (plan node ranking). The primary key has four terms,
// none of which needs a CVE: whether the dynamic tier confirmed the finding,
// whether it is reachable, a per-CWE prior that a fix will be accepted, and
// code proximity. KEV membership, EPSS and CVSS are nullable and only break
// ties. The fingerprint breaks the last tie, so the order is total and the same
// for any input order: a CVE-less finding is never left unordered. No model
// score takes part (the owner chose no ranker for v1).

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// MaxGroup is a fix group's size: one primary plus at most four co-located
// findings. The cap is an inference, not a measurement (plan node ranking).
const MaxGroup = 5

// Item is one finding as ranking sees it.
type Item struct {
	Fingerprint string
	Path        string // primary file, "" for a finding with no file
	Symbol      string // enclosing symbol, "" at file level
	CWE         string // "CWE-89", or ""
	Evidence    record.EvidenceClass
	Proximity   string // anvil/locus.proximityClass, or ""
	Regressed   bool   // a merged fix's reproducer triggered again
	Risk        *record.Risk
}

// Priors is the per-CWE prior that a proposed fix is accepted. It starts at
// Default for every CWE and learns from Anvil's own outcomes (AcceptancePriors).
type Priors struct {
	Default float64
	ByCWE   map[string]float64
}

// Prior is the prior for a CWE.
func (p Priors) Prior(cwe string) float64 {
	if v, ok := p.ByCWE[cwe]; ok {
		return v
	}
	if p.Default == 0 {
		return 0.5
	}
	return p.Default
}

// proximityOrder ranks the proximity classes Anvil knows; any other value,
// including none, ranks lowest.
var proximityOrder = map[string]int{"changed_lines": 3, "changed_function": 2, "changed_file": 1}

// key is an item's sort key, compared term by term.
type key struct {
	regressed, confirmed, reachable bool
	prior                           float64
	proximity                       int
	kev                             bool
	epss, cvss                      float64
	fingerprint                     string
}

func keyOf(it Item, p Priors) key {
	k := key{
		regressed:   it.Regressed,
		confirmed:   it.Evidence == record.EvidenceClassDastConfirmed,
		reachable:   it.Evidence == record.EvidenceClassSastReachable || it.Evidence == record.EvidenceClassDastConfirmed,
		prior:       p.Prior(it.CWE),
		proximity:   proximityOrder[it.Proximity],
		fingerprint: it.Fingerprint,
		epss:        -1,
		cvss:        -1,
	}
	if r := it.Risk; r != nil {
		k.kev = r.KevMember
		if r.EpssScore != nil {
			k.epss = *r.EpssScore
		}
		if r.CvssV4Base != nil {
			k.cvss = *r.CvssV4Base
		}
	}
	return k
}

// before reports whether a sorts ahead of b.
func before(a, b key) bool {
	bools := [][2]bool{{a.regressed, b.regressed}, {a.confirmed, b.confirmed}, {a.reachable, b.reachable}}
	for _, x := range bools {
		if x[0] != x[1] {
			return x[0]
		}
	}
	if a.prior != b.prior {
		return a.prior > b.prior
	}
	if a.proximity != b.proximity {
		return a.proximity > b.proximity
	}
	// Bonus terms: tie-breakers only.
	if a.kev != b.kev {
		return a.kev
	}
	if a.epss != b.epss {
		return a.epss > b.epss
	}
	if a.cvss != b.cvss {
		return a.cvss > b.cvss
	}
	return a.fingerprint < b.fingerprint
}

// Rank orders items, best first. The result does not depend on input order.
func Rank(items []Item, p Priors) []Item {
	out := append([]Item(nil), items...)
	keys := map[string]key{}
	for _, it := range out {
		keys[it.Fingerprint] = keyOf(it, p)
	}
	sort.SliceStable(out, func(i, j int) bool { return before(keys[out[i].Fingerprint], keys[out[j].Fingerprint]) })
	return out
}

// Group is one fix group: the primary and its co-located findings, best first.
type Group struct {
	ID      string
	Members []Item
}

// Groups ranks items and gathers each into a group with up to MaxGroup-1
// co-located findings: same file, same enclosing symbol. A group is led by its
// best-ranked finding, and groups come in the order of their leaders. A
// finding with no file is a group of its own.
func Groups(auditID string, items []Item, p Priors) []Group {
	ranked := Rank(items, p)
	var groups []Group
	open := map[[2]string]int{} // (path, symbol) -> index of the group still taking members
	for _, it := range ranked {
		loc := [2]string{it.Path, it.Symbol}
		if it.Path != "" {
			if gi, ok := open[loc]; ok && len(groups[gi].Members) < MaxGroup {
				groups[gi].Members = append(groups[gi].Members, it)
				continue
			}
		}
		groups = append(groups, Group{Members: []Item{it}})
		if it.Path != "" {
			open[loc] = len(groups) - 1
		}
	}
	for i := range groups {
		h := sha256.New()
		h.Write([]byte(auditID))
		for _, m := range groups[i].Members {
			h.Write([]byte{0})
			h.Write([]byte(m.Fingerprint))
		}
		groups[i].ID = hex.EncodeToString(h.Sum(nil))[:16]
	}
	return groups
}
