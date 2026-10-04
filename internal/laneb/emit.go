// This file places recall candidates on the record.
//
// THE VERDICT MAPPING IS OWNED HERE AND NOWHERE ELSE (CONTRACT.md §1.6). The
// owner's gate decision of 2026-10-03 deleted the adjudicator, so nothing in
// Lane B judges a match: every candidate becomes anvil/verdict unconfirmed,
// and the coding agent's triage gate decides it. VerdictFor is that mapping,
// and TestEveryCandidateReachesTheRecordUnconfirmed holds it.
//
// THE REST FOLLOWS FROM THE SAME DECISION. anvil/confidence is 1, as Lane A
// writes for its comparator: the pattern is certainly present, and whether it
// is a defect is the verdict's job. anvil/detector is kind sast with an empty
// model and revision, because no model ran. A ranker would write result.rank
// and never confidence; none ships in v1 (plan node encoder), so rank is unset.
//
// WHO WROTE WHICH BYTES (CONTRACT.md §2). The snippet, the context, the path,
// the symbol and the rule id all come from outside Anvil (the repository under
// scan, or a rule corpus), so the result's trust default is untrusted. The one
// string Anvil writes is anvil/reasoning, composed from the closed vocabulary
// below and base-10 integers this process computed, never from the bytes it
// describes; it alone is labelled anvil_generated.

package laneb

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/recall"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// VerdictFor is the Lane B pipeline's mapping from a recall candidate to
// anvil/verdict. A candidate is a rule match nobody has judged, so the answer
// does not depend on the candidate.
func VerdictFor(recall.Candidate) record.Verdict { return record.VerdictUnconfirmed }

// The closed vocabulary anvil/reasoning is composed from.
const (
	reasonMatched = "A deterministic recall rule matched this location. No model judged the match: " +
		"the finding is unconfirmed until the coding agent's triage gate decides it."
	reasonCWE      = "The rule's CWE, by number:"
	reasonLines    = "The match spans lines, first then last:"
	reasonSymbol   = "The enclosing function or class was named, by a parser or, for Python, by reading its indentation, so the finding's identity follows it rather than the line."
	reasonNoSymbol = "No enclosing function was named, so the finding's identity follows the file."
)

var reasoningVocabulary = map[string]bool{
	reasonMatched: true, reasonCWE: true, reasonLines: true, reasonSymbol: true, reasonNoSymbol: true,
}

// errReasoning is a reasoning part outside the vocabulary: a bug, never data.
var errReasoning = errors.New("laneb: a reasoning part is neither vocabulary nor an integer this process computed")

func composeReasoning(parts ...string) (string, error) {
	for _, p := range parts {
		if !reasoningVocabulary[p] && !isDigits(p) {
			return "", fmt.Errorf("%w: %q", errReasoning, p)
		}
	}
	return strings.Join(parts, " "), nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// reasoningPointer is the RFC 6901 pointer of anvil/reasoning in a result.
const reasoningPointer = "/properties/anvil~1reasoning"

// CWETaxonomyName names the CWE taxonomy in run.taxonomies.
const CWETaxonomyName = "CWE"

// CWEVersion is the CWE catalogue Lane B's label space is (plan node
// candidatelist): CWE 4.20, the pinned archive under eval/data/cwe.
const CWEVersion = "4.20"

// Emission is Lane B's contribution to the SAST run.
type Emission struct {
	Results    []record.Result
	Extensions []record.ToolComponent
	Taxonomies []record.ToolComponent
	// Refused are candidates that could not be placed on the record, each
	// with the reason. A refusal makes the scan incomplete.
	Refused []string
}

// Emit places candidates on the record for the target targetID. The order of
// the results is the candidates' order.
func Emit(targetID string, cands []recall.Candidate) (Emission, error) {
	if strings.TrimSpace(targetID) == "" {
		return Emission{}, errors.New("laneb: no target id; it is the first field of every anvil-fp/v1 digest")
	}
	var out Emission

	// Identity: anvil-fp/v1's SAST tier, with ordinals over identical matches.
	type placed struct {
		c   recall.Candidate
		cwe int
	}
	var keep []placed
	var batch []record.SastCandidate
	for _, c := range cands {
		in := record.SastInput{
			TargetID: targetID, RuleIDVersioned: c.RuleIDVersioned, RepoRelPath: c.Path,
			EnclosingSymbolPath: c.EnclosingSymbolPath(), Snippet: c.Snippet,
		}
		if _, err := record.SastFields(in); err != nil {
			out.Refused = append(out.Refused, fmt.Sprintf("%s:%d %s: %v", c.Path, c.StartLine, c.RuleIDVersioned, err))
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(c.CWE, "CWE-"))
		if err != nil || n <= 0 {
			out.Refused = append(out.Refused, fmt.Sprintf("%s:%d %s: CWE %q is not CWE-<number>", c.Path, c.StartLine, c.RuleIDVersioned, c.CWE))
			continue
		}
		keep = append(keep, placed{c: c, cwe: n})
		batch = append(batch, record.SastCandidate{Input: in, Line: c.StartLine})
	}
	inputs, err := record.AssignSastOrdinals(batch)
	if err != nil {
		return Emission{}, err
	}

	ext := newExtensions()
	cwes := map[int]bool{}
	lineSeen := map[string]int{}
	for i, p := range keep {
		c := p.c
		digest, err := record.Sast(inputs[i])
		if err != nil {
			return Emission{}, err
		}
		if err := ext.cite(c); err != nil {
			return Emission{}, err
		}
		cwes[p.cwe] = true

		symbolReason := reasonNoSymbol
		if c.Symbol != "" {
			symbolReason = reasonSymbol
		}
		reasoning, err := composeReasoning(reasonMatched, reasonCWE, strconv.Itoa(p.cwe),
			reasonLines, strconv.Itoa(c.StartLine), strconv.Itoa(c.EndLine), symbolReason)
		if err != nil {
			return Emission{}, err
		}

		lh := lineHash(c)
		lineSeen[c.Path+"\x00"+lh]++
		zero, idx := 0, 0 // idx is set below, once every source is known
		res := record.Result{
			RuleID: c.RuleIDVersioned,
			// SARIF's "open": the tool could not determine whether the
			// result is a problem. It is the SARIF-native reading of
			// unconfirmed.
			Kind:    record.KindOpen,
			Message: record.Message{Text: message(c)},
			Rule: &record.ReportingDescriptorReference{
				ID: c.RuleIDVersioned, ToolComponent: &record.ToolComponentRef{Index: &idx},
			},
			Locations: []record.Location{location(c)},
			Taxa: []record.ReportingDescriptorReference{{
				ID: strconv.Itoa(p.cwe), ToolComponent: &record.ToolComponentRef{Name: CWETaxonomyName, Index: &zero},
			}},
			PartialFingerprints: map[string]string{
				record.PartialFingerprintAnvilFindingID: digest,
				record.PartialFingerprintPrimaryLocationLineHash: lh + ":" +
					strconv.Itoa(lineSeen[c.Path+"\x00"+lh]),
			},
			Properties: record.ResultProperties{
				FindingID:  digest,
				Half:       record.HalfSast,
				Confidence: 1,
				Verdict:    VerdictFor(c),
				// First-party source is the coding agent's write surface. An
				// unconfirmed finding still waits for the triage gate before
				// anything is generated (record.taskcard's routing).
				RemediableByAgent: true,
				Reasoning:         reasoning,
				Detector:          record.DetectorRef{Kind: record.DetectorKindSast},
				EvidenceClass:     record.EvidenceClassSastStaticOnly,
				Trust: record.TrustAssertion{
					Default: record.TrustUntrusted,
					Fields:  map[string]record.Trust{reasoningPointer: record.TrustAnvilGenerated},
				},
			},
		}
		if err := record.ValidateResultTrust(&res); err != nil {
			return Emission{}, fmt.Errorf("laneb: a result failed the trust check: %w", err)
		}
		out.Results = append(out.Results, res)
	}
	out.Extensions = ext.components()
	pos := map[string]int{}
	for i, c := range out.Extensions {
		pos[c.Name] = i
	}
	for i := range out.Results {
		n := pos[keepSource(out.Results[i], out.Extensions)]
		out.Results[i].Rule.ToolComponent.Index = &n
	}
	if len(cwes) > 0 {
		out.Taxonomies = []record.ToolComponent{cweTaxonomy(cwes)}
	}
	return out, nil
}

// lineHash is the primaryLocationLineHash Lane B writes: the first 16 hex
// characters of the SHA-256 of the match's first line with its whitespace
// collapsed, then ":" and that hash's 1-based occurrence in the file among this
// scan's results. It is stable when lines move and when indentation changes,
// which is what GitHub reads the key for. It is Anvil's own construction, not
// CodeQL's rolling hash; the key's owner is still an open question in the
// contract (CONTRACT.md, the GitHub projection), and this is the value the
// Lane B pipeline produces until it is answered.
func lineHash(c recall.Candidate) string {
	first, _, _ := strings.Cut(c.Snippet, "\n")
	sum := sha256.Sum256([]byte(strings.Join(strings.Fields(first), " ")))
	return hex.EncodeToString(sum[:8])
}

// message is the result's message: which rule matched where. It quotes a rule
// id and a path, so it is untrusted text, covered by the result's default.
func message(c recall.Candidate) string {
	where := c.Path + ":" + strconv.Itoa(c.StartLine)
	if c.Symbol != "" {
		where += " (in " + c.Symbol + ")"
	}
	return "Unconfirmed " + c.CWE + " candidate: rule " + c.RuleID + " from " + c.Provenance.Source +
		" matched at " + where + ". Nothing has judged the match; the triage gate decides it."
}

func location(c recall.Candidate) record.Location {
	loc := record.Location{PhysicalLocation: &record.PhysicalLocation{
		ArtifactLocation: record.ArtifactLocation{URI: c.Path},
		Region: &record.Region{
			StartLine: c.StartLine, EndLine: c.EndLine,
			Snippet: &record.Snippet{Text: c.Snippet},
		},
		ContextRegion: &record.Region{
			StartLine: c.ContextStartLine, EndLine: c.ContextEndLine,
			Snippet: &record.Snippet{Text: c.Context},
		},
	}}
	if c.Symbol != "" {
		name := c.Symbol[strings.LastIndex(c.Symbol, ".")+1:]
		// No kind: the innermost enclosing block may be a function or a
		// class, and Lane B states only what a parser named.
		loc.LogicalLocations = []record.LogicalLocation{{
			Name: name, FullyQualifiedName: c.EnclosingSymbolPath(),
		}}
	}
	return loc
}

// extensions collects one tool extension per rule source, each holding the
// rules this scan's results cite, in a deterministic order.
type extensions struct {
	order []string
	by    map[string]*record.ToolComponent
	rules map[string]map[string]bool
}

func newExtensions() *extensions {
	return &extensions{by: map[string]*record.ToolComponent{}, rules: map[string]map[string]bool{}}
}

// keepSource names the extension that holds a result's rule.
func keepSource(r record.Result, comps []record.ToolComponent) string {
	for _, c := range comps {
		for _, d := range c.Rules {
			if d.ID == r.RuleID {
				return c.Name
			}
		}
	}
	return ""
}

func (e *extensions) cite(c recall.Candidate) error {
	p := c.Provenance
	prov := &record.RuleProvenance{
		Source: p.Source, Repository: p.Repository, Version: p.Version, RulePath: p.RulePath,
		LicenseSpdx: p.Licence, LicenseEvidence: p.LicenceEvidence,
	}
	if err := prov.Validate(); err != nil {
		return fmt.Errorf("laneb: %s cites a rule with incomplete provenance: %w", c.RuleIDVersioned, err)
	}
	comp, ok := e.by[p.Source]
	if !ok {
		comp = &record.ToolComponent{Name: p.Source, Version: p.Version, InformationURI: p.Repository}
		e.by[p.Source] = comp
		e.rules[p.Source] = map[string]bool{}
		e.order = append(e.order, p.Source)
	}
	if !e.rules[p.Source][c.RuleIDVersioned] {
		e.rules[p.Source][c.RuleIDVersioned] = true
		comp.Rules = append(comp.Rules, record.ReportingDescriptor{
			ID: c.RuleIDVersioned, Name: c.RuleID,
			Properties: &record.RuleProperties{RuleProvenance: prov},
		})
	}
	return nil
}

// components returns the extensions sorted by name, so their order does not
// depend on which result came first.
func (e *extensions) components() []record.ToolComponent {
	names := append([]string(nil), e.order...)
	sort.Strings(names)
	out := make([]record.ToolComponent, 0, len(names))
	for _, n := range names {
		c := *e.by[n]
		sort.Slice(c.Rules, func(i, j int) bool { return c.Rules[i].ID < c.Rules[j].ID })
		out = append(out, c)
	}
	return out
}

func cweTaxonomy(cwes map[int]bool) record.ToolComponent {
	ids := make([]int, 0, len(cwes))
	for n := range cwes {
		ids = append(ids, n)
	}
	sort.Ints(ids)
	t := record.ToolComponent{
		Name: CWETaxonomyName, Version: CWEVersion, Organization: "MITRE",
		InformationURI: "https://cwe.mitre.org/data/index.html",
	}
	for _, n := range ids {
		t.Taxa = append(t.Taxa, record.ReportingDescriptor{ID: strconv.Itoa(n)})
	}
	return t
}
