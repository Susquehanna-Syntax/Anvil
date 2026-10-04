package remediation

// The exploit oracle (plan node oracle): the only road to "verified fixed".
// It replays the dynamic tier's stored reproduction, and a set of mutated
// payloads, inside the dynamic tier's own containment: first against the
// scanned code, to keep only the mutants that are live exploits there, then
// against the patched code. Only "the reproduction and every live mutant now
// fail, and at least one mutant was live" earns LabelVerifiedFixed. A mutant
// that never triggered proves nothing about a patch, so it never counts. LabelFor
// is the one function in Anvil that can return the label
// (TestVerifiedFixedHasOneRoad).
//
// The replay itself belongs to the dynamic tier, which has never run live:
// Phase 8 provides a Replayer. Until it does, every finding is proposed as
// unverified-security, which is honest: most first-party findings have no
// reproduction at all.

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// Label is what a pull request claims about its patch.
type Label string

// The two labels.
const (
	LabelVerifiedFixed      Label = "verified_fixed"
	LabelUnverifiedSecurity Label = "unverified_security"
)

// ReplayTarget is a tree the dynamic tier boots for a replay: a fresh export
// (files only) of the git tree Tree.
type ReplayTarget struct {
	Dir  string
	Tree string
}

// Replayer replays one payload of a stored reproduction against a target and
// says whether the observed signal appeared. Phase 8's dynamic tier implements
// it inside its containment; nothing in this package sends a request.
type Replayer interface {
	Replay(ctx context.Context, t ReplayTarget, repro record.Repro, payload string) (triggered bool, detail string, err error)
}

// OracleVerdict is the oracle's outcome.
type OracleVerdict string

// The oracle outcomes.
const (
	OracleFixedIncludingMutants OracleVerdict = "fixed_including_mutants"
	OracleStillTriggers         OracleVerdict = "still_triggers"
	OracleMutantTriggers        OracleVerdict = "mutant_triggers"
	OracleNoReproduction        OracleVerdict = "no_reproduction"
	OracleNoReplayer            OracleVerdict = "no_replayer"
	OracleReplayFailed          OracleVerdict = "replay_failed"
	OracleBaseDoesNotTrigger    OracleVerdict = "base_does_not_trigger"
)

// OracleResult is one oracle run.
type OracleResult struct {
	Verdict OracleVerdict `json:"verdict"`
	// Mutants counts the mutants that were live exploits against the scanned
	// code; Dead those that never triggered there and so prove nothing.
	Mutants  int      `json:"mutants"`
	Dead     int      `json:"dead"`
	Survived []string `json:"survived,omitempty"` // live mutants that still triggered on the patch
	Detail   string   `json:"detail,omitempty"`
}

// Blocking reports whether the oracle showed the patch does not fix the
// finding: the reproduction or a mutant still triggers.
func (o OracleResult) Blocking() bool {
	return o.Verdict == OracleStillTriggers || o.Verdict == OracleMutantTriggers
}

// LabelFor is the single road to LabelVerifiedFixed.
func LabelFor(o OracleResult) Label {
	if o.Verdict == OracleFixedIncludingMutants && o.Mutants > 0 && len(o.Survived) == 0 {
		return LabelVerifiedFixed
	}
	return LabelUnverifiedSecurity
}

// Mutate returns deterministic variants of a payload that a patch which only
// special-cases the recorded bytes would let through: case changes, encodings,
// whitespace and quoting variants. The original is never among them.
func Mutate(payload string) []string {
	if payload == "" {
		return nil
	}
	cands := []string{
		strings.ToUpper(payload),
		strings.ToLower(payload),
		swapCase(payload),
		url.QueryEscape(payload),
		url.QueryEscape(url.QueryEscape(payload)),
		strings.ReplaceAll(payload, " ", "/**/"),
		strings.ReplaceAll(payload, " ", "\t"),
		strings.ReplaceAll(payload, " ", "  "),
		strings.ReplaceAll(payload, "'", "\""),
		strings.ReplaceAll(payload, "\"", "'"),
		payload + " ",
		" " + payload,
	}
	seen := map[string]bool{payload: true}
	var out []string
	for _, c := range cands {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func swapCase(s string) string {
	b := []rune(s)
	for i, r := range b {
		switch {
		case r >= 'a' && r <= 'z' && i%2 == 0:
			b[i] = r - 32
		case r >= 'A' && r <= 'Z' && i%2 == 1:
			b[i] = r + 32
		}
	}
	return string(b)
}

// RunOracle replays repro against the scanned code (base) and the patched
// code. The reproduction must trigger on base, or nothing can be concluded.
// Each mutant is replayed on base first; only the live ones are replayed on
// the patch.
func RunOracle(ctx context.Context, rp Replayer, base, patched ReplayTarget, repro *record.Repro) OracleResult {
	if repro == nil || repro.Payload == "" {
		return OracleResult{Verdict: OracleNoReproduction, Detail: "the finding carries no stored reproduction"}
	}
	if rp == nil {
		return OracleResult{Verdict: OracleNoReplayer, Detail: "no dynamic tier is connected to replay the reproduction"}
	}
	trig, detail, err := rp.Replay(ctx, base, *repro, repro.Payload)
	if err != nil {
		return OracleResult{Verdict: OracleReplayFailed, Detail: "on the scanned code: " + err.Error()}
	}
	if !trig {
		return OracleResult{Verdict: OracleBaseDoesNotTrigger, Detail: "the stored reproduction does not trigger on the scanned code, so its failing on the patch proves nothing"}
	}
	trig, detail, err = rp.Replay(ctx, patched, *repro, repro.Payload)
	if err != nil {
		return OracleResult{Verdict: OracleReplayFailed, Detail: err.Error()}
	}
	if trig {
		return OracleResult{Verdict: OracleStillTriggers, Detail: detail}
	}
	res := OracleResult{Verdict: OracleFixedIncludingMutants}
	for i, m := range Mutate(repro.Payload) {
		live, _, err := rp.Replay(ctx, base, *repro, m)
		if err != nil {
			return OracleResult{Verdict: OracleReplayFailed, Detail: fmt.Sprintf("mutant %d on the scanned code: %v", i+1, err)}
		}
		if !live {
			res.Dead++
			continue
		}
		res.Mutants++
		trig, _, err := rp.Replay(ctx, patched, *repro, m)
		if err != nil {
			return OracleResult{Verdict: OracleReplayFailed, Detail: fmt.Sprintf("mutant %d: %v", i+1, err)}
		}
		if trig {
			res.Survived = append(res.Survived, fmt.Sprintf("mutant %d", i+1))
		}
	}
	switch {
	case len(res.Survived) > 0:
		res.Verdict = OracleMutantTriggers
		res.Detail = fmt.Sprintf("%d of %d live mutated payloads still trigger: the patch special-cases the recorded payload", len(res.Survived), res.Mutants)
	case res.Mutants == 0:
		res.Detail = fmt.Sprintf("the reproduction no longer triggers, but none of the %d mutants was live on the scanned code, so the patch was not tested beyond the recorded payload", res.Dead)
	}
	return res
}
