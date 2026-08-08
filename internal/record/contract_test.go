package record

import (
	"testing"
)

// The six enums IMPLEMENTATION-PLAN.md section 6 froze, pinned here as literal
// strings.
//
// These are not a restatement of the code for its own sake. Ten confirmed
// cross-area defects came from four areas each declaring their own version of
// this vocabulary, and every one was a produce/consume break: one area wrote
// literals another area's NOT NULL column could not accept. `dast_status` had
// *zero* values in common between two areas that both claimed authority over it.
//
// Comparing these constants against the enum accessors is therefore not circular
// -- the accessors are what other packages consume, and this table is what the
// ruling says they must be. A future edit that "tidies" a literal has to change
// it in two places, and the second one is a wall of comments explaining why not.
var frozenEnums = map[string][]string{
	"anvil/state": {
		"collecting", "sast_sealed", "dast_sealed", "both_sealed", "consumed", "expired",
	},
	"anvil/status": {
		"running", "sealed", "failed", "timed_out", "skipped",
	},
	// TEN values since the section 6 amendment: `completed_failed` was added
	// between completed_partial and target_boot_failed because the nine-value
	// set had no image for "the DAST half itself broke", and DeriveDastStatus
	// was folding that case into completed_partial -- which makes dast_coverage
	// uninterpretable for the same reason S6 requires a failed target to be
	// distinguishable from one scanned clean.
	"anvil/dastStatus": {
		"not_run", "skipped_no_manifest", "running", "completed_clean", "completed_findings",
		"completed_partial", "completed_failed", "target_boot_failed", "target_unreachable",
		"timed_out",
	},
	"anvil/target.provenance": {
		"booted_clean", "boot_failed", "build_failed", "no_target_declared",
		"unreachable_at_scan_time",
	},
	"anvil/target.provisioning": {
		"ephemeral_manifest", "live_url_authorized",
	},
	"anvil/verdict": {
		"true_positive", "false_positive", "insufficient_context",
	},
}

func actualEnums() map[string][]string {
	out := map[string][]string{}
	for _, v := range StateValues() {
		out["anvil/state"] = append(out["anvil/state"], string(v))
	}
	for _, v := range HalfStatusValues() {
		out["anvil/status"] = append(out["anvil/status"], string(v))
	}
	for _, v := range DastStatusValues() {
		out["anvil/dastStatus"] = append(out["anvil/dastStatus"], string(v))
	}
	for _, v := range TargetProvenanceValues() {
		out["anvil/target.provenance"] = append(out["anvil/target.provenance"], string(v))
	}
	for _, v := range TargetProvisioningValues() {
		out["anvil/target.provisioning"] = append(out["anvil/target.provisioning"], string(v))
	}
	for _, v := range VerdictValues() {
		out["anvil/verdict"] = append(out["anvil/verdict"], string(v))
	}
	return out
}

func TestFrozenEnumsMatchTheRuling(t *testing.T) {
	got := actualEnums()
	for name, want := range frozenEnums {
		have, ok := got[name]
		if !ok {
			t.Errorf("%s: no accessor found", name)
			continue
		}
		if len(have) != len(want) {
			t.Errorf("%s: has %d values, ruling froze %d\n  got:  %q\n  want: %q",
				name, len(have), len(want), have, want)
			continue
		}
		for i := range want {
			if have[i] != want[i] {
				t.Errorf("%s[%d] = %q, ruling froze %q (full: got %q want %q)",
					name, i, have[i], want[i], have, want)
			}
		}
	}
}

// The literals four other areas were using before the ruling. Each one is a
// value some area actually wrote, and every one must now be rejected. If any of
// these starts validating, the ruling has been quietly undone.
func TestPreRulingLiteralsAreRejected(t *testing.T) {
	cases := []struct {
		field     string
		literal   string
		validate  func(string) error
		wasUsedBy string
	}{
		{"anvil/state", "open", ValidateState, "area O's old 4-state machine"},
		{"anvil/state", "sealed", ValidateState, "area O -- collides with the per-half token"},
		{"anvil/status", "complete", ValidateHalfStatus, "area O keyed its transitions on this"},
		{"anvil/dastStatus", "clean", ValidateDastStatus, "area D"},
		{"anvil/dastStatus", "findings", ValidateDastStatus, "area D"},
		{"anvil/dastStatus", "failed_to_boot", ValidateDastStatus, "area D"},
		{"anvil/dastStatus", "partial", ValidateDastStatus, "area D -- now completed_partial"},
		{"anvil/target.provenance", "ephemeral_manifest", ValidateTargetProvenance,
			"area D wrote the provisioning path into the provenance field"},
		{"anvil/target.provenance", "live_url_authorized", ValidateTargetProvenance, "area D"},
		{"anvil/verdict", "EXHIBITS", ValidateVerdict, "area B -- B.12 must map, not pass through"},
		{"anvil/verdict", "DOES_NOT_EXHIBIT", ValidateVerdict, "area B"},
		{"anvil/verdict", "INSUFFICIENT_CONTEXT", ValidateVerdict,
			"area B -- the record uses lowercase; case normalisation is B.12's job"},
	}
	for _, c := range cases {
		t.Run(c.field+"/"+c.literal, func(t *testing.T) {
			if err := c.validate(c.literal); err == nil {
				t.Errorf("%q accepted as a legal %s. It was used by %s and the ruling "+
					"in IMPLEMENTATION-PLAN.md section 6 replaced it; accepting it "+
					"re-opens a produce/consume break.", c.literal, c.field, c.wasUsedBy)
			}
		})
	}
}

func TestEveryFrozenValueValidates(t *testing.T) {
	validators := map[string]func(string) error{
		"anvil/state":               ValidateState,
		"anvil/status":              ValidateHalfStatus,
		"anvil/dastStatus":          ValidateDastStatus,
		"anvil/target.provenance":   ValidateTargetProvenance,
		"anvil/target.provisioning": ValidateTargetProvisioning,
		"anvil/verdict":             ValidateVerdict,
	}
	for field, values := range frozenEnums {
		for _, v := range values {
			if err := validators[field](v); err != nil {
				t.Errorf("%s: frozen value %q rejected: %v", field, v, err)
			}
		}
	}
}

// The thirteen handoff dispositions, which are the union of area 40's original
// set and the four that existed only in area 60's rival `anvil_ledger` table.
// That table is deleted by ruling G10; if these four are missing, area X's exit
// criterion 14 ("every disposition has a reachable code path and a test")
// becomes unsatisfiable.
func TestHandoffStateCoversTheDeletedLedgerDispositions(t *testing.T) {
	fromLedgerOnly := []string{
		"fixed_incidentally", "split_required", "withdrawn", "superseded",
	}
	for _, v := range fromLedgerOnly {
		if err := ValidateHandoffState(v); err != nil {
			t.Errorf("handoff.state rejects %q, which area 60's anvil_ledger carried. "+
				"Ruling G10 collapsed that table into handoff; dropping the value "+
				"loses the disposition entirely: %v", v, err)
		}
	}
	if len(HandoffStateValues()) != 13 {
		t.Errorf("handoff.state has %d values, ruling G10 specifies 13",
			len(HandoffStateValues()))
	}
}

// S6: anvil/trust is required on every string originating outside Anvil, and a
// repo source snippet is `untrusted` even though Anvil assembled the struct
// holding it. Area B was found stamping `anvil_generated` on exactly that,
// which would disable area X's containment check on the string that most needs
// it -- attacker-influenced source text heading for a repo-credentialed agent.
func TestTrustLegalityForExternalStrings(t *testing.T) {
	cases := []struct {
		trust Trust
		legal bool
		why   string
	}{
		{TrustUntrusted, true, "the default for anything Anvil did not author"},
		{TrustVerified, true, "explicitly promoted after checking"},
		{TrustAnvilGenerated, false,
			"Anvil assembling a struct around external bytes does not make the bytes Anvil's"},
	}
	for _, c := range cases {
		t.Run(string(c.trust), func(t *testing.T) {
			if got := c.trust.LegalForExternalString(); got != c.legal {
				t.Errorf("Trust(%q).LegalForExternalString() = %v, want %v -- %s",
					c.trust, got, c.legal, c.why)
			}
		})
	}
}

// S7: correlation links, never merges, and requires >=2 independent signals. A
// CWE match alone is explicitly banned as a sole signal -- it is the cheapest
// and least specific thing two findings can share.
func TestCweMatchAloneNeverQualifiesAsVerified(t *testing.T) {
	for _, s := range CorrelationSignalValues() {
		sufficient := s.SufficientForVerified()
		if string(s) == "cweMatch" && sufficient {
			t.Error("a CWE match alone qualifies as verified; S7 bans it as a sole signal")
		}
	}
}

func TestUnknownValuesAreRejectedNotIgnored(t *testing.T) {
	validators := map[string]func(string) error{
		"anvil/state":               ValidateState,
		"anvil/status":              ValidateHalfStatus,
		"anvil/dastStatus":          ValidateDastStatus,
		"anvil/target.provenance":   ValidateTargetProvenance,
		"anvil/target.provisioning": ValidateTargetProvisioning,
		"anvil/verdict":             ValidateVerdict,
		"handoff.state":             ValidateHandoffState,
	}
	// The empty string is the important one: a zero-valued Go string must not
	// silently pass as "unset but fine".
	for _, bogus := range []string{"", "unknown", "PASS", "Sealed", "sealed "} {
		for field, validate := range validators {
			if err := validate(bogus); err == nil {
				t.Errorf("%s accepted %q", field, bogus)
			}
		}
	}
}
