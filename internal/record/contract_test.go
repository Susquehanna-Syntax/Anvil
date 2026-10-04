package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The six enums the shared-vocabulary review froze, pinned here as literal
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
	// TEN values since the shared-vocabulary amendment: `completed_failed` was added
	// between completed_partial and target_boot_failed because the nine-value
	// set had no image for "the DAST half itself broke", and DeriveDastStatus
	// was folding that case into completed_partial -- which makes dast_coverage
	// uninterpretable for the same reason the spine's record section requires a failed target to be
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
	// FOUR values since the gate decision of 2026-10-03 (plan node gate): the owner
	// shrank the model tier to recall plus an optional ranker, so a Lane B finding
	// is a rule match no detector has judged. `unconfirmed` says exactly that;
	// true_positive would overclaim it and insufficient_context would make it
	// report-only for ever.
	"anvil/verdict": {
		"true_positive", "false_positive", "insufficient_context", "unconfirmed",
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
		{"anvil/state", "open", ValidateState, "The control plane's old 4-state machine"},
		{"anvil/state", "sealed", ValidateState, "The control plane -- collides with the per-half token"},
		{"anvil/status", "complete", ValidateHalfStatus, "The control plane keyed its transitions on this"},
		{"anvil/dastStatus", "clean", ValidateDastStatus, "The dynamic tier"},
		{"anvil/dastStatus", "findings", ValidateDastStatus, "The dynamic tier"},
		{"anvil/dastStatus", "failed_to_boot", ValidateDastStatus, "The dynamic tier"},
		{"anvil/dastStatus", "partial", ValidateDastStatus, "The dynamic tier -- now completed_partial"},
		{"anvil/target.provenance", "ephemeral_manifest", ValidateTargetProvenance,
			"The dynamic tier wrote the provisioning path into the provenance field"},
		{"anvil/target.provenance", "live_url_authorized", ValidateTargetProvenance, "The dynamic tier"},
		{"anvil/verdict", "EXHIBITS", ValidateVerdict, "Lane B -- the Lane B pipeline must map, not pass through"},
		{"anvil/verdict", "DOES_NOT_EXHIBIT", ValidateVerdict, "Lane B"},
		{"anvil/verdict", "INSUFFICIENT_CONTEXT", ValidateVerdict,
			"Lane B -- the record uses lowercase; case normalisation is the Lane B pipeline's job"},
	}
	for _, c := range cases {
		t.Run(c.field+"/"+c.literal, func(t *testing.T) {
			if err := c.validate(c.literal); err == nil {
				t.Errorf("%q accepted as a legal %s. It was used by %s and the ruling "+
					"in the shared-vocabulary review replaced it; accepting it "+
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

// The thirteen handoff dispositions, which are the union of the record area's original
// set and the four that existed only in remediation's rival `anvil_ledger` table.
// That table is deleted by the one-ledger ruling; if these four are missing, remediation's exit
// criterion 14 ("every disposition has a reachable code path and a test")
// becomes unsatisfiable.
func TestHandoffStateCoversTheDeletedLedgerDispositions(t *testing.T) {
	fromLedgerOnly := []string{
		"fixed_incidentally", "split_required", "withdrawn", "superseded",
	}
	for _, v := range fromLedgerOnly {
		if err := ValidateHandoffState(v); err != nil {
			t.Errorf("handoff.state rejects %q, which remediation's anvil_ledger carried. "+
				"The one-ledger ruling collapsed that table into handoff; dropping the value "+
				"loses the disposition entirely: %v", v, err)
		}
	}
	if len(HandoffStateValues()) != 13 {
		t.Errorf("handoff.state has %d values, the one-ledger ruling specifies 13",
			len(HandoffStateValues()))
	}
}

// The spine's record section: anvil/trust is required on every string
// originating outside Anvil, and a repo source snippet is `untrusted` even
// though Anvil assembled the struct holding it. Lane B was found stamping
// `anvil_generated` on exactly that, which would disable remediation's
// containment check on the string that most needs it -- attacker-influenced
// source text heading for a repo-credentialed agent.
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

// The spine's safety section: correlation links, never merges, and requires >=2
// independent signals. A CWE match alone is explicitly banned as a sole signal
// -- it is the cheapest and least specific thing two findings can share.
func TestCweMatchAloneNeverQualifiesAsVerified(t *testing.T) {
	for _, s := range CorrelationSignalValues() {
		sufficient := s.SufficientForVerified()
		if string(s) == "cweMatch" && sufficient {
			t.Error("a CWE match alone qualifies as verified; the spine's safety section bans it as a sole signal")
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
		// Not one of the six, but it obeys the same rule and for a sharper
		// reason: the permissive reading of an unset spec-harvest outcome is
		// "the repository ships no API specs", which is what makes a coverage
		// denominator vanish.
		"anvil/specHarvest.outcome": ValidateSpecHarvestOutcome,
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

// ===========================================================================
// anvil/specHarvest -- the slot the repo spec reader's Ruling-7 reconciliation found missing
// ===========================================================================
//
// The repo spec reader (internal/dast/inventory/tier1_repospec.go) consumes spec files the SAST
// pass harvested and turns them into inventory routes. It may not harvest them
// itself: plan/design/dynamic-tier.md:628-630 assigns that to the SAST tier by name. So it
// can only ever see a slice somebody handed it, and an EMPTY slice has three
// meanings that a bare file list cannot tell apart:
//
//	the repository ships no spec files            -- a fact about the repo
//	the harvest pass never ran                    -- a fact about Anvil
//	files arrived and none of them could be read  -- a fact about Anvil
//
// Only the first describes the target. All three flow into the DENOMINATOR of
// DastCoverage.EndpointCoverage, where a vanished denominator is the shape
// every "100% covered" report is made of.
//
// The ruling this section tests: a repo with no specs and a handoff that never
// ran MUST NOT PRODUCE THE SAME RECORD.

// chLog builds the smallest SARIFLog that passes (*SARIFLog).Validate, so every
// guard below is exercised through the real entry point rather than through the
// unit validator alone. A control reachable only from a helper nothing calls is
// not a control.
func chLog(half Half) *SARIFLog {
	created := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	const auditID = "audit-spec-harvest-0001"

	rp := RunProperties{Half: half, Status: HalfStatusRunning}
	if half == HalfDast {
		rp.DastCoverage = &DastCoverage{
			InventoryProvenanceMix: map[InventoryProvenance]int{},
		}
	}
	return &SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Properties: AuditProperties{
			SchemaVersion: SchemaVersion,
			AuditID:       auditID,
			State:         StateCollecting,
			Version:       1,
			CreatedAt:     created,
			Target: Target{
				RepoURL:      "https://github.invalid/org/repo.git",
				Provenance:   TargetProvenanceBootedClean,
				Provisioning: TargetProvisioningEphemeralManifest,
			},
			// Deliberately NOT not_run / skipped_no_manifest: either of those
			// makes an absent DAST half count as sealed and moves the expected
			// anvil/state, which would make these tests fail for a reason that
			// has nothing to do with the spec harvest.
			DastStatus: DastStatusRunning,
			Deadline: Deadline{
				ClaimTimeoutSeconds: DefaultClaimTimeoutSeconds,
				DeadlineAt:          created.Add(DefaultClaimTimeoutSeconds * time.Second),
			},
		},
		Runs: []Run{{
			AutomationDetails: RunAutomationDetails{CorrelationGUID: auditID},
			Properties:        rp,
		}},
	}
}

func chInt(n int) *int { return &n }

// chFile is one legal harvested file, with the real SHA-256 of its exact bytes.
func chFile() SpecHarvestFile {
	const body = "openapi: 3"
	sum := sha256.Sum256([]byte(body))
	return SpecHarvestFile{
		Location:       ArtifactLocation{URI: "openapi.yaml"},
		SizeBytes:      len(body),
		ContentSHA256:  hex.EncodeToString(sum[:]),
		Content:        &ArtifactContent{Text: body},
		DeclaredFormat: "openapi3_yaml",
		Trust:          TrustUntrusted,
	}
}

// THE RULING, TESTED AT THE WIRE. Both of these carry zero spec files. If the
// record cannot tell them apart, the slot has not been added -- it has been
// decorated.
func TestASpeclessRepositoryAndAnUnwiredHandoffAreDifferentRecords(t *testing.T) {
	speclessRepo := chLog(HalfSast)
	speclessRepo.Runs[0].Properties.SpecHarvest = &SpecHarvest{
		Outcome:          SpecHarvestRan,
		Files:            []SpecHarvestFile{},
		OmittedFileCount: chInt(0),
	}
	unwiredHandoff := chLog(HalfSast)
	unwiredHandoff.Runs[0].Properties.SpecHarvest = &SpecHarvest{
		Outcome: SpecHarvestSkipped,
		Files:   nil,
	}

	for name, l := range map[string]*SARIFLog{
		"specless repo":   speclessRepo,
		"unwired handoff": unwiredHandoff,
	} {
		if err := l.Validate(); err != nil {
			t.Fatalf("%s: a legal record was rejected: %v", name, err)
		}
	}

	a, err := json.Marshal(speclessRepo)
	if err != nil {
		t.Fatalf("marshal specless repo: %v", err)
	}
	b, err := json.Marshal(unwiredHandoff)
	if err != nil {
		t.Fatalf("marshal unwired handoff: %v", err)
	}
	if string(a) == string(b) {
		t.Fatalf("a repository that ships no spec files and a harvest handoff that never ran "+
			"serialise to byte-identical records. That is the defect this slot exists to "+
			"close: both land in the denominator of %s and only one of them describes the "+
			"target.\n  %s", PropRunDastCoverage, a)
	}

	// And the distinction has to be READABLE, not merely present in the bytes.
	if !SpecHarvestRan.DescribesTheRepository() {
		t.Error("SpecHarvestRan.DescribesTheRepository() is false; an empty file list under a " +
			"harvest that RAN is a reportable fact about the repository")
	}
	if SpecHarvestSkipped.DescribesTheRepository() {
		t.Error("SpecHarvestSkipped.DescribesTheRepository() is true; an empty file list under " +
			"a harvest that never ran describes Anvil's reach, not the repository, and must " +
			"never become a coverage denominator")
	}

	// The third meaning is NOT a fourth literal, and must not become one: it is
	// not a fact about the harvest at all. Pinned so a future edit that "adds
	// the missing case" has to argue with this comment first.
	if got := len(SpecHarvestOutcomeValues()); got != 2 {
		t.Errorf("SpecHarvestOutcomeValues() has %d values, want 2 (%q, %q). "+
			"\"files arrived and none was readable\" is the DAST tier's own per-file "+
			"accounting, not a harvest outcome; a literal for it here would let two areas "+
			"disagree about which of them observed the failure",
			got, SpecHarvestRan, SpecHarvestSkipped)
	}
}

// The repo spec reader built inventory.HarvestOutcome locally, with these exact literals, while
// this slot did not exist. Pinning them here is what makes the handoff identity
// rather than a mapping -- and internal/record cannot import
// internal/dast/inventory to assert it directly, because inventory imports this
// package. So the literals are pinned by hand, on both sides, and
// AreaMappingOwners records that no translating step is permitted between them.
func TestSpecHarvestOutcomeLiteralsMatchTheTierOneVocabulary(t *testing.T) {
	want := []string{"harvest_ran", "harvest_skipped"}
	got := make([]string, 0, 2)
	for _, v := range SpecHarvestOutcomeValues() {
		got = append(got, string(v))
	}
	if len(got) != len(want) {
		t.Fatalf("anvil/specHarvest.outcome has %d literals %q, the repo spec reader declares %d %q",
			len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("anvil/specHarvest.outcome[%d] = %q, inventory.HarvestOutcome declares "+
				"%q. These two must stay literal-for-literal identical: the moment they "+
				"differ the handoff needs a mapping, and a mapping is the produce/consume "+
				"shape the shared-vocabulary review exists to close", i, got[i], want[i])
		}
	}
	if _, mapped := AreaMappingOwners["anvil/specHarvest.outcome"]; !mapped {
		t.Error("AreaMappingOwners carries no entry for anvil/specHarvest.outcome; the " +
			"no-mapping-permitted ruling must survive in code, not only in a comment")
	}
}

// Every absent decision, refused. Each case is a value some producer could
// plausibly build; none of them may validate.
//
// The POSITIVE CONTROLS are the point of the second table: a refusal that fires
// for every input is not a gate, it is an outage.
func TestValidateSpecHarvestRefusesEveryAbsentDecision(t *testing.T) {
	refused := map[string]struct {
		h   *SpecHarvest
		why string
	}{
		"zero outcome": {
			&SpecHarvest{Files: []SpecHarvestFile{}, OmittedFileCount: chInt(0)},
			"an empty composite literal is what a producer gets for free; the zero Outcome " +
				"must not read as the permissive answer",
		},
		"nil files under harvest_ran": {
			&SpecHarvest{Outcome: SpecHarvestRan, OmittedFileCount: chInt(0)},
			"a null list and an empty list must not be the same observation",
		},
		"nil omittedFileCount under harvest_ran": {
			&SpecHarvest{Outcome: SpecHarvestRan, Files: []SpecHarvestFile{}},
			"an int would default to 0, and 0 asserts that files is COMPLETE",
		},
		"negative omittedFileCount": {
			&SpecHarvest{Outcome: SpecHarvestRan, Files: []SpecHarvestFile{}, OmittedFileCount: chInt(-1)},
			"a count of files not carried cannot be negative",
		},
		"files under harvest_skipped": {
			&SpecHarvest{Outcome: SpecHarvestSkipped, Files: []SpecHarvestFile{chFile()}},
			"a pass that did not run cannot have delivered files",
		},
		"omittedFileCount under harvest_skipped": {
			&SpecHarvest{Outcome: SpecHarvestSkipped, OmittedFileCount: chInt(0)},
			"a pass that did not run saw nothing and therefore omitted nothing",
		},
	}
	for name, c := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			if err := ValidateSpecHarvest(c.h); err == nil {
				t.Errorf("ValidateSpecHarvest accepted %s: %s", name, c.why)
			}
			// And through the whole-record path, which is what producers call.
			l := chLog(HalfSast)
			l.Runs[0].Properties.SpecHarvest = c.h
			if err := l.Validate(); err == nil {
				t.Errorf("(*SARIFLog).Validate accepted %s; the guard is unreachable from "+
					"the entry point every producer actually uses", name)
			}
		})
	}

	admitted := map[string]*SpecHarvest{
		"nil -- the record makes no statement": nil,
		"harvest ran, repository ships no specs": {
			Outcome: SpecHarvestRan, Files: []SpecHarvestFile{}, OmittedFileCount: chInt(0),
		},
		"harvest ran, one file, none omitted": {
			Outcome: SpecHarvestRan, Files: []SpecHarvestFile{chFile()}, OmittedFileCount: chInt(0),
		},
		"harvest ran, one file, three dropped by a bound": {
			Outcome: SpecHarvestRan, Files: []SpecHarvestFile{chFile()}, OmittedFileCount: chInt(3),
		},
		"harvest never ran": {Outcome: SpecHarvestSkipped},
	}
	for name, h := range admitted {
		t.Run("admitted/"+name, func(t *testing.T) {
			if err := ValidateSpecHarvest(h); err != nil {
				t.Errorf("ValidateSpecHarvest refused a legal harvest (%s): %v", name, err)
			}
			l := chLog(HalfSast)
			l.Runs[0].Properties.SpecHarvest = h
			if err := l.Validate(); err != nil {
				t.Errorf("(*SARIFLog).Validate refused a legal record (%s): %v", name, err)
			}
		})
	}
}

// A file the record cannot audit is a file that may as well not be listed.
func TestSpecHarvestFileRefusesUnauditableBytes(t *testing.T) {
	cases := map[string]struct {
		mutate func(*SpecHarvestFile)
		why    string
	}{
		"no uri": {
			func(f *SpecHarvestFile) { f.Location.URI = "" },
			"a harvested file nobody can name is a file no operator can go look at",
		},
		"no digest": {
			func(f *SpecHarvestFile) { f.ContentSHA256 = "" },
			"without a digest the record cannot say WHICH bytes the DAST tier parsed",
		},
		"uppercase digest": {
			func(f *SpecHarvestFile) { f.ContentSHA256 = strings.ToUpper(f.ContentSHA256) },
			"uppercase hex is rejected rather than folded, as everywhere else in this package",
		},
		"truncated digest": {
			func(f *SpecHarvestFile) { f.ContentSHA256 = f.ContentSHA256[:32] },
			"a digest is never truncated",
		},
		"negative size": {
			func(f *SpecHarvestFile) { f.SizeBytes = -1; f.Content = nil },
			"a file's length cannot be negative",
		},
		"inline content shorter than sizeBytes": {
			func(f *SpecHarvestFile) { f.Content = &ArtifactContent{Text: "op"} },
			"a silently truncated spec yields a short route list, which is a SMALLER " +
				"coverage denominator, which makes endpoint_coverage look better than it is",
		},
		"inline content longer than sizeBytes": {
			func(f *SpecHarvestFile) { f.SizeBytes = 2 },
			"the same defect from the other side",
		},
		"anvil_generated trust": {
			func(f *SpecHarvestFile) { f.Trust = TrustAnvilGenerated },
			"a spec file committed to the target repository is external text whatever Anvil " +
				"did to assemble the struct around it -- the exact mislabelling found in Lane B",
		},
		"empty trust": {
			func(f *SpecHarvestFile) { f.Trust = "" },
			"a zero-valued Go string must not pass as \"unset but fine\"",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := chFile()
			c.mutate(&f)
			h := &SpecHarvest{
				Outcome:          SpecHarvestRan,
				Files:            []SpecHarvestFile{f},
				OmittedFileCount: chInt(0),
			}
			if err := ValidateSpecHarvest(h); err == nil {
				t.Errorf("ValidateSpecHarvest accepted a file with %s: %s", name, c.why)
			}
			l := chLog(HalfSast)
			l.Runs[0].Properties.SpecHarvest = h
			if err := l.Validate(); err == nil {
				t.Errorf("(*SARIFLog).Validate accepted a file with %s", name)
			}
		})
	}

	// POSITIVE CONTROLS. The unmutated file validates, and so does the same file
	// with its bytes elided -- eliding content is legal, corrupting the digest
	// is not, and a gate that could not tell those apart would refuse every
	// record that does not inline the repository.
	t.Run("positive control/inline content", func(t *testing.T) {
		h := &SpecHarvest{Outcome: SpecHarvestRan, Files: []SpecHarvestFile{chFile()}, OmittedFileCount: chInt(0)}
		if err := ValidateSpecHarvest(h); err != nil {
			t.Errorf("the unmutated fixture was refused: %v", err)
		}
	})
	t.Run("positive control/content elided", func(t *testing.T) {
		f := chFile()
		f.Content = nil
		h := &SpecHarvest{Outcome: SpecHarvestRan, Files: []SpecHarvestFile{f}, OmittedFileCount: chInt(0)}
		if err := ValidateSpecHarvest(h); err != nil {
			t.Errorf("a file whose bytes are elided but whose digest and size stand was "+
				"refused: %v", err)
		}
	})
	t.Run("positive control/zero-byte spec file", func(t *testing.T) {
		// A repository MAY commit a zero-byte openapi.yaml. Refusing to record
		// that would delete the file from the harvest list, which is the silent
		// loss this struct exists to prevent.
		sum := sha256.Sum256(nil)
		f := SpecHarvestFile{
			Location:      ArtifactLocation{URI: "openapi.yaml"},
			SizeBytes:     0,
			ContentSHA256: hex.EncodeToString(sum[:]),
			Content:       &ArtifactContent{Text: ""},
			Trust:         TrustUntrusted,
		}
		h := &SpecHarvest{Outcome: SpecHarvestRan, Files: []SpecHarvestFile{f}, OmittedFileCount: chInt(0)}
		if err := ValidateSpecHarvest(h); err != nil {
			t.Errorf("a zero-byte committed spec file was refused: %v. It is a true fact "+
				"about the repository and dropping it shrinks the coverage denominator", err)
		}
	})
}

// One durable statement of one fact. plan/design/dynamic-tier.md:628-630 assigns spec
// harvesting to the SAST tier and forbids the DAST tier from re-deriving it, so
// a copy on the DAST run is a second durable copy that can disagree with the
// first -- the shape the spine's corrected-requirements table and the
// one-ledger ruling both refuse.
func TestSpecHarvestIsRefusedOnTheDastRun(t *testing.T) {
	legal := &SpecHarvest{Outcome: SpecHarvestRan, Files: []SpecHarvestFile{}, OmittedFileCount: chInt(0)}

	dast := chLog(HalfDast)
	dast.Runs[0].Properties.SpecHarvest = legal
	if err := dast.Validate(); err == nil {
		t.Errorf("%s was accepted on the DAST run. The DAST tier may not harvest spec files "+
			"(plan/design/dynamic-tier.md:628-630), so a statement here is a second durable copy of the "+
			"SAST half's fact, and two copies drift", PropRunSpecHarvest)
	}

	// POSITIVE CONTROL: the same value on the SAST run is legal, and the DAST
	// run without it is legal. Without these two the assertion above would pass
	// for a validator that refused every DAST run outright.
	sast := chLog(HalfSast)
	sast.Runs[0].Properties.SpecHarvest = legal
	if err := sast.Validate(); err != nil {
		t.Errorf("the same harvest on the SAST run was refused: %v", err)
	}
	if err := chLog(HalfDast).Validate(); err != nil {
		t.Errorf("a DAST run carrying no spec harvest was refused: %v", err)
	}
}

// ===========================================================================
// anvil/advisory.licenseManualNote -- the spine's quoted operative sentence
// ===========================================================================

// chAdvisoryResult is the smallest SAST result that passes (*Result).validate,
// carrying an advisory context to hang the licence note on.
func chAdvisoryResult() *Result {
	return &Result{
		PartialFingerprints: map[string]string{
			PartialFingerprintAnvilFindingID: strings.Repeat("a", FingerprintDigestHexLen),
		},
		Properties: ResultProperties{
			FindingID:     "finding-0001",
			Half:          HalfSast,
			Confidence:    0.9,
			Verdict:       VerdictTruePositive,
			EvidenceClass: EvidenceClassSCA,
			Detector:      DetectorRef{Kind: DetectorKindSCA},
			Trust:         TrustAssertion{Default: TrustUntrusted},
			Advisory: &AdvisoryContext{
				IDs: []string{"CVE-2026-0001"},
				// An empty ARRAY, not null: `cveIds` is a required array on the
				// wire, and a fixture that marshals it as null would not be the
				// record any producer emits.
				CveIDs:         []string{},
				SourceFeed:     "cisa-kev",
				SnapshotDigest: strings.Repeat("b", FingerprintDigestHexLen),
				LicenseSpdx:    "NOASSERTION",
				AsOf:           time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC),
			},
		},
	}
}

// The Lane A chain ledger records the licence gate admitting the KEV metadata
// override ON THE STRENGTH OF A MANUAL NOTE. Before this slot existed the note
// stopped at internal/ingest and the text it licenses travelled on alone, which
// puts the redistribution terms and the redistributed bytes in two places.
func TestLicenseManualNoteTravelsWithTheTextItLicenses(t *testing.T) {
	r := chAdvisoryResult()
	const operative = "This work is in the public domain under CC0 1.0 per the publisher's README."
	r.Properties.Advisory.LicenseManualNote = &TrustedString{
		Text:  operative,
		Trust: TrustUntrusted,
	}
	if err := r.validate(HalfSast); err != nil {
		t.Fatalf("a result carrying a legal manual note was rejected: %v", err)
	}

	encoded, err := json.Marshal(r.Properties.Advisory)
	if err != nil {
		t.Fatalf("marshal advisory: %v", err)
	}
	if !strings.Contains(string(encoded), `"licenseManualNote"`) {
		t.Errorf("the advisory context does not carry a licenseManualNote key on the wire; "+
			"the note does not survive into the record.\n  %s", encoded)
	}
	if !strings.Contains(string(encoded), operative) {
		t.Errorf("the operative sentence is not in the serialised advisory context.\n  %s", encoded)
	}

	// It must not have been smuggled into the identifier field.
	if got := r.Properties.Advisory.LicenseSpdx; got != "NOASSERTION" {
		t.Errorf("licenseSpdx = %q; the note belongs beside it, never inside it -- "+
			"licenseSpdx is an identifier field and prose corrupts it", got)
	}

	// Round-trip: a consumer reading the record back gets the same sentence.
	var back AdvisoryContext
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("unmarshal advisory: %v", err)
	}
	if back.LicenseManualNote == nil {
		t.Fatal("the manual note did not survive a JSON round trip")
	}
	if back.LicenseManualNote.Text != operative {
		t.Errorf("round-tripped note = %q, want %q", back.LicenseManualNote.Text, operative)
	}
	if back.LicenseManualNote.Trust != TrustUntrusted {
		t.Errorf("round-tripped trust = %q, want %q", back.LicenseManualNote.Trust, TrustUntrusted)
	}
}

func TestLicenseManualNoteRefusesTheAbsentValueInLegitimateClothes(t *testing.T) {
	refused := map[string]struct {
		note *TrustedString
		why  string
	}{
		"empty text": {
			&TrustedString{Text: "", Trust: TrustUntrusted},
			"a present note carrying nothing satisfies \"a note exists\" while establishing " +
				"nothing, which is exactly the reading the spine's licence section needs to be impossible",
		},
		"whitespace text": {
			&TrustedString{Text: "   \t\n ", Trust: TrustUntrusted},
			"the ingestion cache enforces length(trim(license_manual_note)) > 0 in SQL; " +
				"the record must not admit what the store refuses",
		},
		"anvil_generated": {
			&TrustedString{Text: "Public domain.", Trust: TrustAnvilGenerated},
			"the note is a QUOTATION from a publisher's LICENSE file; transcribing bytes is " +
				"not authoring them",
		},
		"unset trust": {
			&TrustedString{Text: "Public domain."},
			"a zero-valued Trust must not pass as a classification",
		},
	}
	for name, c := range refused {
		t.Run("refused/"+name, func(t *testing.T) {
			r := chAdvisoryResult()
			r.Properties.Advisory.LicenseManualNote = c.note
			if err := r.validate(HalfSast); err == nil {
				t.Errorf("a manual note with %s was accepted: %s", name, c.why)
			}
		})
	}

	// POSITIVE CONTROLS. Both legal external classifications pass, and so does
	// an absent note -- the record is not the spine's licence section
	// enforcement point (that ruling stands), so a finding whose SPDX id
	// resolves owes no note at all.
	for _, trust := range []Trust{TrustUntrusted, TrustVerified} {
		t.Run("admitted/"+string(trust), func(t *testing.T) {
			r := chAdvisoryResult()
			r.Properties.Advisory.LicenseManualNote = &TrustedString{
				Text: "Redistribution permitted with attribution.", Trust: trust,
			}
			if trust == TrustVerified {
				r.Properties.Trust.ValidationStep = "signature-checked feed snapshot"
			}
			if err := r.validate(HalfSast); err != nil {
				t.Errorf("a note classified %q was refused: %v", trust, err)
			}
		})
	}
	t.Run("admitted/no note at all", func(t *testing.T) {
		r := chAdvisoryResult()
		r.Properties.Advisory.LicenseSpdx = "CC-BY-4.0"
		if err := r.validate(HalfSast); err != nil {
			t.Errorf("a finding whose SPDX id resolves, carrying no manual note, was "+
				"refused: %v. The record does not enforce the spine's licence section -- the CI gate does -- and "+
				"refusing here would be this area claiming a subject that is not its own", err)
		}
	})
}

// TestVerifiedNamesItsValidationStep is plan node contractgaps' trust-validation
// slot. TrustVerified means "passed an explicit validation step that is named
// in the record", so every `verified` label — default, per-field or inline —
// needs anvil/trust.validationStep, and a step with nothing verified is refused.
func TestVerifiedNamesItsValidationStep(t *testing.T) {
	const step = "signature-checked feed snapshot"
	cases := []struct {
		name    string
		mutate  func(r *Result)
		wantErr bool
	}{
		{"nothing verified, no step", func(r *Result) {}, false},
		{"nothing verified, a step anyway", func(r *Result) { r.Properties.Trust.ValidationStep = step }, true},
		{"verified excerpt, no step", func(r *Result) {
			r.Properties.Advisory.Excerpt = &TrustedString{Text: "x", Trust: TrustVerified}
		}, true},
		{"verified excerpt, blank step", func(r *Result) {
			r.Properties.Advisory.Excerpt = &TrustedString{Text: "x", Trust: TrustVerified}
			r.Properties.Trust.ValidationStep = "   "
		}, true},
		{"verified excerpt, named step", func(r *Result) {
			r.Properties.Advisory.Excerpt = &TrustedString{Text: "x", Trust: TrustVerified}
			r.Properties.Trust.ValidationStep = step
		}, false},
		{"verified licence note, no step", func(r *Result) {
			r.Properties.Advisory.LicenseManualNote = &TrustedString{Text: "x", Trust: TrustVerified}
		}, true},
		{"verified default, no step", func(r *Result) { r.Properties.Trust.Default = TrustVerified }, true},
		{"verified field, no step", func(r *Result) {
			r.Properties.Trust.Fields = map[string]Trust{"/message/text": TrustVerified}
		}, true},
		{"verified field, named step", func(r *Result) {
			r.Properties.Trust.Fields = map[string]Trust{"/message/text": TrustVerified}
			r.Properties.Trust.ValidationStep = step
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := chAdvisoryResult()
			c.mutate(r)
			err := ValidateResultTrust(r)
			if c.wantErr && err == nil {
				t.Error("accepted")
			}
			if !c.wantErr && err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}

	// The step reaches the wire.
	r := chAdvisoryResult()
	r.Properties.Trust.Default = TrustVerified
	r.Properties.Trust.ValidationStep = step
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"validationStep":"`+step+`"`) {
		t.Errorf("validationStep did not reach the serialised bytes: %s", raw)
	}
}

// TestProvisioningIsAbsentExactlyWhenNoTargetWasDeclared: both provisioning
// literals describe how a runtime target came to exist, so an audit that
// declared none must carry neither, and an audit that declared one must carry
// one. Plan node cli's first end-to-end run found the contract demanding a
// false value for every core-only audit.
func TestProvisioningIsAbsentExactlyWhenNoTargetWasDeclared(t *testing.T) {
	check := func(prov TargetProvenance, p TargetProvisioning) error {
		l := validLogForTargetTest()
		l.Properties.Target.Provenance = prov
		l.Properties.Target.Provisioning = p
		return l.Validate()
	}
	if err := check(TargetProvenanceNoTargetDeclared, ""); err != nil {
		t.Errorf("no target declared, no provisioning: refused: %v", err)
	}
	if err := check(TargetProvenanceNoTargetDeclared, TargetProvisioningEphemeralManifest); err == nil {
		t.Error("no target declared but a provisioning path claimed: accepted")
	}
	if err := check(TargetProvenanceBootedClean, ""); err == nil {
		t.Error("a booted target with no provisioning path: accepted")
	}
	if err := check(TargetProvenanceBootedClean, TargetProvisioningLiveURLAuthorized); err != nil {
		t.Errorf("a booted target with a provisioning path: refused: %v", err)
	}
}

// validLogForTargetTest is a sealed, DAST-disabled audit with no results.
func validLogForTargetTest() *SARIFLog {
	created := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	sealed := created.Add(time.Minute)
	return &SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Properties: AuditProperties{
			SchemaVersion: SchemaVersion,
			AuditID:       "aud-target-test",
			State:         StateBothSealed,
			Version:       1,
			CreatedAt:     created,
			DastStatus:    DastStatusNotRun,
			Deadline: Deadline{
				DeadlineAt:          created.Add(DefaultClaimTimeoutSeconds * time.Second),
				ClaimTimeoutSeconds: DefaultClaimTimeoutSeconds,
			},
		},
		Runs: []Run{{
			AutomationDetails: RunAutomationDetails{CorrelationGUID: "aud-target-test"},
			Results:           []Result{},
			Properties:        RunProperties{Half: HalfSast, Status: HalfStatusSealed, SealedAt: &sealed},
		}},
	}
}

// The verdict vocabulary lives in five places: contract.go, the wire schema, the store's CHECK
// constraint (internal/store's TestEnumCheckConstraintsMatchContractLiteralForLiteral),
// CONTRACT.md and the consumption routing in taskcard.go. This pins the wire schema and the
// document to contract.go, so a value added in one place cannot be half landed.
func TestVerdictVocabularyAgreesAcrossContractSchemaAndDoc(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "anvil-record-v1.schema.json"))
	if err != nil {
		t.Fatalf("read the wire schema: %v", err)
	}
	var doc struct {
		Defs map[string]struct {
			Enum []string `json:"enum"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse the wire schema: %v", err)
	}
	var want []string
	for _, v := range VerdictValues() {
		want = append(want, string(v))
	}
	if got := doc.Defs["verdict"].Enum; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("wire schema anvil/verdict enum %q, contract.go %q", got, want)
	}
	md, err := os.ReadFile("CONTRACT.md")
	if err != nil {
		t.Fatalf("read CONTRACT.md: %v", err)
	}
	if line := "`" + strings.Join(want, " | ") + "`"; !strings.Contains(string(md), line) {
		t.Errorf("CONTRACT.md section 1.6 does not list %s", line)
	}
}

// After the gate decision (plan node gate), a Lane B finding is a rule match nobody has judged.
// It must not be handed to the coding agent as actionable, and the card must say that the
// triage gate decides it: neither dropped nor report-only.
func TestAnUnconfirmedFindingWaitsForTheTriageGate(t *testing.T) {
	r := Result{Properties: ResultProperties{
		Verdict: VerdictUnconfirmed, RemediableByAgent: true,
		Detector: DetectorRef{Kind: DetectorKindSast},
	}}
	if isActionable(&r) {
		t.Fatal("an unconfirmed finding is actionable before the triage gate has judged it")
	}
	blockers := strings.Join(actionBlockers(&r), "; ")
	if !strings.Contains(blockers, "triage gate") || strings.Contains(blockers, "report-only") {
		t.Errorf("blockers %q must name the triage gate and must not demote to report-only", blockers)
	}
}

// TestARuleReferenceMustResolveToCompleteProvenance holds record 1.1.0's one
// rule: a result that cites a rule through result.rule names a tool extension
// that holds it, agrees with ruleId, and the rule states its provenance in
// full. A result with no result.rule is a 1.0.0 shape and stays valid.
func TestARuleReferenceMustResolveToCompleteProvenance(t *testing.T) {
	zero, one := 0, 1
	prov := func() *RuleProvenance {
		return &RuleProvenance{Source: "gosec", Repository: "https://github.com/securego/gosec", Version: "2.29.0",
			RulePath: "gosec:G204", LicenseSpdx: "Apache-2.0", LicenseEvidence: "LICENSE.txt"}
	}
	build := func(edit func(*Run, *Result)) error {
		run := Run{Tool: Tool{Extensions: []ToolComponent{{Name: "gosec", Rules: []ReportingDescriptor{
			{ID: "gosec/G204@2.29.0", Properties: &RuleProperties{RuleProvenance: prov()}},
		}}}}}
		res := Result{RuleID: "gosec/G204@2.29.0", Rule: &ReportingDescriptorReference{
			ID: "gosec/G204@2.29.0", ToolComponent: &ToolComponentRef{Index: &zero}}}
		edit(&run, &res)
		return run.resolveRule(&res)
	}
	if err := build(func(*Run, *Result) {}); err != nil {
		t.Fatalf("a resolvable rule was refused: %v", err)
	}
	if err := build(func(_ *Run, r *Result) { r.Rule = nil }); err != nil {
		t.Fatalf("a 1.0.0 result with no result.rule was refused: %v", err)
	}
	for name, edit := range map[string]func(*Run, *Result){
		"no extension index":    func(_ *Run, r *Result) { r.Rule.ToolComponent = nil },
		"an index past the end": func(_ *Run, r *Result) { r.Rule.ToolComponent.Index = &one },
		"ruleId disagrees":      func(_ *Run, r *Result) { r.RuleID = "gosec/G101@2.29.0" },
		"no such rule":          func(run *Run, _ *Result) { run.Tool.Extensions[0].Rules[0].ID = "other" },
		"no provenance":         func(run *Run, _ *Result) { run.Tool.Extensions[0].Rules[0].Properties = nil },
		"a blank licence evidence": func(run *Run, _ *Result) {
			run.Tool.Extensions[0].Rules[0].Properties.RuleProvenance.LicenseEvidence = " "
		},
		"a blank repository": func(run *Run, _ *Result) { run.Tool.Extensions[0].Rules[0].Properties.RuleProvenance.Repository = "" },
	} {
		if err := build(edit); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestTheSchemaNamesTheContractVersion: the wire schema's contract version is
// the record's anvil/schemaVersion, so a change to one is a change to both.
func TestTheSchemaNamesTheContractVersion(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", "anvil-record-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"x-anvil-contractVersion"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != SchemaVersion {
		t.Fatalf("the wire schema is contract version %q, the record writes %q", doc.Version, SchemaVersion)
	}
}
