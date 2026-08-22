// Tests for A.19's record emission.
//
// ===========================================================================
// WHAT THESE TESTS ARE BUILT TO CATCH, AND WHERE THEIR INPUTS COME FROM
// ===========================================================================
//
// Two properties are load-bearing and A.20 exists to attack them:
//
//  1. remediable_by_agent is FALSE for every host finding, with no code path,
//     flag or config key able to override it. It is an authorization decision
//     gating what a repo-credentialed coding agent may act on.
//  2. anvil/trust is correct on every string originating outside Anvil.
//
// So property 1 is tested EXHAUSTIVELY over the whole input space of the
// function that computes it (TestRemediableByAgentIsAnAllowlistOverItsWholeInputSpace),
// then again END TO END on the SERIALISED BYTES of every shape that leaves
// this package, and then again on the task card — the artifact that actually
// reaches the agent. Testing the struct field alone is what A.12 found
// insufficient one lane over.
//
// THE FINGERPRINT CORPUS IS NOT THIS PACKAGE'S. TestEmittedFingerprintMatches
// TheFrozenConformanceGoldens reads testdata/fingerprint_corpus/*.json for its
// inputs and *.golden for its expected digests. Those goldens were produced by
// scripts/compute_golden_fingerprints.py — an implementation of
// FINGERPRINT-SPEC.md written WITHOUT reading internal/record/fingerprint.go —
// so the test proves this package emits the canonical digest rather than
// proving it agrees with itself. A test whose corpus comes from the
// implementation is not a test.
//
// EVERY GUARD IS DRIVEN RED. TestEveryRefusalReasonIsReachable drives all
// eighteen refusal reasons and fails if any one of them cannot be provoked; a
// guard that has never failed has not been tested.
//
// ===========================================================================
// NO TEST HERE MAY USE AN INPUT FIELD AS ITS OWN EXPECTED VALUE
// ===========================================================================
//
// A.20 found two tests in this file that could not fail for the reason they
// claimed. The staleness test set `StalenessSeconds` on the input row and
// asserted the same number came out, which proves copy-through and nothing
// else — and copy-through was the defect. Its "fresh" control was worse: it
// depended on the wall-clock distance to a hard-coded fixture date, so it would
// have started failing on a calendar day rather than on a code change.
//
// So `advisory.staleness_seconds` is now a DECOY in the fixtures
// (fixturePublisherLag), deliberately unlike anything the record should carry,
// and the emitted interval is asserted against arithmetic the test states
// itself: a watermark and an assembly instant chosen here, subtracted here.
// Nothing in the assertion comes from the code under test.
package lanea

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/match"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Fixtures
//
// The strings below are deliberately DISTINCTIVE so that
// TestReasoningCarriesNoByteFromOutsideAnvil can look for them: a package
// named "openssl" would be indistinguishable from prose about openssl.
// ---------------------------------------------------------------------------

const (
	fixtureTargetID   = "t-lanea-0001"
	fixtureHostPkg    = "zzhostpkgqx"
	fixtureRepoPkg    = "zzrepopkgqx"
	fixtureHostVer    = "9.9.9zzverqx-1"
	fixtureRepoVer    = "4.4.4zzverqx"
	fixtureExcerpt    = "ZZEXCERPTQX advisory prose that originated outside Anvil."
	fixtureManualNote = "ZZLICENCEQX: \"You may redistribute this database under the ODbL.\""
	fixtureManifest   = "services/zzmanifestqx/pom.xml"

	// fixtureValidationStep names the explicit validation step a row
	// asserting `verified` has to point at. record.Trust says that value
	// means bytes that "passed an explicit validation step that is named in
	// the record ... Never a default", so a fixture that sets `verified`
	// without one is a fixture the emitter refuses.
	fixtureValidationStep = "zzstepqx: detached OpenPGP signature over the snapshot"
)

// fixtureWatermark is the `advisory.as_of` cache watermark every fixture row
// carries. It is in the past and is never "now": the whole point of as_of is
// that it is not the emission instant.
var fixtureWatermark = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

// fixtureAssemblyLagSeconds is the interval the default fixtures span, and
// fixtureAssembledAt is the record-assembly instant that produces it. Both are
// fixed constants, so every default emission carries stalenessSeconds = 3600
// on every calendar day this suite is ever run.
const fixtureAssemblyLagSeconds = 3600

var fixtureAssembledAt = fixtureWatermark.Add(fixtureAssemblyLagSeconds * time.Second)

// fixturePublisherLag is `advisory.staleness_seconds`: the publisher lag
// ingestion stamped at write time.
//
// IT IS A DECOY AND THAT IS ITS WHOLE JOB. The record's staleness_seconds is a
// different quantity — assembly time minus as_of — and this value is chosen to
// resemble it in no way at all. Any assertion in this file that passes while
// this number is being copied onto the record is an assertion that has stopped
// testing anything, and several of them fail loudly if it is.
const fixturePublisherLag = 1234567

func hostMatch() match.MatchResult {
	return match.MatchResult{
		Source:                 "ubuntu",
		SourceID:               "USN-9999-1",
		CVEID:                  "CVE-2026-99999",
		Collector:              match.CollectorHost,
		Ecosystem:              match.EcosystemDeb,
		Scheme:                 match.SchemeDebian,
		Package:                fixtureHostPkg,
		Purl:                   "pkg:deb/ubuntu/" + fixtureHostPkg,
		Arch:                   "amd64",
		InstalledVersion:       fixtureHostVer,
		MatchedRange:           "[0, 9.9.9zzverqx-2)",
		FixedVersion:           "9.9.9zzverqx-2",
		VendorAdvisory:         true,
		DistroBackportDefended: true,
		Detector:               record.DetectorKindHost,
		EvidenceClass:          record.EvidenceClassHost,
		Trust:                  record.TrustAnvilGenerated,
		RemediableByAgent:      false,
	}
}

func repoMatch() match.MatchResult {
	return match.MatchResult{
		Source:            "ghsa",
		SourceID:          "GHSA-zzzz-qqqq-xxxx",
		Collector:         match.CollectorRepoSCA,
		Ecosystem:         "maven",
		Package:           fixtureRepoPkg,
		Purl:              "pkg:maven/org.zzrepoqx/" + fixtureRepoPkg + "@" + fixtureRepoVer,
		ManifestRelPath:   fixtureManifest,
		InstalledVersion:  fixtureRepoVer,
		MatchedRange:      "[4.0.0, 4.5.0)",
		FixedVersion:      "4.5.0",
		Detector:          record.DetectorKindSCA,
		EvidenceClass:     record.EvidenceClassSCA,
		Trust:             record.TrustAnvilGenerated,
		RemediableByAgent: true,
	}
}

func hostRow() AdvisoryRow {
	return AdvisoryRow{
		Source:              "ubuntu",
		SourceID:            "USN-9999-1",
		CVEID:               "CVE-2026-99999",
		FeedID:              "ubuntu-usn",
		SnapshotDigest:      "sha256:zzsnapshotqx",
		LicenseSPDX:         "LicenseRef-ubuntu-usn",
		LicenseManualNote:   fixtureManualNote,
		Trust:               record.TrustUntrusted,
		AsOf:                fixtureWatermark,
		StalenessSeconds:    fixturePublisherLag,
		FreshnessSLOSeconds: 86400,
		ExcerptText:         fixtureExcerpt,
	}
}

func repoRow() AdvisoryRow {
	return AdvisoryRow{
		Source:              "ghsa",
		SourceID:            "GHSA-zzzz-qqqq-xxxx",
		FeedID:              "ghsa",
		SnapshotDigest:      "sha256:zzsnapshotqx",
		LicenseSPDX:         "CC-BY-4.0",
		Trust:               record.TrustUntrusted,
		AsOf:                fixtureWatermark,
		StalenessSeconds:    fixturePublisherLag,
		FreshnessSLOSeconds: 86400,
		ExcerptText:         fixtureExcerpt,
	}
}

// emitter is the fixture Emitter. It carries a FIXED assembly instant: the
// package holds no clock, the caller owns the one it uses, and a test that let
// that instant be "now" would be a test whose expected values change daily.
func emitter() Emitter {
	return Emitter{TargetID: fixtureTargetID, AssembledAt: fixtureAssembledAt}
}

func mustEmit(t *testing.T, m match.MatchResult, a AdvisoryRow) Emission {
	t.Helper()
	em, err := emitter().Emit(m, a)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	return em
}

// ---------------------------------------------------------------------------
// PROPERTY 1 — remediable_by_agent
// ---------------------------------------------------------------------------

// TestRemediableByAgentIsAnAllowlistOverItsWholeInputSpace enumerates the
// ENTIRE input space of the one function that computes the flag and asserts
// the guarantee on every point of it. There are no untested combinations left
// for a config key or a future collector to hide in.
//
// THE ECOSYSTEM IS ONE OF THE ENUMERATED DIMENSIONS. A.20 found it missing:
// the other four arms were covered exhaustively while an OS package arriving
// under the repo-SCA label went through as agent-fixable. The enumeration below
// includes the three host ecosystems, three repository ones, the empty string
// and a near-miss capitalisation, so the arm is allowlisted over its whole
// space rather than spot-checked.
func TestRemediableByAgentIsAnAllowlistOverItsWholeInputSpace(t *testing.T) {
	collectors := []string{
		match.CollectorHost, match.CollectorRepoSCA,
		"", "HOST", "host ", "repo_sca", "sbom", "container", "anything-new",
	}
	kinds := append(record.DetectorKindValues(), record.DetectorKind(""), record.DetectorKind("HOST"))
	classes := append(record.EvidenceClassValues(), record.EvidenceClass(""), record.EvidenceClass("Host"))
	ecosystems := []string{
		match.EcosystemDeb, match.EcosystemRPM, match.EcosystemAPK,
		"maven", "npm", "pypi", "", "DEB",
	}
	fixed := []string{"", "1.2.3"}
	degraded := []bool{false, true}

	trueCount, hostEcoPoints, points := 0, 0, 0
	for _, c := range collectors {
		for _, k := range kinds {
			for _, cl := range classes {
				for _, eco := range ecosystems {
					for _, f := range fixed {
						for _, d := range degraded {
							got := remediableByAgent(c, k, cl, eco, f, d)
							points++

							// THE HOST RULE, from all FOUR directions: the
							// collector that found it, the two frozen enums,
							// and the ecosystem of the thing itself.
							hostEco := eco == match.EcosystemDeb ||
								eco == match.EcosystemRPM || eco == match.EcosystemAPK
							if c == match.CollectorHost || k == record.DetectorKindHost ||
								cl == record.EvidenceClassHost || hostEco {
								if hostEco {
									hostEcoPoints++
								}
								if got {
									t.Fatalf("remediableByAgent(%q,%q,%q,%q,%q,%t) = true; "+
										"an OS package is not agent-fixable and a host finding is "+
										"never remediable (00-SPINE.md S7)",
										c, k, cl, eco, f, d)
								}
								continue
							}

							// THE ALLOWLIST: true on exactly one shape.
							want := c == match.CollectorRepoSCA &&
								k == record.DetectorKindSCA &&
								cl == record.EvidenceClassSCA &&
								f != "" && !d
							if got != want {
								t.Fatalf("remediableByAgent(%q,%q,%q,%q,%q,%t) = %t, want %t",
									c, k, cl, eco, f, d, got, want)
							}
							if got {
								trueCount++
							}
						}
					}
				}
			}
		}
	}
	if trueCount == 0 {
		t.Fatal("no input produced true; a guard that can never say yes has not been exercised")
	}
	if hostEcoPoints == 0 {
		t.Fatal("no point of the space carried a host ecosystem, so the arm A.20 found " +
			"missing is still not covered")
	}
	if want := len(collectors) * len(kinds) * len(classes) * len(ecosystems) * len(fixed) * len(degraded); points != want {
		t.Fatalf("enumerated %d points, want %d; the space is not being walked whole", points, want)
	}
}

// TestAnOSPackageUnderTheRepoLabelIsNotRemediableInTheSERIALISEDBytes is A.20's
// finding 2, end to end.
//
// A repo-SCA MatchResult whose ecosystem is deb, rpm or apk is an OS package
// that a repository collector noticed. The coding agent's write surface is the
// git repository either way, so it cannot bump an apt package however the
// finding was labelled — and being handed "bump openssl in Dockerfile" as
// actionable work is the same authorization defect S7 exists to prevent.
//
// The path is unreachable today only because internal/collector/repo refuses
// Trivy's os-pkgs class. That is one lane up. This asserts it here.
func TestAnOSPackageUnderTheRepoLabelIsNotRemediableInTheSERIALISEDBytes(t *testing.T) {
	for _, eco := range []string{match.EcosystemDeb, match.EcosystemRPM, match.EcosystemAPK} {
		t.Run(eco, func(t *testing.T) {
			m := repoMatch()
			m.Ecosystem = eco
			m.Purl = "pkg:" + eco + "/vendor/" + fixtureRepoPkg + "@" + fixtureRepoVer
			m.RemediableByAgent = true // the most hostile input available

			em := mustEmit(t, m, repoRow())

			if em.Result.Properties.RemediableByAgent {
				t.Error("an OS package under the repo-sca label was emitted as agent-remediable")
			}
			if em.RemediableByAgent() {
				t.Error("Emission.RemediableByAgent() = true for an OS package")
			}
			assertJSONBool(t, em, "remediableByAgent", false)
			assertJSONBool(t, em, "result/properties/anvil~1remediableByAgent", false)
			assertJSONBool(t, em.Result, "properties/anvil~1remediableByAgent", false)
			assertJSONBool(t, Results([]Emission{em})[0], "properties/anvil~1remediableByAgent", false)
		})
	}

	// THE CONTROL: the same match in a repository ecosystem IS remediable, so
	// the arm above is shown to refuse the OS packages rather than everything.
	control := mustEmit(t, repoMatch(), repoRow())
	if !control.RemediableByAgent() {
		t.Fatal("a maven dependency with a named fixed version is not remediable; the ecosystem " +
			"arm is refusing everything and proves nothing")
	}
	assertJSONBool(t, control, "remediableByAgent", true)
}

// TestHostFindingsAreNeverRemediableInTheSERIALISEDBytes is the end-to-end
// half. It varies every host-side input that could plausibly be argued into
// flipping the flag — a named fixed version, a vendor advisory, a defended
// backport, a degraded parse, a verified feed, an arch — and asserts the
// answer in the BYTES of every shape that leaves this package.
func TestHostFindingsAreNeverRemediableInTheSERIALISEDBytes(t *testing.T) {
	fixedVersions := []string{"", "9.9.9zzverqx-2"}
	vendor := []bool{false, true}
	degraded := []bool{false, true}
	trusts := []record.Trust{record.TrustUntrusted, record.TrustVerified}
	arches := []string{"", "amd64", "i386"}

	seen := 0
	for _, fv := range fixedVersions {
		for _, v := range vendor {
			for _, d := range degraded {
				for _, tr := range trusts {
					for _, arch := range arches {
						m := hostMatch()
						m.FixedVersion = fv
						m.VendorAdvisory = v
						m.DistroBackportDefended = v
						m.Arch = arch
						// The most hostile input available: a MatchResult
						// that ASSERTS it is remediable.
						m.RemediableByAgent = true

						a := hostRow()
						a.ParseDegraded = d
						a.Trust = tr
						if tr == record.TrustVerified {
							a.TrustValidationStep = fixtureValidationStep
						}

						em := mustEmit(t, m, a)
						seen++

						if em.Result.Properties.RemediableByAgent {
							t.Fatalf("host finding emitted RemediableByAgent=true (fixed=%q vendor=%t degraded=%t)",
								fv, v, d)
						}
						if em.RemediableByAgent() {
							t.Fatal("Emission.RemediableByAgent() = true for a host finding")
						}

						assertJSONBool(t, em.Result, "properties/anvil~1remediableByAgent", false)
						assertJSONBool(t, em, "remediableByAgent", false)
						// BOTH LEVELS of the crossing object, not just the
						// mirror: A.20 found them able to disagree.
						assertJSONBool(t, em, "result/properties/anvil~1remediableByAgent", false)
						assertJSONBool(t, Results([]Emission{em})[0],
							"properties/anvil~1remediableByAgent", false)
					}
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no host emission was exercised")
	}
}

// TestTheArtifactThatReachesTheAgentSaysHostIsNotActionable pushes emitted
// results through internal/record's OWN read path — the task card is what the
// coding agent actually receives — and asserts the host finding arrives not
// actionable, with a stated reason, while the repo dependency arrives
// actionable. A record-level flag that the card ignored would be a flag that
// never reached the boundary it exists to guard.
func TestTheArtifactThatReachesTheAgentSaysHostIsNotActionable(t *testing.T) {
	hostEm := mustEmit(t, hostMatch(), hostRow())
	repoEm := mustEmit(t, repoMatch(), repoRow())

	log := sealedLog(t, Results([]Emission{hostEm, repoEm}))
	cards, err := record.NewReader(nil).CardsFromLog(&log)
	if err != nil {
		t.Fatalf("CardsFromLog: %v", err)
	}
	if len(cards) != 2 {
		t.Fatalf("got %d cards, want 2", len(cards))
	}

	byID := map[string]record.TaskCard{}
	for _, c := range cards {
		byID[c.FindingID] = c
	}
	hostCard, ok := byID[hostEm.Result.Properties.FindingID]
	if !ok {
		t.Fatal("no card for the host finding")
	}
	repoCard, ok := byID[repoEm.Result.Properties.FindingID]
	if !ok {
		t.Fatal("no card for the repo finding")
	}

	if hostCard.RemediableByAgent {
		t.Error("the host TASK CARD says remediableByAgent=true")
	}
	if hostCard.Actionable {
		t.Error("the host TASK CARD is actionable")
	}
	if len(hostCard.ActionBlockers) == 0 {
		t.Error("the host card is not actionable and says nothing about why")
	}
	assertJSONBool(t, hostCard, "remediableByAgent", false)
	assertJSONBool(t, hostCard, "actionable", false)

	if !repoCard.RemediableByAgent || !repoCard.Actionable {
		t.Errorf("the repo dependency card is not actionable (remediable=%t actionable=%t blockers=%v); "+
			"a guard that refuses everything has not been shown to permit anything",
			repoCard.RemediableByAgent, repoCard.Actionable, repoCard.ActionBlockers)
	}
	assertJSONBool(t, repoCard, "remediableByAgent", true)
}

// TestParseDegradedDemotesARepoFindingRatherThanDroppingIt pins A.16's flag
// end to end: the finding is still emitted, it carries parseDegraded in the
// bytes, its verdict is insufficient_context (report-only, never dropped), and
// it is not offered to the agent.
func TestParseDegradedDemotesARepoFindingRatherThanDroppingIt(t *testing.T) {
	m := repoMatch()
	a := repoRow()
	a.ParseDegraded = true

	em := mustEmit(t, m, a)

	if em.Result.Properties.Verdict != record.VerdictInsufficientContext {
		t.Errorf("verdict = %q, want %q", em.Result.Properties.Verdict, record.VerdictInsufficientContext)
	}
	if em.Result.Properties.RemediableByAgent {
		t.Error("a partially-parsed advisory was offered to the agent as remediable")
	}
	assertJSONBool(t, em.Result, "properties/anvil~1advisory/parseDegraded", true)
	assertJSONBool(t, em.Result, "properties/anvil~1remediableByAgent", false)

	// And the undegraded control, so the demotion is shown to be caused by
	// the flag rather than by everything being demoted.
	clean := mustEmit(t, m, repoRow())
	if clean.Result.Properties.Verdict != record.VerdictTruePositive {
		t.Errorf("undegraded verdict = %q, want %q", clean.Result.Properties.Verdict, record.VerdictTruePositive)
	}
	if !clean.Result.Properties.RemediableByAgent {
		t.Error("an undegraded repo dependency with a fixed version is not remediable")
	}
}

// ---------------------------------------------------------------------------
// PROPERTY 2 — anvil/trust
// ---------------------------------------------------------------------------

// TestTrustDefaultIsUntrustedOnEveryEmission asserts the classification in the
// bytes, for both collectors: every string in a Lane A result came from
// outside Anvil except the reasoning.
func TestTrustDefaultIsUntrustedOnEveryEmission(t *testing.T) {
	for _, em := range []Emission{
		mustEmit(t, hostMatch(), hostRow()),
		mustEmit(t, repoMatch(), repoRow()),
	} {
		if got := em.Result.Properties.Trust.Default; got != record.TrustUntrusted {
			t.Fatalf("trust default = %q, want %q", got, record.TrustUntrusted)
		}
		assertJSONString(t, em.Result, "properties/anvil~1trust/default", string(record.TrustUntrusted))

		fields := em.Result.Properties.Trust.Fields
		if got := fields[reasoningPointer]; got != record.TrustAnvilGenerated {
			t.Fatalf("trust.fields[%q] = %q, want %q", reasoningPointer, got, record.TrustAnvilGenerated)
		}
		// Nothing else may claim anvil_generated.
		for ptr, tr := range fields {
			if tr == record.TrustAnvilGenerated && ptr != reasoningPointer {
				t.Fatalf("%s is classified %q; only the reasoning is Anvil's own", ptr, tr)
			}
		}
		if em.Result.Properties.Advisory.Excerpt.Trust != record.TrustUntrusted {
			t.Fatalf("the advisory excerpt is %q, not the row's own trust",
				em.Result.Properties.Advisory.Excerpt.Trust)
		}
		// record's own check, which is the one that caught area B.
		if err := record.ValidateResultTrust(&em.Result); err != nil {
			t.Fatalf("ValidateResultTrust: %v", err)
		}
	}
}

// TestReasoningCarriesNoByteFromOutsideAnvil is the empirical half of the
// anvil_generated claim. Every distinctive external string in the fixtures is
// searched for in the one field labelled Anvil's own.
func TestReasoningCarriesNoByteFromOutsideAnvil(t *testing.T) {
	external := []string{
		fixtureHostPkg, fixtureRepoPkg, fixtureHostVer, fixtureRepoVer,
		fixtureExcerpt, fixtureManualNote, fixtureManifest,
		"CVE-2026-99999", "GHSA-zzzz-qqqq-xxxx", "USN-9999-1",
		"ubuntu", "ghsa", "amd64", "LicenseRef-ubuntu-usn", "CC-BY-4.0",
		"pkg:deb/ubuntu/", "pkg:maven/",
	}
	for _, em := range []Emission{
		mustEmit(t, hostMatch(), hostRow()),
		mustEmit(t, repoMatch(), repoRow()),
	} {
		reasoning := em.Result.Properties.Reasoning
		if reasoning == "" {
			t.Fatal("empty reasoning labelled anvil_generated")
		}
		for _, s := range external {
			if strings.Contains(reasoning, s) {
				t.Fatalf("the anvil_generated reasoning contains the external string %q: %q", s, reasoning)
			}
		}
		// And the message, which DOES interpolate external bytes, is
		// covered by the untrusted default rather than being sanitised into
		// a claim it is Anvil's.
		if !strings.Contains(em.Result.Message.Text, em.Result.Properties.Advisory.IDs[0]) {
			t.Error("the message does not name the advisory it rests on")
		}
	}
}

// TestComposeReasoningRefusesAnExternalString drives the guard RED. A guard
// that has never failed has not been tested.
func TestComposeReasoningRefusesAnExternalString(t *testing.T) {
	if _, err := composeReasoning([]string{reasonDeterministic, fixtureHostPkg}); err == nil {
		t.Fatal("composeReasoning accepted a package name into an anvil_generated string")
	} else {
		var ref *Refusal
		if !asRefusal(err, &ref) || ref.Reason != RefusalReasoningNotAnvilGenerated {
			t.Fatalf("wrong refusal: %v", err)
		}
	}
	if _, err := composeReasoning(nil); err == nil {
		t.Fatal("composeReasoning accepted an empty explanation")
	}
	// The positive control: the vocabulary plus an integer is accepted.
	got, err := composeReasoning([]string{reasonDeterministic, reasonStaleNum, "3600"})
	if err != nil {
		t.Fatalf("composeReasoning refused its own vocabulary: %v", err)
	}
	if !strings.Contains(got, "3600") {
		t.Fatalf("integer lost: %q", got)
	}
	// Near-misses that must still be refused.
	for _, bad := range []string{"36 00", "+3600", "3600.0", "٣٦٠٠", reasonDeterministic + "!"} {
		if _, err := composeReasoning([]string{bad}); err == nil {
			t.Errorf("composeReasoning accepted %q", bad)
		}
	}
}

// TestAnAdvisoryRowClaimingAnvilGeneratedIsRefused: the record contract pins
// anvil_generated as illegal for an external string, and every byte in the
// advisory table is external.
func TestAnAdvisoryRowClaimingAnvilGeneratedIsRefused(t *testing.T) {
	a := hostRow()
	a.Trust = record.TrustAnvilGenerated
	_, err := emitter().Emit(hostMatch(), a)
	if err == nil {
		t.Fatal("an advisory row claiming anvil_generated was accepted")
	}
	var ref *Refusal
	if !asRefusal(err, &ref) || ref.Reason != RefusalIllegalAdvisoryTrust {
		t.Fatalf("wrong refusal: %v", err)
	}
}

// ---------------------------------------------------------------------------
// as_of / staleness_seconds
// ---------------------------------------------------------------------------

// TestStaleAdvisorySurfacesItsStalenessRatherThanReportingClean is A.19's
// second named validation item, rebuilt after A.20 showed the original could
// not fail.
//
// THE ORIGINAL WAS CIRCULAR. It set `StalenessSeconds` on the input row and
// asserted the same number came out. That proves copy-through — and
// copy-through WAS the defect, because `advisory.staleness_seconds` is the
// publisher lag at write time while the record's field is assembly time minus
// as_of. During a feed outage neither cache column advances, so the copy
// reported three-week-old data as an hour old, inside its SLO, in the prose a
// human reads. The test could not see it: the outage case is exactly the case
// where the input row's number stays small.
//
// SO THE EXPECTED VALUE IS ARITHMETIC THIS TEST DOES ITSELF. The watermark and
// the assembly instant are both stated here, twenty-one days apart, and the row
// carries a SMALL frozen publisher lag — the outage shape. Nothing in the
// assertion is read back from the emitter.
func TestStaleAdvisorySurfacesItsStalenessRatherThanReportingClean(t *testing.T) {
	const (
		slo = 86400
		// The interval the test asserts, computed here and nowhere else.
		wantStaleness = 21 * 24 * 3600
		// What the outage froze in the cache: an hour, and wrong by a factor
		// of 504. Emitting THIS is the blocker A.20 found.
		frozenPublisherLag = 3600
	)
	watermark := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	assembledAt := watermark.Add(wantStaleness * time.Second)

	a := hostRow()
	a.AsOf = watermark
	a.FreshnessSLOSeconds = slo
	a.StalenessSeconds = frozenPublisherLag

	e := Emitter{TargetID: fixtureTargetID, AssembledAt: assembledAt}
	em, err := e.Emit(hostMatch(), a)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	// 1. The finding EXISTS. Nothing was silently dropped.
	if em.Result.Properties.FindingID == "" {
		t.Fatal("a stale advisory produced no finding")
	}

	// 2. as_of is the CACHE WATERMARK — not the assembly instant, which is
	//    the value a clock-reading implementation would have stamped here.
	got := em.Result.Properties.Advisory.AsOf
	if !got.Equal(watermark) {
		t.Fatalf("as_of = %s, want the cache watermark %s", got, watermark)
	}
	if got.Equal(assembledAt) {
		t.Fatalf("as_of = %s, which is the record-assembly instant; as_of states when the DATA "+
			"was current, and stamping assembly time on it reports stale data as fresh", got)
	}
	assertJSONString(t, em.Result, "properties/anvil~1advisory/asOf", watermark.Format(time.RFC3339))

	// 3. staleness_seconds is THE CONTRACT'S INTERVAL: assembly minus as_of.
	//    Not the row's column, which says an hour.
	if n := em.Result.Properties.Advisory.StalenessSeconds; n != wantStaleness {
		t.Fatalf("stalenessSeconds = %d, want %d (assembly %s minus watermark %s). "+
			"%d is the row's frozen publisher-lag column, which is a different quantity: "+
			"emitting it reports twenty-one-day-old data as an hour old",
			n, wantStaleness, assembledAt.Format(time.RFC3339), watermark.Format(time.RFC3339),
			frozenPublisherLag)
	}
	assertJSONNumber(t, em.Result, "properties/anvil~1advisory/stalenessSeconds", float64(wantStaleness))

	// 4. The SLO breach itself is machine-readable on the crossing artifact
	//    (the frozen record has no SLO slot — see the package header). Under
	//    the row's own number this would read "inside the SLO".
	if !em.BeyondFreshnessSLO() {
		t.Fatal("BeyondFreshnessSLO() = false for data three weeks past a one-day SLO")
	}
	assertJSONBool(t, em, "beyondFreshnessSlo", true)
	assertJSONNumber(t, em, "freshnessSloSeconds", float64(slo))

	// 5. And it is said in the reasoning, which is what a human reads — with
	//    the SAME number, so the prose and the field cannot drift apart.
	reasoning := em.Result.Properties.Reasoning
	if !strings.Contains(reasoning, reasonBeyondSLO) {
		t.Errorf("the reasoning does not mention the SLO breach: %q", reasoning)
	}
	if !strings.Contains(reasoning, strconv.Itoa(wantStaleness)) {
		t.Errorf("the reasoning does not state the emitted interval %d: %q", wantStaleness, reasoning)
	}
	if strings.Contains(reasoning, strconv.Itoa(frozenPublisherLag)) {
		t.Errorf("the reasoning states the row's publisher-lag column %d, which is not the age "+
			"of this data: %q", frozenPublisherLag, reasoning)
	}

	// 6. THE CONTROL, and it is CLOCK-FREE. A.20's second circular finding was
	//    that the old control depended on the wall-clock distance to a
	//    hard-coded fixture date, so it would have begun failing on a calendar
	//    day rather than on a code change. Here the same watermark one hour
	//    before assembly is inside the same SLO, on every day, forever.
	freshAt := watermark.Add(time.Hour)
	fresh, err := Emitter{TargetID: fixtureTargetID, AssembledAt: freshAt}.Emit(hostMatch(), a)
	if err != nil {
		t.Fatalf("Emit (fresh control): %v", err)
	}
	if n := fresh.Result.Properties.Advisory.StalenessSeconds; n != 3600 {
		t.Fatalf("the control emitted stalenessSeconds = %d, want 3600", n)
	}
	if fresh.BeyondFreshnessSLO() {
		t.Fatal("BeyondFreshnessSLO() = true for data one hour into a one-day SLO")
	}
	assertJSONBool(t, fresh, "beyondFreshnessSlo", false)

	// 7. Staleness does NOT suppress the finding or demote it. An outage is
	//    what serve_stale exists for; refusing every finding during one is
	//    the over-refusal that gets a control switched off.
	if em.Result.Properties.Verdict != record.VerdictTruePositive {
		t.Errorf("stale data demoted the verdict to %q", em.Result.Properties.Verdict)
	}
}

// TestStalenessIsMeasuredFromTheWatermarkNotCopiedFromTheRow walks a table of
// (watermark, assembly) pairs whose expected intervals are stated as arithmetic
// and whose rows all carry the SAME decoy publisher lag.
//
// One row of the table is enough to catch copy-through; the table is here so
// that the emitted number is shown to TRACK the interval rather than to match
// it once. A constant would satisfy a single-point test.
func TestStalenessIsMeasuredFromTheWatermarkNotCopiedFromTheRow(t *testing.T) {
	watermark := time.Date(2026, 3, 14, 15, 9, 26, 0, time.UTC)
	for _, c := range []struct {
		name string
		lag  time.Duration
		want int
	}{
		{"zero: assembled at the watermark", 0, 0},
		{"one second", time.Second, 1},
		{"one hour", time.Hour, 3600},
		{"one day", 24 * time.Hour, 86400},
		{"three weeks", 21 * 24 * time.Hour, 1814400},
		{"sub-second truncates toward zero", 1500 * time.Millisecond, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := hostRow()
			a.AsOf = watermark
			a.StalenessSeconds = fixturePublisherLag // the decoy
			em, err := Emitter{
				TargetID:    fixtureTargetID,
				AssembledAt: watermark.Add(c.lag),
			}.Emit(hostMatch(), a)
			if err != nil {
				t.Fatalf("Emit: %v", err)
			}
			if n := em.Result.Properties.Advisory.StalenessSeconds; n != c.want {
				t.Fatalf("stalenessSeconds = %d, want %d", n, c.want)
			}
			assertJSONNumber(t, em.Result, "properties/anvil~1advisory/stalenessSeconds", float64(c.want))
		})
	}
}

// TestAnAssemblyInstantIsRequiredRatherThanDefaulted: the zero value is
// refused, because a zero default would measure every finding's age against the
// Unix epoch — and, worse, would be the silent no-op that reinstates the
// copy-through the whole field exists to remove.
func TestAnAssemblyInstantIsRequiredRatherThanDefaulted(t *testing.T) {
	_, err := Emitter{TargetID: fixtureTargetID}.Emit(hostMatch(), hostRow())
	if err == nil {
		t.Fatal("an emitter with no assembly instant emitted a record; staleness_seconds is " +
			"defined as assembly time minus as_of and there was no assembly time")
	}
	var ref *Refusal
	if !asRefusal(err, &ref) || ref.Reason != RefusalNoAssemblyTime {
		t.Fatalf("wrong refusal: %v", err)
	}

	// And an assembly instant BEFORE the watermark is refused rather than
	// clamped to zero: "current as of now" is not a claim to make about data
	// whose own timestamps say otherwise.
	_, err = Emitter{
		TargetID:    fixtureTargetID,
		AssembledAt: fixtureWatermark.Add(-time.Second),
	}.Emit(hostMatch(), hostRow())
	if err == nil {
		t.Fatal("a negative age was emitted")
	}
	if !asRefusal(err, &ref) || ref.Reason != RefusalNegativeStaleness {
		t.Fatalf("wrong refusal for a negative age: %v", err)
	}
}

// TestAnUnstatedSLOIsNotAMetSLO: zero means "the caller stated none", and the
// package answers false rather than inventing a default it could then claim a
// breach against.
func TestAnUnstatedSLOIsNotAMetSLO(t *testing.T) {
	const wantStaleness = 99999999
	a := hostRow()
	a.FreshnessSLOSeconds = 0
	em, err := Emitter{
		TargetID:    fixtureTargetID,
		AssembledAt: fixtureWatermark.Add(wantStaleness * time.Second),
	}.Emit(hostMatch(), a)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if em.BeyondFreshnessSLO() {
		t.Fatal("a breach was asserted against an SLO nobody configured")
	}
	if n := em.Result.Properties.Advisory.StalenessSeconds; n != wantStaleness {
		t.Fatalf("stalenessSeconds = %d, want %d; the staleness was lost when the SLO was unstated",
			n, wantStaleness)
	}
}

// TestThisPackageReadsNoClock is structural, and it is the property that makes
// the assembly instant an INPUT rather than a reading. as_of comes from the
// cache watermark and staleness_seconds is measured against an instant the
// caller states; the only way to be sure neither is a clock reading is that
// there is no clock to read.
func TestThisPackageReadsNoClock(t *testing.T) {
	src, err := os.ReadFile("emit.go")
	if err != nil {
		t.Fatalf("reading emit.go: %v", err)
	}
	code := stripComments(t, "emit.go", src)
	for _, banned := range []string{
		"time.Now", "time.Since", "time.Until", "time.Tick", "time.After",
		"func() time.Time", "rand.", "os.Getenv",
	} {
		if strings.Contains(code, banned) {
			t.Errorf("emit.go references %s; as_of must come from the cache watermark, the "+
				"assembly instant must ARRIVE from the caller, and nothing here may depend on a "+
				"clock, a random source or the environment", banned)
		}
	}
}

// TestThePackageImportsNothingItShouldNot pins the dependency graph, the way
// internal/match pins its own. A SQL driver or an HTTP client appearing in a
// pure field-population step is a change worth failing a build over.
func TestThePackageImportsNothingItShouldNot(t *testing.T) {
	allowed := map[string]bool{
		"encoding/json": true, "fmt": true, "strconv": true, "strings": true, "time": true,
		"github.com/Susquehanna-Syntax/Anvil/internal/match":  true,
		"github.com/Susquehanna-Syntax/Anvil/internal/record": true,
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "emit.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing emit.go: %v", err)
	}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if !allowed[path] {
			t.Errorf("emit.go imports %q, which is not on the allowlist", path)
		}
	}
}

// ---------------------------------------------------------------------------
// The fingerprint: one algorithm, and it is not this package's
// ---------------------------------------------------------------------------

// corpusVector is the subset of a testdata/fingerprint_corpus fixture this
// test reads.
type corpusVector struct {
	ID    string `json:"id"`
	Tier  string `json:"tier"`
	Input struct {
		TargetID        string `json:"target_id"`
		AdvisoryID      string `json:"advisory_id"`
		Purl            string `json:"purl"`
		ManifestRelPath string `json:"manifest_rel_path"`
		PackageManager  string `json:"package_manager"`
		HostIdentifier  string `json:"host_identifier"`
	} `json:"input"`
	Mutations []struct {
		Name  string `json:"name"`
		Input struct {
			TargetID        string `json:"target_id"`
			AdvisoryID      string `json:"advisory_id"`
			Purl            string `json:"purl"`
			ManifestRelPath string `json:"manifest_rel_path"`
			PackageManager  string `json:"package_manager"`
			HostIdentifier  string `json:"host_identifier"`
		} `json:"input"`
	} `json:"mutations"`
}

// inexpressibleMutations are corpus mutations this package CANNOT produce,
// with the reason. They are listed rather than skipped silently: a mutation
// that is neither exercised nor listed fails the test, so a corpus that grows
// cannot be quietly under-covered.
//
// Both entries are inexpressible because they vary a locator segment this
// package derives from a closed vocabulary rather than accepting from a
// caller — which is a stronger guarantee than the mutation asks for, not a
// weaker one.
var inexpressibleMutations = map[string]string{
	"package_manager_uppercased": "the manager segment comes from hostPackageManagers, " +
		"which has no uppercase member",
	"package_manager_and_identifier_padded": "both segments are composed from " +
		"MatchResult fields, so no padding can enter",
}

// TestEmittedFingerprintMatchesTheFrozenConformanceGoldens is the
// one-fingerprint check, and its expected values come from a file this
// package did not write and cannot influence.
func TestEmittedFingerprintMatchesTheFrozenConformanceGoldens(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "testdata", "fingerprint_corpus")

	for _, name := range []string{"host-01-openssl-debian", "sca-01-log4shell-maven"} {
		t.Run(name, func(t *testing.T) {
			var v corpusVector
			raw, err := os.ReadFile(filepath.Join(dir, name+".json"))
			if err != nil {
				t.Fatalf("reading fixture: %v", err)
			}
			if err := json.Unmarshal(raw, &v); err != nil {
				t.Fatalf("parsing fixture: %v", err)
			}
			goldens := readGoldenDigests(t, filepath.Join(dir, name+".golden"))

			check := func(label, targetID, advisoryID, purl, manifest, manager, hostID string) {
				t.Helper()
				want, ok := goldens[label]
				if !ok {
					t.Fatalf("no golden digest labelled %q", label)
				}
				m, a := matchFromCorpus(t, v.Tier, advisoryID, purl, manifest, manager, hostID)
				em, err := Emitter{TargetID: targetID, AssembledAt: fixtureAssembledAt}.Emit(m, a)
				if err != nil {
					t.Fatalf("%s: Emit: %v", label, err)
				}
				got := em.Result.PartialFingerprints[record.PartialFingerprintAnvilFindingID]
				if got != want {
					t.Fatalf("%s: emitted digest %s, golden %s "+
						"(a second fingerprint under one name breaks regression matching forever)",
						label, got, want)
				}
				if em.Result.Properties.FindingID != want {
					t.Fatalf("%s: findingId %s disagrees with the digest %s",
						label, em.Result.Properties.FindingID, want)
				}
			}

			in := v.Input
			check("base", in.TargetID, in.AdvisoryID, in.Purl, in.ManifestRelPath,
				in.PackageManager, in.HostIdentifier)

			exercised := 0
			for _, mu := range v.Mutations {
				if reason, listed := inexpressibleMutations[mu.Name]; listed {
					t.Logf("mutation %q not exercised: %s", mu.Name, reason)
					continue
				}
				check("mutation:"+mu.Name, mu.Input.TargetID, mu.Input.AdvisoryID,
					mu.Input.Purl, mu.Input.ManifestRelPath,
					mu.Input.PackageManager, mu.Input.HostIdentifier)
				exercised++
			}
			if exercised == 0 {
				t.Fatal("no mutation was exercised; the corpus is being read but not used")
			}
		})
	}
}

// matchFromCorpus builds the MatchResult and AdvisoryRow that a corpus vector
// describes. The host vector's `host_identifier` is split back into package
// and arch, which is the mapping this package performs in the other
// direction; the manager is NOT taken from the vector, because deriving it is
// the behaviour under test.
func matchFromCorpus(t *testing.T, tier, advisoryID, purl, manifest, manager, hostID string) (match.MatchResult, AdvisoryRow) {
	t.Helper()
	a := AdvisoryRow{
		Source:           "corpus",
		SourceID:         advisoryID,
		LicenseSPDX:      "CC0-1.0",
		Trust:            record.TrustUntrusted,
		AsOf:             fixtureWatermark,
		StalenessSeconds: 1,
	}
	m := match.MatchResult{
		Source:           "corpus",
		SourceID:         advisoryID,
		Purl:             purl,
		InstalledVersion: "0",
		MatchedRange:     "[0, 1)",
	}
	switch tier {
	case "host":
		if want := "apt"; manager != want {
			t.Fatalf("the corpus vector's package_manager is %q; hostPackageManagers maps %q to %q, "+
				"and the two must agree or every Debian host finding forks identity",
				manager, match.EcosystemDeb, want)
		}
		name, arch, _ := strings.Cut(hostID, ":")
		m.Collector = match.CollectorHost
		m.Ecosystem = match.EcosystemDeb
		m.Package = name
		m.Arch = arch
		m.Detector = record.DetectorKindHost
		m.EvidenceClass = record.EvidenceClassHost
	case "sca":
		m.Collector = match.CollectorRepoSCA
		m.Ecosystem = "maven"
		m.Package = "corpus-package"
		m.ManifestRelPath = manifest
		m.Detector = record.DetectorKindSCA
		m.EvidenceClass = record.EvidenceClassSCA
	default:
		t.Fatalf("unexpected tier %q", tier)
	}
	return m, a
}

// readGoldenDigests parses the TSV golden file: `digest <TAB> label <TAB> hex`.
func readGoldenDigests(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 || parts[0] != "digest" {
			continue
		}
		out[parts[1]] = parts[2]
	}
	if len(out) == 0 {
		t.Fatalf("%s carried no digests", path)
	}
	return out
}

// TestThisPackageComputesNoDigestOfItsOwn is the structural half of the
// one-fingerprint rule: no hash import, no digest arithmetic, only delegation.
func TestThisPackageComputesNoDigestOfItsOwn(t *testing.T) {
	src, err := os.ReadFile("emit.go")
	if err != nil {
		t.Fatalf("reading emit.go: %v", err)
	}
	code := stripComments(t, "emit.go", src)
	for _, banned := range []string{"sha256", "sha1", "md5", "fnv", "crc32", "crypto/"} {
		if strings.Contains(code, banned) {
			t.Errorf("emit.go references %q; anvil-fp/v1 is defined once, in internal/record", banned)
		}
	}
	for _, required := range []string{"record.Host(", "record.Sca("} {
		if !strings.Contains(code, required) {
			t.Errorf("emit.go does not call %s; the digest must be delegated", required)
		}
	}
}

// ---------------------------------------------------------------------------
// The seven fields, over A.17's own output
// ---------------------------------------------------------------------------

// TestEveryRecordFromTheComparatorCarriesTheSevenLaneAFields runs the REAL
// comparator over a real inventory, emits every result it produces, and
// asserts all seven Lane-A-owned fields on the SERIALISED bytes of each one.
// The findings are A.17's, not this test's construction.
func TestEveryRecordFromTheComparatorCarriesTheSevenLaneAFields(t *testing.T) {
	ranges := []match.AffectedRange{
		{
			Source: "ubuntu", SourceID: "USN-9999-1", CVEID: "CVE-2026-99999",
			Ecosystem: match.EcosystemDeb, Package: fixtureHostPkg,
			Purl:  "pkg:deb/ubuntu/" + fixtureHostPkg,
			Fixed: "9.9.9zzverqx-2", DistroBackport: true,
		},
		{
			Source: "alpine", SourceID: "CVE-2026-88888", CVEID: "CVE-2026-88888",
			Ecosystem: match.EcosystemAPK, Package: "zzapkpkgqx",
			Purl: "pkg:apk/alpine/zzapkpkgqx", Fixed: "2.0.0-r1",
		},
	}
	inventory := []match.PackageRecord{
		{
			Collector: match.CollectorHost, Ecosystem: match.EcosystemDeb,
			Name: fixtureHostPkg, Version: fixtureHostVer, Arch: "amd64",
		},
		{
			Collector: match.CollectorHost, Ecosystem: match.EcosystemAPK,
			Name: "zzapkpkgqx", Version: "1.9.0-r0",
		},
	}

	matcher, err := match.NewMatcher(match.NewStaticSource(ranges))
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	findings, coverage, err := matcher.Match(context.Background(), inventory)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if err := coverage.AssertNotSilentlyClean(findings); err != nil {
		t.Fatalf("the fixture run was silently clean: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("the comparator produced %d findings, want 2", len(findings))
	}

	rows := map[string]AdvisoryRow{
		"ubuntu/USN-9999-1": {
			Source: "ubuntu", SourceID: "USN-9999-1", CVEID: "CVE-2026-99999",
			FeedID: "ubuntu-usn", LicenseSPDX: "LicenseRef-ubuntu-usn",
			LicenseManualNote: fixtureManualNote, Trust: record.TrustUntrusted,
			AsOf: fixtureWatermark, StalenessSeconds: fixturePublisherLag, FreshnessSLOSeconds: 3600,
			ParseDegraded: true, ExcerptText: fixtureExcerpt,
		},
		"alpine/CVE-2026-88888": {
			Source: "alpine", SourceID: "CVE-2026-88888", CVEID: "CVE-2026-88888",
			FeedID: "alpine-secdb", LicenseSPDX: "MIT", Trust: record.TrustVerified,
			TrustValidationStep: fixtureValidationStep,
			AsOf:                fixtureWatermark, StalenessSeconds: fixturePublisherLag,
			FreshnessSLOSeconds: 3600,
		},
	}
	ems, err := emitter().EmitAll(findings, func(source, sourceID string) (AdvisoryRow, bool) {
		r, ok := rows[source+"/"+sourceID]
		return r, ok
	})
	if err != nil {
		t.Fatalf("EmitAll: %v", err)
	}
	if len(ems) != len(findings) {
		t.Fatalf("emitted %d records for %d findings", len(ems), len(findings))
	}

	byFeed := map[string]AdvisoryRow{}
	for _, r := range rows {
		byFeed[r.FeedID] = r
	}

	for i, em := range ems {
		raw := marshal(t, em.Result)
		src, ok := byFeed[em.Result.Properties.Advisory.SourceFeed]
		if !ok {
			t.Fatalf("result %d names feed %q, which no fixture row supplied",
				i, em.Result.Properties.Advisory.SourceFeed)
		}

		// 1. remediable_by_agent — present, and false: both findings are
		//    host findings.
		assertJSONBool(t, em.Result, "properties/anvil~1remediableByAgent", false)
		// 2. as_of, 3. staleness_seconds, 4. parse_degraded.
		//    The staleness is asserted against the interval this test set up —
		//    emitter()'s assembly instant minus the fixture watermark — and
		//    NOT against the row's own column, which carries the decoy.
		assertJSONString(t, em.Result, "properties/anvil~1advisory/asOf",
			fixtureWatermark.Format(time.RFC3339))
		assertJSONNumber(t, em.Result, "properties/anvil~1advisory/stalenessSeconds",
			float64(fixtureAssemblyLagSeconds))
		if src.StalenessSeconds == fixtureAssemblyLagSeconds {
			t.Errorf("result %d: the fixture row's publisher-lag column equals the interval under "+
				"test, so this assertion could pass by copy-through", i)
		}
		if _, err := jsonAt(raw, "properties/anvil~1advisory/parseDegraded"); err != nil {
			t.Errorf("result %d: %v", i, err)
		}
		// 5. anvil/trust.
		assertJSONString(t, em.Result, "properties/anvil~1trust/default", string(record.TrustUntrusted))
		// 6. license_spdx.
		if _, err := jsonAt(raw, "properties/anvil~1advisory/licenseSpdx"); err != nil {
			t.Errorf("result %d: %v", i, err)
		}
		// 7. license_manual_note, on the crossing artifact.
		if src.LicenseManualNote != "" {
			if em.LicenseManualNote == nil || em.LicenseManualNote.Text != src.LicenseManualNote {
				t.Errorf("result %d lost the licence manual note", i)
			}
			if em.LicenseManualNote.Trust == record.TrustAnvilGenerated {
				t.Errorf("result %d labels a quoted licence sentence as Anvil's own", i)
			}
			assertJSONString(t, em, "licenseManualNote/text", src.LicenseManualNote)
		} else if em.LicenseManualNote != nil {
			t.Errorf("result %d invented a licence manual note", i)
		}

		// And the record's own validator agrees this is a legal result.
		if err := record.ValidateResultTrust(&em.Result); err != nil {
			t.Errorf("result %d: %v", i, err)
		}
	}

	// The whole assembled log validates: this is the record area's gate, not
	// this package's.
	log := sealedLog(t, Results(ems))
	if err := log.Validate(); err != nil {
		t.Fatalf("the assembled record does not validate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

// TestEveryRefusalReasonIsReachable drives all fifteen guards and fails if any
// one cannot be provoked. An unreachable refusal is a guard that is not there.
func TestEveryRefusalReasonIsReachable(t *testing.T) {
	cases := map[RefusalReason]func() (Emitter, match.MatchResult, AdvisoryRow){
		RefusalNoTargetID: func() (Emitter, match.MatchResult, AdvisoryRow) {
			return Emitter{}, hostMatch(), hostRow()
		},
		RefusalUnrecognisedCollector: func() (Emitter, match.MatchResult, AdvisoryRow) {
			m := hostMatch()
			m.Collector = "container-image"
			return emitter(), m, hostRow()
		},
		RefusalInconsistentMatch: func() (Emitter, match.MatchResult, AdvisoryRow) {
			m := hostMatch()
			m.Detector = record.DetectorKindSCA
			m.EvidenceClass = record.EvidenceClassSCA
			return emitter(), m, hostRow()
		},
		RefusalAdvisoryMismatch: func() (Emitter, match.MatchResult, AdvisoryRow) {
			a := hostRow()
			a.SourceID = "USN-0000-1"
			return emitter(), hostMatch(), a
		},
		RefusalNoAdvisoryID: func() (Emitter, match.MatchResult, AdvisoryRow) {
			m, a := hostMatch(), hostRow()
			m.CVEID, m.SourceID = "", ""
			a.CVEID, a.SourceID = "", ""
			return emitter(), m, a
		},
		RefusalNoPurl: func() (Emitter, match.MatchResult, AdvisoryRow) {
			m := hostMatch()
			m.Purl = ""
			return emitter(), m, hostRow()
		},
		RefusalNoManifestPath: func() (Emitter, match.MatchResult, AdvisoryRow) {
			m := repoMatch()
			m.ManifestRelPath = ""
			return emitter(), m, repoRow()
		},
		RefusalUnsupportedHostEcosystem: func() (Emitter, match.MatchResult, AdvisoryRow) {
			m := hostMatch()
			m.Ecosystem = "gentoo"
			return emitter(), m, hostRow()
		},
		RefusalNoWatermark: func() (Emitter, match.MatchResult, AdvisoryRow) {
			a := hostRow()
			a.AsOf = time.Time{}
			return emitter(), hostMatch(), a
		},
		RefusalNoAssemblyTime: func() (Emitter, match.MatchResult, AdvisoryRow) {
			return Emitter{TargetID: fixtureTargetID}, hostMatch(), hostRow()
		},
		RefusalNegativeStaleness: func() (Emitter, match.MatchResult, AdvisoryRow) {
			a := hostRow()
			a.StalenessSeconds = -1
			return emitter(), hostMatch(), a
		},
		RefusalTrustValidationStep: func() (Emitter, match.MatchResult, AdvisoryRow) {
			a := hostRow()
			a.Trust = record.TrustVerified // and no step named
			return emitter(), hostMatch(), a
		},
		RefusalExcerptTooLong: func() (Emitter, match.MatchResult, AdvisoryRow) {
			a := hostRow()
			a.ExcerptText = strings.Repeat("z", record.MaxAdvisoryExcerptBytes+1)
			return emitter(), hostMatch(), a
		},
		RefusalIllegalAdvisoryTrust: func() (Emitter, match.MatchResult, AdvisoryRow) {
			a := hostRow()
			a.Trust = record.TrustAnvilGenerated
			return emitter(), hostMatch(), a
		},
		RefusalNoLicenceDeclared: func() (Emitter, match.MatchResult, AdvisoryRow) {
			a := hostRow()
			a.LicenseSPDX, a.LicenseManualNote = "", "   "
			return emitter(), hostMatch(), a
		},
		RefusalFingerprint: func() (Emitter, match.MatchResult, AdvisoryRow) {
			m := hostMatch()
			m.Purl = "not-a-purl"
			return emitter(), m, hostRow()
		},
	}

	for reason, build := range cases {
		e, m, a := build()
		_, err := e.Emit(m, a)
		if err == nil {
			t.Errorf("%s: Emit accepted the input", reason)
			continue
		}
		var ref *Refusal
		if !asRefusal(err, &ref) {
			t.Errorf("%s: error is not a *Refusal: %v", reason, err)
			continue
		}
		if ref.Reason != reason {
			t.Errorf("wanted refusal %s, got %s (%v)", reason, ref.Reason, err)
		}
		if !ref.Reason.Valid() {
			t.Errorf("%s is not in the closed set", ref.Reason)
		}
	}

	// The two reasons above are reached through composeReasoning and the
	// contract validator rather than through an Emit input, so they are
	// driven directly; every reason must be accounted for.
	if _, err := composeReasoning([]string{"external"}); err == nil {
		t.Error("RefusalReasoningNotAnvilGenerated is unreachable")
	}
	if err := validateEmitted(&record.Result{}); err == nil {
		t.Error("validateEmitted accepted an empty result, so RefusalContractViolation is unreachable")
	}
	// And the trust arm of the same gate, which record's own validator is
	// vacuous for on this shape — see validateEmitted's comment.
	mislabelled := mustEmit(t, hostMatch(), hostRow()).Result
	mislabelled.Properties.Trust.Default = record.TrustAnvilGenerated
	if err := validateEmitted(&mislabelled); err == nil {
		t.Error("validateEmitted accepted anvil_generated as the trust default")
	}
	stolen := mustEmit(t, hostMatch(), hostRow()).Result
	stolen.Properties.Trust.Fields["/message/text"] = record.TrustAnvilGenerated
	if err := validateEmitted(&stolen); err == nil {
		t.Error("validateEmitted accepted anvil_generated on a string this step did not write")
	}

	covered := map[RefusalReason]bool{
		RefusalReasoningNotAnvilGenerated: true,
		RefusalContractViolation:          true,
	}
	for r := range cases {
		covered[r] = true
	}
	for _, r := range RefusalReasons() {
		if !covered[r] {
			t.Errorf("refusal reason %s is declared but never exercised", r)
		}
	}
	if len(covered) != len(RefusalReasons()) {
		t.Errorf("exercised %d reasons, declared %d", len(covered), len(RefusalReasons()))
	}
}

// TestEmitAllRefusesRatherThanSkipping: a match whose advisory row cannot be
// resolved must stop the run, because a finding dropped between the comparator
// and the record is indistinguishable from a clean scan.
func TestEmitAllRefusesRatherThanSkipping(t *testing.T) {
	ms := []match.MatchResult{hostMatch(), repoMatch()}
	got, err := emitter().EmitAll(ms, func(source, sourceID string) (AdvisoryRow, bool) {
		if source == "ubuntu" {
			return hostRow(), true
		}
		return AdvisoryRow{}, false
	})
	if err == nil {
		t.Fatalf("EmitAll silently dropped a finding and returned %d records", len(got))
	}
	if got != nil {
		t.Error("EmitAll returned records alongside its refusal")
	}
	if _, err := emitter().EmitAll(ms, nil); err == nil {
		t.Error("EmitAll accepted a nil lookup")
	}
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

// TestEmissionIsDeterministic: the same inputs produce byte-identical output.
// Lane A is zero-inference, and a record that varies run to run cannot be
// diffed, cached or trusted.
func TestEmissionIsDeterministic(t *testing.T) {
	for _, pair := range []struct {
		m match.MatchResult
		a AdvisoryRow
	}{{hostMatch(), hostRow()}, {repoMatch(), repoRow()}} {
		first := marshal(t, mustEmit(t, pair.m, pair.a))
		for i := 0; i < 20; i++ {
			if got := marshal(t, mustEmit(t, pair.m, pair.a)); !bytes.Equal(first, got) {
				t.Fatalf("emission %d differs:\n%s\n%s", i, first, got)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------------

// TestCvssV4BaseIsSetOnlyForAV4Vector: writing a v3.1 score into a field named
// CvssV4Base puts a number in the record that is wrong in a way no consumer
// can detect.
func TestCvssV4BaseIsSetOnlyForAV4Vector(t *testing.T) {
	score := 9.8
	v4 := repoRow()
	v4.CVSSScore, v4.CVSSVector = &score, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	if got := mustEmit(t, repoMatch(), v4).Result.Properties.Risk; got == nil || got.CvssV4Base == nil {
		t.Fatal("a v4 vector did not populate CvssV4Base")
	} else if *got.CvssV4Base != score {
		t.Fatalf("CvssV4Base = %v, want %v", *got.CvssV4Base, score)
	}

	v31 := repoRow()
	v31.CVSSScore, v31.CVSSVector = &score, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	em := mustEmit(t, repoMatch(), v31)
	if em.Result.Properties.Risk != nil && em.Result.Properties.Risk.CvssV4Base != nil {
		t.Fatal("a v3.1 score was written into CvssV4Base")
	}

	// KEV alone still produces a Risk block; no risk inputs produce none.
	kev := repoRow()
	kev.KEVMember = true
	if mustEmit(t, repoMatch(), kev).Result.Properties.Risk == nil {
		t.Fatal("KEV membership was dropped")
	}
	if mustEmit(t, repoMatch(), repoRow()).Result.Properties.Risk != nil {
		t.Fatal("a Risk block was invented for a row carrying no risk inputs")
	}
}

// ---------------------------------------------------------------------------
// The crossing bytes, for a Result this package did not build
// ---------------------------------------------------------------------------

// TestAResultThatDidNotComeFromEmitIsClampedInTheCrossingBytes is A.20's
// finding 3, made true rather than deleted.
//
// Emission.RemediableByAgent's doc claims a Result arriving from anywhere other
// than Emit — hand-built, deserialised, or mutated after emission — cannot
// present a host finding as actionable. A.20 showed the clamp reached the
// top-level mirror only: the nested canonical record inside the SAME object,
// and Results(), both still said true. An object that disagrees with itself is
// not a guarantee, and this project's standard is that a claim which cannot be
// demonstrated is deleted rather than qualified. So the claim is now
// demonstrated, ON THE SERIALISED BYTES, for all three shapes and all three
// provenances.
func TestAResultThatDidNotComeFromEmitIsClampedInTheCrossingBytes(t *testing.T) {
	// A Result that never went through Emit at all.
	handBuilt := record.Result{
		RuleID:  "CVE-2026-00000",
		Message: record.Message{Text: "hand-built, never validated, asserting it is actionable"},
		Properties: record.ResultProperties{
			FindingID:         "0000000000000000000000000000000000000000000000000000000000000000",
			Half:              record.HalfSast,
			Confidence:        1,
			Verdict:           record.VerdictTruePositive,
			RemediableByAgent: true,
			Detector:          record.DetectorRef{Kind: record.DetectorKindHost},
			EvidenceClass:     record.EvidenceClassHost,
			Trust:             record.TrustAssertion{Default: record.TrustUntrusted},
		},
	}

	// The same host finding, emitted properly and then MUTATED afterwards.
	mutated := mustEmit(t, hostMatch(), hostRow())
	mutated.Result.Properties.RemediableByAgent = true

	// And one that made the round trip through JSON before being mutated,
	// which is the "deserialised" arm of the same sentence.
	var deserialised record.Result
	if err := json.Unmarshal(marshal(t, mustEmit(t, hostMatch(), hostRow()).Result), &deserialised); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	deserialised.Properties.RemediableByAgent = true

	for _, c := range []struct {
		name string
		em   Emission
	}{
		{"hand-built", Emission{Result: handBuilt}},
		{"mutated after emission", mutated},
		{"deserialised then mutated", Emission{Result: deserialised}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.em.RemediableByAgent() {
				t.Error("Emission.RemediableByAgent() = true")
			}
			// 1. the top-level mirror,
			assertJSONBool(t, c.em, "remediableByAgent", false)
			// 2. the nested canonical record in the same object — the half
			//    that used to disagree,
			assertJSONBool(t, c.em, "result/properties/anvil~1remediableByAgent", false)
			// 3. and Results(), which is what reaches the SARIF log and the
			//    store.
			projected := Results([]Emission{c.em})
			if len(projected) != 1 {
				t.Fatalf("Results() returned %d results", len(projected))
			}
			if projected[0].Properties.RemediableByAgent {
				t.Error("Results()[0] carries RemediableByAgent=true for a host finding")
			}
			assertJSONBool(t, projected[0], "properties/anvil~1remediableByAgent", false)
		})
	}

	// THE CALLER'S OWN STRUCT IS NOT WRITTEN. The clamp is a copy, so a
	// consumer cannot observe this package reaching into a value it was handed
	// — and a test that passed because the input was quietly rewritten would
	// be proving something else.
	if !mutated.Result.Properties.RemediableByAgent {
		t.Error("clamping rewrote the caller's own Result rather than a copy")
	}

	// THE CONTROL: clamping refuses host findings, not everything. A repo
	// dependency still crosses as actionable at both levels.
	repo := mustEmit(t, repoMatch(), repoRow())
	assertJSONBool(t, repo, "remediableByAgent", true)
	assertJSONBool(t, repo, "result/properties/anvil~1remediableByAgent", true)
	assertJSONBool(t, Results([]Emission{repo})[0], "properties/anvil~1remediableByAgent", true)
}

// ---------------------------------------------------------------------------
// The advisory excerpt, and the trust it claims
// ---------------------------------------------------------------------------

// TestTheAdvisoryExcerptBoundIsCheckedRatherThanAssumed: A.19 asserted the
// excerpt was pre-trimmed by ingestion and copied it through unexamined, so a
// 24 KB excerpt reached the record and the store. The read path's cap trims
// only the agent-facing card, so "bounded downstream" was not bounded here.
//
// NOTE WHAT THIS DOES NOT CLAIM. Sanitisation is still not verified in this
// package and AdvisoryRow.ExcerptText now says so instead of asserting it: the
// invisible-character vocabulary lives in internal/ingest/invisible, which this
// package does not import and must not re-spell.
func TestTheAdvisoryExcerptBoundIsCheckedRatherThanAssumed(t *testing.T) {
	a := hostRow()
	a.ExcerptText = strings.Repeat("z", record.MaxAdvisoryExcerptBytes+1)
	_, err := emitter().Emit(hostMatch(), a)
	if err == nil {
		t.Fatalf("an excerpt of %d bytes was emitted; the record's cap is %d",
			len(a.ExcerptText), record.MaxAdvisoryExcerptBytes)
	}
	var ref *Refusal
	if !asRefusal(err, &ref) || ref.Reason != RefusalExcerptTooLong {
		t.Fatalf("wrong refusal: %v", err)
	}

	// The boundary itself is accepted: a guard that refuses the legal maximum
	// would be refusing conforming ingestion output.
	atCap := hostRow()
	atCap.ExcerptText = strings.Repeat("z", record.MaxAdvisoryExcerptBytes)
	em := mustEmit(t, hostMatch(), atCap)
	if em.Result.Properties.Advisory.Excerpt == nil {
		t.Fatal("an excerpt exactly at the cap was dropped")
	}
	if got := len(em.Result.Properties.Advisory.Excerpt.Text); got != record.MaxAdvisoryExcerptBytes {
		t.Fatalf("the emitted excerpt is %d bytes, want %d", got, record.MaxAdvisoryExcerptBytes)
	}
}

// TestVerifiedTrustMustNameItsValidationStep: record.Trust defines `verified`
// as bytes that "passed an explicit validation step that is named in the record
// ... Never a default". A.19 passed the level through with no step named
// anywhere, which publishes the label without the thing that gives it meaning.
//
// Not live today — internal/ingest/delta always binds `untrusted` — so this is
// the guard standing in front of the signature-checked snapshot path before it
// lands, rather than a fix for a live defect.
func TestVerifiedTrustMustNameItsValidationStep(t *testing.T) {
	unnamed := hostRow()
	unnamed.Trust = record.TrustVerified
	_, err := emitter().Emit(hostMatch(), unnamed)
	if err == nil {
		t.Fatal("a row asserting verified with no validation step named was accepted")
	}
	var ref *Refusal
	if !asRefusal(err, &ref) || ref.Reason != RefusalTrustValidationStep {
		t.Fatalf("wrong refusal: %v", err)
	}

	// The other direction: a step named beside untrusted bytes is a validation
	// claim nothing validated, and is refused too.
	laundered := hostRow()
	laundered.TrustValidationStep = fixtureValidationStep
	if _, err := emitter().Emit(hostMatch(), laundered); err == nil {
		t.Error("a validation step was named on an untrusted row")
	} else if !asRefusal(err, &ref) || ref.Reason != RefusalTrustValidationStep {
		t.Errorf("wrong refusal: %v", err)
	}

	// Whitespace is not a name.
	blank := hostRow()
	blank.Trust = record.TrustVerified
	blank.TrustValidationStep = "   "
	if _, err := emitter().Emit(hostMatch(), blank); err == nil {
		t.Error("a blank validation step satisfied the naming requirement")
	}

	// AND THE NAME TRAVELS. Refusing an unnamed step would be pointless if the
	// name were then dropped: the contract's requirement is that the step is
	// NAMED, not merely that one existed.
	named := hostRow()
	named.Trust = record.TrustVerified
	named.TrustValidationStep = fixtureValidationStep
	em := mustEmit(t, hostMatch(), named)
	if em.TrustValidationStep != fixtureValidationStep {
		t.Fatalf("the validation step was lost: %q", em.TrustValidationStep)
	}
	assertJSONString(t, em, "trustValidationStep", fixtureValidationStep)
	if em.Result.Properties.Advisory.Excerpt.Trust != record.TrustVerified {
		t.Fatalf("the excerpt is %q, not the row's own trust",
			em.Result.Properties.Advisory.Excerpt.Trust)
	}

	// An untrusted row names nothing, and the key is absent from the bytes
	// rather than present and empty.
	plain := mustEmit(t, hostMatch(), hostRow())
	if plain.TrustValidationStep != "" {
		t.Errorf("an untrusted row produced the validation step %q", plain.TrustValidationStep)
	}
	if _, err := jsonAt(marshal(t, plain), "trustValidationStep"); err == nil {
		t.Error("an untrusted emission carries a trustValidationStep key")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func asRefusal(err error, out **Refusal) bool { return errors.As(err, out) }

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// jsonAt walks a '/'-separated path through the marshalled document, decoding
// '~1' as '/' per RFC 6901 so that `anvil/trust` can be addressed.
func jsonAt(raw []byte, path string) (any, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	cur := doc
	for _, seg := range strings.Split(path, "/") {
		seg = strings.ReplaceAll(seg, "~1", "/")
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, errAt(path, "not an object at "+seg)
		}
		v, present := obj[seg]
		if !present {
			return nil, errAt(path, "key "+seg+" is absent from the serialised bytes")
		}
		cur = v
	}
	return cur, nil
}

type pathError struct{ path, msg string }

func (e *pathError) Error() string { return e.path + ": " + e.msg }

func errAt(path, msg string) error { return &pathError{path, msg} }

func assertJSONBool(t *testing.T, v any, path string, want bool) {
	t.Helper()
	got, err := jsonAt(marshal(t, v), path)
	if err != nil {
		t.Fatalf("%v", err)
	}
	b, ok := got.(bool)
	if !ok {
		t.Fatalf("%s is %T, want bool", path, got)
	}
	if b != want {
		t.Fatalf("%s = %t in the serialised bytes, want %t", path, b, want)
	}
}

func assertJSONString(t *testing.T, v any, path, want string) {
	t.Helper()
	got, err := jsonAt(marshal(t, v), path)
	if err != nil {
		t.Fatalf("%v", err)
	}
	s, ok := got.(string)
	if !ok {
		t.Fatalf("%s is %T, want string", path, got)
	}
	if s != want {
		t.Fatalf("%s = %q in the serialised bytes, want %q", path, s, want)
	}
}

func assertJSONNumber(t *testing.T, v any, path string, want float64) {
	t.Helper()
	got, err := jsonAt(marshal(t, v), path)
	if err != nil {
		t.Fatalf("%v", err)
	}
	n, ok := got.(float64)
	if !ok {
		t.Fatalf("%s is %T, want number", path, got)
	}
	if n != want {
		t.Fatalf("%s = %v in the serialised bytes, want %v", path, n, want)
	}
}

// stripComments returns the file's code with every comment removed, so that a
// banned token quoted inside a doc comment does not fail a structural test.
func stripComments(t *testing.T, name string, src []byte) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	out := make([]byte, len(src))
	copy(out, src)
	base := fset.File(f.Pos()).Base()
	for _, group := range f.Comments {
		for i := int(group.Pos()) - base; i < int(group.End())-base && i < len(out); i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	return string(out)
}

// sealedLog wraps results in a minimal sealed SAST-half record, so the read
// path and the contract validator can be exercised over what this package
// emits. The envelope belongs to the scan controller (O.2); this is a stand-in
// for a test and nothing more.
func sealedLog(t *testing.T, results []record.Result) record.SARIFLog {
	t.Helper()
	created := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	sealed := created.Add(time.Hour)
	const auditID = "audit-lanea-test"
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Properties.FindingID < results[j].Properties.FindingID
	})
	return record.SARIFLog{
		Schema:  record.SARIFSchemaURI,
		Version: record.SARIFVersion,
		Properties: record.AuditProperties{
			SchemaVersion: record.SchemaVersion,
			AuditID:       auditID,
			State:         record.StateBothSealed,
			Version:       1,
			CreatedAt:     created,
			Target: record.Target{
				RepoURL:      "https://example.invalid/zzrepoqx.git",
				Ref:          "refs/heads/main",
				Commit:       "0000000000000000000000000000000000000000",
				Provenance:   record.TargetProvenanceNoTargetDeclared,
				Provisioning: record.TargetProvisioningEphemeralManifest,
			},
			DastStatus: record.DastStatusNotRun,
			Deadline: record.Deadline{
				DeadlineAt:          created.Add(record.DefaultClaimTimeoutSeconds * time.Second),
				ClaimTimeoutSeconds: record.DefaultClaimTimeoutSeconds,
			},
		},
		Runs: []record.Run{{
			Tool:              record.Tool{Driver: record.ToolComponent{Name: "anvil-lane-a"}},
			AutomationDetails: record.RunAutomationDetails{ID: auditID, CorrelationGUID: auditID},
			Results:           results,
			Properties: record.RunProperties{
				Half:     record.HalfSast,
				Status:   record.HalfStatusSealed,
				SealedAt: &sealed,
			},
		}},
	}
}
