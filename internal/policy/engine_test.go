package policy

// Tests for step O.6, the policy engine.
//
// Two things are being proved here, and they are not the same thing:
//
//  1. The owner's explicit requirement -- "SAST on every push, SAST+DAST only
//     on tagged releases, gated by semver bump" -- resolves correctly, end to
//     end, from the LITERAL YAML of research/09's example policy. Not from a
//     Go struct that says roughly the same thing: from the file text, decoded
//     and evaluated, so the schema, the decoder and the evaluator are checked
//     against each other rather than against my own restatement.
//
//  2. Nothing about which rule fires is compiled into Go. The genericity tests
//     drive the engine with invented event names, invented refs and invented
//     detector-free rules; if any vocabulary were hard-coded, they would fail.
//
// The YAML fixture and the tiny test-only YAML decoder both come from
// schema_test.go (step O.5). They are reused rather than copied: a second copy
// of the owner-requirement fixture could drift from the one the schema is
// tested against, and two fixtures claiming to be the same requirement is the
// defect shape this repository keeps closing.

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustDur(t *testing.T, s string) time.Duration {
	t.Helper()
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatalf("bad duration in the test itself: %q: %v", s, err)
	}
	return d
}

func durPtr(t *testing.T, s string) *time.Duration {
	t.Helper()
	d := mustDur(t, s)
	return &d
}

func boolPtr(b bool) *bool { return &b }

// ownerPolicy decodes research/09's example policy -- the one the owner's
// requirement is written in -- into a Policy.
func ownerPolicy(t *testing.T) Policy {
	t.Helper()
	doc, err := o5yamlDecode(o5fixtureOwnerRequirement)
	if err != nil {
		t.Fatalf("decoding the owner-requirement fixture: %v", err)
	}
	p, err := FromDocument(doc)
	if err != nil {
		t.Fatalf("FromDocument on the owner-requirement fixture: %v", err)
	}
	return p
}

func mustEvaluate(t *testing.T, p Policy, ctx TriggerContext) ResolvedRule {
	t.Helper()
	got, err := Evaluate(p, ctx)
	if err != nil {
		t.Fatalf("Evaluate(%+v): %v", ctx, err)
	}
	return got
}

func detectors(kinds ...record.DetectorKind) []record.DetectorKind { return kinds }

func durText(d *time.Duration) string {
	if d == nil {
		return "(unset)"
	}
	return d.String()
}

// ---------------------------------------------------------------------------
// 1. The fixture decodes to the shape the rest of this file assumes
// ---------------------------------------------------------------------------

// TestOwnerFixtureDecodesToPolicy stops every scenario test below from being
// vacuous. If FromDocument silently dropped `scanRules`, every "no rule
// matched" assertion would still pass while proving nothing.
func TestOwnerFixtureDecodesToPolicy(t *testing.T) {
	p := ownerPolicy(t)

	if p.Version != SchemaVersion {
		t.Errorf("Version = %d, want %d", p.Version, SchemaVersion)
	}
	if p.Defaults == nil {
		t.Fatal("defaults were dropped")
	}
	if got, want := p.Defaults.Detectors, detectors(record.DetectorKindSast); !slices.Equal(got, want) {
		t.Errorf("defaults.detectors = %v, want %v -- DAST must never be a default", got, want)
	}
	if got := p.Defaults.Depth; got != DepthDelta {
		t.Errorf("defaults.depth = %q, want %q", got, DepthDelta)
	}
	if got, want := durText(p.Defaults.Timeout), "20m0s"; got != want {
		t.Errorf("defaults.timeout = %s, want %s", got, want)
	}
	if got := p.Defaults.FailOn; got != "high" {
		t.Errorf("defaults.failOn = %q, want %q (carried opaquely, never interpreted)", got, "high")
	}

	wantOrder := []string{"push-delta", "major-release-full", "minor-release-sast-full", "nightly-regression"}
	var gotOrder []string
	for _, r := range p.ScanRules {
		gotOrder = append(gotOrder, r.Name)
	}
	if !slices.Equal(gotOrder, wantOrder) {
		t.Fatalf("scanRules order = %v, want %v -- array order IS the precedence order", gotOrder, wantOrder)
	}

	push := p.ScanRules[0]
	if got, want := push.MatchEvents, []string{"push"}; !slices.Equal(got, want) {
		t.Errorf("push-delta.matchEvents = %v, want %v", got, want)
	}
	if got, want := push.MatchPathsIgnore, []string{"docs/**", "**/*.md"}; !slices.Equal(got, want) {
		t.Errorf("push-delta.matchPathsIgnore = %v, want %v", got, want)
	}

	release := p.ScanRules[1]
	if got, want := release.MatchSemverBump, []BumpKind{BumpMajor}; !slices.Equal(got, want) {
		t.Errorf("major-release-full.matchSemverBump = %v, want %v", got, want)
	}
	if release.Dast == nil || release.Dast.Profile != "authenticated" {
		t.Errorf("major-release-full.dast = %+v, want profile=authenticated", release.Dast)
	}

	nightly := p.ScanRules[3]
	if nightly.Schedule == nil || nightly.Schedule.OnCalendar != "*-*-* 03:17:00" {
		t.Errorf("nightly-regression.schedule = %+v, want the calendar expression verbatim", nightly.Schedule)
	}
}

// ---------------------------------------------------------------------------
// 2. The two owner-requirement scenarios (the packet's named evidence)
// ---------------------------------------------------------------------------

func TestOwnerRequirementScenarios(t *testing.T) {
	p := ownerPolicy(t)

	cases := []struct {
		name string
		ctx  TriggerContext

		wantMatched   []string
		wantDetectors []record.DetectorKind
		wantDepth     Depth
		wantTimeout   string
		wantDast      bool // resolved detectors include dast
	}{
		{
			// THE FIRST OWNER REQUIREMENT: SAST on every push.
			name: "push to a branch runs SAST at delta depth",
			ctx: TriggerContext{
				Event:        "push",
				Ref:          "refs/heads/main",
				ChangedPaths: []string{"internal/policy/engine.go"},
			},
			wantMatched:   []string{"push-delta"},
			wantDetectors: detectors(record.DetectorKindSast),
			wantDepth:     DepthDelta,
			wantTimeout:   "20m0s",
		},
		{
			// THE SECOND OWNER REQUIREMENT: SAST+DAST only on tagged
			// releases, and only when the bump Anvil computed is major.
			name: "major tag push runs SAST+DAST at full depth",
			ctx: TriggerContext{
				Event:      "push",
				Ref:        "refs/tags/v2.0.0",
				SemverBump: BumpMajor,
			},
			wantMatched:   []string{"major-release-full"},
			wantDetectors: detectors(record.DetectorKindSast, record.DetectorKindDast),
			wantDepth:     DepthFull,
			wantTimeout:   "1h30m0s",
			wantDast:      true,
		},
		{
			// The same tag, arriving as a `release` event -- listed
			// alongside push because >3 tags at once drops plain push
			// events. Both spellings must resolve identically.
			name: "major release event resolves the same as the push",
			ctx: TriggerContext{
				Event:      "release",
				Ref:        "refs/tags/v2.0.0",
				SemverBump: BumpMajor,
			},
			wantMatched:   []string{"major-release-full"},
			wantDetectors: detectors(record.DetectorKindSast, record.DetectorKindDast),
			wantDepth:     DepthFull,
			wantTimeout:   "1h30m0s",
			wantDast:      true,
		},
		{
			// A minor bump is a full SAST pass and NO DAST. The timeout
			// comes from defaults because that rule sets none -- the
			// field-by-field merge, visible in a real fixture.
			name: "minor tag push runs SAST only, timeout inherited from defaults",
			ctx: TriggerContext{
				Event:      "push",
				Ref:        "refs/tags/v1.1.0",
				SemverBump: BumpMinor,
			},
			wantMatched:   []string{"minor-release-sast-full"},
			wantDetectors: detectors(record.DetectorKindSast),
			wantDepth:     DepthFull,
			wantTimeout:   "20m0s",
		},
		{
			name: "patch tag push runs SAST only",
			ctx: TriggerContext{
				Event:      "push",
				Ref:        "refs/tags/v1.1.1",
				SemverBump: BumpPatch,
			},
			wantMatched:   []string{"minor-release-sast-full"},
			wantDetectors: detectors(record.DetectorKindSast),
			wantDepth:     DepthFull,
			wantTimeout:   "20m0s",
		},
		{
			// No rule in this policy lists prerelease, so nothing fires
			// and only defaults survive. DAST in particular must NOT be
			// reached by a bump kind nobody opted into.
			name: "prerelease tag matches no rule",
			ctx: TriggerContext{
				Event:      "push",
				Ref:        "refs/tags/v2.0.0-rc.1",
				SemverBump: BumpPrerelease,
			},
			wantMatched:   nil,
			wantDetectors: detectors(record.DetectorKindSast),
			wantDepth:     DepthDelta,
			wantTimeout:   "20m0s",
		},
		{
			// The bump-gate as a gate: the same tag ref with no computed
			// bump fires no bump-gated rule. This is what keeps DAST off
			// when O.7 has not run.
			name: "tag ref with no computed bump fires no bump-gated rule",
			ctx: TriggerContext{
				Event:      "push",
				Ref:        "refs/tags/v2.0.0",
				SemverBump: BumpNone,
			},
			wantMatched:   nil,
			wantDetectors: detectors(record.DetectorKindSast),
			wantDepth:     DepthDelta,
			wantTimeout:   "20m0s",
		},
		{
			// Docs-only push: matchPathsIgnore excludes the rule, because
			// EVERY changed path is ignored.
			name: "docs-only push matches no rule",
			ctx: TriggerContext{
				Event:        "push",
				Ref:          "refs/heads/main",
				ChangedPaths: []string{"docs/design.md", "README.md"},
			},
			wantMatched:   nil,
			wantDetectors: detectors(record.DetectorKindSast),
			wantDepth:     DepthDelta,
			wantTimeout:   "20m0s",
		},
		{
			// ... but a change set that touches docs AND source is not
			// excluded, because the ignore list is applied per path.
			name: "mixed docs and source push still matches",
			ctx: TriggerContext{
				Event:        "push",
				Ref:          "refs/heads/main",
				ChangedPaths: []string{"docs/design.md", "internal/store/schema.sql"},
			},
			wantMatched:   []string{"push-delta"},
			wantDetectors: detectors(record.DetectorKindSast),
			wantDepth:     DepthDelta,
			wantTimeout:   "20m0s",
		},
		{
			name: "scheduled event resolves the nightly rule",
			ctx: TriggerContext{
				Event: "schedule",
			},
			wantMatched:   []string{"nightly-regression"},
			wantDetectors: detectors(record.DetectorKindSast),
			wantDepth:     DepthFull,
			wantTimeout:   "20m0s",
		},
		{
			name: "an event no rule names matches nothing",
			ctx: TriggerContext{
				Event: "workflow_dispatch",
				Ref:   "refs/heads/main",
			},
			wantMatched:   nil,
			wantDetectors: detectors(record.DetectorKindSast),
			wantDepth:     DepthDelta,
			wantTimeout:   "20m0s",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mustEvaluate(t, p, tc.ctx)

			if !slices.Equal(got.MatchedNames(), tc.wantMatched) {
				t.Errorf("matched %v, want %v", got.MatchedNames(), tc.wantMatched)
			}
			if !slices.Equal(got.Detectors, tc.wantDetectors) {
				t.Errorf("detectors = %v, want %v", got.Detectors, tc.wantDetectors)
			}
			if got.Depth != tc.wantDepth {
				t.Errorf("depth = %q, want %q", got.Depth, tc.wantDepth)
			}
			if durText(got.Timeout) != tc.wantTimeout {
				t.Errorf("timeout = %s, want %s", durText(got.Timeout), tc.wantTimeout)
			}
			if got.HasDetector(record.DetectorKindDast) != tc.wantDast {
				t.Errorf("HasDetector(dast) = %v, want %v", got.HasDetector(record.DetectorKindDast), tc.wantDast)
			}

			// failOn and publish come from defaults in every scenario of
			// this fixture; assert once here so a merge regression that
			// dropped defaults could not hide.
			if got.FailOn != "high" {
				t.Errorf("failOn = %q, want %q", got.FailOn, "high")
			}
			if !slices.Equal(got.Publish, []string{"sarif"}) {
				t.Errorf("publish = %v, want [sarif]", got.Publish)
			}
		})
	}
}

// TestOwnerRequirementDastOverridesResolve checks the half of the second
// requirement the scenario table above only summarises: the DAST profile and
// its duration cap reach the resolved rule, and only on the tagged-release
// path.
func TestOwnerRequirementDastOverridesResolve(t *testing.T) {
	p := ownerPolicy(t)

	major := mustEvaluate(t, p, TriggerContext{
		Event: "push", Ref: "refs/tags/v2.0.0", SemverBump: BumpMajor,
	})
	if major.Dast == nil {
		t.Fatal("major release resolved no dast overrides")
	}
	if major.Dast.Profile != "authenticated" {
		t.Errorf("dast.profile = %q, want %q", major.Dast.Profile, "authenticated")
	}
	if durText(major.Dast.MaxDuration) != "45m0s" {
		t.Errorf("dast.maxDuration = %s, want 45m0s", durText(major.Dast.MaxDuration))
	}
	if len(major.Warnings) != 0 {
		t.Errorf("warnings = %v, want none when the dast tier is actually enabled", major.Warnings)
	}

	push := mustEvaluate(t, p, TriggerContext{
		Event: "push", Ref: "refs/heads/main", ChangedPaths: []string{"main.go"},
	})
	if push.Dast != nil {
		t.Errorf("branch push resolved dast overrides %+v, want none", push.Dast)
	}
}

// ---------------------------------------------------------------------------
// 3. Evaluation order: the documented rule, not an accident
// ---------------------------------------------------------------------------

// orderPolicy is three rules that all match the same context. Rule order is
// the whole point, so the fixture is deliberately built so that a
// first-match-wins engine, a whole-object-replace engine and a correct
// field-by-field engine each produce a DIFFERENT answer.
func orderPolicy(t *testing.T) Policy {
	t.Helper()
	return Policy{
		Version: SchemaVersion,
		Defaults: &Settings{
			Detectors: detectors(record.DetectorKindSast),
			Depth:     DepthDelta,
			Timeout:   durPtr(t, "20m"),
			FailOn:    "low",
			Publish:   []string{"sarif"},
		},
		ScanRules: []ScanRule{
			{
				Name:     "broad",
				Settings: Settings{Depth: DepthFull, FailOn: "medium", Timeout: durPtr(t, "30m")},
			},
			{
				Name:        "narrower",
				MatchEvents: []string{"alpha"},
				Settings:    Settings{Detectors: detectors(record.DetectorKindSast, record.DetectorKindSCA), FailOn: "high"},
			},
			{
				Name:        "narrowest",
				MatchEvents: []string{"alpha"},
				MatchRefs:   []string{"refs/heads/**"},
				Settings:    Settings{Timeout: durPtr(t, "90m")},
			},
		},
	}
}

func TestEvaluationAppliesEveryMatchingRuleInArrayOrder(t *testing.T) {
	p := orderPolicy(t)
	got := mustEvaluate(t, p, TriggerContext{Event: "alpha", Ref: "refs/heads/main"})

	if want := []string{"broad", "narrower", "narrowest"}; !slices.Equal(got.MatchedNames(), want) {
		t.Fatalf("matched %v, want %v -- evaluation must not short-circuit on the first match",
			got.MatchedNames(), want)
	}

	// Field by field, the winner is the LAST matching rule that set the
	// field; a field no rule set falls through to defaults.
	checks := []struct {
		field, got, want, source, wantSource string
	}{
		{"depth", string(got.Depth), string(DepthFull), got.Source.Depth.Label(), `scanRules[0] "broad"`},
		{"failOn", got.FailOn, "high", got.Source.FailOn.Label(), `scanRules[1] "narrower"`},
		{"timeout", durText(got.Timeout), "1h30m0s", got.Source.Timeout.Label(), `scanRules[2] "narrowest"`},
		{"publish", strings.Join(got.Publish, ","), "sarif", got.Source.Publish.Label(), "defaults"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.field, c.got, c.want)
		}
		if c.source != c.wantSource {
			t.Errorf("%s provenance = %s, want %s", c.field, c.source, c.wantSource)
		}
	}

	// Lists are replaced wholesale by a later rule, not unioned: a rule must
	// be able to narrow the detector set back down.
	if want := detectors(record.DetectorKindSast, record.DetectorKindSCA); !slices.Equal(got.Detectors, want) {
		t.Errorf("detectors = %v, want %v", got.Detectors, want)
	}
	if got.Source.Detectors.Label() != `scanRules[1] "narrower"` {
		t.Errorf("detectors provenance = %s", got.Source.Detectors.Label())
	}
}

func TestLaterMatchingRuleNarrowsAList(t *testing.T) {
	p := Policy{
		Version:  SchemaVersion,
		Defaults: &Settings{Detectors: detectors(record.DetectorKindSast, record.DetectorKindDast)},
		ScanRules: []ScanRule{
			{Name: "de-escalate", Settings: Settings{Detectors: detectors(record.DetectorKindSast)}},
		},
	}
	got := mustEvaluate(t, p, TriggerContext{Event: "anything"})
	if want := detectors(record.DetectorKindSast); !slices.Equal(got.Detectors, want) {
		t.Fatalf("detectors = %v, want %v -- a list is one field and is replaced, not unioned "+
			"(a union would make de-escalation inexpressible)", got.Detectors, want)
	}
}

func TestNestedObjectsMergePerLeafField(t *testing.T) {
	p := Policy{
		Version: SchemaVersion,
		ScanRules: []ScanRule{
			{Name: "sets-maxduration", Settings: Settings{
				Detectors: detectors(record.DetectorKindDast),
				Dast:      &DastOverrides{MaxDuration: durPtr(t, "45m")},
			}},
			{Name: "sets-profile", Settings: Settings{
				Dast: &DastOverrides{Profile: "authenticated"},
			}},
		},
	}
	got := mustEvaluate(t, p, TriggerContext{Event: "anything"})

	if got.Dast == nil {
		t.Fatal("dast overrides were lost")
	}
	if got.Dast.Profile != "authenticated" {
		t.Errorf("dast.profile = %q, want %q", got.Dast.Profile, "authenticated")
	}
	if durText(got.Dast.MaxDuration) != "45m0s" {
		t.Errorf("dast.maxDuration = %s, want 45m0s -- a later rule setting only `profile` must not "+
			"erase an earlier rule's `maxDuration`", durText(got.Dast.MaxDuration))
	}
	if got.Source.DastProfile.Label() != `scanRules[1] "sets-profile"` ||
		got.Source.DastMaxDuration.Label() != `scanRules[0] "sets-maxduration"` {
		t.Errorf("dast provenance = profile:%s maxDuration:%s",
			got.Source.DastProfile.Label(), got.Source.DastMaxDuration.Label())
	}
}

func TestScheduleMergesPerLeafFieldAndDefaultsCannotSetIt(t *testing.T) {
	p := Policy{
		Version: SchemaVersion,
		ScanRules: []ScanRule{
			{Name: "cadence", Schedule: &Schedule{OnCalendar: "*-*-* 03:17:00", Persistent: boolPtr(true)}},
			{Name: "jitter", Schedule: &Schedule{RandomizedDelay: durPtr(t, "20m")}},
		},
	}
	got := mustEvaluate(t, p, TriggerContext{Event: "anything"})

	if got.Schedule == nil {
		t.Fatal("schedule was lost")
	}
	if got.Schedule.OnCalendar != "*-*-* 03:17:00" {
		t.Errorf("onCalendar = %q -- the calendar expression is passed through verbatim", got.Schedule.OnCalendar)
	}
	if got.Schedule.Persistent == nil || !*got.Schedule.Persistent {
		t.Errorf("persistent = %v, want true", got.Schedule.Persistent)
	}
	if durText(got.Schedule.RandomizedDelay) != "20m0s" {
		t.Errorf("randomizedDelay = %s, want 20m0s", durText(got.Schedule.RandomizedDelay))
	}
}

// TestEvaluateIsDeterministic guards the class of bug that has already shipped
// in this repository once: ranging a Go map without sorting its keys. Nothing
// in a resolution may depend on iteration order.
func TestEvaluateIsDeterministic(t *testing.T) {
	p := ownerPolicy(t)
	ctx := TriggerContext{Event: "push", Ref: "refs/tags/v2.0.0", SemverBump: BumpMajor}

	first := mustEvaluate(t, p, ctx)
	for i := 0; i < 500; i++ {
		got := mustEvaluate(t, p, ctx)
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("run %d differed from run 0:\n first = %+v\n got   = %+v", i, first, got)
		}
	}
}

// TestUnknownKeyErrorIsDeterministic covers the same class on the decode side:
// a document with two typos must always produce the same message, so the
// unknown-key set is sorted rather than reported in map order.
func TestUnknownKeyErrorIsDeterministic(t *testing.T) {
	doc := map[string]any{
		"version": int64(1),
		"zeta":    "x",
		"alpha":   "y",
		"beta":    "z",
	}
	_, err := FromDocument(doc)
	if err == nil {
		t.Fatal("unknown keys must be rejected")
	}
	first := err.Error()
	if !strings.Contains(first, "[alpha beta zeta]") {
		t.Fatalf("unknown keys must be reported sorted, got: %s", first)
	}
	for i := 0; i < 200; i++ {
		_, err := FromDocument(doc)
		if err == nil || err.Error() != first {
			t.Fatalf("run %d produced a different message:\n first = %s\n got   = %v", i, first, err)
		}
	}
}

// TestEvaluateDoesNotAliasThePolicy: a caller mutating what it got back must
// not be able to change what the next evaluation sees.
func TestEvaluateDoesNotAliasThePolicy(t *testing.T) {
	p := ownerPolicy(t)
	ctx := TriggerContext{Event: "push", Ref: "refs/tags/v2.0.0", SemverBump: BumpMajor}

	got := mustEvaluate(t, p, ctx)
	got.Detectors[0] = record.DetectorKind("clobbered")
	got.Publish[0] = "clobbered"
	*got.Timeout = 0
	got.Dast.Profile = "clobbered"

	again := mustEvaluate(t, p, ctx)
	if again.Detectors[0] != record.DetectorKindSast {
		t.Errorf("detectors aliased the policy: %v", again.Detectors)
	}
	if again.Publish[0] != "sarif" {
		t.Errorf("publish aliased the policy: %v", again.Publish)
	}
	if durText(again.Timeout) != "1h30m0s" {
		t.Errorf("timeout aliased the policy: %s", durText(again.Timeout))
	}
	if again.Dast.Profile != "authenticated" {
		t.Errorf("dast overrides aliased the policy: %+v", again.Dast)
	}
}

// ---------------------------------------------------------------------------
// 4. Nothing is compiled in
// ---------------------------------------------------------------------------

// TestEngineIsGenericOverInventedVocabulary is the owner's hard constraint,
// tested directly. Every token here is nonsense that appears nowhere in
// Anvil's source. If any event name, ref shape or path shape were special-cased
// in Go, these would not resolve.
func TestEngineIsGenericOverInventedVocabulary(t *testing.T) {
	p := Policy{
		Version:  SchemaVersion,
		Defaults: &Settings{Depth: DepthDelta},
		ScanRules: []ScanRule{
			{
				Name:        "moon",
				MatchEvents: []string{"moon_phase", "tide_change"},
				MatchRefs:   []string{"orbits/luna/**"},
				MatchPaths:  []string{"charts/*.tide"},
				Settings:    Settings{Depth: DepthFull, FailOn: "lunar"},
			},
		},
	}

	fires := mustEvaluate(t, p, TriggerContext{
		Event:        "tide_change",
		Ref:          "orbits/luna/waxing/gibbous",
		ChangedPaths: []string{"charts/spring.tide"},
	})
	if !slices.Equal(fires.MatchedNames(), []string{"moon"}) {
		t.Fatalf("invented vocabulary did not resolve: matched %v", fires.MatchedNames())
	}
	if fires.Depth != DepthFull || fires.FailOn != "lunar" {
		t.Errorf("resolved %q/%q, want full/lunar -- failOn is carried opaquely, never interpreted",
			fires.Depth, fires.FailOn)
	}

	misses := mustEvaluate(t, p, TriggerContext{
		Event:        "moon_phase",
		Ref:          "orbits/sol/noon",
		ChangedPaths: []string{"charts/spring.tide"},
	})
	if len(misses.Matched) != 0 {
		t.Errorf("matched %v, want none", misses.MatchedNames())
	}
}

func TestRuleWithNoMatchKeysMatchesEverything(t *testing.T) {
	p := Policy{
		Version: SchemaVersion,
		ScanRules: []ScanRule{
			{Name: "baseline", Settings: Settings{Depth: DepthFull}},
		},
	}
	for _, ctx := range []TriggerContext{
		{},
		{Event: "push", Ref: "refs/heads/main", ChangedPaths: []string{"a.go"}},
		{Event: "schedule"},
		{Ref: "refs/tags/v1.0.0", SemverBump: BumpMajor},
	} {
		got := mustEvaluate(t, p, ctx)
		if len(got.Matched) != 1 {
			t.Errorf("ctx %+v matched %v, want the baseline rule", ctx, got.MatchedNames())
		}
	}
}

// ---------------------------------------------------------------------------
// 5. Match semantics, key by key
// ---------------------------------------------------------------------------

func TestMatchesInclusionAndExclusionAsymmetry(t *testing.T) {
	cases := []struct {
		name string
		rule ScanRule
		ctx  TriggerContext
		want bool
	}{
		{
			name: "inclusion key unsatisfiable by a silent context: no event",
			rule: ScanRule{Name: "r", MatchEvents: []string{"push"}},
			ctx:  TriggerContext{},
			want: false,
		},
		{
			name: "inclusion key unsatisfiable by a silent context: no ref",
			rule: ScanRule{Name: "r", MatchRefs: []string{"**"}},
			ctx:  TriggerContext{Event: "push"},
			want: false,
		},
		{
			name: "inclusion key unsatisfiable by a silent context: no changed paths",
			rule: ScanRule{Name: "r", MatchPaths: []string{"**"}},
			ctx:  TriggerContext{Event: "push"},
			want: false,
		},
		{
			name: "inclusion key unsatisfiable by a silent context: no bump",
			rule: ScanRule{Name: "r", MatchSemverBump: []BumpKind{BumpMajor}},
			ctx:  TriggerContext{Event: "push", Ref: "refs/tags/v1.0.0"},
			want: false,
		},
		{
			name: "exclusion key cannot fire on a silent context: no ref",
			rule: ScanRule{Name: "r", MatchRefsIgnore: []string{"**"}},
			ctx:  TriggerContext{Event: "push"},
			want: true,
		},
		{
			name: "exclusion key cannot fire on a silent context: no changed paths",
			rule: ScanRule{Name: "r", MatchPathsIgnore: []string{"**"}},
			ctx:  TriggerContext{Event: "push", Ref: "refs/tags/v1.0.0"},
			want: true,
		},
		{
			name: "matchRefsIgnore excludes a ref matchRefs accepted",
			rule: ScanRule{Name: "r", MatchRefs: []string{"refs/heads/**"}, MatchRefsIgnore: []string{"refs/heads/wip/**"}},
			ctx:  TriggerContext{Ref: "refs/heads/wip/spike"},
			want: false,
		},
		{
			name: "matchRefsIgnore leaves other refs alone",
			rule: ScanRule{Name: "r", MatchRefs: []string{"refs/heads/**"}, MatchRefsIgnore: []string{"refs/heads/wip/**"}},
			ctx:  TriggerContext{Ref: "refs/heads/main"},
			want: true,
		},
		{
			name: "matchPathsIgnore excludes only when EVERY path is ignored",
			rule: ScanRule{Name: "r", MatchPathsIgnore: []string{"docs/**", "**/*.md"}},
			ctx:  TriggerContext{ChangedPaths: []string{"docs/a.md", "CHANGELOG.md", "docs/b/c.txt"}},
			want: false,
		},
		{
			name: "matchPathsIgnore keeps the rule when one path is not ignored",
			rule: ScanRule{Name: "r", MatchPathsIgnore: []string{"docs/**", "**/*.md"}},
			ctx:  TriggerContext{ChangedPaths: []string{"docs/a.md", "internal/x.go"}},
			want: true,
		},
		{
			name: "match keys are ANDed",
			rule: ScanRule{Name: "r", MatchEvents: []string{"push"}, MatchRefs: []string{"refs/tags/**"}},
			ctx:  TriggerContext{Event: "push", Ref: "refs/heads/main"},
			want: false,
		},
		{
			name: "event comparison is exact, not case-folded",
			rule: ScanRule{Name: "r", MatchEvents: []string{"push"}},
			ctx:  TriggerContext{Event: "PUSH"},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rule.Matches(tc.ctx)
			if err != nil {
				t.Fatalf("Matches: %v", err)
			}
			if got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6. Globs
// ---------------------------------------------------------------------------

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"**", "", true},
		{"**", "a", true},
		{"**", "a/b/c", true},
		{"refs/heads/**", "refs/heads/main", true},
		{"refs/heads/**", "refs/heads/feature/deep/branch", true},
		{"refs/heads/**", "refs/heads", true}, // ** matches zero segments
		{"refs/heads/**", "refs/tags/v1", false},
		{"refs/tags/v*", "refs/tags/v2.0.0", true},
		{"refs/tags/v*", "refs/tags/rc1", false},
		{"refs/tags/v*", "refs/tags/v2/extra", false}, // * does not cross /
		{"docs/**", "docs/a/b.md", true},
		{"docs/**", "docs", true},
		{"docs/**", "documents/a.md", false},
		{"**/*.md", "README.md", true}, // ** matching zero segments is load-bearing
		{"**/*.md", "docs/a/b.md", true},
		{"**/*.md", "docs/a/b.go", false},
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b", "a/x/y/c", false},
		{"*.go", "main.go", true},
		{"*.go", "internal/main.go", false},
		{"charts/?.tide", "charts/a.tide", true},
		{"charts/[ab].tide", "charts/b.tide", true},
		{"charts/[^ab].tide", "charts/b.tide", false},
		{"charts/[^ab].tide", "charts/c.tide", true},
		// path.Match's negation is '^', not '!'. `[!ab]` is the class
		// {'!','a','b'} -- documented on MatchGlob, asserted here so the
		// dialect cannot drift silently.
		{"charts/[!ab].tide", "charts/b.tide", true},
		{"charts/[!ab].tide", "charts/!.tide", true},
		{"charts/[!ab].tide", "charts/c.tide", false},
	}

	for _, tc := range cases {
		t.Run(tc.pattern+" vs "+tc.name, func(t *testing.T) {
			got, err := MatchGlob(tc.pattern, tc.name)
			if err != nil {
				t.Fatalf("MatchGlob: %v", err)
			}
			if got != tc.want {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
			}
		})
	}
}

// TestMalformedGlobErrorsRegardlessOfTheContext is the reason validateGlob
// exists. path.Match only reports a bad pattern when its scan reaches the bad
// part, so a naive implementation would error for some inputs and silently
// not-match for others -- a rule that fails differently depending on which
// commit arrived.
func TestMalformedGlobErrorsRegardlessOfTheContext(t *testing.T) {
	for _, pattern := range []string{"refs/[heads/**", "refs/heads/x\\", "a[b-"} {
		if _, err := MatchGlob(pattern, "zzz/no/chance/of/a/match"); !errors.Is(err, ErrBadPattern) {
			t.Errorf("MatchGlob(%q, ...) err = %v, want ErrBadPattern", pattern, err)
		}
	}

	rule := ScanRule{
		Name:        "broken",
		MatchEvents: []string{"push"},
		MatchPaths:  []string{"src/[unterminated"},
	}
	// The event key alone would have decided "no match"; the malformed glob
	// must still surface.
	if _, err := rule.Matches(TriggerContext{Event: "release"}); !errors.Is(err, ErrBadPattern) {
		t.Errorf("Matches err = %v, want ErrBadPattern even when another key would have short-circuited", err)
	}

	p := Policy{Version: SchemaVersion, ScanRules: []ScanRule{rule}}
	_, err := Evaluate(p, TriggerContext{Event: "release"})
	if !errors.Is(err, ErrBadPattern) {
		t.Fatalf("Evaluate err = %v, want ErrBadPattern", err)
	}
	if !strings.Contains(err.Error(), `scanRules[0] "broken"`) ||
		!strings.Contains(err.Error(), "matchPaths[0]") {
		t.Errorf("error must name the rule and the key, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 6b. The glob matcher is BOUNDED — CRITIQUE O.4 finding O4-M4
//
// `.anvil/policy.yml` is read from the repository under scan. On the public-repo
// path that makes every pattern in it attacker-controlled input reaching a
// matcher, so "how long can one MatchGlob take" is a security question and not a
// benchmark. The previous `**` handling recursed over every split point with no
// memoisation: the critic measured 8.5s for ten `**` segments against a
// thirty-segment path, 29s for one rule over two hundred changed paths, and no
// termination inside a ten-minute test timeout at twelve.
//
// These three tests are the regression. They assert TERMINATION UNDER A BUDGET,
// not a wall-clock speed target, so they do not become flaky on a loaded CI box:
// the bound they check is four orders of magnitude above the measured cost of
// the fixed matcher and four orders of magnitude below the broken one.
// ---------------------------------------------------------------------------

// globBudget is the per-case time budget. The bottom-up matcher does the work
// below in single-digit milliseconds; the recursive one did not finish at all.
const globBudget = 5 * time.Second

// runWithin runs fn and fails if it has not returned within budget. It reports
// the elapsed time either way, so a regression shows up as a number in the log
// rather than only as a hung test binary.
func runWithin(t *testing.T, budget time.Duration, name string, fn func()) {
	t.Helper()
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		fn()
		done <- time.Since(start)
	}()
	select {
	case elapsed := <-done:
		t.Logf("%s: %s", name, elapsed)
		if elapsed > budget {
			t.Errorf("%s took %s, over the %s budget", name, elapsed, budget)
		}
	case <-time.After(budget):
		// The goroutine is left running; the test binary will exit and take it
		// with it. Blocking on a matcher that may never return is precisely the
		// failure being tested for.
		t.Fatalf("%s did not return within %s: the glob matcher is unbounded again (O4-M4)", name, budget)
	}
}

func TestPathologicalGlobPatternsTerminateFast(t *testing.T) {
	// The critic's exact construction: k independent `**` segments against an
	// n-segment path, with a final literal that cannot match, so every split
	// point is explored before the matcher can answer false.
	//
	// 20 `**` segments is under MaxGlobPatternSegments and is therefore a
	// pattern this engine ACCEPTS and must evaluate; the old matcher's cost
	// here is O(n^20).
	for _, tc := range []struct{ stars, segments int }{
		{6, 20}, {11, 20}, {11, 30}, {20, 40}, {20, 200},
	} {
		pattern := strings.Repeat(doubleStar+"/", tc.stars) + "zzz"
		name := strings.TrimSuffix(strings.Repeat("a/", tc.segments), "/")
		runWithin(t, globBudget, fmt.Sprintf("MatchGlob(%d **, %d segments)", tc.stars, tc.segments), func() {
			ok, err := MatchGlob(pattern, name)
			if err != nil {
				t.Errorf("MatchGlob: %v", err)
			}
			if ok {
				t.Errorf("MatchGlob(%q, %q) = true; the trailing literal cannot match", pattern, name)
			}
		})
	}
}

// The cost the critic actually measured inside Evaluate: one rule, one pattern,
// two hundred changed paths, because Matches loops anyGlobMatches per path and
// Evaluate loops that per rule. 29.3s before; this asserts the whole evaluation
// fits in the budget.
func TestPathologicalGlobInsideEvaluateTerminatesFast(t *testing.T) {
	paths := make([]string, 200)
	for i := range paths {
		paths[i] = strings.TrimSuffix(strings.Repeat("a/", 30), "/") + fmt.Sprintf("/f%d.go", i)
	}
	p := Policy{
		Version: SchemaVersion,
		ScanRules: []ScanRule{{
			Name:       "pathological",
			MatchPaths: []string{strings.Repeat(doubleStar+"/", 12) + "zzz"},
			Settings:   Settings{Depth: DepthFull},
		}},
	}
	runWithin(t, globBudget, "Evaluate over 200 changed paths with 12 **", func() {
		got, err := Evaluate(p, TriggerContext{Event: "push", ChangedPaths: paths})
		if err != nil {
			t.Errorf("Evaluate: %v", err)
		}
		if len(got.MatchedNames()) != 0 {
			t.Errorf("MatchedNames = %v, want none", got.MatchedNames())
		}
	})
}

// Past the cap the pattern is REFUSED, with an error naming the bound. A refused
// policy is a diagnosable outcome; the failure this replaces was a scan that
// never started and never said why.
func TestOverCapGlobPatternsAreRefusedNotMatched(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
	}{
		{"too many bytes", strings.Repeat("a", MaxGlobPatternBytes+1)},
		{"too many segments", strings.TrimSuffix(strings.Repeat("*/", MaxGlobPatternSegments+1), "/")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := MatchGlob(tc.pattern, "a/b/c")
			if !errors.Is(err, ErrPatternTooComplex) {
				t.Fatalf("MatchGlob err = %v, want ErrPatternTooComplex", err)
			}
			// Callers written before the cap existed branch on ErrBadPattern.
			if !errors.Is(err, ErrBadPattern) {
				t.Errorf("err = %v, must also satisfy errors.Is(err, ErrBadPattern)", err)
			}

			// It is refused at RULE level too, before any path is walked, so a
			// rule carrying one over-cap pattern cannot evaluate at all.
			rule := ScanRule{Name: "over-cap", MatchPaths: []string{tc.pattern}}
			if _, err := rule.Matches(TriggerContext{Event: "push"}); !errors.Is(err, ErrPatternTooComplex) {
				t.Errorf("Matches err = %v, want ErrPatternTooComplex", err)
			}
			p := Policy{Version: SchemaVersion, ScanRules: []ScanRule{rule}}
			if _, err := Evaluate(p, TriggerContext{Event: "push"}); !errors.Is(err, ErrPatternTooComplex) {
				t.Errorf("Evaluate err = %v, want ErrPatternTooComplex", err)
			}
		})
	}

	// Negative control: exactly AT the cap is legal. A cap that also rejected
	// the boundary would be a different, undocumented cap.
	atBytes := strings.Repeat("a", MaxGlobPatternBytes)
	if _, err := MatchGlob(atBytes, "a"); err != nil {
		t.Errorf("a pattern of exactly %d bytes must be accepted, got %v", MaxGlobPatternBytes, err)
	}
	atSegments := strings.TrimSuffix(strings.Repeat("*/", MaxGlobPatternSegments), "/")
	if _, err := MatchGlob(atSegments, "a"); err != nil {
		t.Errorf("a pattern of exactly %d segments must be accepted, got %v", MaxGlobPatternSegments, err)
	}
}

// ---------------------------------------------------------------------------
// 6b. AGGREGATE BOUNDS — the same outage, reached by multiplication
// ---------------------------------------------------------------------------
//
// The tests above bound the price of ONE pattern. These bound the QUANTITY.
// Ten thousand cheap rules cost the same outage as one expensive one, and
// `.anvil/policy.yml` comes from the repository under scan in both cases, so a
// per-pattern cap with no aggregate cap is a bounded unit price on an unbounded
// order. See the AGGREGATE BOUNDS section of engine.go for the arithmetic these
// numbers were chosen against.
//
// Every case below asserts three things, because a bound is only useful if all
// three hold: a policy AT the cap still works, a policy PAST it is refused
// FAST, and the refusal NAMES the bound and the limit.

// aggPolicy builds a policy of n rules, each carrying pathPatterns changed-path
// globs that cannot match anything.
//
// Nothing may match, on purpose: ScanRule.Matches short-circuits on the first
// pattern that hits, so a policy whose patterns match measures the best case.
// The bounds exist for the worst case, which is the one an attacker picks.
func aggPolicy(n, pathPatterns int) Policy {
	p := Policy{Version: SchemaVersion, ScanRules: make([]ScanRule, n)}
	for i := range p.ScanRules {
		r := ScanRule{Name: fmt.Sprintf("r%d", i)}
		for j := 0; j < pathPatterns; j++ {
			r.MatchPaths = append(r.MatchPaths, fmt.Sprintf("zz%d/**/nope%d.zzz", i, j))
		}
		p.ScanRules[i] = r
	}
	return p
}

// aggPaths builds n changed paths, none of which any aggPolicy pattern matches.
func aggPaths(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("src/pkg%d/file%d.go", i%64, i)
	}
	return out
}

// TestAggregateBoundsAcceptTheCapAndRefuseOneOver walks each of the four bounds
// to its exact edge from both sides.
//
// The policies here are built as Go values and never pass through FromDocument
// or through schema validation, which is the point: the schema's maxItems
// cannot help a Policy that did not come from the schema, so the engine has to
// hold the bound itself.
func TestAggregateBoundsAcceptTheCapAndRefuseOneOver(t *testing.T) {
	cases := []struct {
		name string
		// atCap and overCap differ by exactly one unit of the bound.
		atCap, overCap func() (Policy, TriggerContext)
		// constant is the Go constant the refusal must name, and limit and
		// observed are the two numbers it must carry.
		constant string
		limit    int
		observed int
	}{
		{
			name:     "MaxScanRules",
			atCap:    func() (Policy, TriggerContext) { return aggPolicy(MaxScanRules, 0), TriggerContext{Event: "push"} },
			overCap:  func() (Policy, TriggerContext) { return aggPolicy(MaxScanRules+1, 0), TriggerContext{Event: "push"} },
			constant: "MaxScanRules",
			limit:    MaxScanRules,
			observed: MaxScanRules + 1,
		},
		{
			name: "MaxListItems",
			atCap: func() (Policy, TriggerContext) {
				return aggPolicy(1, MaxListItems), TriggerContext{Event: "push", ChangedPaths: aggPaths(4)}
			},
			overCap: func() (Policy, TriggerContext) {
				return aggPolicy(1, MaxListItems+1), TriggerContext{Event: "push", ChangedPaths: aggPaths(4)}
			},
			constant: "MaxListItems",
			limit:    MaxListItems,
			observed: MaxListItems + 1,
		},
		{
			name: "MaxChangedPaths",
			atCap: func() (Policy, TriggerContext) {
				return aggPolicy(1, 1), TriggerContext{Event: "push", ChangedPaths: aggPaths(MaxChangedPaths)}
			},
			overCap: func() (Policy, TriggerContext) {
				return aggPolicy(1, 1), TriggerContext{Event: "push", ChangedPaths: aggPaths(MaxChangedPaths + 1)}
			},
			constant: "MaxChangedPaths",
			limit:    MaxChangedPaths,
			observed: MaxChangedPaths + 1,
		},
		{
			// 250 rules x 1 pattern x 1000 paths is exactly the budget; one
			// more rule is exactly 1000 over it.
			name: "MaxEvaluationMatchOps",
			atCap: func() (Policy, TriggerContext) {
				return aggPolicy(250, 1), TriggerContext{Event: "push", ChangedPaths: aggPaths(1000)}
			},
			overCap: func() (Policy, TriggerContext) {
				return aggPolicy(251, 1), TriggerContext{Event: "push", ChangedPaths: aggPaths(1000)}
			},
			constant: "MaxEvaluationMatchOps",
			limit:    MaxEvaluationMatchOps,
			observed: 251 * 1000,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// AT the cap: it works, and it works in full. A bound that also
			// rejected its own boundary would be a different, undocumented
			// bound -- and the operator would be reading the wrong number.
			p, ctx := tc.atCap()
			runWithin(t, globBudget, tc.name+" at the cap", func() {
				if _, err := Evaluate(p, ctx); err != nil {
					t.Errorf("a policy exactly AT %s was refused: %v", tc.constant, err)
				}
			})

			// PAST the cap: refused, fast. The check is O(rules) arithmetic
			// performed before the first path.Match call, so "fast" here means
			// microseconds and the budget is enormous slack.
			over, overCtx := tc.overCap()
			var err error
			runWithin(t, globBudget, tc.name+" one over the cap", func() {
				_, err = Evaluate(over, overCtx)
			})
			if err == nil {
				t.Fatalf("a policy one unit past %s was ACCEPTED; the bound does not exist", tc.constant)
			}
			if !errors.Is(err, ErrPolicyTooLarge) {
				t.Errorf("err = %v, want errors.Is(err, ErrPolicyTooLarge)", err)
			}

			// The refusal must be actionable: which bound, what the limit is,
			// and what was actually seen. "Too large" without the numbers sends
			// an operator to guess at a policy they cannot run.
			msg := err.Error()
			for _, want := range []string{tc.constant, fmt.Sprint(tc.limit), fmt.Sprint(tc.observed)} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal does not carry %q:\n    %v", want, err)
				}
			}
		})
	}
}

// TestTenThousandCheapRulesAreRefusedFast is the residual's own scenario, in its
// own words: "Ten thousand cheap rules is the same outage as one expensive one."
//
// Unbounded, this policy performs 10,000 x 500 = 5,000,000 pattern matches per
// event — several seconds of a scanner doing nothing an operator asked for, on
// every push, triggered by committing a file. It is refused after 1 comparison.
func TestTenThousandCheapRulesAreRefusedFast(t *testing.T) {
	p := aggPolicy(10_000, 1)
	ctx := TriggerContext{Event: "push", ChangedPaths: aggPaths(500)}

	var err error
	runWithin(t, globBudget, "Evaluate over 10,000 cheap rules", func() {
		var got ResolvedRule
		got, err = Evaluate(p, ctx)
		if err == nil {
			t.Errorf("10,000 rules evaluated instead of being refused; %d matched", len(got.Matched))
		}
	})
	if !errors.Is(err, ErrPolicyTooLarge) {
		t.Fatalf("err = %v, want ErrPolicyTooLarge", err)
	}
	// It is refused on the RULE COUNT, before the work budget ever multiplies
	// anything -- which is what keeps the budget arithmetic itself bounded.
	if !strings.Contains(err.Error(), "MaxScanRules") {
		t.Errorf("the refusal does not name MaxScanRules:\n    %v", err)
	}

	// The same file, arriving through the loader, is refused before it is
	// decoded rule by rule.
	doc := map[string]any{"version": 1, "scanRules": make([]any, 10_000)}
	for i := range doc["scanRules"].([]any) {
		doc["scanRules"].([]any)[i] = map[string]any{"name": fmt.Sprintf("r%d", i)}
	}
	runWithin(t, globBudget, "FromDocument over 10,000 cheap rules", func() {
		got, ferr := FromDocument(doc)
		if ferr == nil {
			t.Errorf("FromDocument accepted 10,000 rules")
		}
		if !errors.Is(ferr, ErrPolicyTooLarge) || !errors.Is(ferr, ErrInvalidDocument) {
			t.Errorf("FromDocument err = %v, want both ErrPolicyTooLarge and ErrInvalidDocument", ferr)
		}
		if len(got.ScanRules) != 0 || got.Version != 0 {
			t.Errorf("FromDocument returned a partial policy (%d rules, version %d) alongside its "+
				"error; a refusal must yield nothing", len(got.ScanRules), got.Version)
		}
	})
}

// TestAggregateRefusalIsNeverATruncation is the property the residual singles
// out as the one that must not be got wrong:
//
//	"A refused policy is a good outcome; a silently truncated policy is the
//	 worst outcome, because the operator believes rules are in force that are
//	 not."
//
// So: an over-cap policy yields NOTHING, and an at-cap policy yields ALL of it.
func TestAggregateRefusalIsNeverATruncation(t *testing.T) {
	ctx := TriggerContext{Event: "push"}

	// Over the cap: the zero ResolvedRule and an error. Not the first 256
	// rules, not a best-effort resolution, nothing.
	over := aggPolicy(MaxScanRules+1, 0)
	over.Defaults = &Settings{Depth: DepthFull, Detectors: detectors(record.DetectorKindSast)}
	got, err := Evaluate(over, ctx)
	if err == nil {
		t.Fatal("an over-cap policy was evaluated")
	}
	if len(got.Matched) != 0 || len(got.Detectors) != 0 || got.Depth != "" {
		t.Errorf("a refused evaluation returned settings (%d matched, detectors %v, depth %q); "+
			"a caller that ignored the error would act on a policy that was never applied",
			len(got.Matched), got.Detectors, got.Depth)
	}

	// At the cap: every one of the rules is applied. A bound implemented as
	// "stop after N" instead of "refuse past N" would pass every assertion
	// above and fail this one, which is exactly the silent truncation the
	// operator would never see.
	atCap := aggPolicy(MaxScanRules, 0)
	for i := range atCap.ScanRules {
		atCap.ScanRules[i].Settings.FailOn = fmt.Sprintf("level%d", i)
	}
	resolved, err := Evaluate(atCap, ctx)
	if err != nil {
		t.Fatalf("a policy exactly at MaxScanRules was refused: %v", err)
	}
	if len(resolved.Matched) != MaxScanRules {
		t.Errorf("%d of %d rules were applied; the rest were dropped silently",
			len(resolved.Matched), MaxScanRules)
	}
	if want := fmt.Sprintf("level%d", MaxScanRules-1); resolved.FailOn != want {
		t.Errorf("failOn = %q, want %q from the LAST rule; a truncated evaluation would carry an "+
			"earlier rule's value and look entirely plausible", resolved.FailOn, want)
	}
}

// TestFromDocumentEnforcesTheAggregateBoundsToo covers the loader arm. The
// schema's maxItems and these checks must agree, and
// TestPolicySchemaAggregateBoundsMatchTheEngineCaps is what keeps them agreeing;
// this asserts the loader refuses rather than merely that the numbers match.
func TestFromDocumentEnforcesTheAggregateBoundsToo(t *testing.T) {
	rule := func(patterns int) map[string]any {
		globs := make([]any, patterns)
		for i := range globs {
			globs[i] = fmt.Sprintf("src/**/f%d.go", i)
		}
		return map[string]any{"name": "r", "matchPaths": globs}
	}

	cases := []struct {
		name string
		doc  any
		want string
	}{
		{
			name: "one rule past MaxScanRules",
			doc: func() any {
				rules := make([]any, MaxScanRules+1)
				for i := range rules {
					rules[i] = map[string]any{"name": fmt.Sprintf("r%d", i)}
				}
				return map[string]any{"version": 1, "scanRules": rules}
			}(),
			want: "MaxScanRules",
		},
		{
			name: "one glob past MaxListItems",
			doc:  map[string]any{"version": 1, "scanRules": []any{rule(MaxListItems + 1)}},
			want: "MaxListItems",
		},
		{
			name: "a token list past MaxListItems in defaults",
			doc: func() any {
				sinks := make([]any, MaxListItems+1)
				for i := range sinks {
					sinks[i] = fmt.Sprintf("sink%d", i)
				}
				return map[string]any{"version": 1, "defaults": map[string]any{"publish": sinks}}
			}(),
			want: "MaxListItems",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := FromDocument(tc.doc)
			if err == nil {
				t.Fatalf("FromDocument accepted an over-cap document (%d rules)", len(p.ScanRules))
			}
			if !errors.Is(err, ErrPolicyTooLarge) {
				t.Errorf("err = %v, want ErrPolicyTooLarge", err)
			}
			// A document past a maxItems the schema declares is an invalid
			// document, so callers branching on ErrInvalidDocument still work.
			if !errors.Is(err, ErrInvalidDocument) {
				t.Errorf("err = %v, must also satisfy errors.Is(err, ErrInvalidDocument)", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name %s:\n    %v", tc.want, err)
			}
		})
	}

	// Negative control: exactly AT each cap, the loader accepts and decodes in
	// full. Without this the assertions above would pass against a loader that
	// had been broken shut.
	rules := make([]any, MaxScanRules)
	for i := range rules {
		rules[i] = map[string]any{"name": fmt.Sprintf("r%d", i)}
	}
	rules[0] = rule(MaxListItems)
	p, err := FromDocument(map[string]any{"version": 1, "scanRules": rules})
	if err != nil {
		t.Fatalf("a document exactly at both caps was refused: %v", err)
	}
	if len(p.ScanRules) != MaxScanRules {
		t.Errorf("decoded %d rules, want %d", len(p.ScanRules), MaxScanRules)
	}
	if len(p.ScanRules[0].MatchPaths) != MaxListItems {
		t.Errorf("decoded %d globs on the first rule, want %d",
			len(p.ScanRules[0].MatchPaths), MaxListItems)
	}
}

// TestMatchesEnforcesTheBoundsAtItsOwnEntryPoint: ScanRule.Matches is exported
// and is therefore an entry point in its own right. A caller that reaches it
// directly, without Evaluate, must hit the same bounds — an entry point that
// enforced nothing would be the bypass this section exists to close, and this
// package's sibling has now paid four times for exactly that shape.
func TestMatchesEnforcesTheBoundsAtItsOwnEntryPoint(t *testing.T) {
	overList := aggPolicy(1, MaxListItems+1).ScanRules[0]
	if _, err := overList.Matches(TriggerContext{Event: "push"}); !errors.Is(err, ErrPolicyTooLarge) {
		t.Errorf("Matches on an over-cap pattern list = %v, want ErrPolicyTooLarge", err)
	}

	cheap := aggPolicy(1, 1).ScanRules[0]
	if _, err := cheap.Matches(TriggerContext{Event: "push", ChangedPaths: aggPaths(MaxChangedPaths + 1)}); !errors.Is(err, ErrPolicyTooLarge) {
		t.Errorf("Matches over %d changed paths = %v, want ErrPolicyTooLarge", MaxChangedPaths+1, err)
	}

	wide := aggPolicy(1, MaxListItems).ScanRules[0]
	if _, err := wide.Matches(TriggerContext{Event: "push", ChangedPaths: aggPaths(MaxChangedPaths)}); !errors.Is(err, ErrPolicyTooLarge) {
		t.Errorf("Matches at %d patterns x %d paths (%d ops) = %v, want ErrPolicyTooLarge",
			MaxListItems, MaxChangedPaths, MaxListItems*MaxChangedPaths, err)
	}

	// Negative control: the ordinary case still matches.
	ok, err := cheap.Matches(TriggerContext{Event: "push", ChangedPaths: aggPaths(10)})
	if err != nil {
		t.Errorf("an ordinary rule was refused: %v", err)
	}
	if ok {
		t.Error("the control rule matched; its patterns are built not to")
	}
}

// ---------------------------------------------------------------------------
// 7. Warnings and version
// ---------------------------------------------------------------------------

func TestDastOverridesWithoutTheDastTierWarn(t *testing.T) {
	p := Policy{
		Version:  SchemaVersion,
		Defaults: &Settings{Detectors: detectors(record.DetectorKindSast)},
		ScanRules: []ScanRule{
			{Name: "oops", Settings: Settings{Dast: &DastOverrides{Profile: "authenticated"}}},
		},
	}
	got := mustEvaluate(t, p, TriggerContext{Event: "anything"})

	if len(got.Warnings) != 1 {
		t.Fatalf("warnings = %v, want exactly one -- the schema requires a warning rather than "+
			"silent ignoring", got.Warnings)
	}
	w := got.Warnings[0]
	for _, want := range []string{`scanRules[0] "oops"`, string(record.DetectorKindDast), "no effect"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning %q must mention %q", w, want)
		}
	}

	// The warning is a diagnostic and changes nothing about the resolution.
	if !slices.Equal(got.Detectors, detectors(record.DetectorKindSast)) {
		t.Errorf("detectors = %v; a warning must not alter the resolution", got.Detectors)
	}
	if got.Dast == nil || got.Dast.Profile != "authenticated" {
		t.Errorf("dast overrides must still be carried, got %+v", got.Dast)
	}
}

func TestEvaluateRejectsAnUnsupportedVersion(t *testing.T) {
	for _, v := range []int{0, 2, -1} {
		_, err := Evaluate(Policy{Version: v}, TriggerContext{})
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("Evaluate(version=%d) err = %v, want ErrUnsupportedVersion", v, err)
		}
	}
}

// ---------------------------------------------------------------------------
// 8. The decoder
// ---------------------------------------------------------------------------

func TestFromDocumentRejects(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr error
		want    string // substring the message must carry
	}{
		{
			name:    "the matchEvent typo the schema exists to catch",
			yaml:    "version: 1\nscanRules:\n  - name: r\n    matchEvent: [push]\n",
			wantErr: ErrInvalidDocument,
			want:    "matchEvent",
		},
		{
			name:    "unknown top-level key",
			yaml:    "version: 1\nscanRule: []\n",
			wantErr: ErrInvalidDocument,
			want:    "scanRule",
		},
		{
			name:    "unknown dast key",
			yaml:    "version: 1\ndefaults:\n  dast:\n    profile: a\n    maxDurationn: 5m\n",
			wantErr: ErrInvalidDocument,
			want:    "maxDurationn",
		},
		{
			name:    "missing version",
			yaml:    "defaults:\n  depth: full\n",
			wantErr: ErrInvalidDocument,
			want:    "/version is required",
		},
		{
			name:    "wrong version",
			yaml:    "version: 2\n",
			wantErr: ErrUnsupportedVersion,
			want:    "want 1",
		},
		{
			name:    "empty list means matches nothing, which is always a mistake",
			yaml:    "version: 1\nscanRules:\n  - name: r\n    matchEvents: []\n",
			wantErr: ErrInvalidDocument,
			want:    "must not be empty",
		},
		{
			name:    "duplicate list item",
			yaml:    "version: 1\nscanRules:\n  - name: r\n    matchEvents: [push, push]\n",
			wantErr: ErrInvalidDocument,
			want:    "duplicate",
		},
		{
			name:    "duplicate rule name",
			yaml:    "version: 1\nscanRules:\n  - name: r\n  - name: r\n",
			wantErr: ErrInvalidDocument,
			want:    "unique",
		},
		{
			name:    "missing rule name",
			yaml:    "version: 1\nscanRules:\n  - depth: full\n",
			wantErr: ErrInvalidDocument,
			want:    "/name is required",
		},
		{
			name:    "depth outside the schema's enum",
			yaml:    "version: 1\ndefaults:\n  depth: deep\n",
			wantErr: ErrInvalidDocument,
			want:    "/depth",
		},
		{
			name:    "detector outside area 40's enum",
			yaml:    "version: 1\ndefaults:\n  detectors: [sast, iast]\n",
			wantErr: ErrInvalidDocument,
			want:    "detectors/1",
		},
		{
			name:    "semver bump outside the schema's enum",
			yaml:    "version: 1\nscanRules:\n  - name: r\n    matchSemverBump: [mayor]\n",
			wantErr: ErrInvalidDocument,
			want:    "matchSemverBump/0",
		},
		{
			name:    "duration that is not a duration",
			yaml:    "version: 1\ndefaults:\n  timeout: soon\n",
			wantErr: ErrInvalidDocument,
			want:    "is not a duration",
		},
		{
			name:    "signed duration",
			yaml:    "version: 1\ndefaults:\n  timeout: -20m\n",
			wantErr: ErrInvalidDocument,
			want:    "must not be signed",
		},
		{
			name:    "scanRules is not a sequence",
			yaml:    "version: 1\nscanRules:\n  name: r\n",
			wantErr: ErrInvalidDocument,
			want:    "must be a sequence",
		},
		{
			name:    "persistent is not a boolean",
			yaml:    "version: 1\nscanRules:\n  - name: r\n    schedule: { persistent: yesterday }\n",
			wantErr: ErrInvalidDocument,
			want:    "must be a boolean",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := o5yamlDecode(tc.yaml)
			if err != nil {
				t.Fatalf("the fixture itself did not decode: %v", err)
			}
			_, err = FromDocument(doc)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q must mention %q", err, tc.want)
			}
		})
	}
}

func TestFromDocumentAcceptsAMinimalPolicy(t *testing.T) {
	doc, err := o5yamlDecode("version: 1\n")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	p, err := FromDocument(doc)
	if err != nil {
		t.Fatalf("FromDocument: %v", err)
	}
	got := mustEvaluate(t, p, TriggerContext{Event: "push"})

	// A policy with no defaults inherits NOTHING implicitly: the engine's own
	// fallback is the empty settings object.
	if len(got.Detectors) != 0 || got.Depth != "" || got.Timeout != nil ||
		got.FailOn != "" || len(got.Publish) != 0 || got.Dast != nil {
		t.Errorf("empty policy resolved to %+v, want everything unset -- the engine must have no "+
			"built-in defaults of its own", got)
	}
	if got.Source.Detectors.Label() != "(unset)" {
		t.Errorf("provenance = %s, want (unset)", got.Source.Detectors.Label())
	}
}

// TestDecoderKeySetsMatchSchema keeps the Go decoder a faithful projection of
// schemas/policy.schema.json instead of a second, drifting definition of the
// document shape. Adding a key to the schema without teaching the decoder
// fails here, and so does the reverse.
func TestDecoderKeySetsMatchSchema(t *testing.T) {
	raw, err := os.ReadFile("../../" + SchemaPath)
	if err != nil {
		t.Fatalf("reading the schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parsing the schema: %v", err)
	}

	defs, _ := schema["$defs"].(map[string]any)
	if defs == nil {
		t.Fatal("schema has no $defs")
	}

	propsOf := func(node any, where string) []string {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("%s is not an object", where)
		}
		props, ok := m["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s has no properties", where)
		}
		out := make([]string, 0, len(props))
		for k := range props {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}

	cases := []struct {
		where string
		node  any
		keys  []string
	}{
		{"(document root)", schema, keysPolicy},
		{"$defs/settings", defs["settings"], keysSettings},
		{"$defs/scanRule", defs["scanRule"], keysScanRule},
		{"$defs/dastOverrides", defs["dastOverrides"], keysDast},
		{"$defs/schedule", defs["schedule"], keysSchedule},
	}
	for _, tc := range cases {
		want := propsOf(tc.node, tc.where)
		got := slices.Clone(tc.keys)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s: decoder accepts %v, schema declares %v", tc.where, got, want)
		}
	}
}

// TestFrozenEnumsAreNotForked: the two enums this package owns are the
// schema's, and the detector vocabulary is area 40's. Assert the schema's own
// text still says so, and that this package never re-enumerates detectors.
func TestFrozenEnumsAreNotForked(t *testing.T) {
	raw, err := os.ReadFile("../../" + SchemaPath)
	if err != nil {
		t.Fatalf("reading the schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parsing the schema: %v", err)
	}
	defs := schema["$defs"].(map[string]any)

	enumOf := func(name string) []string {
		node := defs[name].(map[string]any)
		vals, ok := node["enum"].([]any)
		if !ok {
			t.Fatalf("$defs/%s has no enum", name)
		}
		out := make([]string, len(vals))
		for i, v := range vals {
			out[i] = fmt.Sprint(v)
		}
		return out
	}

	var gotDepth []string
	for _, d := range DepthValues() {
		gotDepth = append(gotDepth, string(d))
	}
	if want := enumOf("depth"); !slices.Equal(gotDepth, want) {
		t.Errorf("DepthValues() = %v, schema says %v", gotDepth, want)
	}

	var gotBump []string
	for _, b := range BumpKindValues() {
		gotBump = append(gotBump, string(b))
	}
	if want := enumOf("semverBump"); !slices.Equal(gotBump, want) {
		t.Errorf("BumpKindValues() = %v, schema says %v", gotBump, want)
	}

	// The detector vocabulary must be reachable ONLY through area 40. A
	// literal detector token anywhere in engine.go's CODE would be a second
	// definition of area 40's enum.
	//
	// This walks the AST rather than grepping, for two reasons: comments and
	// doc prose legitimately name the tiers, and `"dast"` is also a schema
	// KEY name (the dastOverrides block), which the key-set declarations must
	// spell. So the check skips the `keys*` var specs -- whose contents
	// TestDecoderKeySetsMatchSchema already pins to the schema -- and looks
	// at every other string literal in the file. `keyDast` is skipped by the
	// same prefix rule and is the one place the key spelling lives.
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "engine.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing engine.go: %v", err)
	}

	banned := map[string]bool{}
	for _, kind := range record.DetectorKindValues() {
		banned[string(kind)] = true
	}

	ast.Inspect(file, func(n ast.Node) bool {
		if spec, ok := n.(*ast.ValueSpec); ok {
			for _, name := range spec.Names {
				if strings.HasPrefix(name.Name, "key") {
					return false // the schema's key names, pinned elsewhere
				}
			}
		}
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if banned[val] {
			t.Errorf("engine.go line %d contains the detector literal %q; detector tokens come "+
				"from internal/record, never from a second list here",
				fset.Position(lit.Pos()).Line, val)
		}
		return true
	})
}
