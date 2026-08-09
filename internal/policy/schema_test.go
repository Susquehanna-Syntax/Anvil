package policy

// Schema conformance tests for schemas/policy.schema.json (step O.5).
//
// Anvil's module graph carries exactly one dependency (modernc.org/sqlite) and
// adding a YAML library or a JSON Schema library for a test is not on the
// table. So this file carries two small, TEST-ONLY implementations:
//
//   - o5yamlDecode: a decoder for the YAML subset policy files are written in
//     (block mappings, block sequences, flow sequences and flow mappings,
//     comments, quoted and bare scalars). It is deliberately strict and errors
//     on anything outside that subset rather than guessing, because a decoder
//     that silently drops a key would make every assertion below vacuous.
//
//   - o5validateSchema: a validator for the JSON Schema 2020-12 keyword subset
//     policy.schema.json actually uses. It REJECTS any keyword it does not
//     implement (see TestPolicySchemaUsesOnlySupportedKeywords), so adding
//     `allOf` to the schema without teaching the validator fails the build
//     instead of quietly validating nothing.
//
// Neither is a general-purpose implementation and neither is exported. The
// production loader (O.6) will parse with whatever the daemon links; these
// exist so the schema's claims are checked here, now, against the fixture the
// owner's requirement is written in.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const o5schemaFile = "../../" + SchemaPath

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// o5fixtureOwnerRequirement is the policy the owner's explicit requirement
// demands -- SAST on every push, SAST+DAST on tagged releases gated by semver
// bump -- in the shape research/09 Recommendation 2 specifies. It is the
// acceptance fixture: if this does not validate, the schema is wrong, not the
// fixture.
const o5fixtureOwnerRequirement = `
# yaml-language-server: $schema=https://anvil.invalid/schemas/policy.schema.json
version: 1

defaults:
  detectors: [sast]          # DAST is opt-in, never a default
  depth: delta
  timeout: 20m
  failOn: high
  publish: [sarif]

scanRules:
  # SAST-only on every branch push
  - name: push-delta
    matchEvents: [push]
    matchRefs: ["refs/heads/**"]
    matchPaths: ["**"]
    matchPathsIgnore: ["docs/**", "**/*.md"]
    detectors: [sast]
    depth: delta

  # SAST + DAST only on release tags, and only for major bumps
  - name: major-release-full
    matchEvents: [push, release]
    matchRefs: ["refs/tags/v*"]
    matchSemverBump: [major]
    detectors: [sast, dast]
    depth: full
    timeout: 90m
    dast:
      profile: authenticated
      maxDuration: 45m

  - name: minor-release-sast-full
    matchEvents: [push, release]
    matchRefs: ["refs/tags/v*"]
    matchSemverBump: [minor, patch]
    detectors: [sast]
    depth: full

  # The real full-scan clock lives on the daemon, not on GitHub
  - name: nightly-regression
    matchEvents: [schedule]
    schedule: { onCalendar: "*-*-* 03:17:00", persistent: true, randomizedDelay: 20m }
    detectors: [sast]
    depth: full
`

// o5fixtureBadSemverBump is the same policy with one character changed: a
// matchSemverBump value that is not a bump kind. The packet names this case
// specifically, because matchSemverBump is the one match key whose vocabulary
// Anvil computes rather than reads, so a typo here silently means "this rule
// never fires" -- the exact silent failure the schema exists to catch.
const o5fixtureBadSemverBump = `
version: 1

scanRules:
  - name: major-release-full
    matchEvents: [push, release]
    matchRefs: ["refs/tags/v*"]
    matchSemverBump: [mayor]
    detectors: [sast, dast]
    depth: full
`

// ---------------------------------------------------------------------------
// The tests the packet requires
// ---------------------------------------------------------------------------

func TestPolicySchemaAcceptsOwnerRequirementFixture(t *testing.T) {
	schema := o5loadSchema(t)

	doc, err := o5yamlDecode(o5fixtureOwnerRequirement)
	if err != nil {
		t.Fatalf("decoding the fixture failed: %v", err)
	}

	if errs := o5validateSchema(schema, doc); len(errs) != 0 {
		t.Fatalf("owner-requirement fixture must validate cleanly, got:\n  %s",
			strings.Join(errs, "\n  "))
	}
}

// TestPolicyFixtureDecodesToTheExpectedShape guards the test above from being
// vacuous. A decoder that dropped `scanRules` entirely would make the fixture
// "validate cleanly" while proving nothing, so assert the structure the
// validator was handed is the structure the fixture describes.
func TestPolicyFixtureDecodesToTheExpectedShape(t *testing.T) {
	doc, err := o5yamlDecode(o5fixtureOwnerRequirement)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	top, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("fixture decoded to %T, want a mapping", doc)
	}
	if got := top["version"]; !o5deepEqual(got, int64(1)) {
		t.Errorf("version = %#v, want 1", got)
	}

	defaults, ok := top["defaults"].(map[string]any)
	if !ok {
		t.Fatalf("defaults decoded to %T, want a mapping", top["defaults"])
	}
	if got, want := defaults["detectors"], []any{"sast"}; !o5deepEqual(got, want) {
		t.Errorf("defaults.detectors = %#v, want %#v -- DAST must not be a default", got, want)
	}
	if got := defaults["timeout"]; got != "20m" {
		t.Errorf("defaults.timeout = %#v, want \"20m\" (a bare duration must stay a string)", got)
	}

	rules, ok := top["scanRules"].([]any)
	if !ok {
		t.Fatalf("scanRules decoded to %T, want a sequence", top["scanRules"])
	}
	if len(rules) != 4 {
		t.Fatalf("decoded %d scanRules, want 4", len(rules))
	}

	byName := map[string]map[string]any{}
	for i, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("scanRules[%d] decoded to %T, want a mapping", i, raw)
		}
		name, _ := rule["name"].(string)
		byName[name] = rule
	}

	// The two rules the owner's requirement names, checked field by field.
	push := byName["push-delta"]
	if push == nil {
		t.Fatalf("fixture lost the push rule; decoded names: %v", o5keys(byName))
	}
	if got, want := push["matchEvents"], []any{"push"}; !o5deepEqual(got, want) {
		t.Errorf("push-delta.matchEvents = %#v, want %#v", got, want)
	}
	if got, want := push["matchPathsIgnore"], []any{"docs/**", "**/*.md"}; !o5deepEqual(got, want) {
		t.Errorf("push-delta.matchPathsIgnore = %#v, want %#v", got, want)
	}

	release := byName["major-release-full"]
	if release == nil {
		t.Fatalf("fixture lost the tagged-release rule; decoded names: %v", o5keys(byName))
	}
	if got, want := release["matchSemverBump"], []any{"major"}; !o5deepEqual(got, want) {
		t.Errorf("major-release-full.matchSemverBump = %#v, want %#v", got, want)
	}
	if got, want := release["detectors"], []any{"sast", "dast"}; !o5deepEqual(got, want) {
		t.Errorf("major-release-full.detectors = %#v, want %#v", got, want)
	}
	dast, ok := release["dast"].(map[string]any)
	if !ok {
		t.Fatalf("major-release-full.dast decoded to %T, want a mapping", release["dast"])
	}
	if dast["profile"] != "authenticated" || dast["maxDuration"] != "45m" {
		t.Errorf("major-release-full.dast = %#v", dast)
	}

	nightly := byName["nightly-regression"]
	if nightly == nil {
		t.Fatalf("fixture lost the schedule rule; decoded names: %v", o5keys(byName))
	}
	sched, ok := nightly["schedule"].(map[string]any)
	if !ok {
		t.Fatalf("nightly-regression.schedule decoded to %T, want a mapping (flow form)", nightly["schedule"])
	}
	if sched["onCalendar"] != "*-*-* 03:17:00" {
		t.Errorf("schedule.onCalendar = %#v -- the calendar expression must survive verbatim", sched["onCalendar"])
	}
	if sched["persistent"] != true {
		t.Errorf("schedule.persistent = %#v, want true", sched["persistent"])
	}
}

// TestPolicySchemaRejects is the negative half. The first case is the one the
// packet names; the rest cover the other silent-failure shapes the schema's
// strictness exists for.
func TestPolicySchemaRejects(t *testing.T) {
	schema := o5loadSchema(t)

	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "invalid matchSemverBump enum value",
			yaml: o5fixtureBadSemverBump,
			want: `/scanRules/0/matchSemverBump/0`,
		},
		{
			name: "misspelled match key is not silently ignored",
			yaml: "version: 1\nscanRules:\n  - name: r\n    matchEvent: [push]\n",
			want: `matchEvent`,
		},
		{
			name: "unknown top-level key",
			yaml: "version: 1\nscanRule: []\n",
			want: `scanRule`,
		},
		{
			name: "missing version",
			yaml: "scanRules: []\n",
			want: `version`,
		},
		{
			name: "unknown policy-file version",
			yaml: "version: 2\n",
			want: `/version`,
		},
		{
			name: "version is not a string",
			yaml: `version: "1"` + "\n",
			want: `/version`,
		},
		{
			name: "rule without a name",
			yaml: "version: 1\nscanRules:\n  - matchEvents: [push]\n",
			want: `name`,
		},
		{
			name: "empty rule name",
			yaml: "version: 1\nscanRules:\n  - name: \"\"\n",
			want: `/scanRules/0/name`,
		},
		{
			name: "unknown depth",
			yaml: "version: 1\ndefaults:\n  depth: shallow\n",
			want: `/defaults/depth`,
		},
		{
			name: "empty detector list",
			yaml: "version: 1\ndefaults:\n  detectors: []\n",
			want: `/defaults/detectors`,
		},
		{
			name: "duplicate match events",
			yaml: "version: 1\nscanRules:\n  - name: r\n    matchEvents: [push, push]\n",
			want: `/scanRules/0/matchEvents`,
		},
		{
			name: "empty match ref list",
			yaml: "version: 1\nscanRules:\n  - name: r\n    matchRefs: []\n",
			want: `/scanRules/0/matchRefs`,
		},
		{
			name: "non-duration timeout",
			yaml: "version: 1\ndefaults:\n  timeout: 20 minutes\n",
			want: `/defaults/timeout`,
		},
		{
			name: "misspelled dast override key",
			yaml: "version: 1\nscanRules:\n  - name: r\n    dast:\n      profil: authenticated\n",
			want: `profil`,
		},
		{
			name: "non-duration randomizedDelay",
			yaml: "version: 1\nscanRules:\n  - name: r\n    schedule: { onCalendar: \"daily\", randomizedDelay: soon }\n",
			want: `/scanRules/0/schedule/randomizedDelay`,
		},
		{
			name: "scanRules is not an array",
			yaml: "version: 1\nscanRules:\n  name: r\n",
			want: `/scanRules`,
		},
		{
			name: "detector token is not a string",
			yaml: "version: 1\ndefaults:\n  detectors: [1]\n",
			want: `/defaults/detectors/0`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := o5yamlDecode(tc.yaml)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}

			errs := o5validateSchema(schema, doc)
			if len(errs) == 0 {
				t.Fatalf("document validated cleanly but must be rejected:\n%s", tc.yaml)
			}
			joined := strings.Join(errs, "\n  ")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("rejection did not mention %q; got:\n  %s", tc.want, joined)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Schema hygiene
// ---------------------------------------------------------------------------

func TestPolicySchemaIdentity(t *testing.T) {
	schema := o5loadSchema(t)

	if got, want := schema["$id"], SchemaID; got != want {
		t.Errorf("$id = %v, want %v (policy.SchemaID is what consumers dereference)", got, want)
	}
	if got, want := schema["$schema"], "https://json-schema.org/draft/2020-12/schema"; got != want {
		t.Errorf("$schema = %v, want %v -- same draft as schemas/anvil-record-v1.schema.json", got, want)
	}
	if _, ok := schema["title"].(string); !ok {
		t.Error("schema has no title")
	}
}

// TestPolicySchemaSearchOrderMatchesLocate keeps the schema's documented search
// order and the code's search order from drifting. Two copies of a list is how
// section 6's ten defects happened; this is the cheap guard against an
// eleventh.
func TestPolicySchemaSearchOrderMatchesLocate(t *testing.T) {
	schema := o5loadSchema(t)

	raw, ok := schema["x-anvil-searchOrder"].([]any)
	if !ok {
		t.Fatalf("x-anvil-searchOrder is %T, want an array", schema["x-anvil-searchOrder"])
	}
	got := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("x-anvil-searchOrder contains %T, want strings", v)
		}
		got = append(got, s)
	}

	want := SearchOrder()
	if len(got) != len(want) {
		t.Fatalf("schema search order %v != policy.SearchOrder() %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("search order drifted at %d: schema %q, code %q", i, got[i], want[i])
		}
	}
}

// TestPolicySchemaUsesOnlySupportedKeywords is the anti-vacuous-PASS guard: the
// validator below implements a subset of JSON Schema, and this walks the WHOLE
// schema (including $defs a fixture may never reach) asserting every keyword in
// it is one the validator actually enforces. Without it, adding `allOf` or
// `oneOf` to the schema would leave those constraints unchecked and every test
// above would still pass.
func TestPolicySchemaUsesOnlySupportedKeywords(t *testing.T) {
	schema := o5loadSchema(t)

	var errs []string
	o5walkSchema(schema, "#", &errs)
	if len(errs) != 0 {
		sort.Strings(errs)
		t.Fatalf("schema uses keywords this test's validator does not enforce:\n  %s",
			strings.Join(errs, "\n  "))
	}
}

// TestPolicySchemaDoesNotForkFrozenEnums: `detectors` names area 40's
// DetectorKind vocabulary, and `failOn` names area 40's severity vocabulary.
// Neither may be re-enumerated here -- plan/IMPLEMENTATION-PLAN.md section 6
// ruled that area 40 owns every shared enum and no other area may declare one.
// A copy would validate today and drift tomorrow.
func TestPolicySchemaDoesNotForkFrozenEnums(t *testing.T) {
	schema := o5loadSchema(t)
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("$defs is %T", schema["$defs"])
	}

	detectorList, ok := defs["detectorList"].(map[string]any)
	if !ok {
		t.Fatalf("$defs/detectorList is %T", defs["detectorList"])
	}
	if _, forked := detectorList["enum"]; forked {
		t.Error("$defs/detectorList enumerates detector kinds -- that is area 40's DetectorKind, " +
			"and copying it here creates the second definition section 6 closed ten of")
	}
	if _, ok := detectorList["x-anvil-enumSource"].(string); !ok {
		t.Error("$defs/detectorList must name where its vocabulary is defined (x-anvil-enumSource)")
	}

	// The two enums this schema DOES own must stay owned and stay labelled,
	// so a later area consumes them instead of declaring a third copy.
	for _, name := range []string{"depth", "semverBump"} {
		def, ok := defs[name].(map[string]any)
		if !ok {
			t.Fatalf("$defs/%s is %T", name, defs[name])
		}
		if _, ok := def["enum"].([]any); !ok {
			t.Errorf("$defs/%s must enumerate its values -- it is owned here", name)
		}
		if _, ok := def["x-anvil-enumOwner"].(string); !ok {
			t.Errorf("$defs/%s must declare x-anvil-enumOwner", name)
		}
	}
}

// TestPolicySchemaGlobBoundMatchesTheEngineCap pins the ONE bound that exists in
// two places: schemas/policy.schema.json#/$defs/glob's `maxLength` and
// internal/policy.MaxGlobPatternBytes.
//
// The bound is not decoration. CRITIQUE O.4 finding O4-M4 established that this
// file is read from the repository under scan, so a pattern in it is untrusted
// input reaching a matcher, and that the matcher was super-polynomial. The
// matcher is now linear in len(pattern) x len(name); the cap is what bounds the
// first factor. A schema that promised a looser bound than the engine enforces
// would send an author a policy that validates and then refuses to run.
func TestPolicySchemaGlobBoundMatchesTheEngineCap(t *testing.T) {
	schema := o5loadSchema(t)
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("$defs is %T", schema["$defs"])
	}
	glob, ok := defs["glob"].(map[string]any)
	if !ok {
		t.Fatalf("$defs/glob is %T", defs["glob"])
	}

	max, ok := o5number(glob["maxLength"])
	if !ok {
		t.Fatal("$defs/glob must carry maxLength: an unbounded pattern from the scanned " +
			"repository is O4-M4, and the schema must say so as well as the engine")
	}
	if int(max) != MaxGlobPatternBytes {
		t.Errorf("$defs/glob maxLength = %d but policy.MaxGlobPatternBytes = %d; the two bounds have drifted",
			int(max), MaxGlobPatternBytes)
	}
	if _, ok := glob["x-anvil-engineCap"].(string); !ok {
		t.Error("$defs/glob must name the Go constant its maxLength mirrors (x-anvil-engineCap)")
	}

	// The bound is real on both sides: a pattern one byte over is refused by
	// the engine, and one byte at the bound is accepted by both.
	if _, err := MatchGlob(strings.Repeat("a", int(max)+1), "a"); !errors.Is(err, ErrPatternTooComplex) {
		t.Errorf("a pattern one byte over the schema bound was not refused: %v", err)
	}
	if _, err := MatchGlob(strings.Repeat("a", int(max)), "a"); err != nil {
		t.Errorf("a pattern exactly at the schema bound was refused: %v", err)
	}
}

// TestPolicySchemaAggregateBoundsMatchTheEngineCaps pins the bounds that exist
// in two places, the way TestPolicySchemaGlobBoundMatchesTheEngineCap already
// pins the per-pattern one.
//
// The per-pattern cap bounded the price of one match. It left the QUANTITY
// unbounded, and the re-verification of O.4 counted the consequence: this schema
// contained zero maxItems, so nothing bounded the number of rules or the number
// of patterns in a rule, and the denial of service closed by recursion was open
// again by multiplication. A schema that promised a looser bound than the engine
// enforces would send an author a policy that validates and then refuses to run.
func TestPolicySchemaAggregateBoundsMatchTheEngineCaps(t *testing.T) {
	schema := o5loadSchema(t)
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("$defs is %T", schema["$defs"])
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties is %T", schema["properties"])
	}
	scanRule, ok := defs["scanRule"].(map[string]any)
	if !ok {
		t.Fatalf("$defs/scanRule is %T", defs["scanRule"])
	}
	ruleProps, ok := scanRule["properties"].(map[string]any)
	if !ok {
		t.Fatalf("$defs/scanRule/properties is %T", scanRule["properties"])
	}

	// Every array-valued node in the schema, and the Go constant it mirrors.
	cases := []struct {
		path string
		node any
		want int
	}{
		{"#/properties/scanRules", props["scanRules"], MaxScanRules},
		{"#/$defs/globList", defs["globList"], MaxListItems},
		{"#/$defs/tokenList", defs["tokenList"], MaxListItems},
		{"#/$defs/scanRule/properties/matchSemverBump", ruleProps["matchSemverBump"], MaxListItems},
	}
	for _, tc := range cases {
		node, ok := tc.node.(map[string]any)
		if !ok {
			t.Errorf("%s is %T, not a subschema", tc.path, tc.node)
			continue
		}
		max, ok := o5number(node["maxItems"])
		if !ok {
			t.Errorf("%s must carry maxItems: an unbounded array from the scanned repository is "+
				"the same denial of service as an unbounded pattern, reached by multiplication "+
				"instead of by recursion", tc.path)
			continue
		}
		if int(max) != tc.want {
			t.Errorf("%s maxItems = %d but the engine cap is %d; the two bounds have drifted",
				tc.path, int(max), tc.want)
		}
		if _, ok := node["x-anvil-engineCap"].(string); !ok {
			t.Errorf("%s must name the Go constant its maxItems mirrors (x-anvil-engineCap)", tc.path)
		}
	}

	// EVERY array in the schema must be bounded, not merely the four above. A
	// new list-valued key added without maxItems is exactly how this file came
	// to have zero of them.
	var walk func(sch map[string]any, path string)
	walk = func(sch map[string]any, path string) {
		if typ, _ := sch["type"].(string); typ == "array" {
			if _, ok := o5number(sch["maxItems"]); !ok {
				t.Errorf("%s is an unbounded array; every array in this file is read from the "+
					"repository under scan and must carry maxItems", path)
			}
		}
		for _, key := range []string{"properties", "$defs"} {
			if m, ok := sch[key].(map[string]any); ok {
				for name, sub := range m {
					if subm, ok := sub.(map[string]any); ok {
						walk(subm, path+"/"+key+"/"+name)
					}
				}
			}
		}
		if items, ok := sch["items"].(map[string]any); ok {
			walk(items, path+"/items")
		}
	}
	walk(schema, "#")

	// The two bounds JSON Schema CANNOT express must still be documented here,
	// because a reader of this file would otherwise conclude that maxItems is
	// the whole story -- and rules x patterns x paths at the caps above is 134
	// million matches, which is precisely the outage the caps look like they
	// prevent.
	note, _ := schema["x-anvil-aggregateBounds"].(string)
	for _, want := range []string{"MaxScanRules", "MaxListItems", "MaxChangedPaths", "MaxEvaluationMatchOps"} {
		if !strings.Contains(note, want) {
			t.Errorf("x-anvil-aggregateBounds does not name policy.%s", want)
		}
	}
}

// TestPolicySchemaIsStrictEverywhere: every object in the schema must reject
// unknown keys. A policy file is not a document where a typo may be ignored --
// `matchEvent:` for `matchEvents:` produces a rule that never fires and never
// complains.
func TestPolicySchemaIsStrictEverywhere(t *testing.T) {
	schema := o5loadSchema(t)

	var check func(sch map[string]any, path string)
	check = func(sch map[string]any, path string) {
		if t2, _ := sch["type"].(string); t2 == "object" {
			ap, present := sch["additionalProperties"]
			if !present || ap != false {
				t.Errorf("%s: object schema must set additionalProperties:false (got %#v)", path, ap)
			}
		}
		for _, key := range []string{"properties", "$defs"} {
			if m, ok := sch[key].(map[string]any); ok {
				for name, sub := range m {
					if subm, ok := sub.(map[string]any); ok {
						check(subm, path+"/"+key+"/"+name)
					}
				}
			}
		}
		if items, ok := sch["items"].(map[string]any); ok {
			check(items, path+"/items")
		}
	}
	check(schema, "#")
}

// ---------------------------------------------------------------------------
// Test-only JSON Schema 2020-12 subset validator
// ---------------------------------------------------------------------------

func o5loadSchema(t *testing.T) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(o5schemaFile)
	if err != nil {
		t.Fatalf("reading %s: %v", o5schemaFile, err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("%s is not valid JSON: %v", o5schemaFile, err)
	}
	return schema
}

// o5dataKeywords are schema keywords whose values are data, not subschemas.
var o5dataKeywords = map[string]bool{
	"$schema": true, "$id": true, "$ref": true, "title": true,
	"description": true, "$comment": true, "type": true, "const": true,
	"enum": true, "required": true, "minItems": true, "maxItems": true, "uniqueItems": true,
	"minLength": true, "maxLength": true, "pattern": true,
	"minimum": true, "maximum": true,
}

func o5walkSchema(sch map[string]any, path string, errs *[]string) {
	for key, val := range sch {
		if strings.HasPrefix(key, "x-anvil-") || o5dataKeywords[key] {
			continue
		}
		switch key {
		case "properties", "$defs":
			m, ok := val.(map[string]any)
			if !ok {
				*errs = append(*errs, fmt.Sprintf("%s/%s: expected an object of subschemas, got %T", path, key, val))
				continue
			}
			for name, sub := range m {
				subm, ok := sub.(map[string]any)
				if !ok {
					*errs = append(*errs, fmt.Sprintf("%s/%s/%s: expected a subschema, got %T", path, key, name, sub))
					continue
				}
				o5walkSchema(subm, path+"/"+key+"/"+name, errs)
			}
		case "items":
			subm, ok := val.(map[string]any)
			if !ok {
				*errs = append(*errs, fmt.Sprintf("%s/items: expected a subschema, got %T", path, val))
				continue
			}
			o5walkSchema(subm, path+"/items", errs)
		case "additionalProperties":
			switch v := val.(type) {
			case bool:
			case map[string]any:
				o5walkSchema(v, path+"/additionalProperties", errs)
			default:
				*errs = append(*errs, fmt.Sprintf("%s/additionalProperties: expected bool or subschema, got %T", path, v))
			}
		default:
			*errs = append(*errs, fmt.Sprintf("%s: unsupported keyword %q", path, key))
		}
	}
}

// o5validateSchema validates doc against schema and returns every violation,
// sorted so failures read the same way on every run.
func o5validateSchema(schema map[string]any, doc any) []string {
	var errs []string
	o5validateNode(schema, schema, doc, "", &errs)
	sort.Strings(errs)
	return errs
}

func o5validateNode(root, sch map[string]any, val any, path string, errs *[]string) {
	if path == "" {
		path = "#"
	}

	if ref, ok := sch["$ref"].(string); ok {
		target, err := o5resolveRef(root, ref)
		if err != nil {
			*errs = append(*errs, fmt.Sprintf("%s: %v", path, err))
		} else {
			o5validateNode(root, target, val, path, errs)
		}
	}

	if want, ok := sch["type"].(string); ok && !o5typeMatches(want, val) {
		*errs = append(*errs, fmt.Sprintf("%s: expected type %q, got %s", path, want, o5typeOf(val)))
		return // downstream keyword checks would only add noise
	}

	if want, ok := sch["const"]; ok && !o5deepEqual(want, val) {
		*errs = append(*errs, fmt.Sprintf("%s: value %#v is not the required constant %#v", path, val, want))
	}

	if allowed, ok := sch["enum"].([]any); ok {
		found := false
		for _, cand := range allowed {
			if o5deepEqual(cand, val) {
				found = true
				break
			}
		}
		if !found {
			*errs = append(*errs, fmt.Sprintf("%s: value %#v is not one of %v", path, val, allowed))
		}
	}

	switch typed := val.(type) {
	case map[string]any:
		if required, ok := sch["required"].([]any); ok {
			for _, r := range required {
				name, _ := r.(string)
				if _, present := typed[name]; !present {
					*errs = append(*errs, fmt.Sprintf("%s: missing required key %q", path, name))
				}
			}
		}

		props, _ := sch["properties"].(map[string]any)
		ap, apPresent := sch["additionalProperties"]

		for name, child := range typed {
			if sub, ok := props[name].(map[string]any); ok {
				o5validateNode(root, sub, child, path+"/"+name, errs)
				continue
			}
			if !apPresent {
				continue
			}
			switch policy := ap.(type) {
			case bool:
				if !policy {
					*errs = append(*errs, fmt.Sprintf("%s: unknown key %q is not allowed here", path, name))
				}
			case map[string]any:
				o5validateNode(root, policy, child, path+"/"+name, errs)
			}
		}

	case []any:
		if min, ok := o5number(sch["minItems"]); ok && float64(len(typed)) < min {
			*errs = append(*errs, fmt.Sprintf("%s: has %d items, needs at least %d", path, len(typed), int(min)))
		}
		if max, ok := o5number(sch["maxItems"]); ok && float64(len(typed)) > max {
			*errs = append(*errs, fmt.Sprintf("%s: has %d items, which is more than the %d allowed", path, len(typed), int(max)))
		}
		if unique, ok := sch["uniqueItems"].(bool); ok && unique {
			for i := range typed {
				for j := i + 1; j < len(typed); j++ {
					if o5deepEqual(typed[i], typed[j]) {
						*errs = append(*errs, fmt.Sprintf("%s: duplicate item %#v at %d and %d", path, typed[i], i, j))
					}
				}
			}
		}
		if items, ok := sch["items"].(map[string]any); ok {
			for i, child := range typed {
				o5validateNode(root, items, child, fmt.Sprintf("%s/%d", path, i), errs)
			}
		}

	case string:
		if min, ok := o5number(sch["minLength"]); ok && float64(len([]rune(typed))) < min {
			*errs = append(*errs, fmt.Sprintf("%s: %q is shorter than %d characters", path, typed, int(min)))
		}
		if max, ok := o5number(sch["maxLength"]); ok && float64(len([]rune(typed))) > max {
			*errs = append(*errs, fmt.Sprintf("%s: string of %d characters is longer than the %d-character maximum",
				path, len([]rune(typed)), int(max)))
		}
		if pattern, ok := sch["pattern"].(string); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				*errs = append(*errs, fmt.Sprintf("%s: schema pattern %q does not compile: %v", path, pattern, err))
			} else if !re.MatchString(typed) {
				*errs = append(*errs, fmt.Sprintf("%s: %q does not match %q", path, typed, pattern))
			}
		}

	default:
		if num, isNum := o5number(val); isNum {
			if min, ok := o5number(sch["minimum"]); ok && num < min {
				*errs = append(*errs, fmt.Sprintf("%s: %v is below the minimum %v", path, num, min))
			}
			if max, ok := o5number(sch["maximum"]); ok && num > max {
				*errs = append(*errs, fmt.Sprintf("%s: %v is above the maximum %v", path, num, max))
			}
		}
	}
}

func o5resolveRef(root map[string]any, ref string) (map[string]any, error) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("only local $ref is supported, got %q", ref)
	}
	cursor := any(root)
	for _, segment := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		m, ok := cursor.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("$ref %q: %q is not reachable", ref, segment)
		}
		cursor, ok = m[segment]
		if !ok {
			return nil, fmt.Errorf("$ref %q: no such member %q", ref, segment)
		}
	}
	target, ok := cursor.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("$ref %q does not point at a schema object", ref)
	}
	return target, nil
}

func o5typeMatches(want string, val any) bool {
	switch want {
	case "object":
		_, ok := val.(map[string]any)
		return ok
	case "array":
		_, ok := val.([]any)
		return ok
	case "string":
		_, ok := val.(string)
		return ok
	case "boolean":
		_, ok := val.(bool)
		return ok
	case "null":
		return val == nil
	case "number":
		_, ok := o5number(val)
		return ok
	case "integer":
		n, ok := o5number(val)
		return ok && n == float64(int64(n))
	default:
		return false
	}
}

func o5typeOf(val any) string {
	switch v := val.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case int64, float64:
		return "number"
	default:
		return fmt.Sprintf("%T", v)
	}
}

func o5number(val any) (float64, bool) {
	switch v := val.(type) {
	case int64:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}

func o5deepEqual(a, b any) bool {
	an, aIsNum := o5number(a)
	bn, bIsNum := o5number(b)
	if aIsNum || bIsNum {
		return aIsNum && bIsNum && an == bn
	}

	switch av := a.(type) {
	case nil:
		return b == nil
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !o5deepEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			other, present := bv[k]
			if !present || !o5deepEqual(v, other) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func o5keys(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Test-only YAML subset decoder
// ---------------------------------------------------------------------------

type o5line struct {
	num    int
	indent int
	text   string
}

// o5yamlDecode decodes the YAML subset policy files are written in. Anything
// outside that subset -- tabs for indentation, anchors, multi-document streams,
// block scalars, duplicate keys -- is an error, never a guess.
func o5yamlDecode(src string) (any, error) {
	lines, err := o5yamlScan(src)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}
	return o5yamlBlock(lines)
}

func o5yamlScan(src string) ([]o5line, error) {
	var out []o5line

	for i, raw := range strings.Split(src, "\n") {
		num := i + 1
		text := strings.TrimSuffix(raw, "\r")

		if strings.ContainsRune(text[:len(text)-len(strings.TrimLeft(text, " \t"))], '\t') {
			return nil, fmt.Errorf("line %d: tab in indentation is not supported", num)
		}

		text = o5stripComment(text)
		trimmed := strings.TrimRight(text, " ")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		if strings.TrimSpace(trimmed) == "---" || strings.TrimSpace(trimmed) == "..." {
			return nil, fmt.Errorf("line %d: document markers are not supported", num)
		}

		indent := len(trimmed) - len(strings.TrimLeft(trimmed, " "))
		out = append(out, o5line{num: num, indent: indent, text: strings.TrimLeft(trimmed, " ")})
	}
	return out, nil
}

// o5stripComment removes a trailing comment. A '#' only starts a comment when
// it is outside quotes and at the start of the line or preceded by a space, so
// a pattern like "**/#tag" survives.
func o5stripComment(text string) string {
	var quote rune
	for i, r := range text {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#':
			if i == 0 || text[i-1] == ' ' || text[i-1] == '\t' {
				return text[:i]
			}
		}
	}
	return text
}

func o5yamlBlock(lines []o5line) (any, error) {
	if len(lines) == 0 {
		return nil, nil
	}
	base := lines[0].indent
	for _, ln := range lines {
		if ln.indent < base {
			return nil, fmt.Errorf("line %d: indent %d is shallower than the block's %d", ln.num, ln.indent, base)
		}
	}
	if o5isSeqItem(lines[0].text) {
		return o5yamlSequence(lines, base)
	}
	return o5yamlMapping(lines, base)
}

func o5isSeqItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

func o5yamlSequence(lines []o5line, base int) ([]any, error) {
	out := []any{}

	for i := 0; i < len(lines); {
		ln := lines[i]
		if ln.indent != base {
			return nil, fmt.Errorf("line %d: expected a sequence item at indent %d", ln.num, base)
		}
		if !o5isSeqItem(ln.text) {
			return nil, fmt.Errorf("line %d: expected %q to start with %q", ln.num, ln.text, "- ")
		}

		end := i + 1
		for end < len(lines) && lines[end].indent > base {
			end++
		}

		after := ln.text[1:]
		rest := strings.TrimLeft(after, " ")
		restIndent := ln.indent + 1 + (len(after) - len(rest))

		var (
			item any
			err  error
		)
		switch {
		case rest == "":
			item, err = o5yamlBlock(lines[i+1 : end])
		case o5isMappingEntry(rest):
			sub := make([]o5line, 0, end-i)
			sub = append(sub, o5line{num: ln.num, indent: restIndent, text: rest})
			sub = append(sub, lines[i+1:end]...)
			item, err = o5yamlBlock(sub)
		default:
			if end > i+1 {
				return nil, fmt.Errorf("line %d: a scalar sequence item cannot have child lines", ln.num)
			}
			item, err = o5yamlValue(rest, ln.num)
		}
		if err != nil {
			return nil, err
		}

		out = append(out, item)
		i = end
	}
	return out, nil
}

func o5yamlMapping(lines []o5line, base int) (map[string]any, error) {
	out := map[string]any{}

	for i := 0; i < len(lines); {
		ln := lines[i]
		if ln.indent != base {
			return nil, fmt.Errorf("line %d: indent %d does not line up with the mapping's %d", ln.num, ln.indent, base)
		}

		key, rest, ok := o5splitKey(ln.text)
		if !ok {
			return nil, fmt.Errorf("line %d: %q is not a mapping entry", ln.num, ln.text)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q", ln.num, key)
		}

		end := i + 1
		for end < len(lines) && lines[end].indent > base {
			end++
		}

		var (
			val any
			err error
		)
		if rest != "" {
			if end > i+1 {
				return nil, fmt.Errorf("line %d: key %q has both an inline value and child lines", ln.num, key)
			}
			val, err = o5yamlValue(rest, ln.num)
		} else {
			val, err = o5yamlBlock(lines[i+1 : end])
		}
		if err != nil {
			return nil, err
		}

		out[key] = val
		i = end
	}
	return out, nil
}

func o5isMappingEntry(text string) bool {
	_, _, ok := o5splitKey(text)
	return ok
}

// o5splitKey splits "key: value" at the first top-level colon. The colon must
// end the line or be followed by a space, which is what keeps a bare scalar
// containing a colon from being misread as a key.
func o5splitKey(text string) (key, rest string, ok bool) {
	var quote rune
	depth := 0

	for i, r := range text {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '[' || r == '{':
			depth++
		case r == ']' || r == '}':
			depth--
		case r == ':' && depth == 0:
			if i+1 < len(text) && text[i+1] != ' ' {
				return "", "", false
			}
			key = strings.TrimSpace(text[:i])
			if unquoted, wasQuoted := o5unquote(key); wasQuoted {
				key = unquoted
			}
			if key == "" {
				return "", "", false
			}
			return key, strings.TrimSpace(text[i+1:]), true
		}
	}
	return "", "", false
}

func o5yamlValue(text string, line int) (any, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	if text[0] == '[' || text[0] == '{' {
		flow := &o5flow{src: []rune(text), line: line}
		val, err := flow.value()
		if err != nil {
			return nil, err
		}
		flow.skipSpace()
		if flow.pos != len(flow.src) {
			return nil, fmt.Errorf("line %d: trailing text after flow collection: %q", line, string(flow.src[flow.pos:]))
		}
		return val, nil
	}
	return o5scalar(text, line)
}

type o5flow struct {
	src  []rune
	pos  int
	line int
}

func (f *o5flow) skipSpace() {
	for f.pos < len(f.src) && (f.src[f.pos] == ' ' || f.src[f.pos] == '\t') {
		f.pos++
	}
}

func (f *o5flow) value() (any, error) {
	f.skipSpace()
	if f.pos >= len(f.src) {
		return nil, fmt.Errorf("line %d: unexpected end of flow collection", f.line)
	}
	switch f.src[f.pos] {
	case '[':
		return f.sequence()
	case '{':
		return f.mapping()
	default:
		return o5scalar(f.token(), f.line)
	}
}

// token reads a bare or quoted token, stopping at a flow delimiter.
func (f *o5flow) token() string {
	f.skipSpace()
	start := f.pos

	if f.pos < len(f.src) && (f.src[f.pos] == '"' || f.src[f.pos] == '\'') {
		quote := f.src[f.pos]
		f.pos++
		for f.pos < len(f.src) {
			if f.src[f.pos] == '\\' && quote == '"' && f.pos+1 < len(f.src) {
				f.pos += 2
				continue
			}
			if f.src[f.pos] == quote {
				f.pos++
				break
			}
			f.pos++
		}
		return string(f.src[start:f.pos])
	}

	for f.pos < len(f.src) && !strings.ContainsRune(",[]{}:", f.src[f.pos]) {
		f.pos++
	}
	return strings.TrimSpace(string(f.src[start:f.pos]))
}

func (f *o5flow) sequence() ([]any, error) {
	f.pos++ // '['
	out := []any{}

	for {
		f.skipSpace()
		if f.pos >= len(f.src) {
			return nil, fmt.Errorf("line %d: unterminated flow sequence", f.line)
		}
		if f.src[f.pos] == ']' {
			f.pos++
			return out, nil
		}

		item, err := f.value()
		if err != nil {
			return nil, err
		}
		out = append(out, item)

		f.skipSpace()
		if f.pos >= len(f.src) {
			return nil, fmt.Errorf("line %d: unterminated flow sequence", f.line)
		}
		switch f.src[f.pos] {
		case ',':
			f.pos++
		case ']':
			f.pos++
			return out, nil
		default:
			return nil, fmt.Errorf("line %d: expected %q or %q in flow sequence, got %q", f.line, ",", "]", string(f.src[f.pos]))
		}
	}
}

func (f *o5flow) mapping() (map[string]any, error) {
	f.pos++ // '{'
	out := map[string]any{}

	for {
		f.skipSpace()
		if f.pos >= len(f.src) {
			return nil, fmt.Errorf("line %d: unterminated flow mapping", f.line)
		}
		if f.src[f.pos] == '}' {
			f.pos++
			return out, nil
		}

		key := f.token()
		if unquoted, wasQuoted := o5unquote(key); wasQuoted {
			key = unquoted
		}
		if key == "" {
			return nil, fmt.Errorf("line %d: empty key in flow mapping", f.line)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q in flow mapping", f.line, key)
		}

		f.skipSpace()
		if f.pos >= len(f.src) || f.src[f.pos] != ':' {
			return nil, fmt.Errorf("line %d: expected %q after key %q in flow mapping", f.line, ":", key)
		}
		f.pos++

		val, err := f.value()
		if err != nil {
			return nil, err
		}
		out[key] = val

		f.skipSpace()
		if f.pos >= len(f.src) {
			return nil, fmt.Errorf("line %d: unterminated flow mapping", f.line)
		}
		switch f.src[f.pos] {
		case ',':
			f.pos++
		case '}':
			f.pos++
			return out, nil
		default:
			return nil, fmt.Errorf("line %d: expected %q or %q in flow mapping, got %q", f.line, ",", "}", string(f.src[f.pos]))
		}
	}
}

var (
	o5intPattern   = regexp.MustCompile(`^-?[0-9]+$`)
	o5floatPattern = regexp.MustCompile(`^-?[0-9]+\.[0-9]+$`)
)

func o5scalar(text string, line int) (any, error) {
	text = strings.TrimSpace(text)

	if unquoted, wasQuoted := o5unquote(text); wasQuoted {
		return unquoted, nil
	}

	switch text {
	case "", "null", "~":
		return nil, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}

	if o5intPattern.MatchString(text) {
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: %q looks like an integer but does not parse: %v", line, text, err)
		}
		return n, nil
	}
	if o5floatPattern.MatchString(text) {
		n, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: %q looks like a float but does not parse: %v", line, text, err)
		}
		return n, nil
	}
	return text, nil
}

// o5unquote strips one layer of quoting, reporting whether the input was
// quoted at all. Only the escapes policy files plausibly use are handled.
func o5unquote(text string) (string, bool) {
	if len(text) < 2 {
		return text, false
	}

	switch {
	case text[0] == '\'' && text[len(text)-1] == '\'':
		return strings.ReplaceAll(text[1:len(text)-1], "''", "'"), true

	case text[0] == '"' && text[len(text)-1] == '"':
		body := text[1 : len(text)-1]
		var b strings.Builder
		for i := 0; i < len(body); i++ {
			if body[i] == '\\' && i+1 < len(body) {
				i++
				switch body[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					b.WriteByte(body[i])
				}
				continue
			}
			b.WriteByte(body[i])
		}
		return b.String(), true
	}
	return text, false
}
