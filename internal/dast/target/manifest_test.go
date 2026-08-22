package target

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Hand-written corpus
// ---------------------------------------------------------------------------
//
// Every fixture below was typed by hand from plan/50-dast.md's "Target Manifest
// Schema" section. None of it is produced by the code under test: a corpus the
// implementation generated would agree with the implementation by construction
// and prove nothing. The one place a fixture is compared against Marshal output
// (TestCanonicalFormRoundTripsByteForByte) compares against a literal written
// out below, so a change in Marshal's output has to be justified by editing a
// visible expected value.

// planExampleManifest is plan/50-dast.md's example, transcribed verbatim,
// comments and all. The single backtick pair is spliced in because Go raw
// string literals cannot contain one.
const planExampleManifest = `schema_version: 1

# Path to the Compose file that defines the target stack, relative to repo root. Required.
compose_file: ./docker-compose.anvil.yaml

# Name of the Compose service Anvil is authorized to attack. Required. Every other service in the
# Compose file is provisioned (for realistic dependencies) but is not itself a probe target.
service: web

health:
  url: http://web:8080/healthz     # Required. No health definition means no DAST — provisioning aborts.
  timeout_seconds: 120              # Hard timeout on Compose ` + "`service_healthy`" + ` wait.
  interval_seconds: 5

seed:                               # Optional. Run once after health passes, before any probe fires.
  command: ["make", "seed"]
  timeout_seconds: 60

reset:
  strategy: destroy_recreate        # The only supported value in v1 (research 19: snapshot/restore is
                                     # reserved for a future Firecracker tier and is unsafe for anything
                                     # holding a real credential). Explicit so a future value never
                                     # silently changes behaviour by omission.

auth:                               # Optional. Consumed by the ZAP Authentication Helper (Tier 3 only).
  method: browser
  steps_ref: ./.anvil/auth-steps.yaml   # AUTO_STEPS/CLICK/CUSTOM_FIELD/TOTP_FIELD/WAIT list — never
                                         # autodetection.

inventory:
  runtime_spec_endpoints:           # Optional override of the Tier 0 probe list; config, never hard-coded.
    - /openapi.json
    - /v3/api-docs
    - /graphql

scope:
  additional_egress_allow: []       # Optional, empty by default. Anything listed here still passes
                                     # through the kernel's non-configurable reserved-range denylist
                                     # (gate 10) — this field cannot punch a hole in that floor; it only
                                     # narrows what the *scope layer* permits within what the kernel
                                     # already allows.
`

// canonicalManifest is the byte-for-byte output Marshal must produce for the
// plan example. Written by hand; it is the contract, not a recording.
const canonicalManifest = `schema_version: 1
compose_file: ./docker-compose.anvil.yaml
service: web
health:
  url: http://web:8080/healthz
  timeout_seconds: 120
  interval_seconds: 5
seed:
  command: ["make", "seed"]
  timeout_seconds: 60
reset:
  strategy: destroy_recreate
auth:
  method: browser
  steps_ref: ./.anvil/auth-steps.yaml
inventory:
  runtime_spec_endpoints: ["/openapi.json", "/v3/api-docs", "/graphql"]
scope:
  additional_egress_allow: []
`

// minimalManifest carries only the required fields.
const minimalManifest = `schema_version: 1
compose_file: ./docker-compose.anvil.yaml
service: web
health:
  url: http://web:8080/healthz
reset:
  strategy: destroy_recreate
`

// ---------------------------------------------------------------------------
// Repo helpers
// ---------------------------------------------------------------------------

// newRepo lays out a repo root with a manifest at .anvil/target.yaml plus any
// extra files, and returns (repoRoot, manifestPath). Extra file paths are
// slash-separated and relative to the repo root.
func newRepo(t *testing.T, manifest string, extra map[string]string) (string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ManifestDirName), 0o755); err != nil {
		t.Fatalf("mkdir .anvil: %v", err)
	}
	manifestPath := filepath.Join(root, ManifestDirName, ManifestFileName)
	if manifest != "" {
		if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
	}
	for rel, body := range extra {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root, manifestPath
}

// fullRepoFiles are the files the plan example and the canonical form declare.
func fullRepoFiles() map[string]string {
	return map[string]string{
		"docker-compose.anvil.yaml": "services:\n  web: {}\n",
		".anvil/auth-steps.yaml":    "steps: []\n",
	}
}

func mutate(t *testing.T, base, old, replacement string) string {
	t.Helper()
	if strings.Count(base, old) != 1 {
		t.Fatalf("fixture mutation %q does not appear exactly once in the base fixture", old)
	}
	return strings.Replace(base, old, replacement, 1)
}

// ---------------------------------------------------------------------------
// The distinction this package exists to keep
// ---------------------------------------------------------------------------

func TestAbsentManifestIsASkipNotAnError(t *testing.T) {
	_, manifestPath := newRepo(t, "", nil)

	m, reason, err := Load(manifestPath)
	if err != nil {
		t.Fatalf("a repo with no manifest must not be an error, got %v", err)
	}
	if m != nil {
		t.Fatalf("expected a nil Manifest, got %+v", m)
	}
	if reason != SkipReasonNoManifest {
		t.Fatalf("reason = %q, want %q", reason, SkipReasonNoManifest)
	}
	if !reason.Skips() {
		t.Error("SkipReasonNoManifest must skip the DAST half")
	}
}

func TestAbsentAnvilDirectoryIsASkipNotAnError(t *testing.T) {
	root := t.TempDir()

	m, reason, err := LoadInRepo(root)
	if err != nil {
		t.Fatalf("a repo with no .anvil directory must not be an error, got %v", err)
	}
	if m != nil || reason != SkipReasonNoManifest {
		t.Fatalf("got (%v, %q), want (nil, %q)", m, reason, SkipReasonNoManifest)
	}
}

// TestNoInferenceFromRepoContents is the "declared only" guard. A repo stuffed
// with everything an inferring loader would happily latch onto still yields a
// skip, because none of it is a declaration.
func TestNoInferenceFromRepoContents(t *testing.T) {
	root := t.TempDir()
	for rel, body := range map[string]string{
		"docker-compose.yml":        "services:\n  web:\n    build: .\n    ports: ['8080:8080']\n",
		"docker-compose.yaml":       "services:\n  api:\n    build: .\n",
		"Dockerfile":                "FROM scratch\nEXPOSE 8080\n",
		"package.json":              `{"scripts":{"start":"node server.js"}}`,
		"Makefile":                  "run:\n\tdocker compose up\n",
		"compose.yaml":              "services:\n  db: {}\n",
		"docker-compose.anvil.yaml": "services:\n  web: {}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	m, reason, err := LoadInRepo(root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Fatalf("Anvil inferred a target from repo contents: %+v. The manifest is declared only.", m)
	}
	if reason != SkipReasonNoManifest {
		t.Fatalf("reason = %q, want %q", reason, SkipReasonNoManifest)
	}
}

// TestAbsentAndInvalidAreDifferentOutcomes is the headline guard for this
// packet. If these two ever collapse, an operator cannot tell "this repo opted
// out" from "this repo's opt-in is broken", and the second silently reads as
// the first.
func TestAbsentAndInvalidAreDifferentOutcomes(t *testing.T) {
	_, absentPath := newRepo(t, "", nil)
	_, brokenPath := newRepo(t, "schema_version: 1\ncompose_file: [\n", nil)

	_, absentReason, absentErr := Load(absentPath)
	brokenManifest, brokenReason, brokenErr := Load(brokenPath)

	if absentReason == brokenReason {
		t.Fatalf("absent and invalid both produced %q; they must be distinguishable", absentReason)
	}
	if absentReason != SkipReasonNoManifest {
		t.Errorf("absent reason = %q, want %q", absentReason, SkipReasonNoManifest)
	}
	if brokenReason != SkipReasonInvalidManifest {
		t.Errorf("invalid reason = %q, want %q", brokenReason, SkipReasonInvalidManifest)
	}
	if absentErr != nil {
		t.Errorf("absent must not be an error, got %v", absentErr)
	}
	if brokenErr == nil {
		t.Error("a broken manifest must be a refusal: Load returned a nil error, so a caller " +
			"that only checks err would read the broken opt-in as a clean skip")
	}
	if brokenManifest != nil {
		t.Errorf("a broken manifest must not yield a Manifest, got %+v", brokenManifest)
	}

	// And they must stay distinguishable once written to the record.
	absentStatus, absentProv, err := absentReason.RecordOutcome()
	if err != nil {
		t.Fatalf("RecordOutcome(absent): %v", err)
	}
	brokenStatus, brokenProv, err := brokenReason.RecordOutcome()
	if err != nil {
		t.Fatalf("RecordOutcome(invalid): %v", err)
	}
	if absentStatus == brokenStatus {
		t.Errorf("both skips map to dast_status %q; the record cannot tell them apart", absentStatus)
	}
	if absentProv == brokenProv {
		t.Errorf("both skips map to target.provenance %q; the record cannot tell them apart", absentProv)
	}
	if absentStatus.MeansDynamicallyScannedClean() || brokenStatus.MeansDynamicallyScannedClean() {
		t.Error("a skip must never read as dynamically-scanned-clean")
	}
}

func TestInvalidManifestErrorIsWrapped(t *testing.T) {
	_, p := newRepo(t, "schema_version: 1\nunknown_field: x\n", nil)
	_, reason, err := Load(p)
	if reason != SkipReasonInvalidManifest {
		t.Fatalf("reason = %q", reason)
	}
	if !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("error %v does not wrap ErrInvalidManifest", err)
	}
}

// ---------------------------------------------------------------------------
// The happy paths
// ---------------------------------------------------------------------------

func TestPlanExampleManifestLoads(t *testing.T) {
	_, p := newRepo(t, planExampleManifest, fullRepoFiles())

	m, reason, err := Load(p)
	if err != nil {
		t.Fatalf("the plan's own example must load: %v", err)
	}
	if reason != SkipReasonNotSkipped {
		t.Fatalf("reason = %q, want %q", reason, SkipReasonNotSkipped)
	}
	if reason.Skips() {
		t.Fatal("a valid manifest must not skip")
	}

	if m.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", m.SchemaVersion)
	}
	if m.ComposeFile != "./docker-compose.anvil.yaml" {
		t.Errorf("ComposeFile = %q", m.ComposeFile)
	}
	if got := m.AuthorizedService().Name(); got != "web" {
		t.Errorf("AuthorizedService = %q, want %q", got, "web")
	}
	if m.Health != (Health{URL: "http://web:8080/healthz", TimeoutSeconds: 120, IntervalSeconds: 5}) {
		t.Errorf("Health = %+v", m.Health)
	}
	if m.Reset.Strategy != ResetStrategyDestroyRecreate {
		t.Errorf("Reset.Strategy = %q", m.Reset.Strategy)
	}
	if m.Seed == nil || !reflect.DeepEqual(m.Seed.Command, []string{"make", "seed"}) ||
		m.Seed.TimeoutSeconds != 60 {
		t.Errorf("Seed = %+v", m.Seed)
	}
	if m.Auth == nil || m.Auth.Method != AuthMethodBrowser ||
		m.Auth.StepsRef != "./.anvil/auth-steps.yaml" {
		t.Errorf("Auth = %+v", m.Auth)
	}
	want := []string{"/openapi.json", "/v3/api-docs", "/graphql"}
	if m.Inventory == nil || !reflect.DeepEqual(m.Inventory.RuntimeSpecEndpoints, want) {
		t.Errorf("Inventory = %+v", m.Inventory)
	}
	if m.Scope == nil || len(m.Scope.AdditionalEgressAllow) != 0 {
		t.Errorf("Scope = %+v; the example declares an explicitly empty list", m.Scope)
	}
	if m.Provisioning() != record.TargetProvisioningEphemeralManifest {
		t.Errorf("Provisioning = %q", m.Provisioning())
	}
}

func TestCanonicalFormRoundTripsByteForByte(t *testing.T) {
	_, p := newRepo(t, canonicalManifest, fullRepoFiles())

	m, reason, err := Load(p)
	if err != nil || reason != SkipReasonNotSkipped {
		t.Fatalf("Load: (%q, %v)", reason, err)
	}
	out, err := m.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != canonicalManifest {
		t.Errorf("re-marshal is not byte-for-byte:\n--- got ---\n%s\n--- want ---\n%s",
			out, canonicalManifest)
	}
}

// The plan example and the canonical form differ only in comments and sequence
// style, so they must parse to the same manifest and marshal to the same bytes.
func TestPlanExampleMarshalsToTheCanonicalForm(t *testing.T) {
	fromExample, err := Parse([]byte(planExampleManifest))
	if err != nil {
		t.Fatalf("Parse(plan example): %v", err)
	}
	out, err := fromExample.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != canonicalManifest {
		t.Errorf("plan example marshals to:\n%s\nwant:\n%s", out, canonicalManifest)
	}
}

func TestMarshalIsAFixedPoint(t *testing.T) {
	for name, src := range map[string]string{
		"minimal":  minimalManifest,
		"full":     canonicalManifest,
		"example":  planExampleManifest,
		"lf_input": strings.ReplaceAll(canonicalManifest, "\n", "\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			first, err := Parse([]byte(src))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			once, err := first.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			second, err := Parse(once)
			if err != nil {
				t.Fatalf("re-Parse: %v", err)
			}
			twice, err := second.Marshal()
			if err != nil {
				t.Fatalf("re-Marshal: %v", err)
			}
			if string(once) != string(twice) {
				t.Errorf("Marshal is not a fixed point:\n%s\nvs\n%s", once, twice)
			}
			if strings.Contains(string(once), "\r") {
				t.Error("Marshal emitted a CR; output must be LF-only")
			}
		})
	}
}

// The three defaults are all timeouts -- caps on how long Anvil waits. No field
// that grants or widens anything is defaulted; those are required, and the
// reject table proves each one refuses when omitted.
func TestOnlyTimeoutsAreDefaulted(t *testing.T) {
	m, err := Parse([]byte(minimalManifest))
	if err != nil {
		t.Fatalf("Parse(minimal): %v", err)
	}
	if m.Health.TimeoutSeconds != defaultHealthTimeoutSeconds {
		t.Errorf("health.timeout_seconds default = %d, want %d",
			m.Health.TimeoutSeconds, defaultHealthTimeoutSeconds)
	}
	if m.Health.IntervalSeconds != defaultHealthIntervalSeconds {
		t.Errorf("health.interval_seconds default = %d, want %d",
			m.Health.IntervalSeconds, defaultHealthIntervalSeconds)
	}
	if m.Seed != nil || m.Auth != nil || m.Inventory != nil || m.Scope != nil {
		t.Error("an omitted optional section must stay nil, not be filled with a default")
	}
}

// ---------------------------------------------------------------------------
// Refusals: schema
// ---------------------------------------------------------------------------

func TestBaseFixturesAreValid(t *testing.T) {
	for name, src := range map[string]string{
		"minimal":   minimalManifest,
		"canonical": canonicalManifest,
		"example":   planExampleManifest,
	} {
		if _, err := Parse([]byte(src)); err != nil {
			t.Errorf("%s fixture must parse (every mutation test depends on it): %v", name, err)
		}
	}
}

func TestRejectsSchemaViolations(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		// --- unknown fields reject, they do not warn ---
		{"unknown root key", mutate(t, minimalManifest, "service: web", "service: web\ncompose: x"),
			"unknown field"},
		{"unknown nested key", mutate(t, minimalManifest, "  url: http://web:8080/healthz",
			"  url: http://web:8080/healthz\n  retries: 3"), "unknown field"},
		{"misspelled health key", mutate(t, minimalManifest, "health:", "helth:"), "unknown field"},
		{"unknown key in an optional section",
			minimalManifest + "scope:\n  additional_egress_allow: []\n  deny: []\n", "unknown field"},

		// --- schema_version ---
		{"missing schema_version", strings.TrimPrefix(minimalManifest, "schema_version: 1\n"),
			"schema_version is required"},
		{"future schema_version", mutate(t, minimalManifest, "schema_version: 1", "schema_version: 2"),
			"not supported"},
		{"quoted schema_version", mutate(t, minimalManifest, "schema_version: 1", `schema_version: "1"`),
			"must be an integer"},
		{"zero schema_version", mutate(t, minimalManifest, "schema_version: 1", "schema_version: 0"),
			"not supported"},

		// --- compose_file ---
		{"missing compose_file", mutate(t, minimalManifest, "compose_file: ./docker-compose.anvil.yaml\n", ""),
			"compose_file is required"},
		{"empty compose_file", mutate(t, minimalManifest, "compose_file: ./docker-compose.anvil.yaml",
			`compose_file: ""`), "compose_file is empty"},
		{"absolute compose_file", mutate(t, minimalManifest, "compose_file: ./docker-compose.anvil.yaml",
			"compose_file: /etc/docker-compose.yaml"), "absolute"},
		{"home-relative compose_file", mutate(t, minimalManifest, "compose_file: ./docker-compose.anvil.yaml",
			"compose_file: ~/docker-compose.yaml"), "absolute"},
		{"drive-qualified compose_file", mutate(t, minimalManifest, "compose_file: ./docker-compose.anvil.yaml",
			`compose_file: "C:/docker-compose.yaml"`), "drive-qualified"},
		{"escaping compose_file", mutate(t, minimalManifest, "compose_file: ./docker-compose.anvil.yaml",
			"compose_file: ../elsewhere/docker-compose.yaml"), "escapes the repo root"},
		{"escaping compose_file, disguised", mutate(t, minimalManifest,
			"compose_file: ./docker-compose.anvil.yaml",
			"compose_file: a/b/../../../docker-compose.yaml"), "escapes the repo root"},
		{"backslash compose_file", mutate(t, minimalManifest, "compose_file: ./docker-compose.anvil.yaml",
			`compose_file: "sub\\compose.yaml"`), "backslash"},
		{"compose_file is not YAML", mutate(t, minimalManifest, "compose_file: ./docker-compose.anvil.yaml",
			"compose_file: ./Dockerfile"), "must be a YAML file"},
		{"compose_file is a list", mutate(t, minimalManifest, "compose_file: ./docker-compose.anvil.yaml",
			`compose_file: ["a.yaml"]`), "must be a string"},

		// --- service: exactly one, and it must be nameable ---
		{"missing service", mutate(t, minimalManifest, "service: web\n", ""), "service is required"},
		{"empty service", mutate(t, minimalManifest, "service: web", `service: ""`), "service is empty"},
		{"service is a list", mutate(t, minimalManifest, "service: web", `service: ["web", "api"]`),
			"must be a string"},
		{"service with a slash", mutate(t, minimalManifest, "service: web", "service: web/api"),
			"is not permitted"},
		{"service with a space", mutate(t, minimalManifest, "service: web", `service: "web api"`),
			"is not permitted"},
		{"service starting with a dash", mutate(t, minimalManifest, "service: web", `service: "-web"`),
			"is not permitted"},
		{"unquoted numeric service", mutate(t, minimalManifest, "service: web", "service: 2fa"),
			"looks numeric"},

		// --- health ---
		{"missing health", strings.Replace(minimalManifest,
			"health:\n  url: http://web:8080/healthz\n", "", 1), "health is required"},
		{"empty health section", mutate(t, minimalManifest,
			"health:\n  url: http://web:8080/healthz", "health:"), "must be a mapping"},
		{"missing health.url", mutate(t, minimalManifest,
			"  url: http://web:8080/healthz", "  timeout_seconds: 30"), "health.url is required"},
		{"health.url is not http", mutate(t, minimalManifest, "url: http://web:8080/healthz",
			"url: file:///etc/passwd"), "only http and https"},
		{"health.url has no scheme", mutate(t, minimalManifest, "url: http://web:8080/healthz",
			"url: web:8080/healthz"), "only http and https"},
		{"health.url carries credentials", mutate(t, minimalManifest, "url: http://web:8080/healthz",
			"url: http://user:pass@web:8080/healthz"), "credentials"},
		{"health.url has a fragment", mutate(t, minimalManifest, "url: http://web:8080/healthz",
			`url: "http://web:8080/healthz#frag"`), "fragment"},
		{"health.url port out of range", mutate(t, minimalManifest, "url: http://web:8080/healthz",
			"url: http://web:99999/healthz"), "1-65535"},
		{"health.url addresses another service", mutate(t, minimalManifest,
			"url: http://web:8080/healthz", "url: http://db:5432/healthz"),
			"neither the authorized service"},
		{"health.url addresses a third party", mutate(t, minimalManifest,
			"url: http://web:8080/healthz", "url: https://example.com/healthz"),
			"neither the authorized service"},
		{"health.timeout_seconds is zero", mutate(t, minimalManifest,
			"  url: http://web:8080/healthz", "  url: http://web:8080/healthz\n  timeout_seconds: 0"),
			"must be between"},
		{"health.timeout_seconds is negative", mutate(t, minimalManifest,
			"  url: http://web:8080/healthz", "  url: http://web:8080/healthz\n  timeout_seconds: -1"),
			"must be between"},
		{"health.timeout_seconds is enormous", mutate(t, minimalManifest,
			"  url: http://web:8080/healthz", "  url: http://web:8080/healthz\n  timeout_seconds: 99999"),
			"must be between"},
		{"health.timeout_seconds is a float", mutate(t, minimalManifest,
			"  url: http://web:8080/healthz", "  url: http://web:8080/healthz\n  timeout_seconds: 1.5"),
			"looks numeric"},
		{"interval exceeds timeout", mutate(t, minimalManifest, "  url: http://web:8080/healthz",
			"  url: http://web:8080/healthz\n  timeout_seconds: 10\n  interval_seconds: 30"),
			"would never poll"},

		// --- reset ---
		{"missing reset", strings.Replace(minimalManifest,
			"reset:\n  strategy: destroy_recreate\n", "", 1), "reset is required"},
		{"missing reset.strategy", mutate(t, minimalManifest, "  strategy: destroy_recreate", "  strategy:"),
			"must be a string, got nothing"},
		{"unknown reset.strategy", mutate(t, minimalManifest, "strategy: destroy_recreate",
			"strategy: snapshot_restore"), "v1 accepts"},

		// --- seed ---
		{"seed present but empty", minimalManifest + "seed:\n", "present but empty"},
		{"seed without command", minimalManifest + "seed:\n  timeout_seconds: 30\n",
			"seed.command is required"},
		{"seed command as a shell string", minimalManifest + "seed:\n  command: make seed\n",
			"exec form"},
		{"seed command empty list", minimalManifest + "seed:\n  command: []\n", "seed.command is empty"},
		{"seed command with an empty argument", minimalManifest + `seed:` + "\n" +
			`  command: ["make", ""]` + "\n", "is empty"},
		{"seed timeout out of range", minimalManifest + "seed:\n  command: [\"make\"]\n  timeout_seconds: 0\n",
			"must be between"},

		// --- auth ---
		{"auth present but empty", minimalManifest + "auth:\n", "present but empty"},
		{"auth without steps_ref", minimalManifest + "auth:\n  method: browser\n",
			"auth.steps_ref is required"},
		{"auth without method", minimalManifest + "auth:\n  steps_ref: ./.anvil/auth-steps.yaml\n",
			"auth.method is required"},
		{"unknown auth method", minimalManifest + "auth:\n  method: autodetect\n" +
			"  steps_ref: ./.anvil/auth-steps.yaml\n", "v1 accepts"},
		{"auth steps_ref escapes the repo", minimalManifest + "auth:\n  method: browser\n" +
			"  steps_ref: ../secrets/auth-steps.yaml\n", "escapes the repo root"},

		// --- inventory ---
		{"inventory present but empty", minimalManifest + "inventory:\n", "present but empty"},
		{"inventory without endpoints", minimalManifest + "inventory:\n  runtime_spec_endpoints:\n",
			"must be a list, got nothing"},
		{"inventory with an empty list", minimalManifest + "inventory:\n  runtime_spec_endpoints: []\n",
			"is empty"},
		{"endpoint without a leading slash", minimalManifest +
			"inventory:\n  runtime_spec_endpoints: [\"openapi.json\"]\n", "absolute path on the target"},
		{"endpoint as a full URL", minimalManifest +
			"inventory:\n  runtime_spec_endpoints: [\"http://evil.example/openapi.json\"]\n",
			"absolute path on the target"},
		{"protocol-relative endpoint", minimalManifest +
			"inventory:\n  runtime_spec_endpoints: [\"//evil.example/openapi.json\"]\n",
			"protocol-relative"},
		{"endpoint with a parent segment", minimalManifest +
			"inventory:\n  runtime_spec_endpoints: [\"/a/../../b\"]\n", "segment"},
		{"duplicate endpoints", minimalManifest +
			"inventory:\n  runtime_spec_endpoints: [\"/openapi.json\", \"/openapi.json\"]\n",
			"appears twice"},

		// --- scope ---
		{"scope present but empty", minimalManifest + "scope:\n", "present but empty"},
		{"scope without the key", minimalManifest + "scope:\n  additional_egress_allow:\n",
			"must be a list, got nothing"},
		{"egress entry is not a host or CIDR", minimalManifest +
			"scope:\n  additional_egress_allow: [\"not a host\"]\n", "not an IP address"},
		{"wildcard egress entry", minimalManifest +
			"scope:\n  additional_egress_allow: [\"*.example.com\"]\n", "not an IP address"},
		{"malformed CIDR", minimalManifest +
			"scope:\n  additional_egress_allow: [\"10.0.0.0/99\"]\n", "not a valid CIDR"},
		{"duplicate egress entries", minimalManifest +
			"scope:\n  additional_egress_allow: [\"10.0.0.0/8\", \"10.0.0.0/8\"]\n", "appears twice"},

		// --- YAML surface: everything outside the subset refuses ---
		{"empty document", "", "manifest is empty"},
		{"whitespace-only document", "\n\n   \n", "manifest is empty"},
		{"comment-only document", "# nothing here\n", "manifest is empty"},
		{"root is a sequence", "- web\n- api\n", "must be a mapping"},
		{"root is a scalar", "just-a-string\n", "not a mapping entry"},
		{"duplicate key", minimalManifest + "service: api\n", "duplicate key"},
		{"tab indentation", "schema_version: 1\nhealth:\n\turl: http://web/x\n", "control character"},
		{"document marker", "---\n" + minimalManifest, "document markers"},
		{"directive", "%YAML 1.2\n" + minimalManifest, "directives"},
		{"anchor", mutate(t, minimalManifest, "service: web", "service: &svc web"), "anchors"},
		{"alias", mutate(t, minimalManifest, "service: web", "service: *svc"), "aliases"},
		{"tag", mutate(t, minimalManifest, "service: web", "service: !!str web"), "tags"},
		{"block scalar", mutate(t, minimalManifest, "service: web", "service: |"), "block scalars"},
		{"folded scalar", mutate(t, minimalManifest, "service: web", "service: >"), "block scalars"},
		{"block scalar with a body", mutate(t, minimalManifest, "service: web", "service: |\n  web"),
			"both an inline value and child lines"},
		{"flow mapping", mutate(t, minimalManifest, "health:\n  url: http://web:8080/healthz",
			"health: {url: http://web:8080/healthz}"), "flow mappings"},
		{"key with a value and children", mutate(t, minimalManifest, "health:", "health: inline"),
			"both an inline value and child lines"},
		{"nested sequence", minimalManifest +
			"inventory:\n  runtime_spec_endpoints: [[\"/a\"]]\n", "nested collections"},
		{"sequence of mappings", minimalManifest +
			"inventory:\n  runtime_spec_endpoints:\n    - path: /a\n      method: GET\n",
			"may not have child lines"},
		{"unterminated flow sequence", minimalManifest +
			"inventory:\n  runtime_spec_endpoints: [\"/a\"\n", "unterminated"},
		{"unterminated quoted scalar", mutate(t, minimalManifest, "service: web", `service: "web`),
			"unterminated"},
		{"unsupported escape", mutate(t, minimalManifest, "service: web", `service: "we\tb"`),
			"is not supported"},
		{"reserved word as a value", mutate(t, minimalManifest, "service: web", "service: no"),
			"reserved word"},
		{"null as a value", mutate(t, minimalManifest, "service: web", "service: null"),
			"reserved word"},
		{"octal-looking integer", mutate(t, minimalManifest, "schema_version: 1", "schema_version: 01"),
			"looks numeric"},
		{"underscore-separated integer", mutate(t, minimalManifest, "  url: http://web:8080/healthz",
			"  url: http://web:8080/healthz\n  timeout_seconds: 1_000"), "looks numeric"},
		{"misaligned indent", "schema_version: 1\nhealth:\n  url: http://web/x\n interval_seconds: 5\n",
			"shallower than the block's"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse([]byte(tc.src))
			if err == nil {
				t.Fatalf("accepted a manifest that must be refused; got %+v", m)
			}
			if !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("error does not wrap ErrInvalidManifest: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.want)
			}
			if m != nil {
				t.Fatalf("a refused manifest must be nil, got %+v", m)
			}
		})
	}
}

// A quoted numeric service name is accepted -- the refusal above is about
// ambiguity, not about the characters.
func TestQuotedNumericServiceIsAccepted(t *testing.T) {
	src := mutate(t, minimalManifest, "service: web", `service: "2fa"`)
	src = mutate(t, src, "url: http://web:8080/healthz", "url: http://2fa:8080/healthz")
	m, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := m.AuthorizedService().Name(); got != "2fa" {
		t.Errorf("service = %q, want %q", got, "2fa")
	}
}

// ---------------------------------------------------------------------------
// Refusals: filesystem and layout
// ---------------------------------------------------------------------------

func TestRejectsFilesystemViolations(t *testing.T) {
	t.Run("compose_file does not exist", func(t *testing.T) {
		_, p := newRepo(t, minimalManifest, nil)
		m, reason, err := Load(p)
		if err == nil || reason != SkipReasonInvalidManifest || m != nil {
			t.Fatalf("got (%v, %q, %v)", m, reason, err)
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("compose_file is a directory", func(t *testing.T) {
		root, p := newRepo(t, minimalManifest, nil)
		if err := os.MkdirAll(filepath.Join(root, "docker-compose.anvil.yaml"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, reason, err := Load(p)
		if err == nil || reason != SkipReasonInvalidManifest {
			t.Fatalf("got (%q, %v)", reason, err)
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("auth steps_ref does not exist", func(t *testing.T) {
		src := minimalManifest + "auth:\n  method: browser\n  steps_ref: ./.anvil/auth-steps.yaml\n"
		_, p := newRepo(t, src, map[string]string{"docker-compose.anvil.yaml": "services: {}\n"})
		_, reason, err := Load(p)
		if err == nil || reason != SkipReasonInvalidManifest {
			t.Fatalf("got (%q, %v)", reason, err)
		}
		if !strings.Contains(err.Error(), "auth.steps_ref") {
			t.Errorf("error = %v", err)
		}
	})
}

// TestLoadRefusesAWrongLayout isolates the layout guard: every declared file
// exists at every candidate root, so the ONLY thing wrong is the location. The
// error text is asserted for the same reason -- otherwise a refusal for some
// unrelated reason would let this test pass with the guard deleted.
func TestLoadRefusesAWrongLayout(t *testing.T) {
	for _, rel := range []string{"target.yaml", "config/target.yaml", ".anvil/manifest.yaml"} {
		t.Run(rel, func(t *testing.T) {
			outer := t.TempDir()
			root := filepath.Join(outer, "repo")
			p := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(minimalManifest), 0o644); err != nil {
				t.Fatal(err)
			}
			// Satisfy compose_file relative to every root Load could pick,
			// so nothing but the layout can be the cause of the refusal.
			for _, base := range []string{outer, root, filepath.Dir(p)} {
				f := filepath.Join(base, "docker-compose.anvil.yaml")
				if err := os.WriteFile(f, []byte("services: {}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			_, reason, err := Load(p)
			if reason != SkipReasonInvalidManifest || err == nil {
				t.Fatalf("a manifest outside %s must be refused; got (%q, %v)", DefaultRelPath, reason, err)
			}
			if !strings.Contains(err.Error(), "must be named") &&
				!strings.Contains(err.Error(), "must live in") {
				t.Fatalf("refused, but not for the layout: %v", err)
			}
		})
	}
}

func TestLoadRefusesTheEmptyPath(t *testing.T) {
	for _, p := range []string{"", "   "} {
		m, reason, err := Load(p)
		if reason != SkipReasonInvalidManifest || err == nil || m != nil {
			t.Fatalf("Load(%q) = (%v, %q, %v); the empty path is a refusal, not a skip", p, m, reason, err)
		}
	}
	if _, reason, err := LoadInRepo(""); reason != SkipReasonInvalidManifest || err == nil {
		t.Fatalf("LoadInRepo(\"\") = (%q, %v); want a refusal", reason, err)
	}
}

func TestLoadRefusesANonRegularFile(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, ManifestDirName, ManifestFileName)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	_, reason, err := Load(p)
	if reason != SkipReasonInvalidManifest || err == nil {
		t.Fatalf("a directory at the manifest path must be refused; got (%q, %v)", reason, err)
	}
}

func TestLoadRefusesAnOversizeFile(t *testing.T) {
	padding := strings.Repeat("# padding\n", (maxManifestBytes/10)+16)
	_, p := newRepo(t, minimalManifest+padding, fullRepoFiles())
	_, reason, err := Load(p)
	if reason != SkipReasonInvalidManifest || err == nil {
		t.Fatalf("got (%q, %v)", reason, err)
	}
	if !strings.Contains(err.Error(), "the limit is") {
		t.Errorf("error = %v", err)
	}
}

func TestLoadRefusesNonUTF8(t *testing.T) {
	_, p := newRepo(t, "", nil)
	if err := os.WriteFile(p, []byte{'s', 'e', 'r', 'v', 'i', 'c', 'e', ':', ' ', 0xff, '\n'}, 0o644); err != nil {
		t.Fatal(err)
	}
	_, reason, err := Load(p)
	if reason != SkipReasonInvalidManifest || err == nil {
		t.Fatalf("got (%q, %v)", reason, err)
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("error = %v", err)
	}
}

func TestLoadAcceptsCRLF(t *testing.T) {
	_, p := newRepo(t, strings.ReplaceAll(canonicalManifest, "\n", "\r\n"), fullRepoFiles())
	m, reason, err := Load(p)
	if err != nil || reason != SkipReasonNotSkipped {
		t.Fatalf("a CRLF checkout must still load: (%q, %v)", reason, err)
	}
	if m.Health.URL != "http://web:8080/healthz" {
		t.Errorf("Health.URL = %q; a CR leaked into the value", m.Health.URL)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed zero values
// ---------------------------------------------------------------------------

func TestSkipReasonZeroValueFailsClosed(t *testing.T) {
	var zero SkipReason
	if zero != SkipReasonUnset {
		t.Fatalf("the zero SkipReason is %q, not SkipReasonUnset", zero)
	}
	if zero.Valid() {
		t.Error("the zero SkipReason must not be a legal outcome")
	}
	if !zero.Skips() {
		t.Error("the zero SkipReason must skip; a Go zero value must never mean the DAST half may run")
	}
	if _, _, err := zero.RecordOutcome(); err == nil {
		t.Error("RecordOutcome on the zero value must refuse")
	}
	if _, _, err := SkipReason("something_else").RecordOutcome(); err == nil {
		t.Error("RecordOutcome on an unrecognised value must refuse")
	}
	if _, _, err := SkipReasonNotSkipped.RecordOutcome(); err == nil {
		t.Error("RecordOutcome on a non-skip must refuse; the run reports its own outcome")
	}
	if !SkipReason("something_else").Skips() {
		t.Error("an unrecognised SkipReason must skip")
	}
}

func TestAuthorizedServiceZeroValueAuthorizesNothing(t *testing.T) {
	var zero AuthorizedService
	if !zero.IsZero() || zero.Name() != "" {
		t.Fatalf("zero AuthorizedService = %+v", zero)
	}
	for _, probe := range []string{"", "web", "db", "*", "localhost"} {
		if zero.Authorizes(probe) {
			t.Errorf("the zero AuthorizedService authorized %q", probe)
		}
	}
	web := AuthorizedService{name: "web"}
	if web.Authorizes("") {
		t.Error(`an authorized service must never authorize ""`)
	}
	if web.Authorizes("db") {
		t.Error("an authorized service must not authorize a different service")
	}
	if !web.Authorizes("web") {
		t.Error("an authorized service must authorize itself")
	}
}

// TestExactlyOneServiceIsStructural asserts the single-target rule is carried
// by the TYPE, not by a convention a later edit could quietly widen.
func TestExactlyOneServiceIsStructural(t *testing.T) {
	svcType := reflect.TypeOf(AuthorizedService{})
	if svcType.NumField() != 1 {
		t.Fatalf("AuthorizedService has %d fields; it must wrap exactly one name", svcType.NumField())
	}
	f := svcType.Field(0)
	if f.IsExported() {
		t.Error("AuthorizedService's field is exported, so any package can forge one")
	}
	if f.Type.Kind() != reflect.String {
		t.Errorf("AuthorizedService's field is %s; it must be a single string", f.Type.Kind())
	}

	found := 0
	var walk func(reflect.Type, string, int)
	walk = func(ty reflect.Type, path string, depth int) {
		if depth > 4 {
			return
		}
		for ty.Kind() == reflect.Pointer {
			ty = ty.Elem()
		}
		if ty == svcType {
			found++
			return
		}
		switch ty.Kind() {
		case reflect.Slice, reflect.Array, reflect.Map:
			elem := ty.Elem()
			for elem.Kind() == reflect.Pointer {
				elem = elem.Elem()
			}
			if elem == svcType {
				t.Errorf("%s is a collection of AuthorizedService; exactly one service is authorized",
					path)
			}
		case reflect.Struct:
			for i := 0; i < ty.NumField(); i++ {
				walk(ty.Field(i).Type, path+"."+ty.Field(i).Name, depth+1)
			}
		}
	}
	walk(reflect.TypeOf(Manifest{}), "Manifest", 0)
	if found != 1 {
		t.Errorf("Manifest reaches AuthorizedService %d times; want exactly 1", found)
	}
}

func TestZeroManifestDoesNotMarshal(t *testing.T) {
	if _, err := (&Manifest{}).Marshal(); err == nil {
		t.Error("the zero Manifest marshalled; a zero value must never be a usable target")
	}
	if _, err := (*Manifest)(nil).Marshal(); err == nil {
		t.Error("a nil Manifest marshalled")
	}
	// A Manifest assembled outside this package cannot name a service, so it
	// must not marshal either.
	forged := &Manifest{
		SchemaVersion: SchemaVersion,
		ComposeFile:   "./docker-compose.anvil.yaml",
		Health:        Health{URL: "http://web:8080/healthz", TimeoutSeconds: 120, IntervalSeconds: 5},
		Reset:         Reset{Strategy: ResetStrategyDestroyRecreate},
	}
	if _, err := forged.Marshal(); err == nil {
		t.Error("a Manifest with no authorized service marshalled")
	}
}

// ---------------------------------------------------------------------------
// Record mapping
// ---------------------------------------------------------------------------

func TestRecordOutcomeUsesTheFrozenEnums(t *testing.T) {
	for _, r := range []SkipReason{SkipReasonNoManifest, SkipReasonInvalidManifest} {
		status, prov, err := r.RecordOutcome()
		if err != nil {
			t.Fatalf("RecordOutcome(%q): %v", r, err)
		}
		if err := record.ValidateDastStatus(string(status)); err != nil {
			t.Errorf("%q -> dast_status %q: %v", r, status, err)
		}
		if err := record.ValidateTargetProvenance(string(prov)); err != nil {
			t.Errorf("%q -> target.provenance %q: %v", r, prov, err)
		}
	}

	status, prov, err := SkipReasonNoManifest.RecordOutcome()
	if err != nil {
		t.Fatal(err)
	}
	if status != record.DastStatusSkippedNoManifest {
		t.Errorf("no-manifest dast_status = %q, want %q", status, record.DastStatusSkippedNoManifest)
	}
	if prov != record.TargetProvenanceNoTargetDeclared {
		t.Errorf("no-manifest provenance = %q, want %q", prov, record.TargetProvenanceNoTargetDeclared)
	}
}

// The literals plan/50-dast.md:1149-1150 still names. internal/record's
// contract test rejects every one of them and attributes them to "area D";
// this package is area D, so it asserts the same thing at its own boundary.
func TestRecordOutcomeNeverEmitsTheStaleLiterals(t *testing.T) {
	staleStatuses := []string{"clean", "findings", "failed_to_boot", "partial"}
	staleProvenances := []string{"ephemeral_manifest", "live_url_authorized"}

	for _, r := range SkipReasonValues() {
		status, prov, err := r.RecordOutcome()
		if err != nil {
			continue // SkipReasonNotSkipped has no record outcome of its own.
		}
		for _, bad := range staleStatuses {
			if string(status) == bad {
				t.Errorf("%q emits the withdrawn dast_status %q", r, bad)
			}
		}
		for _, bad := range staleProvenances {
			if string(prov) == bad {
				t.Errorf("%q writes the provisioning literal %q into the provenance field; "+
					"they are two separate fields", r, bad)
			}
		}
	}

	// The provisioning literals are legal -- in the provisioning field.
	if err := record.ValidateTargetProvisioning(string(record.TargetProvisioningEphemeralManifest)); err != nil {
		t.Fatalf("provisioning literal rejected: %v", err)
	}
	m := &Manifest{}
	if m.Provisioning() != record.TargetProvisioningEphemeralManifest {
		t.Errorf("Provisioning() = %q; a manifest always means Anvil built the target itself",
			m.Provisioning())
	}
}

// ---------------------------------------------------------------------------
// Unit guards on the containment helpers
// ---------------------------------------------------------------------------

func TestCheckRepoRelPathRefusesEscapes(t *testing.T) {
	refuse := []string{
		"", "/etc/passwd", "~/x.yaml", "../x.yaml", "../../x.yaml", "a/../../x.yaml",
		"a/b/../../../x.yaml", `sub\x.yaml`, "C:/x.yaml", ".", "..", "/",
		strings.Repeat("a", maxScalarBytes+1),
	}
	for _, p := range refuse {
		if err := checkRepoRelPath(p, "compose_file"); err == nil {
			t.Errorf("checkRepoRelPath(%q) accepted an escaping or malformed path", p)
		}
	}
	accept := []string{
		"docker-compose.yaml", "./docker-compose.yaml", "deploy/compose.yaml",
		"./a/b/../c.yaml", ".anvil/auth-steps.yaml",
	}
	for _, p := range accept {
		if err := checkRepoRelPath(p, "compose_file"); err != nil {
			t.Errorf("checkRepoRelPath(%q) refused a legitimate path: %v", p, err)
		}
	}
}

func TestWithinRefusesEscapes(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "repo")
	if !within(root, filepath.Join(root, "a", "b.yaml")) {
		t.Error("a path inside the root must be within it")
	}
	if !within(root, root) {
		t.Error("the root is within itself")
	}
	if within(root, filepath.Join(string(filepath.Separator), "elsewhere", "b.yaml")) {
		t.Error("a sibling directory is not within the root")
	}
	if within(root, filepath.Join(string(filepath.Separator), "repository", "b.yaml")) {
		t.Error("a directory sharing a name prefix is not within the root")
	}
	if within(root, filepath.Dir(root)) {
		t.Error("the parent is not within the root")
	}
}

func TestParseStrictIntRefusesAmbiguousForms(t *testing.T) {
	for _, s := range []string{"01", "0x10", "1_000", "1e3", "1.5", "+1", "-", "", "1a", "0b1"} {
		if n, err := parseStrictInt(s); err == nil {
			t.Errorf("parseStrictInt(%q) = %d; every one of these is ambiguous across YAML versions", s, n)
		}
	}
	for s, want := range map[string]int{"0": 0, "1": 1, "120": 120, "-5": -5} {
		got, err := parseStrictInt(s)
		if err != nil || got != want {
			t.Errorf("parseStrictInt(%q) = (%d, %v), want (%d, nil)", s, got, err, want)
		}
	}
}

func TestPlainSafeAndQuotingAgreeWithTheDecoder(t *testing.T) {
	// Every value the canonical fixture emits plain must decode back to itself.
	for _, s := range []string{
		"./docker-compose.anvil.yaml", "web", "http://web:8080/healthz",
		"destroy_recreate", "browser", "./.anvil/auth-steps.yaml",
	} {
		if !plainSafe(s) {
			t.Errorf("plainSafe(%q) = false; the canonical form emits it unquoted", s)
		}
	}
	for _, s := range []string{"", "no", "NO", "null", "~", "-x", "1", "2fa", "a b", "a#b", `a"b`} {
		if plainSafe(s) {
			t.Errorf("plainSafe(%q) = true; it would not decode back to itself", s)
		}
	}
	for _, s := range []string{`a"b`, `a\b`, "a b", "no", "2fa"} {
		v, err := parseScalar(quoteYAML(s), 1)
		if err != nil {
			t.Errorf("parseScalar(quoteYAML(%q)): %v", s, err)
			continue
		}
		if v != s {
			t.Errorf("round trip of %q gave %v", s, v)
		}
	}
}
