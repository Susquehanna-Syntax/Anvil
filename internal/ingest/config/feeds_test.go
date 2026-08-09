package config

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------
//
// Fixtures are synthetic and use the reserved .invalid TLD (RFC 2606): a test
// that reached a real feed would not be a test, and A.1's packet forbids this
// step from fetching anything at all. The cadences below are fixture values,
// not Anvil's cadences — the real ones live in feeds.example.yaml, and
// TestNoFeedDataInSource is what keeps them out of feeds.go.

const baseDoc = `version: 1
feeds:
  - id: alpha
    url: https://feeds.invalid/alpha.json
    auth_mode: none
    sync_mechanism: conditional_get_etag
    interval_seconds: 900
    freshness_slo_seconds: 3600
    on_failure: serve_stale
    license_tier: 0
    license_spdx: CC0-1.0
    bootstrap_mechanism: bulk_archive
`

// mutate rewrites one fragment of a fixture and fails the test if the fragment
// was not there — a silently-stale fixture would make its assertion vacuous.
func mutate(t *testing.T, doc string, pairs ...string) string {
	t.Helper()
	if len(pairs)%2 != 0 {
		t.Fatalf("mutate: odd number of arguments")
	}
	for i := 0; i < len(pairs); i += 2 {
		old, new := pairs[i], pairs[i+1]
		if !strings.Contains(doc, old) {
			t.Fatalf("mutate: fixture does not contain %q", old)
		}
		doc = strings.Replace(doc, old, new, 1)
	}
	return doc
}

func mustParse(t *testing.T, doc string) FeedSet {
	t.Helper()
	set, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: unexpected error: %v", err)
	}
	return set
}

// ---------------------------------------------------------------------------
// The example file is the acceptance fixture
// ---------------------------------------------------------------------------

func loadExample(t *testing.T) FeedSet {
	t.Helper()
	set, err := Load(ExampleFileName)
	if err != nil {
		t.Fatalf("Load(%s): %v", ExampleFileName, err)
	}
	return set
}

// TestExampleFileLoads is A.1's stop condition in its positive direction: the
// loader accepts a config covering every feed in the plan's Feed Table.
func TestExampleFileLoads(t *testing.T) {
	set := loadExample(t)

	if set.Version != SchemaVersion {
		t.Errorf("version = %d, want %d", set.Version, SchemaVersion)
	}
	if len(set.Feeds) == 0 {
		t.Fatal("example declares no feeds")
	}
	for _, f := range set.Feeds {
		if f.LicenseSPDX == "" {
			t.Errorf("feed %q states no licence", f.ID)
		}
		if f.FreshnessSLOSeconds <= 0 {
			t.Errorf("feed %q has no freshness SLO", f.ID)
		}
		if f.SyncMechanism.Polled() && f.IntervalSeconds <= 0 {
			t.Errorf("feed %q is polled with no interval", f.ID)
		}
	}
}

// TestExampleCoversFeedTable checks the example against every row of the Feed
// Table in plan/20-lane-a-ingestion-sca.md, with the tier that table assigns.
// This is the packet's required evidence, expressed as an assertion rather
// than as prose in a report.
//
// The table's OSV row is conditional — "2 — segregated mirror/tier2/osv/ if
// pulled as the merged all.zip; per-ecosystem licence tag otherwise" — so the
// example renders BOTH branches, and both are checked.
func TestExampleCoversFeedTable(t *testing.T) {
	set := loadExample(t)

	wantTier := map[string]LicenseTier{
		"cvelistv5":         LicenseTier0, // CVE List V5
		"cisa-vulnrichment": LicenseTier0, // CISA Vulnrichment, inside the ADP container
		"cisa-kev":          LicenseTier0, // CISA KEV via the kev-data mirror
		"cwe":               LicenseTier0, // CWE 4.20
		"nvd":               LicenseTier0, // NVD CVE API 2.0, supplementary
		"ghsa":              LicenseTier1, // github/advisory-database
		"redhat-csaf":       LicenseTier1, // Red Hat CSAF/VEX
		"osv-pypi":          LicenseTier1, // OSV, per-ecosystem branch
		"ubuntu-osv":        LicenseTier2, // Ubuntu, share-alike
		"alpine-secdb":      LicenseTier2, // Alpine secdb, share-alike
		"osv-merged":        LicenseTier2, // OSV, merged-aggregate branch
		"epss":              LicenseTier3, // EPSS, undeclared licence
	}

	for id, tier := range wantTier {
		f, ok := set.ByID(id)
		if !ok {
			t.Errorf("Feed Table row %q is missing from %s", id, ExampleFileName)
			continue
		}
		if f.LicenseTier != tier {
			t.Errorf("feed %q: license_tier = %d, want %d", id, f.LicenseTier.Int(), tier.Int())
		}
	}
	for _, f := range set.Feeds {
		if _, ok := wantTier[f.ID]; !ok {
			t.Errorf("%s declares feed %q, which is not a row of the Feed Table", ExampleFileName, f.ID)
		}
	}

	// Greenbone/OpenVAS content is ODbL-1.0 share-alike and belongs to the
	// dynamic/host tier, not to Lane A's advisory feed table
	// (plan/IMPLEMENTATION-PLAN.md 2.3, spine S8). Its appearance here would
	// mean the quarantine was reasoned about in the wrong lane.
	for _, f := range set.Feeds {
		if strings.Contains(strings.ToLower(f.ID), "greenbone") ||
			strings.Contains(strings.ToLower(f.ID), "openvas") {
			t.Errorf("feed %q belongs to the dynamic/host tier, not Lane A's feed table", f.ID)
		}
	}
}

// TestExampleShareAlikeIsTier2 checks the licence fact spine S8 quarantines
// on: a CC-BY-SA-4.0 source is Tier 2 and lives in a segregated directory.
// A.4 owns the gate; this asserts the DATA it will gate on is right.
func TestExampleShareAlikeIsTier2(t *testing.T) {
	set := loadExample(t)
	for _, f := range set.Feeds {
		if f.LicenseSPDX == "CC-BY-SA-4.0" && f.LicenseTier != LicenseTier2 {
			t.Errorf("feed %q is share-alike (%s) at tier %d, want tier %d",
				f.ID, f.LicenseSPDX, f.LicenseTier.Int(), LicenseTier2.Int())
		}
	}
	tier2 := set.ByTier(LicenseTier2)
	if len(tier2) == 0 {
		t.Fatal("no tier-2 feeds in the example; the share-alike rows are missing")
	}
}

// TestExampleEPSSIsUndeclared is the specific ruling this lane was told not to
// get wrong: EPSS has no licence and no SPDX identifier, "attribution is
// requested" is not a grant of rights (research/01 S18/S19), and Anvil must
// never describe it as open licensed.
func TestExampleEPSSIsUndeclared(t *testing.T) {
	set := loadExample(t)
	f, ok := set.ByID("epss")
	if !ok {
		t.Skip("the example does not carry an EPSS row; nothing to constrain")
	}
	if f.LicenseSPDX != LicenseNone {
		t.Errorf("epss license_spdx = %q, want %q — no grant of rights exists",
			f.LicenseSPDX, LicenseNone)
	}
	if f.LicenseDeclared() {
		t.Error("epss reports a declared licence")
	}
	if f.LicenseTier != LicenseTier3 {
		t.Errorf("epss tier = %d, want %d (optional, opt-in, risk-accepted)",
			f.LicenseTier.Int(), LicenseTier3.Int())
	}
	if f.Enabled {
		t.Error("epss ships enabled; a Tier 3 source is opt-in at install time")
	}
	if strings.TrimSpace(f.LicenseManualNote) == "" {
		t.Error("epss carries no license_manual_note")
	}
}

// TestExampleAuthenticatesGitHubFeeds encodes research/06 Risk #8: an
// unauthenticated conditional GET against a GitHub-hosted feed still costs the
// 60/hour budget, so those rows must ask for a credential. A.7 enforces the
// send side; this asserts the config asks for it in the first place.
func TestExampleAuthenticatesGitHubFeeds(t *testing.T) {
	set := loadExample(t)
	for _, f := range set.Feeds {
		if f.URL == "" {
			continue
		}
		u, err := url.Parse(f.URL)
		if err != nil {
			t.Fatalf("feed %q: %v", f.ID, err)
		}
		host := u.Hostname()
		gh := host == "github.com" ||
			strings.HasSuffix(host, ".github.com") ||
			strings.HasSuffix(host, ".githubusercontent.com")
		if gh && f.AuthMode != AuthGitHubToken {
			t.Errorf("feed %q is GitHub-hosted (%s) with auth_mode %q; an unauthenticated 304 costs rate-limit budget",
				f.ID, host, f.AuthMode)
		}
	}
}

// TestExampleCarriesNoSecret asserts the file names environment variables,
// never values. The loader enforces the shape; this asserts the shipped
// example obeys it and that no URL smuggles a credential in userinfo.
func TestExampleCarriesNoSecret(t *testing.T) {
	set := loadExample(t)
	for _, f := range set.Feeds {
		if f.AuthMode != AuthNone && !validEnvName(f.CredentialEnv) {
			t.Errorf("feed %q credential_env %q is not an environment variable name", f.ID, f.CredentialEnv)
		}
		for _, raw := range []string{f.URL, f.BootstrapURL} {
			if raw == "" {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("feed %q: %v", f.ID, err)
			}
			if u.User != nil {
				t.Errorf("feed %q URL carries inline credentials", f.ID)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Defaults and accessors
// ---------------------------------------------------------------------------

func TestEnabledDefaultsToTrue(t *testing.T) {
	set := mustParse(t, baseDoc)
	if !set.Feeds[0].Enabled {
		t.Error("a feed with no `enabled` key is not enabled by default")
	}

	off := mutate(t, baseDoc, "    auth_mode: none\n", "    enabled: false\n    auth_mode: none\n")
	set = mustParse(t, off)
	if set.Feeds[0].Enabled {
		t.Error("`enabled: false` was ignored")
	}
	if got := len(set.EnabledFeeds()); got != 0 {
		t.Errorf("EnabledFeeds returned %d rows, want 0", got)
	}
}

func TestBootstrapURLDefaultsToURL(t *testing.T) {
	set := mustParse(t, baseDoc)
	f := set.Feeds[0]
	if f.BootstrapURL != f.URL {
		t.Errorf("BootstrapURL = %q, want it defaulted to URL %q", f.BootstrapURL, f.URL)
	}

	explicit := mutate(t, baseDoc,
		"    bootstrap_mechanism: bulk_archive\n",
		"    bootstrap_url: https://feeds.invalid/alpha-bulk.zip\n    bootstrap_mechanism: bulk_archive\n")
	set = mustParse(t, explicit)
	if got := set.Feeds[0].BootstrapURL; got != "https://feeds.invalid/alpha-bulk.zip" {
		t.Errorf("explicit bootstrap_url was not kept: %q", got)
	}
}

func TestAccessorsAndDurations(t *testing.T) {
	doc := baseDoc + `  - id: beta
    url: https://feeds.invalid/beta.json
    enabled: false
    auth_mode: none
    sync_mechanism: conditional_get_last_modified
    interval_seconds: 86400
    reconcile_interval_seconds: 172800
    baseline_interval_seconds: 604800
    freshness_slo_seconds: 259200
    on_failure: serve_stale
    license_tier: 2
    license_spdx: CC-BY-SA-4.0
    bootstrap_mechanism: bulk_archive
`
	set := mustParse(t, doc)

	if got := set.IDs(); len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Fatalf("IDs = %v, want document order [alpha beta]", got)
	}
	if _, ok := set.ByID("gamma"); ok {
		t.Error("ByID found a feed that is not there")
	}
	if got := set.EnabledFeeds(); len(got) != 1 || got[0].ID != "alpha" {
		t.Errorf("EnabledFeeds = %v, want [alpha]", got)
	}
	if got := set.ByTier(LicenseTier2); len(got) != 1 || got[0].ID != "beta" {
		t.Errorf("ByTier(2) = %v, want [beta]", got)
	}

	beta, _ := set.ByID("beta")
	if beta.Interval() != 24*time.Hour {
		t.Errorf("Interval = %v", beta.Interval())
	}
	if beta.ReconcileInterval() != 48*time.Hour {
		t.Errorf("ReconcileInterval = %v", beta.ReconcileInterval())
	}
	if beta.BaselineInterval() != 168*time.Hour {
		t.Errorf("BaselineInterval = %v", beta.BaselineInterval())
	}
	if beta.FreshnessSLO() != 72*time.Hour {
		t.Errorf("FreshnessSLO = %v", beta.FreshnessSLO())
	}
}

func TestDerivedFeedResolves(t *testing.T) {
	doc := baseDoc + `  - id: rider
    auth_mode: none
    sync_mechanism: derived
    derived_from: alpha
    interval_seconds: 0
    freshness_slo_seconds: 3600
    on_failure: serve_stale
    license_tier: 0
    license_spdx: CC0-1.0
    bootstrap_mechanism: none
`
	set := mustParse(t, doc)
	rider, ok := set.ByID("rider")
	if !ok {
		t.Fatal("derived feed missing")
	}
	if rider.DerivedFrom != "alpha" {
		t.Errorf("DerivedFrom = %q", rider.DerivedFrom)
	}
	if rider.URL != "" || rider.BootstrapURL != "" {
		t.Errorf("a derived feed acquired a URL: %q / %q", rider.URL, rider.BootstrapURL)
	}
	if rider.SyncMechanism.Polled() {
		t.Error("a derived feed reports as polled")
	}
}

// ---------------------------------------------------------------------------
// Refusals — A.1's stop condition in its negative direction
// ---------------------------------------------------------------------------

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want []error // every sentinel the error must satisfy
	}{
		{
			name: "missing license_tier",
			doc:  mutate(t, baseDoc, "    license_tier: 0\n", ""),
			want: []error{ErrInvalidDocument, ErrMissingLicenseTier},
		},
		{
			name: "license_tier out of range",
			doc:  mutate(t, baseDoc, "license_tier: 0", "license_tier: 4"),
			want: []error{ErrInvalidDocument, ErrMissingLicenseTier},
		},
		{
			name: "license_tier is not a number",
			doc:  mutate(t, baseDoc, "license_tier: 0", "license_tier: tier0"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "missing interval_seconds",
			doc:  mutate(t, baseDoc, "    interval_seconds: 900\n", ""),
			want: []error{ErrInvalidDocument, ErrMissingInterval},
		},
		{
			name: "zero interval on a polled feed",
			doc:  mutate(t, baseDoc, "interval_seconds: 900", "interval_seconds: 0"),
			want: []error{ErrInvalidDocument, ErrMissingInterval},
		},
		{
			name: "interval on a feed that is not polled",
			doc: mutate(t, baseDoc,
				"sync_mechanism: conditional_get_etag", "sync_mechanism: none"),
			want: []error{ErrInvalidDocument, ErrMissingInterval},
		},
		{
			name: "no licence stated",
			doc:  mutate(t, baseDoc, "    license_spdx: CC0-1.0\n", ""),
			want: []error{ErrInvalidDocument, ErrMissingLicense},
		},
		{
			name: "licence is not an identifier",
			doc:  mutate(t, baseDoc, "license_spdx: CC0-1.0", "license_spdx: \"probably fine?\""),
			want: []error{ErrInvalidDocument, ErrMissingLicense},
		},
		{
			name: "NOASSERTION without the operative sentence",
			doc:  mutate(t, baseDoc, "license_spdx: CC0-1.0", "license_spdx: NOASSERTION"),
			want: []error{ErrInvalidDocument, ErrMissingLicenseNote},
		},
		{
			name: "LicenseRef without the operative sentence",
			doc:  mutate(t, baseDoc, "license_spdx: CC0-1.0", "license_spdx: LicenseRef-Vendor-ToU"),
			want: []error{ErrInvalidDocument, ErrMissingLicenseNote},
		},
		{
			name: "empty LicenseRef",
			doc: mutate(t, baseDoc, "license_spdx: CC0-1.0",
				"license_spdx: LicenseRef-\n    license_manual_note: \"n/a\""),
			want: []error{ErrInvalidDocument, ErrMissingLicense},
		},
		{
			name: "undeclared licence outside tier 3",
			doc: mutate(t, baseDoc, "license_spdx: CC0-1.0",
				"license_spdx: NONE\n    license_manual_note: \"no licence document exists\""),
			want: []error{ErrInvalidDocument, ErrUndeclaredLicenseTier},
		},
		{
			name: "feed dropped on failure outside tier 3",
			doc:  mutate(t, baseDoc, "on_failure: serve_stale", "on_failure: disable_feed"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "unknown on_failure value",
			doc:  mutate(t, baseDoc, "on_failure: serve_stale", "on_failure: fail_scan"),
			want: []error{ErrInvalidDocument, ErrInvalidEnum},
		},
		{
			name: "unknown auth_mode value",
			doc:  mutate(t, baseDoc, "auth_mode: none", "auth_mode: basic"),
			want: []error{ErrInvalidDocument, ErrInvalidEnum},
		},
		{
			name: "unknown sync_mechanism value",
			doc:  mutate(t, baseDoc, "sync_mechanism: conditional_get_etag", "sync_mechanism: webhook"),
			want: []error{ErrInvalidDocument, ErrInvalidEnum},
		},
		{
			name: "unknown bootstrap_mechanism value",
			doc:  mutate(t, baseDoc, "bootstrap_mechanism: bulk_archive", "bootstrap_mechanism: shallow_clone"),
			want: []error{ErrInvalidDocument, ErrInvalidEnum},
		},
		{
			name: "unknown key",
			doc:  mutate(t, baseDoc, "    on_failure:", "    intervall_seconds: 60\n    on_failure:"),
			want: []error{ErrInvalidDocument, ErrUnknownKey},
		},
		{
			name: "unknown top-level key",
			doc:  "version: 1\nregistry: https://feeds.invalid/\n" + strings.SplitN(baseDoc, "\n", 2)[1],
			want: []error{ErrInvalidDocument, ErrUnknownKey},
		},
		{
			name: "duplicate key in one feed",
			doc:  mutate(t, baseDoc, "    on_failure:", "    license_tier: 1\n    on_failure:"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "duplicate feed id",
			doc:  baseDoc + strings.SplitN(baseDoc, "feeds:\n", 2)[1],
			want: []error{ErrInvalidDocument, ErrDuplicateFeedID},
		},
		{
			name: "feed id with upper case",
			doc:  mutate(t, baseDoc, "id: alpha", "id: Alpha"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "no version",
			doc:  strings.TrimPrefix(baseDoc, "version: 1\n"),
			want: []error{ErrInvalidDocument, ErrUnsupportedVersion},
		},
		{
			name: "future version",
			doc:  mutate(t, baseDoc, "version: 1", "version: 2"),
			want: []error{ErrUnsupportedVersion},
		},
		{
			name: "quoted version",
			doc:  mutate(t, baseDoc, "version: 1", `version: "1"`),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "no feeds key",
			doc:  "version: 1\n",
			want: []error{ErrInvalidDocument},
		},
		{
			name: "plaintext transport",
			doc:  mutate(t, baseDoc, "url: https://", "url: http://"),
			want: []error{ErrInvalidDocument, ErrInvalidURL},
		},
		{
			name: "credentials inline in the url",
			doc:  mutate(t, baseDoc, "url: https://feeds.invalid", "url: https://user:hunter2@feeds.invalid"),
			want: []error{ErrInvalidDocument, ErrInvalidURL},
		},
		{
			name: "polled feed with no url",
			doc:  mutate(t, baseDoc, "    url: https://feeds.invalid/alpha.json\n", ""),
			want: []error{ErrInvalidDocument, ErrInvalidURL},
		},
		{
			name: "auth mode with no credential_env",
			doc:  mutate(t, baseDoc, "auth_mode: none", "auth_mode: github_token"),
			want: []error{ErrInvalidDocument, ErrInvalidCredentialRef},
		},
		{
			name: "a token pasted where a variable name belongs",
			doc: mutate(t, baseDoc, "auth_mode: none",
				"auth_mode: github_token\n    credential_env: ghp_examplenotarealtoken"),
			want: []error{ErrInvalidDocument, ErrInvalidCredentialRef},
		},
		{
			name: "credential_env with no auth mode",
			doc:  mutate(t, baseDoc, "auth_mode: none", "auth_mode: none\n    credential_env: ANVIL_TOKEN"),
			want: []error{ErrInvalidDocument, ErrInvalidCredentialRef},
		},
		{
			name: "api key mode with no header named",
			doc: mutate(t, baseDoc, "auth_mode: none",
				"auth_mode: api_key_header\n    credential_env: ANVIL_KEY"),
			want: []error{ErrInvalidDocument, ErrInvalidCredentialRef},
		},
		{
			name: "credential_header without the api key mode",
			doc:  mutate(t, baseDoc, "auth_mode: none", "auth_mode: none\n    credential_header: apiKey"),
			want: []error{ErrInvalidDocument, ErrInvalidCredentialRef},
		},
		{
			name: "freshness SLO shorter than the poll that refreshes it",
			doc:  mutate(t, baseDoc, "freshness_slo_seconds: 3600", "freshness_slo_seconds: 60"),
			want: []error{ErrInvalidDocument, ErrInconsistentSchedule},
		},
		{
			name: "no freshness SLO",
			doc:  mutate(t, baseDoc, "    freshness_slo_seconds: 3600\n", ""),
			want: []error{ErrInvalidDocument, ErrInconsistentSchedule},
		},
		{
			name: "reconciliation more frequent than the steady-state poll",
			doc: mutate(t, baseDoc, "    on_failure:",
				"    reconcile_interval_seconds: 60\n    on_failure:"),
			want: []error{ErrInvalidDocument, ErrInconsistentSchedule},
		},
		{
			name: "baseline self-heal with no artifact to re-pull",
			doc: mutate(t, baseDoc,
				"    bootstrap_mechanism: bulk_archive\n",
				"    baseline_interval_seconds: 604800\n    bootstrap_mechanism: incremental_api\n"),
			want: []error{ErrInvalidDocument, ErrInconsistentSchedule},
		},
		{
			name: "bootstrap_url on a mechanism that fetches nothing",
			doc: mutate(t, baseDoc, "    bootstrap_mechanism: bulk_archive\n",
				"    bootstrap_url: https://feeds.invalid/a.zip\n    bootstrap_mechanism: incremental_api\n"),
			want: []error{ErrInvalidDocument, ErrInvalidURL},
		},
		{
			name: "git fetch without a clone to fetch into",
			doc:  mutate(t, baseDoc, "sync_mechanism: conditional_get_etag", "sync_mechanism: git_blobless_fetch"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "clone without the git fetch that maintains it",
			doc:  mutate(t, baseDoc, "bootstrap_mechanism: bulk_archive", "bootstrap_mechanism: blobless_clone"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "neither polled nor bootstrapped",
			doc: mutate(t, baseDoc,
				"sync_mechanism: conditional_get_etag", "sync_mechanism: none",
				"interval_seconds: 900", "interval_seconds: 0",
				"bootstrap_mechanism: bulk_archive", "bootstrap_mechanism: none"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "derived with no parent named",
			doc: mutate(t, baseDoc,
				"sync_mechanism: conditional_get_etag", "sync_mechanism: derived",
				"interval_seconds: 900", "interval_seconds: 0",
				"    url: https://feeds.invalid/alpha.json\n", "",
				"bootstrap_mechanism: bulk_archive", "bootstrap_mechanism: none"),
			want: []error{ErrInvalidDocument, ErrUnresolvedReference},
		},
		{
			name: "derived from a feed that is not in the document",
			doc: mutate(t, baseDoc,
				"sync_mechanism: conditional_get_etag", "sync_mechanism: derived\n    derived_from: nowhere",
				"interval_seconds: 900", "interval_seconds: 0",
				"    url: https://feeds.invalid/alpha.json\n", "",
				"bootstrap_mechanism: bulk_archive", "bootstrap_mechanism: none"),
			want: []error{ErrInvalidDocument, ErrUnresolvedReference},
		},
		{
			name: "derived_from on a feed that is polled",
			doc:  mutate(t, baseDoc, "    on_failure:", "    derived_from: alpha\n    on_failure:"),
			want: []error{ErrInvalidDocument, ErrUnresolvedReference},
		},
		{
			name: "derived feed keeping a url of its own",
			doc: mutate(t, baseDoc,
				"sync_mechanism: conditional_get_etag", "sync_mechanism: derived\n    derived_from: beta",
				"interval_seconds: 900", "interval_seconds: 0",
				"bootstrap_mechanism: bulk_archive", "bootstrap_mechanism: none"),
			want: []error{ErrInvalidDocument, ErrInvalidURL},
		},
		{
			name: "empty feeds sequence",
			doc:  "version: 1\nfeeds:\n  - \n",
			want: []error{ErrInvalidDocument},
		},
		{
			name: "feed that is a scalar, not a mapping",
			doc:  "version: 1\nfeeds:\n  - alpha\n",
			want: []error{ErrInvalidDocument},
		},
		{
			name: "tab indentation",
			doc:  strings.Replace(baseDoc, "  - id: alpha", "\t- id: alpha", 1),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "flow collection",
			doc:  mutate(t, baseDoc, "license_spdx: CC0-1.0", "license_spdx: [CC0-1.0]"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "block scalar",
			doc:  mutate(t, baseDoc, "license_spdx: CC0-1.0", "license_spdx: |\n      CC0-1.0"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "anchor",
			doc:  mutate(t, baseDoc, "license_spdx: CC0-1.0", "license_spdx: &l CC0-1.0"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "multi-document stream",
			doc:  baseDoc + "---\n" + baseDoc,
			want: []error{ErrInvalidDocument},
		},
		{
			name: "quoted number where a number belongs",
			doc:  mutate(t, baseDoc, "interval_seconds: 900", `interval_seconds: "900"`),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "quoted boolean where a boolean belongs",
			doc:  mutate(t, baseDoc, "    auth_mode:", "    enabled: \"false\"\n    auth_mode:"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "non-boolean enabled",
			doc:  mutate(t, baseDoc, "    auth_mode:", "    enabled: yes\n    auth_mode:"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "key with no value",
			doc:  mutate(t, baseDoc, "license_spdx: CC0-1.0", "license_spdx:"),
			want: []error{ErrInvalidDocument},
		},
		{
			name: "empty document",
			doc:  "\n# only a comment\n",
			want: []error{ErrInvalidDocument},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := Parse([]byte(tc.doc))
			if err == nil {
				t.Fatalf("Parse accepted a document it must refuse; got %+v", set)
			}
			for _, want := range tc.want {
				if !errors.Is(err, want) {
					t.Errorf("error %q does not satisfy errors.Is(%v)", err, want)
				}
			}
		})
	}
}

func TestParseAcceptsTier0Explicitly(t *testing.T) {
	// license_tier 0 is a legal tier and must not read as "absent". This is
	// the reason the binder tracks presence rather than trusting the zero
	// value, and it is the difference between a Tier 0 feed loading and a
	// Tier 0 feed being rejected as unlicensed.
	set := mustParse(t, baseDoc)
	if set.Feeds[0].LicenseTier != LicenseTier0 {
		t.Errorf("license_tier = %d, want 0", set.Feeds[0].LicenseTier.Int())
	}
}

func TestSelfDerivedFeedRefused(t *testing.T) {
	doc := `version: 1
feeds:
  - id: loop
    auth_mode: none
    sync_mechanism: derived
    derived_from: loop
    interval_seconds: 0
    freshness_slo_seconds: 3600
    on_failure: serve_stale
    license_tier: 0
    license_spdx: CC0-1.0
    bootstrap_mechanism: none
`
	if _, err := Parse([]byte(doc)); !errors.Is(err, ErrUnresolvedReference) {
		t.Fatalf("Parse accepted a self-derived feed: %v", err)
	}
}

func TestChainedDerivationRefused(t *testing.T) {
	doc := baseDoc + `  - id: rider
    auth_mode: none
    sync_mechanism: derived
    derived_from: alpha
    interval_seconds: 0
    freshness_slo_seconds: 3600
    on_failure: serve_stale
    license_tier: 0
    license_spdx: CC0-1.0
    bootstrap_mechanism: none
  - id: pillion
    auth_mode: none
    sync_mechanism: derived
    derived_from: rider
    interval_seconds: 0
    freshness_slo_seconds: 3600
    on_failure: serve_stale
    license_tier: 0
    license_spdx: CC0-1.0
    bootstrap_mechanism: none
`
	if _, err := Parse([]byte(doc)); !errors.Is(err, ErrUnresolvedReference) {
		t.Fatalf("Parse accepted a feed derived from a derived feed: %v", err)
	}
}

func TestTooManyFeeds(t *testing.T) {
	var b strings.Builder
	b.WriteString("version: 1\nfeeds:\n")
	for i := 0; i <= MaxFeeds; i++ {
		b.WriteString("  - id: f")
		b.WriteString(strconv.Itoa(i))
		b.WriteString("\n    url: https://feeds.invalid/f.json\n" +
			"    auth_mode: none\n    sync_mechanism: conditional_get_etag\n" +
			"    interval_seconds: 900\n    freshness_slo_seconds: 3600\n" +
			"    on_failure: serve_stale\n    license_tier: 0\n" +
			"    license_spdx: CC0-1.0\n    bootstrap_mechanism: bulk_archive\n")
	}
	if _, err := Parse([]byte(b.String())); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("Parse accepted more than %d feeds: %v", MaxFeeds, err)
	}
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), DefaultFileName))
	if err == nil {
		t.Fatal("Load succeeded on a file that does not exist")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error %q does not satisfy errors.Is(os.ErrNotExist)", err)
	}
}

func TestLoadNamesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	if err := os.WriteFile(path, []byte(mutate(t, baseDoc, "version: 1", "version: 9")), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted an unsupported version")
	}
	if !strings.Contains(err.Error(), DefaultFileName) {
		t.Errorf("error %q does not name the offending file", err)
	}
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("error %q does not satisfy errors.Is(ErrUnsupportedVersion)", err)
	}
}

func TestLoadOversizeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	blob := strings.Repeat("# padding\n", (MaxDocumentBytes/10)+16)
	if err := os.WriteFile(path, []byte(blob), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("Load accepted an oversize file: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The constraint, asserted against the source
// ---------------------------------------------------------------------------

// TestNoFeedDataInSource is the mechanical form of A.1's Forbidden actions:
// "No feed URL, cadence, or credential literal anywhere outside
// feeds.yaml/feeds.example.yaml." It parses feeds.go and walks its literals.
//
// It works on the AST, not on the text, so prose in a comment naming a feed is
// not a violation — a BRANCH on a feed identity is, and that needs a literal.
func TestNoFeedDataInSource(t *testing.T) {
	set := loadExample(t)

	feedIDs := map[string]bool{}
	hosts := map[string]bool{}
	cadences := map[int]string{}
	for _, f := range set.Feeds {
		feedIDs[f.ID] = true
		for _, raw := range []string{f.URL, f.BootstrapURL} {
			if raw == "" {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("feed %q: %v", f.ID, err)
			}
			hosts[u.Hostname()] = true
		}
		for _, c := range []struct {
			v    int
			what string
		}{
			{f.IntervalSeconds, "interval_seconds"},
			{f.ReconcileIntervalSeconds, "reconcile_interval_seconds"},
			{f.BaselineIntervalSeconds, "baseline_interval_seconds"},
			{f.FreshnessSLOSeconds, "freshness_slo_seconds"},
		} {
			if c.v > 0 {
				cadences[c.v] = f.ID + "." + c.what
			}
		}
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "feeds.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing feeds.go: %v", err)
	}

	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok {
			return true
		}
		pos := fset.Position(lit.Pos())
		switch lit.Kind {
		case token.STRING:
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if strings.Contains(s, "://") {
				t.Errorf("%s: feeds.go contains a URL literal %q; feed URLs live in %s",
					pos, s, ExampleFileName)
			}
			if feedIDs[s] {
				t.Errorf("%s: feeds.go contains the feed id %q; a branch on feed identity is a hard-coded feed table",
					pos, s)
			}
			for host := range hosts {
				if strings.Contains(s, host) {
					t.Errorf("%s: feeds.go contains the feed host %q", pos, host)
				}
			}
		case token.INT:
			v, err := strconv.Atoi(lit.Value)
			if err != nil {
				return true
			}
			if what, ok := cadences[v]; ok {
				t.Errorf("%s: feeds.go contains the integer %d, which is %s; every cadence lives in %s",
					pos, v, what, ExampleFileName)
			}
		}
		return true
	})
}

// TestPackageMakesNoNetworkCalls asserts A.1's other Forbidden action —
// "Do not fetch any network resource from this step — config loading only" —
// at the import graph, where it cannot be violated by accident. net/url is
// allowed: it parses, it does not dial.
func TestPackageMakesNoNetworkCalls(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "feeds.go", nil, parser.SkipObjectResolution|parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing feeds.go: %v", err)
	}
	banned := map[string]bool{
		`"net"`:          true,
		`"net/http"`:     true,
		`"os/exec"`:      true,
		`"net/rpc"`:      true,
		`"crypto/tls"`:   true,
		`"database/sql"`: true,
	}
	for _, imp := range file.Imports {
		if banned[imp.Path.Value] {
			t.Errorf("feeds.go imports %s; A.1 loads config and fetches nothing", imp.Path.Value)
		}
	}
}

// TestEnumsAreClosed asserts each vocabulary's Values()/Valid() pair agrees
// with itself. The six FROZEN record enums are area 40's and are not
// redeclared here; these four are Lane-A-local ingestion vocabulary with no
// counterpart in internal/record.
func TestEnumsAreClosed(t *testing.T) {
	for _, v := range AuthModeValues() {
		if !v.Valid() {
			t.Errorf("AuthMode %q is in Values but not Valid", v)
		}
	}
	for _, v := range SyncMechanismValues() {
		if !v.Valid() {
			t.Errorf("SyncMechanism %q is in Values but not Valid", v)
		}
	}
	for _, v := range BootstrapMechanismValues() {
		if !v.Valid() {
			t.Errorf("BootstrapMechanism %q is in Values but not Valid", v)
		}
	}
	for _, v := range OnFailureValues() {
		if !v.Valid() {
			t.Errorf("OnFailure %q is in Values but not Valid", v)
		}
	}
	for _, v := range LicenseTierValues() {
		if !v.Valid() {
			t.Errorf("LicenseTier %d is in Values but not Valid", v.Int())
		}
	}
	if AuthMode("").Valid() || SyncMechanism("").Valid() ||
		BootstrapMechanism("").Valid() || OnFailure("").Valid() {
		t.Error("an empty value passed a closed vocabulary")
	}
	if LicenseTier(-1).Valid() || LicenseTier(4).Valid() {
		t.Error("a tier outside {0,1,2,3} passed")
	}
	// research/06 Risk #5: feed outage must never fail the scan, so no
	// vocabulary value may offer it.
	for _, v := range OnFailureValues() {
		if strings.Contains(string(v), "fail") {
			t.Errorf("OnFailure offers %q; research/06 Risk #5 says never fail the scan on feed outage", v)
		}
	}
}

// ---------------------------------------------------------------------------
// A.6 M4 — the vocabulary this package owns and A.4 consumes
// ---------------------------------------------------------------------------
//
// A.6 found TWO produce/consume breaks between A.1 and A.4 on the same values:
// the feed-id character rules and the recognition of the NONE token. Each was
// answered independently in both packages, and each pair of answers disagreed.
// The tests below pin this package's half; internal/ingest/license's
// gate_test.go pins the other half against the SAME exported functions, so
// there is one definition and two call sites rather than two definitions.

// TestValidFeedIDIsThePathSegmentRuleToo covers the tightening a shared rule
// forced. MirrorDir defaults to the feed id and therefore becomes a directory
// under mirror/, so `.` and `..` had to stop being legal feed ids: the loader
// used to accept both, and only A.4's separate (and otherwise incompatible)
// rule caught them.
func TestValidFeedIDIsThePathSegmentRuleToo(t *testing.T) {
	valid := []string{"alpha", "cisa-kev", "osv.dev", "a1", "cvelistv5"}
	for _, id := range valid {
		if !ValidFeedID(id) {
			t.Errorf("ValidFeedID(%q) = false", id)
		}
		if !ValidPathSegment(id) {
			t.Errorf("ValidPathSegment(%q) = false; the segment rule must be a SUPERSET of the "+
				"id rule, because mirror_dir defaults to the id", id)
		}
	}
	invalid := []string{"", ".", "..", "...", "-lead", "trail-", "a--b", ".hidden", "hidden.",
		"Alpha", "a/b", `a\b`, "a b", "a_b"}
	for _, id := range invalid {
		if ValidFeedID(id) {
			t.Errorf("ValidFeedID(%q) = true", id)
		}
	}
	for _, seg := range []string{"", ".", "..", "a/b", `a\b`, "Ubuntu", "-x", "x-", ".x"} {
		if ValidPathSegment(seg) {
			t.Errorf("ValidPathSegment(%q) = true; a quarantine a path segment can walk out of "+
				"is not a quarantine", seg)
		}
	}
	// '_' is the one thing the segment rule adds.
	if !ValidPathSegment("a_b") || ValidFeedID("a_b") {
		t.Error("ValidPathSegment must accept '_' and ValidFeedID must not")
	}
}

// TestDottedFeedIDLoads is the direct regression: this loader has always
// accepted dots in a feed id, and A.4 used to refuse them, so a feed the
// operator could configure could not have its licence gated.
func TestDottedFeedIDLoads(t *testing.T) {
	set := mustParse(t, mutate(t, baseDoc, "id: alpha", "id: osv.dev"))
	if set.Feeds[0].ID != "osv.dev" {
		t.Fatalf("id = %q", set.Feeds[0].ID)
	}
	if set.Feeds[0].MirrorDir != "osv.dev" {
		t.Errorf("mirror_dir = %q, want the id", set.Feeds[0].MirrorDir)
	}
}

// TestLicenceTokensAreCaseFolded is the second break. This loader compared the
// NONE token with `==` while A.4's gate compared with strings.EqualFold, so
// `license_spdx: none` loaded clean at tier 0 here and was refused as an
// undeclared licence there. Both now call SPDXIsNone.
func TestLicenceTokensAreCaseFolded(t *testing.T) {
	for _, tok := range []string{"NONE", "none", "None"} {
		if !SPDXIsNone(tok) {
			t.Errorf("SPDXIsNone(%q) = false", tok)
		}
		// NONE at a mirrored tier must be refused however it is spelled.
		_, err := Parse([]byte(mutate(t, baseDoc, "license_spdx: CC0-1.0",
			"license_spdx: "+tok+"\n    license_manual_note: \"no grant exists\"")))
		if !errors.Is(err, ErrUndeclaredLicenseTier) {
			t.Errorf("license_spdx %q at tier 0 = %v, want ErrUndeclaredLicenseTier", tok, err)
		}
	}
	for _, tok := range []string{"NOASSERTION", "noassertion", "LicenseRef-x", "licenseref-x"} {
		if SPDXResolvable(tok) {
			t.Errorf("SPDXResolvable(%q) = true", tok)
		}
		if !SPDXNeedsManualNote(tok) {
			t.Errorf("SPDXNeedsManualNote(%q) = false", tok)
		}
		// ...and the note is demanded however it is spelled.
		_, err := Parse([]byte(mutate(t, baseDoc, "license_spdx: CC0-1.0", "license_spdx: "+tok)))
		if !errors.Is(err, ErrMissingLicenseNote) {
			t.Errorf("license_spdx %q with no note = %v, want ErrMissingLicenseNote", tok, err)
		}
	}
	if !SPDXResolvable("CC-BY-4.0") || SPDXNeedsManualNote("CC-BY-4.0") {
		t.Error("a real identifier must resolve and must not demand the S8 note")
	}
}

// ---------------------------------------------------------------------------
// A.6 B2 — mirror_dir, without which tier 2 has no production caller
// ---------------------------------------------------------------------------

// TestMirrorDirDefaultsToTheFeedID pins the resolution. Parse resolves the
// default so that no consumer re-derives it — the same rule BootstrapURL
// follows, and for the same reason.
func TestMirrorDirDefaultsToTheFeedID(t *testing.T) {
	set := mustParse(t, baseDoc)
	if got := set.Feeds[0].MirrorDir; got != "alpha" {
		t.Errorf("mirror_dir = %q, want the feed id", got)
	}

	set = mustParse(t, mutate(t, baseDoc, "license_tier: 0", "license_tier: 0\n    mirror_dir: elsewhere"))
	if got := set.Feeds[0].MirrorDir; got != "elsewhere" {
		t.Errorf("mirror_dir = %q, want the declared value", got)
	}
}

func TestMirrorDirMustBeOneSafePathSegment(t *testing.T) {
	for _, bad := range []string{"../etc", "a/b", `a\b`, "..", ".", "Ubuntu", "-x"} {
		doc := mutate(t, baseDoc, "license_tier: 0", "license_tier: 0\n    mirror_dir: \""+bad+"\"")
		if _, err := Parse([]byte(doc)); !errors.Is(err, ErrInvalidDocument) {
			t.Errorf("mirror_dir %q = %v, want a refusal; the value becomes a directory under "+
				"mirror/ and a licence gate pointed at ../../LICENSE reads the wrong body", bad, err)
		}
	}
}

// TestExampleTableGivesEveryTier2RowItsQuarantineDirectory is B2 at the level
// that matters: the three share-alike rows have ids that differ from their
// quarantine directories, and before mirror_dir existed the mapping lived
// nowhere a production caller could reach.
func TestExampleTableGivesEveryTier2RowItsQuarantineDirectory(t *testing.T) {
	set, err := Load(ExampleFileName)
	if err != nil {
		t.Fatalf("loading %s: %v", ExampleFileName, err)
	}
	want := map[string]string{"ubuntu-osv": "ubuntu", "alpine-secdb": "alpine", "osv-merged": "osv"}
	seen := 0
	for _, f := range set.Feeds {
		if f.LicenseTier != LicenseTier2 {
			continue
		}
		seen++
		w, ok := want[f.ID]
		if !ok {
			t.Errorf("unexpected tier 2 feed %q; give it a mirror_dir and add it here", f.ID)
			continue
		}
		if f.MirrorDir != w {
			t.Errorf("feed %q: mirror_dir = %q, want %q", f.ID, f.MirrorDir, w)
		}
		if f.MirrorDir == f.ID {
			t.Errorf("feed %q: the directory equals the id, so this assertion proves nothing", f.ID)
		}
	}
	if seen != len(want) {
		t.Errorf("found %d tier 2 rows, want %d", seen, len(want))
	}
}
