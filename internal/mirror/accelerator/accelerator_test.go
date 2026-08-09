package accelerator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
)

// ===========================================================================
// NO TEST IN THIS FILE TOUCHES THE NETWORK.
//
// Every server is an httptest server on loopback. DefaultConfig() is disabled,
// so no test can accidentally reach ghcr.io or grype.anchore.io by forgetting
// to override an endpoint: a test that forgets pulls nothing at all, which
// fails loudly rather than silently succeeding against the real internet.
//
// EVERY SERVER IS httptest.NewTLSServer, NOT NewServer. The package is https
// only, with no loopback exception, so a cleartext test server would not be
// testable against it — and that is the right way round. A loopback exception
// would be a hole an operator could configure into; a TLS loopback server is
// still loopback, still offline, and exercises the code the operator runs.
// ===========================================================================

const fakeToken = "ghp_FAKE_TOKEN_NEVER_A_REAL_CREDENTIAL_0123456789"

// testCacheDir builds a cache root with the layout the guard requires, rooted
// in a temp directory. The "internal/mirror/..." prefix is not decoration: it
// is the case that proves the guard distinguishes the accelerator's own
// directory (which contains a component named "mirror") from the licence mirror.
func testCacheDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "internal", "mirror", "accelerator", ".cache")
}

// ---------------------------------------------------------------------------
// A mock OCI registry
// ---------------------------------------------------------------------------

type mockRegistry struct {
	t          *testing.T
	repo       string
	blob       []byte
	digest     string
	layerType  string
	manifest   []byte // when non-nil, served verbatim instead of the generated one
	requireTok bool
	blobStatus int
	retryAfter string

	// realmOverride makes the mock challenge with a token realm on a host of
	// its own choosing, which is the whole of the credential-exfiltration
	// attack: the WWW-Authenticate header is written by the registry.
	realmOverride string

	server *httptest.Server

	mu        sync.Mutex
	hits      int32
	basicUser string
	basicPass string
	sawBasic  bool
}

func newMockRegistry(t *testing.T, repo string, blob []byte) *mockRegistry {
	t.Helper()
	sum := sha256.Sum256(blob)
	m := &mockRegistry{
		t:         t,
		repo:      repo,
		blob:      blob,
		digest:    "sha256:" + hex.EncodeToString(sum[:]),
		layerType: trivyDBLayerMediaType,
	}
	m.server = httptest.NewTLSServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

// realm is the token realm the mock advertises: its own, unless a test is
// playing the malicious registry.
func (m *mockRegistry) realm() string {
	if m.realmOverride != "" {
		return m.realmOverride
	}
	return m.server.URL + "/token"
}

func (m *mockRegistry) handle(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&m.hits, 1)
	switch {
	case r.URL.Path == "/token":
		if u, p, ok := r.BasicAuth(); ok {
			m.mu.Lock()
			m.sawBasic, m.basicUser, m.basicPass = true, u, p
			m.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"issued-registry-token"}`))

	case strings.HasPrefix(r.URL.Path, "/v2/"+m.repo+"/manifests/"):
		if m.requireTok && r.Header.Get("Authorization") != "Bearer issued-registry-token" {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer realm="%s",service="mock-registry",scope="repository:%s:pull"`,
					m.realm(), m.repo))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body := m.manifest
		if body == nil {
			body = []byte(fmt.Sprintf(
				`{"schemaVersion":2,"mediaType":%q,"layers":[{"mediaType":%q,"digest":%q,"size":%d}]}`,
				ociManifestMediaType, m.layerType, m.digest, len(m.blob)))
		}
		w.Header().Set("Content-Type", ociManifestMediaType)
		_, _ = w.Write(body)

	case strings.HasPrefix(r.URL.Path, "/v2/"+m.repo+"/blobs/"):
		if m.blobStatus != 0 {
			if m.retryAfter != "" {
				w.Header().Set("Retry-After", m.retryAfter)
			}
			w.WriteHeader(m.blobStatus)
			return
		}
		_, _ = w.Write(m.blob)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (m *mockRegistry) hitCount() int { return int(atomic.LoadInt32(&m.hits)) }

// trivyOnlyConfig wires a Config at the mock registry with Grype disabled.
func trivyOnlyConfig(reg *mockRegistry, cacheDir string) Config {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.CacheDir = cacheDir
	cfg.HTTPClient = reg.server.Client()
	cfg.Now = func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) }
	cfg.Trivy.RegistryBase = reg.server.URL
	cfg.Trivy.Repository = reg.repo
	cfg.Grype.Enabled = false
	return cfg
}

// ---------------------------------------------------------------------------
// The optionality contract
// ---------------------------------------------------------------------------

// TestDefaultConfigIsDisabledAndPullsNothing is the first line of the
// optionality contract. A fresh clone must not open a socket to a third-party
// registry because a binary started.
func TestDefaultConfigIsDisabledAndPullsNothing(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Enabled {
		t.Fatal("DefaultConfig() is enabled; a fresh clone must pull nothing until an operator says so")
	}
	if err := WarmStart(context.Background()); err != nil {
		t.Fatalf("WarmStart on the default (disabled) config returned %v; it must be a silent no-op", err)
	}
	// The no-op must not have created the default cache directory either.
	// Creating a directory is a side effect, and an optional component that
	// leaves side effects when disabled is not disabled.
	def, err := DefaultCacheDir()
	if err != nil {
		t.Fatalf("DefaultCacheDir: %v", err)
	}
	if _, err := os.Stat(def); err == nil {
		t.Fatalf("disabled WarmStart created %s", def)
	}
}

// TestDefaultCacheDirIsOutsideAnyWorkingTree is blocker B-2's first half.
//
// The write-path guard proves Anvil's code never writes into a licence tier. It
// says nothing whatever about `git add -A`, and a cache root inside a checkout
// stages ~165 MB of an artifact with no stated redistribution terms into a
// public repository. That is redistribution, and it is unrecoverable once
// pushed. So the default root is not merely ignored — it is somewhere git
// cannot be pointed at by accident in the first place.
func TestDefaultCacheDirIsOutsideAnyWorkingTree(t *testing.T) {
	got, err := DefaultCacheDir()
	if err != nil {
		t.Fatalf("DefaultCacheDir: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("DefaultCacheDir() = %q; a relative path is resolved against whatever the working "+
			"directory happens to be, which may be a checkout", got)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("os.UserCacheDir: %v", err)
	}
	if !pathWithin(base, got) {
		t.Fatalf("DefaultCacheDir() = %q, which is not under the OS user cache directory %q", got, base)
	}

	// And it must still be shaped like an accelerator cache, so relocating it
	// out of the tree did not relocate it out of the guard.
	cfg := DefaultConfig()
	if strings.TrimSpace(cfg.CacheDir) != "" {
		t.Fatalf("DefaultConfig().CacheDir = %q; it must be resolved by normalise, not baked in", cfg.CacheDir)
	}
	resolved, err := CacheDir(cfg)
	if err != nil {
		t.Fatalf("CacheDir on the default config: %v", err)
	}
	if !hasPathSuffix(resolved, CacheDirSuffix) {
		t.Fatalf("resolved default cache root %q does not end in %q", resolved, CacheDirSuffix)
	}

	// The repository root must not contain it under any spelling.
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if pathWithin(repoRoot, got) {
		t.Fatalf("DefaultCacheDir() = %q is inside the repository at %q", got, repoRoot)
	}
}

// TestTheCacheDirectoryCannotBeCommitted is blocker B-2's second half, and it
// exists because a .gitignore with no test is a line somebody deletes in a
// merge. The two protections are independent — moving the location does not
// imply the ignore rule and the ignore rule does not imply the location — so
// both are asserted.
func TestTheCacheDirectoryCannotBeCommitted(t *testing.T) {
	local, err := os.ReadFile(".gitignore")
	if err != nil {
		t.Fatalf("internal/mirror/accelerator/.gitignore is missing (%v); the pulled database has no "+
			"stated redistribution terms and committing it would be redistribution", err)
	}
	if !hasIgnoreRule(string(local), ".cache/") {
		t.Fatalf("internal/mirror/accelerator/.gitignore does not ignore .cache/:\n%s", local)
	}

	root, err := os.ReadFile(filepath.Join("..", "..", "..", ".gitignore"))
	if err != nil {
		t.Fatalf("reading the root .gitignore: %v", err)
	}
	if !hasIgnoreRule(string(root), "internal/mirror/accelerator/.cache/") {
		t.Fatalf("the root .gitignore does not ignore internal/mirror/accelerator/.cache/; the local " +
			"rule and the root rule fail independently, so both must exist")
	}
}

// hasIgnoreRule reports whether a .gitignore body carries a rule, ignoring
// comments and surrounding whitespace. It does not implement gitignore
// matching — it checks that the LINE is there, which is the thing a merge
// deletes.
func hasIgnoreRule(body, rule string) bool {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.TrimSuffix(line, "/") == strings.TrimSuffix(rule, "/") {
			return true
		}
	}
	return false
}

// TestWarmStartFailureIsNotFatalAndLeavesNoPartialArtifact records the second
// half of the contract: every failure is advisory, and a failed warm start
// leaves no half-written database that a later run would treat as warm.
func TestWarmStartFailureIsNotFatalAndLeavesNoPartialArtifact(t *testing.T) {
	reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("trivy-db-bytes"))
	reg.blobStatus = http.StatusTooManyRequests
	reg.retryAfter = "3600"
	dir := testCacheDir(t)

	err := WarmStartWith(context.Background(), trivyOnlyConfig(reg, dir))
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	if !errors.Is(err, ErrAccelerator) {
		t.Fatalf("every refusal must satisfy errors.Is(err, ErrAccelerator); got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "trivy-db.tar.gz")); statErr == nil {
		t.Fatal("a failed pull left a database file behind")
	}
	// The caller is entitled to ignore the error entirely; nothing about the
	// on-disk state after a failure may be inconsistent.
	man := readManifestForTest(t, dir)
	if !man.ConsumeOnly {
		t.Fatal("manifest written after a failed pull is not marked consume_only")
	}
	if len(man.Sources) != 0 {
		t.Fatalf("failed pull recorded %d sources", len(man.Sources))
	}
}

// ---------------------------------------------------------------------------
// The OCI pull
// ---------------------------------------------------------------------------

func TestWarmStartPullsTrivyDBFromMockedRegistry(t *testing.T) {
	payload := []byte("this stands in for a ~100MB BoltDB tarball")
	reg := newMockRegistry(t, "aquasecurity/trivy-db", payload)
	reg.requireTok = true
	dir := testCacheDir(t)

	if err := WarmStartWith(context.Background(), trivyOnlyConfig(reg, dir)); err != nil {
		t.Fatalf("WarmStartWith: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "trivy-db.tar.gz"))
	if err != nil {
		t.Fatalf("reading pulled artifact: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatal("pulled artifact does not match the served blob")
	}

	man := readManifestForTest(t, dir)
	if !man.ConsumeOnly {
		t.Fatal("manifest is not marked consume_only")
	}
	if !man.OutsideLicenceMirror {
		t.Fatal("manifest does not record that the cache sits outside the licence mirror")
	}
	if !strings.Contains(man.Redistribution, "CONSUME ONLY") {
		t.Fatalf("manifest redistribution notice is missing: %q", man.Redistribution)
	}
	rec, ok := man.find(SourceTrivyDB)
	if !ok {
		t.Fatal("manifest has no trivy-db record")
	}
	if rec.Digest != reg.digest {
		t.Fatalf("recorded digest %q, served %q", rec.Digest, reg.digest)
	}
	if rec.SchemaVersion != TrivyDBSchemaVersion {
		t.Fatalf("recorded schema %d, want %d", rec.SchemaVersion, TrivyDBSchemaVersion)
	}
	if !rec.ChecksumVerified {
		t.Fatal("trivy record does not claim checksum verification, but the blob digest was checked")
	}
}

// TestManifestRecordsOnlyWhatWasActuallyEstablished covers both manifest
// honesty defects at once, because they are the same defect: a field that
// states more than was checked, in the one file an operator reads months later
// without this source.
func TestManifestRecordsOnlyWhatWasActuallyEstablished(t *testing.T) {
	// (a) schema_version is DERIVED from the reference, not asserted from a
	// constant. Reference is operator-settable and IS recorded faithfully, so
	// a constant beside it produced {"reference":"3","schema_version":2}.
	t.Run("schema is derived from the reference", func(t *testing.T) {
		cases := map[string]int{
			TrivyDBSchemaReference: TrivyDBSchemaVersion,
			"3":                    3,
			// Not a bare schema integer: the schema is unknown, so the field is
			// omitted rather than fabricated. Reading it would mean opening the
			// database, and this package deliberately cannot.
			"sha256:" + strings.Repeat("ab", 32): 0,
			"latest":                             0,
		}
		for ref, want := range cases {
			t.Run(ref, func(t *testing.T) {
				reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
				dir := testCacheDir(t)
				cfg := trivyOnlyConfig(reg, dir)
				cfg.Trivy.Reference = ref
				if err := WarmStartWith(context.Background(), cfg); err != nil {
					t.Fatalf("WarmStartWith: %v", err)
				}
				rec, ok := readManifestForTest(t, dir).find(SourceTrivyDB)
				if !ok {
					t.Fatal("no trivy-db record")
				}
				if rec.Reference != ref {
					t.Fatalf("recorded reference %q, configured %q", rec.Reference, ref)
				}
				if rec.SchemaVersion != want {
					t.Fatalf("reference %q recorded schema_version %d, want %d",
						ref, rec.SchemaVersion, want)
				}
			})
		}

		// And the field must be ABSENT from the JSON, not present as zero: a
		// reader distinguishes "no claim" from "schema 0" only if it is absent.
		reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
		dir := testCacheDir(t)
		cfg := trivyOnlyConfig(reg, dir)
		cfg.Trivy.Reference = "latest"
		if err := WarmStartWith(context.Background(), cfg); err != nil {
			t.Fatalf("WarmStartWith: %v", err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, ManifestFileName))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "schema_version") {
			t.Fatalf("the manifest states a schema_version for a reference that does not determine "+
				"one:\n%s", raw)
		}
	})

	// (b) checksum_verified:true is qualified on disk. It reads as provenance
	// and it is not: the digest came out of the same unauthenticated response
	// as the content that was checked against it.
	t.Run("checksum_verified says what it was verified against", func(t *testing.T) {
		reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
		dir := testCacheDir(t)
		cfg := trivyOnlyConfig(reg, dir)
		cfg.Grype.Enabled = true
		grype := newGrypeServer(t, grypeV6Listing)
		cfg.Grype.ListingURL = grype.URL + "/databases/v6/latest.json"
		if err := WarmStartWith(context.Background(), cfg); err != nil {
			t.Fatalf("WarmStartWith: %v", err)
		}
		man := readManifestForTest(t, dir)
		for _, name := range []string{SourceTrivyDB, SourceGrypeDB} {
			rec, ok := man.find(name)
			if !ok {
				t.Fatalf("no %s record", name)
			}
			if !rec.ChecksumVerified {
				t.Fatalf("%s: checksum not verified", name)
			}
			if rec.VerifiedAgainst == "" {
				t.Fatalf("%s records checksum_verified:true with no verified_against; "+
					"\"digest verified\" reads as provenance and this is transport integrity", name)
			}
			if !strings.Contains(rec.VerifiedAgainst, "TRANSPORT INTEGRITY ONLY") {
				t.Fatalf("%s: verified_against does not say what it is NOT: %q", name, rec.VerifiedAgainst)
			}
		}
	})
}

func TestTrivyBlobDigestMismatchIsRefused(t *testing.T) {
	reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
	// Advertise a digest the blob does not have.
	reg.manifest = []byte(fmt.Sprintf(
		`{"schemaVersion":2,"mediaType":%q,"layers":[{"mediaType":%q,"digest":"sha256:%s","size":7}]}`,
		ociManifestMediaType, trivyDBLayerMediaType, strings.Repeat("ab", 32)))
	dir := testCacheDir(t)

	err := WarmStartWith(context.Background(), trivyOnlyConfig(reg, dir))
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "trivy-db.tar.gz")); statErr == nil {
		t.Fatal("a digest mismatch still wrote the artifact")
	}
}

func TestAmbiguousManifestIsRefusedRatherThanGuessed(t *testing.T) {
	cases := map[string]string{
		"image index": fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"digest":"sha256:aa"}]}`,
			ociIndexMediaType),
		"two unlabelled layers": `{"schemaVersion":2,"layers":[` +
			`{"mediaType":"application/octet-stream","digest":"sha256:aa","size":1},` +
			`{"mediaType":"application/octet-stream","digest":"sha256:bb","size":1}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("x"))
			reg.manifest = []byte(body)
			err := WarmStartWith(context.Background(), trivyOnlyConfig(reg, testCacheDir(t)))
			if !errors.Is(err, ErrRegistry) {
				t.Fatalf("want ErrRegistry, got %v", err)
			}
		})
	}
}

func TestFreshCacheSuppressesTheNextPull(t *testing.T) {
	reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
	dir := testCacheDir(t)
	cfg := trivyOnlyConfig(reg, dir)

	if err := WarmStartWith(context.Background(), cfg); err != nil {
		t.Fatalf("first warm start: %v", err)
	}
	first := reg.hitCount()
	if first == 0 {
		t.Fatal("first warm start made no requests")
	}
	if err := WarmStartWith(context.Background(), cfg); err != nil {
		t.Fatalf("second warm start: %v", err)
	}
	if reg.hitCount() != first {
		t.Fatalf("second warm start made %d extra requests; the publisher's cadence is %v and "+
			"out-pulling it spends a shared rate-limit budget for nothing",
			reg.hitCount()-first, cfg.MinRefreshInterval)
	}

	// Past the interval, it pulls again.
	cfg.Now = func() time.Time { return time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC) }
	if err := WarmStartWith(context.Background(), cfg); err != nil {
		t.Fatalf("third warm start: %v", err)
	}
	if reg.hitCount() == first {
		t.Fatal("a stale cache did not refresh")
	}
}

func TestTamperedManifestIsRefused(t *testing.T) {
	reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
	dir := testCacheDir(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFileName),
		[]byte(`{"consume_only":false,"sources":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := WarmStartWith(context.Background(), trivyOnlyConfig(reg, dir))
	if !errors.Is(err, ErrTamperedManifest) {
		t.Fatalf("want ErrTamperedManifest, got %v", err)
	}
	if reg.hitCount() != 0 {
		t.Fatal("a tampered manifest still triggered a network pull")
	}
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

// TestCredentialIsReadByEnvNameAndNeverPersisted is the credential contract:
// the configuration carries a NAME, the value is read at the moment of use,
// and the value appears in no file this package writes and in no error it
// returns.
func TestCredentialIsReadByEnvNameAndNeverPersisted(t *testing.T) {
	const envName = "ANVIL_TEST_FAKE_REGISTRY_TOKEN"
	t.Setenv(envName, fakeToken)

	reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
	reg.requireTok = true
	dir := testCacheDir(t)
	cfg := trivyOnlyConfig(reg, dir)
	cfg.Trivy.CredentialEnv = envName

	if err := WarmStartWith(context.Background(), cfg); err != nil {
		t.Fatalf("WarmStartWith: %v", err)
	}

	reg.mu.Lock()
	sawBasic, user, pass := reg.sawBasic, reg.basicUser, reg.basicPass
	reg.mu.Unlock()
	if !sawBasic {
		t.Fatal("the token exchange sent no credential even though credential_env was set")
	}
	if user != "x-access-token" || pass != fakeToken {
		t.Fatalf("token exchange sent unexpected credential shape (user=%q)", user)
	}

	// Nothing under the cache root may contain the secret.
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(raw), fakeToken) {
			return fmt.Errorf("credential value written to %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCredentialEnvMustBeANameNotAValue(t *testing.T) {
	reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
	cfg := trivyOnlyConfig(reg, testCacheDir(t))
	cfg.Trivy.CredentialEnv = fakeToken // a pasted secret where a name belongs

	err := WarmStartWith(context.Background(), cfg)
	if !errors.Is(err, ErrBadConfig) {
		t.Fatalf("want ErrBadConfig, got %v", err)
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Fatal("the error message echoed the value that was mistaken for a name")
	}
	if reg.hitCount() != 0 {
		t.Fatal("a rejected credential configuration still made a request")
	}
}

// TestRegistryCannotChooseWhereTheCredentialIsSent is blocker B-3.
//
// The WWW-Authenticate header is written by the thing being talked to. If the
// realm inside it decides where the token exchange goes, then a compromised
// registry, a pull-through cache somebody else operates, a mistyped hostname,
// or anything that can inject that header chooses the destination of an
// ops-provisioned PAT. The old code checked only that the realm parsed and had
// a non-empty host — a syntax note, not a check — and then called SetBasicAuth.
//
// The refusal must be total: no credential AND no request. "Proceed
// anonymously to the attacker's host" is still a request driven by untrusted
// input to a host the configuration never named.
func TestRegistryCannotChooseWhereTheCredentialIsSent(t *testing.T) {
	const envName = "ANVIL_TEST_FAKE_REGISTRY_TOKEN"
	t.Setenv(envName, fakeToken)

	var attackerHits int32
	attacker := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attackerHits, 1)
		if _, _, ok := r.BasicAuth(); ok {
			t.Error("the operator's credential was sent to a host named by the registry")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"attacker-issued"}`))
	}))
	t.Cleanup(attacker.Close)

	reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
	reg.requireTok = true
	reg.realmOverride = attacker.URL + "/token"

	dir := testCacheDir(t)
	cfg := trivyOnlyConfig(reg, dir)
	cfg.Trivy.CredentialEnv = envName

	err := WarmStartWith(context.Background(), cfg)
	if !errors.Is(err, ErrTokenRealmNotAllowed) {
		t.Fatalf("want ErrTokenRealmNotAllowed, got %v", err)
	}
	if n := atomic.LoadInt32(&attackerHits); n != 0 {
		t.Fatalf("the registry-named host received %d request(s); the refusal must happen before "+
			"the request is built, not after the credential is omitted from it", n)
	}
	if strings.Contains(err.Error(), fakeToken) {
		t.Fatal("the refusal echoed the credential")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "trivy-db.tar.gz")); statErr == nil {
		t.Fatal("a refused token exchange still wrote the artifact")
	}
}

// TestATokenRealmOnAnotherHostWorksONLYWhenAllowlisted is the other half: the
// pin must not break the registries that legitimately challenge with a realm
// elsewhere — Docker Hub's registry-1.docker.io answers with auth.docker.io.
// The difference between the two tests is one line of CONFIGURATION, which is
// the whole point: where a credential may be sent is configured, never
// discovered.
func TestATokenRealmOnAnotherHostWorksONLYWhenAllowlisted(t *testing.T) {
	const envName = "ANVIL_TEST_FAKE_REGISTRY_TOKEN"
	t.Setenv(envName, fakeToken)

	var sawUser, sawPass string
	var mu sync.Mutex
	auth := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		mu.Lock()
		sawUser, sawPass = u, p
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"issued-registry-token"}`))
	}))
	t.Cleanup(auth.Close)

	authURL, err := url.Parse(auth.URL)
	if err != nil {
		t.Fatal(err)
	}

	reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
	reg.requireTok = true
	reg.realmOverride = auth.URL + "/token"

	// Without the allowlist entry: refused.
	cfg := trivyOnlyConfig(reg, testCacheDir(t))
	cfg.Trivy.CredentialEnv = envName
	if err := WarmStartWith(context.Background(), cfg); !errors.Is(err, ErrTokenRealmNotAllowed) {
		t.Fatalf("an unlisted auth host was accepted: %v", err)
	}

	// With it: the exchange proceeds and the pull completes. The registry and
	// the auth server share a client, so one httptest CA covers both.
	dir := testCacheDir(t)
	cfg = trivyOnlyConfig(reg, dir)
	cfg.Trivy.CredentialEnv = envName
	cfg.Trivy.TokenHosts = []string{authURL.Host}
	cfg.HTTPClient = auth.Client()
	if err := WarmStartWith(context.Background(), cfg); err != nil {
		t.Fatalf("an allowlisted auth host was still refused: %v", err)
	}
	mu.Lock()
	gotUser, gotPass := sawUser, sawPass
	mu.Unlock()
	if gotUser != "x-access-token" || gotPass != fakeToken {
		t.Fatalf("the allowlisted host did not receive the credential (user=%q)", gotUser)
	}
	if _, err := os.Stat(filepath.Join(dir, "trivy-db.tar.gz")); err != nil {
		t.Fatalf("the pull did not complete through an allowlisted auth host: %v", err)
	}
}

// TestTokenRealmScopeRulesMatchTheRestOfAnvil pins the realm through the same
// scope rule S7 applies everywhere else: https, a host, no inline credentials,
// and the exact host:port that was configured.
func TestTokenRealmScopeRulesMatchTheRestOfAnvil(t *testing.T) {
	reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
	rc, err := newRegistryClient(trivyOnlyConfig(reg, testCacheDir(t)))
	if err != nil {
		t.Fatal(err)
	}
	base := rc.base

	cases := map[string]struct {
		realm string
		want  error
	}{
		"the registry itself": {base.String() + "/token", nil},
		"cleartext downgrade": {"http://" + base.Host + "/token", ErrInsecureTransport},
		"another host":        {"https://evil.example/token", ErrTokenRealmNotAllowed},
		"another port":        {"https://" + base.Hostname() + ":1/token", ErrTokenRealmNotAllowed},
		"inline credentials":  {"https://u:p@" + base.Host + "/token", ErrTokenRealmNotAllowed},
		"not a url":           {"://///", ErrTokenRealmNotAllowed},
		"no host":             {"https:///token", ErrTokenRealmNotAllowed},
		"subdomain lookalike": {"https://" + base.Hostname() + ".evil.example/token", ErrTokenRealmNotAllowed},
		// A scheme-relative realm names another host AND states no scheme.
		// Both are refusals; the scheme check runs first because it is the
		// more fundamental defect, so that is the error it carries.
		"scheme-relative host": {"//evil.example/token", ErrInsecureTransport},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := rc.checkTokenRealm(tc.realm)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("checkTokenRealm(%q) = %v, want accepted", tc.realm, err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("checkTokenRealm(%q) = %v, want %v", tc.realm, err, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

// TestCleartextEndpointsAreRefused closes the gap between ErrBadConfig's doc,
// which has always said this package refuses "an http URL where https is
// required", and the code, which accepted http for both sources.
//
// It matters most in combination with the realm pin: over cleartext, an
// on-path attacker writes the 401 and the realm, and takes the PAT off the
// wire without compromising anything. It also matters on its own, because
// AllowUnverifiedArchiveChecksum is justified entirely by "TLS is the only
// integrity evidence", and over http there is no TLS.
func TestCleartextEndpointsAreRefused(t *testing.T) {
	cases := map[string]func(*Config){
		"trivy registry base": func(c *Config) {
			c.Trivy.Enabled, c.Grype.Enabled = true, false
			c.Trivy.RegistryBase = "http://registry.internal.example"
		},
		"grype listing url": func(c *Config) {
			c.Trivy.Enabled, c.Grype.Enabled = false, true
			c.Grype.ListingURL = "http://grype.example/databases/v6/latest.json"
		},
		"trivy token host": func(c *Config) {
			c.Trivy.Enabled, c.Grype.Enabled = true, false
			c.Trivy.RegistryBase = "https://registry.internal.example"
			c.Trivy.TokenHosts = []string{"http://auth.internal.example"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Enabled = true
			cfg.CacheDir = testCacheDir(t)
			mutate(&cfg)
			err := WarmStartWith(context.Background(), cfg)
			if !errors.Is(err, ErrInsecureTransport) {
				t.Fatalf("want ErrInsecureTransport, got %v", err)
			}
			if !errors.Is(err, ErrAccelerator) {
				t.Fatalf("every refusal must satisfy errors.Is(err, ErrAccelerator); got %v", err)
			}
		})
	}
}

// TestShippedEndpointsAreHTTPS guards the constants, so a future edit cannot
// downgrade the shipped defaults past the rule above.
func TestShippedEndpointsAreHTTPS(t *testing.T) {
	for _, u := range []string{DefaultTrivyRegistry, DefaultGrypeListingURL} {
		if !strings.HasPrefix(u, "https://") {
			t.Errorf("shipped endpoint %q is not https", u)
		}
	}
}

// ---------------------------------------------------------------------------
// THE LICENCE-TIER WRITE GUARD — the reason A.13 exists
// ---------------------------------------------------------------------------

// TestWritePathNeverResolvesIntoTheLicenceTieredMirror is the packet's primary
// evidence item. Every path shape that resolves under mirror/tier{0,1,2,3} must
// be refused, at any root, with any separator.
func TestWritePathNeverResolvesIntoTheLicenceTieredMirror(t *testing.T) {
	tiered := []string{
		"mirror/tier0",
		"mirror/tier0/nvd",
		"mirror/tier1/ghsa",
		"mirror/tier2",
		"mirror/tier2/ubuntu", // CC-BY-SA-4.0 quarantine
		"mirror/tier2/alpine",
		"mirror/tier3/greenbone",
		`mirror\tier2\ubuntu`, // Windows separators must not walk out of the quarantine
		"C:/build/anvil/mirror/tier2/ubuntu",
		"/srv/anvil/mirror/tier0",
		"internal/mirror/accelerator/../../../mirror/tier2/ubuntu",
		"./mirror/tier1/osv/../osv",

		// The shapes that defeated the byte-exact comparison. Windows and
		// macOS resolve all of these to mirror/tier2, so a guard that refuses
		// only the lower-case spelling is not comparing paths — it is
		// comparing strings that happen to look like paths, and the thing it
		// is failing to guard is the share-alike quarantine.
		"MIRROR/TIER2",
		"MIRROR/Tier2/Ubuntu",
		"mirror/Tier2",
		`C:\build\anvil\MIRROR\Tier2\mirror\accelerator\.cache`,
		`C:\BUILD\ANVIL\Mirror\Tier2\Ubuntu`,
		// Win32 strips trailing dots and spaces from a component before the
		// path reaches the filesystem, so these name mirror/tier2 too.
		"mirror/tier2.",
		"mirror./tier2",
		"MIRROR/TIER2./ubuntu",
	}
	for _, p := range tiered {
		if err := guardNotTiered(p); !errors.Is(err, ErrLicenceTierWrite) {
			t.Errorf("guardNotTiered(%q) = %v; the accelerator artifact has no stated "+
				"redistribution terms and must never be written to a licence tier", p, err)
		}
	}

	// And the guard must not be a blunt instrument: the accelerator's own home
	// contains a component literally named "mirror", and that is legal.
	legal := []string{
		"internal/mirror/accelerator/.cache",
		"internal/mirror/accelerator/.cache/trivy-db.tar.gz",
		"C:/build/anvil/internal/mirror/accelerator/.cache",
		"/srv/anvil/internal/mirror/accelerator/.cache/grype-db.tar.zst",
		"mirror/accelerator/.cache",
	}
	for _, p := range legal {
		if err := guardNotTiered(p); err != nil {
			t.Errorf("guardNotTiered(%q) = %v; the accelerator's own directory is not a licence tier", p, err)
		}
	}
}

// TestGuardAgreesWithTheLicenceGate proves the guard is the licence gate's
// inverse rather than a private rule that could drift from it.
func TestGuardAgreesWithTheLicenceGate(t *testing.T) {
	for _, tier := range config.LicenseTierValues() {
		dir := license.TierDir(tier)
		if dir == "" {
			t.Fatalf("license.TierDir(%d) is empty", tier.Int())
		}
		// The licence gate accepts this path for this tier ...
		if err := license.CheckWritePath(tier, dir+"/some-feed"); err != nil {
			t.Fatalf("license.CheckWritePath(%d, %q) = %v", tier.Int(), dir, err)
		}
		// ... and therefore the accelerator must refuse it, in every spelling
		// the filesystem resolves to the same directory. The fold lives in the
		// accelerator because the licence gate is frozen and its byte-exact
		// comparison may be load-bearing for the admission path; this loop is
		// what pins the fold to the gate's own answer rather than to a
		// hard-coded "mirror/tier2".
		for _, spelling := range []string{
			dir + "/some-feed",
			strings.ToUpper(dir) + "/some-feed",
			strings.ToUpper(dir[:1]) + dir[1:] + "/some-feed",
			filepath.FromSlash(dir) + `\some-feed`,
			dir + "./some-feed",
		} {
			if err := guardNotTiered(spelling); !errors.Is(err, ErrLicenceTierWrite) {
				t.Fatalf("guardNotTiered(%q) = %v, want ErrLicenceTierWrite", spelling, err)
			}
		}
	}
}

// TestPathsAreComparedAsPathsNotAsStrings pins the comparison primitives the
// guard is built out of. A component-wise comparison is not a nicety here: a
// string prefix test accepts "/a/bc" for the parent "/a/b", and a string
// suffix test accepts ".../notmirror/accelerator/.cache" for the accelerator
// layout.
func TestPathsAreComparedAsPathsNotAsStrings(t *testing.T) {
	suffix := []struct {
		p, sfx string
		want   bool
	}{
		{"/srv/anvil/internal/mirror/accelerator/.cache", CacheDirSuffix, true},
		{`C:\anvil\internal\mirror\accelerator\.cache`, CacheDirSuffix, true},
		{"/srv/anvil/internal/notmirror/accelerator/.cache", CacheDirSuffix, false},
		{"/srv/mirror/accelerator/.cache/inner", CacheDirSuffix, false},
		{"/srv/anvil/mirror/accelerator", CacheDirSuffix, false},
	}
	for _, c := range suffix {
		if got := hasPathSuffix(c.p, c.sfx); got != c.want {
			t.Errorf("hasPathSuffix(%q, %q) = %v, want %v", c.p, c.sfx, got, c.want)
		}
	}

	within := []struct {
		parent, child string
		want          bool
	}{
		{"/a/b", "/a/b/c", true},
		{"/a/b", "/a/bc", false},
		{"/a/b", "/a/b", false},
		{"/a/b", "/a", false},
		{`C:\a\b`, `C:\a\b\c`, true},
	}
	for _, c := range within {
		if got := pathWithin(c.parent, c.child); got != c.want {
			t.Errorf("pathWithin(%q, %q) = %v, want %v", c.parent, c.child, got, c.want)
		}
	}
}

// TestCacheRootMustBeAnAcceleratorCache is the guard's positive half.
func TestCacheRootMustBeAnAcceleratorCache(t *testing.T) {
	bad := []string{
		filepath.Join(t.TempDir(), "cache"),
		filepath.Join(t.TempDir(), "mirror", "tier2", "ubuntu"),
		filepath.Join(t.TempDir(), "accelerator"),
		"",
	}
	for _, p := range bad {
		cfg := DefaultConfig()
		cfg.Enabled = true
		cfg.CacheDir = p
		if p == "" {
			// An empty CacheDir means DefaultCacheDir, which is legal; the
			// interesting empty case is the guard called directly.
			if _, err := guardCacheRoot(""); !errors.Is(err, ErrBadCacheDir) {
				t.Errorf("guardCacheRoot(%q) = %v, want ErrBadCacheDir", p, err)
			}
			continue
		}
		if _, err := CacheDir(cfg); err == nil {
			t.Errorf("CacheDir accepted %q as an accelerator cache root", p)
		}
	}

	good := testCacheDir(t)
	cfg := DefaultConfig()
	cfg.CacheDir = good
	if _, err := CacheDir(cfg); err != nil {
		t.Fatalf("CacheDir(%q) = %v", good, err)
	}
}

// TestWarmStartIntoTheQuarantineIsRefusedAndWritesNothing runs the whole warm
// start pointed at the share-alike quarantine and proves nothing lands there.
func TestWarmStartIntoTheQuarantineIsRefusedAndWritesNothing(t *testing.T) {
	root := t.TempDir()
	quarantine := filepath.Join(root, "mirror", "tier2", "ubuntu")
	if err := os.MkdirAll(quarantine, 0o755); err != nil {
		t.Fatal(err)
	}
	reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
	cfg := trivyOnlyConfig(reg, quarantine)

	err := WarmStartWith(context.Background(), cfg)
	if !errors.Is(err, ErrLicenceTierWrite) {
		t.Fatalf("want ErrLicenceTierWrite, got %v", err)
	}
	if reg.hitCount() != 0 {
		t.Fatal("a refused cache root still triggered a network pull")
	}
	assertDirEmpty(t, quarantine)
}

// TestWarmStartIntoACaseVariedQuarantineIsRefused is blocker B-1 as an
// end-to-end claim rather than a unit one.
//
// The direct guard call and the full warm start are different tests because
// they failed for different reasons. guardCacheRoot partially masked the case
// hole by resolving symlinks on the deepest EXISTING ancestor, which
// canonicalises the case of components already on disk — but the accelerator
// creates its own tree, so on a first run the components do not exist yet and
// nothing canonicalises them. That is the ordinary case, and it is the one
// that put both the manifest and a ~100 MB untermed database inside
// mirror/tier2 while WarmStartWith returned nil.
func TestWarmStartIntoACaseVariedQuarantineIsRefused(t *testing.T) {
	for _, spelling := range []string{
		filepath.Join("MIRROR", "Tier2", "mirror", "accelerator", ".cache"),
		filepath.Join("Mirror", "TIER2", "mirror", "accelerator", ".cache"),
		filepath.Join("mirror", "Tier2", "ubuntu", "mirror", "accelerator", ".cache"),
	} {
		t.Run(spelling, func(t *testing.T) {
			root := t.TempDir()
			// The lower-case quarantine is the directory that actually exists;
			// on a case-insensitive host the cache root below resolves into it.
			realQuarantine := filepath.Join(root, "mirror", "tier2")
			if err := os.MkdirAll(realQuarantine, 0o755); err != nil {
				t.Fatal(err)
			}

			reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
			cfg := trivyOnlyConfig(reg, filepath.Join(root, spelling))

			if err := WarmStartWith(context.Background(), cfg); !errors.Is(err, ErrLicenceTierWrite) {
				t.Fatalf("want ErrLicenceTierWrite, got %v", err)
			}
			if reg.hitCount() != 0 {
				t.Fatal("a refused cache root still triggered a network pull")
			}
			// Nothing may be reachable under the quarantine by ANY spelling.
			assertNoFilesUnder(t, realQuarantine)
			assertNoFilesUnder(t, filepath.Join(root, "MIRROR"))
			assertNoFilesUnder(t, filepath.Join(root, "Mirror"))
		})
	}
}

// assertNoFilesUnder walks a directory, if it exists, and fails on any file.
// It tolerates a missing directory: "it was never created" is a pass.
func assertNoFilesUnder(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return
	}
	var found []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	if len(found) != 0 {
		t.Fatalf("the warm start wrote %d file(s) reachable under the share-alike quarantine %s: %v",
			len(found), dir, found)
	}
}

// TestAFullWarmStartLeavesEveryTierDirectoryUntouched is the end-to-end form of
// the same claim: run a successful pull inside a tree that HAS a licence
// mirror, then prove every tier directory is still empty and every written file
// is inside the accelerator cache.
func TestAFullWarmStartLeavesEveryTierDirectoryUntouched(t *testing.T) {
	root := t.TempDir()
	for _, tier := range config.LicenseTierValues() {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(license.TierDir(tier))), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cache := filepath.Join(root, "internal", "mirror", "accelerator", ".cache")

	reg := newMockRegistry(t, "aquasecurity/trivy-db", []byte("payload"))
	grype := newGrypeServer(t, grypeV6Listing)
	cfg := trivyOnlyConfig(reg, cache)
	cfg.Grype.Enabled = true
	cfg.Grype.ListingURL = grype.URL + "/databases/v6/latest.json"

	if err := WarmStartWith(context.Background(), cfg); err != nil {
		t.Fatalf("WarmStartWith: %v", err)
	}

	for _, tier := range config.LicenseTierValues() {
		assertDirEmpty(t, filepath.Join(root, filepath.FromSlash(license.TierDir(tier))))
	}
	// Every file written anywhere in the tree must be inside the cache root.
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasPrefix(filepath.Clean(p), filepath.Clean(cache)+string(filepath.Separator)) {
			return fmt.Errorf("file written outside the accelerator cache: %s", p)
		}
		return guardNotTiered(p)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestSymlinkedCacheRootIntoTheQuarantineIsRefused closes the obvious bypass:
// a directory that passes every string check and resolves elsewhere.
//
// THIS TEST USED TO SKIP ON WINDOWS, AND THAT SKIP IS THE FIRST OF THE TWO
// INCIDENTS internal/SKIPPED-CONTROLS.md exists for. os.Symlink needs
// SeCreateSymbolicLinkPrivilege (Developer Mode or an elevated shell), so on an
// ordinary Windows host the whole guard reported SUCCESS while checking
// nothing, and the package still printed ok. A Windows DIRECTORY JUNCTION then
// walked through the quarantine unnoticed.
//
// A junction is the right link to test with, not a substitute for a symlink:
// mklink /J needs NO privilege, so it is the link an unprivileged process on a
// customer's Windows host can actually create, and it is therefore the one the
// guard has to survive. linkInto below creates the strongest link the host
// permits and NEVER skips: a host that can create neither is a host where the
// bypass is impossible, which is a claim that must be proven, not assumed.
func TestSymlinkedCacheRootIntoTheQuarantineIsRefused(t *testing.T) {
	cases := map[string]string{
		// The link resolves straight into the quarantine.
		"direct":       filepath.Join("mirror", "tier2", "ubuntu"),
		"tier root":    filepath.Join("mirror", "tier2"),
		"case varied":  filepath.Join("MIRROR", "Tier2", "ubuntu"),
		"trailing dot": filepath.Join("mirror", "tier2."),
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			quarantine := filepath.Join(root, target)
			if err := os.MkdirAll(quarantine, 0o755); err != nil {
				// NOT a skip. This is the test's own setup, and a setup step
				// that fails is a failure: skipping here would retire the
				// guard for this spelling the day the filesystem changed
				// shape, with a green tick.
				t.Fatalf("creating the quarantine fixture %s failed: %v", target, err)
			}
			linkParent := filepath.Join(root, "internal", "mirror", "accelerator")
			if err := os.MkdirAll(linkParent, 0o755); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(linkParent, ".cache")
			kind := linkInto(t, quarantine, link)
			if _, err := guardCacheRoot(link); !errors.Is(err, ErrLicenceTierWrite) {
				t.Fatalf("a .cache %s into %s was accepted: %v", kind, target, err)
			}
		})
	}
}

// linkInto points link at target using the strongest link primitive the host
// allows, and reports which one it used. It fails rather than skips.
//
// On Windows it prefers a real symlink (Developer Mode) and falls back to a
// directory junction, which any unprivileged user can create with mklink /J.
// Both are reparse points that a path-string check cannot see through, so both
// are bypasses guardCacheRoot must refuse.
func linkInto(t *testing.T, target, link string) string {
	t.Helper()
	symErr := os.Symlink(target, link)
	if symErr == nil {
		return "symlink"
	}
	if runtime.GOOS != "windows" {
		t.Fatalf("creating a symlink %s -> %s: %v", link, target, symErr)
	}
	// mklink is a cmd builtin, so it cannot be exec'd directly.
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Fatalf("this Windows host created neither a symlink (%v) nor a junction (%v: %s). "+
			"Both are reparse points an unprivileged process can aim at the share-alike "+
			"quarantine; if neither can be created here, say so with evidence rather than "+
			"leaving the guard unchecked.", symErr, err, strings.TrimSpace(string(out)))
	}
	return "junction"
}

// TestCacheFileNamesCannotEscapeTheRoot covers the join step.
func TestCacheFileNamesCannotEscapeTheRoot(t *testing.T) {
	root := testCacheDir(t)
	for _, name := range []string{"..", ".", "", "a/b", `a\b`, "../../mirror/tier2/x"} {
		if _, err := cachePath(root, name); err == nil {
			t.Errorf("cachePath accepted %q", name)
		}
	}
	if _, err := cachePath(root, ManifestFileName); err != nil {
		t.Fatalf("cachePath rejected a legal name: %v", err)
	}
}

func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("%s is not empty: %v", dir, names)
	}
}

// ---------------------------------------------------------------------------
// The Grype schema gate
// ---------------------------------------------------------------------------

var grypeArchiveBytes = []byte("this stands in for a ~65MB zstd tarball")

func grypeV6Listing(base string, archive []byte) string {
	sum := sha256.Sum256(archive)
	return fmt.Sprintf(
		`{"status":"active","schemaVersion":"v6.0.0","built":"2026-08-09T00:00:00Z",`+
			`"path":"vulnerability-db_v6.0.0_2026-08-09.tar.zst","checksum":"sha256:%s"}`,
		hex.EncodeToString(sum[:]))
}

// newGrypeServer serves a listing and the archive it names, on one host.
func newGrypeServer(t *testing.T, listing func(base string, archive []byte) string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".json") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(listing(srv.URL, grypeArchiveBytes)))
			return
		}
		_, _ = w.Write(grypeArchiveBytes)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func grypeOnlyConfig(srv *httptest.Server, cacheDir string) Config {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.CacheDir = cacheDir
	cfg.HTTPClient = srv.Client()
	cfg.Now = func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) }
	cfg.Trivy.Enabled = false
	cfg.Grype.ListingURL = srv.URL + "/databases/v6/latest.json"
	return cfg
}

// TestGrypeSchemaV5IsRejected is the packet's second evidence item. Both the v5
// listing shape and an explicit v5 schema string must be refused, because a v5
// database no longer receives updates and answers CLEAN for everything
// published since 2026-03-06.
func TestGrypeSchemaV5IsRejected(t *testing.T) {
	cases := map[string]struct {
		listing func(string, []byte) string
		want    error
	}{
		"explicit schema v5 string": {
			listing: func(base string, a []byte) string {
				return `{"status":"active","schemaVersion":"v5.0.5","path":"db.tar.gz","checksum":"sha256:00"}`
			},
			want: ErrSchemaTooOld,
		},
		"numeric schema 5": {
			listing: func(base string, a []byte) string {
				return `{"schemaVersion":5,"path":"db.tar.gz","checksum":"sha256:00"}`
			},
			want: ErrSchemaTooOld,
		},
		"legacy v5 listing.json shape": {
			listing: func(base string, a []byte) string {
				return `{"available":{"5":[{"built":"2026-01-01T00:00:00Z","url":"db.tar.gz"}]}}`
			},
			want: ErrSchemaTooOld,
		},
		"schema object model 5": {
			listing: func(base string, a []byte) string {
				return `{"schemaVersion":{"model":5,"revision":0},"path":"db.tar.gz"}`
			},
			want: ErrSchemaTooOld,
		},
		"no schema stated at all": {
			listing: func(base string, a []byte) string {
				return `{"status":"active","path":"db.tar.gz","checksum":"sha256:00"}`
			},
			want: ErrSchemaUnknown,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newGrypeServer(t, tc.listing)
			dir := testCacheDir(t)
			err := WarmStartWith(context.Background(), grypeOnlyConfig(srv, dir))
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "grype-db.tar.zst")); statErr == nil {
				t.Fatal("an end-of-life schema still wrote a database")
			}
		})
	}
}

func TestGrypeSchemaV6IsAccepted(t *testing.T) {
	srv := newGrypeServer(t, grypeV6Listing)
	dir := testCacheDir(t)
	if err := WarmStartWith(context.Background(), grypeOnlyConfig(srv, dir)); err != nil {
		t.Fatalf("WarmStartWith: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "grype-db.tar.zst"))
	if err != nil {
		t.Fatalf("reading pulled archive: %v", err)
	}
	if string(got) != string(grypeArchiveBytes) {
		t.Fatal("pulled archive does not match the served bytes")
	}
	rec, ok := readManifestForTest(t, dir).find(SourceGrypeDB)
	if !ok {
		t.Fatal("manifest has no grype-db record")
	}
	if rec.SchemaVersion < MinGrypeDBSchemaMajor {
		t.Fatalf("recorded schema %d", rec.SchemaVersion)
	}
	if !rec.ChecksumVerified || rec.ChecksumAlgorithm != "sha256" {
		t.Fatalf("checksum verification not recorded: %+v", rec)
	}
	if rec.ClientPin != GrypeClientVersionPin {
		t.Fatalf("client pin not recorded: %q", rec.ClientPin)
	}
}

func TestGrypeArchiveChecksumIsEnforced(t *testing.T) {
	wrong := func(base string, a []byte) string {
		return fmt.Sprintf(`{"schemaVersion":"v6.0.0","path":"db.tar.zst","checksum":"sha256:%s"}`,
			strings.Repeat("ab", 32))
	}
	srv := newGrypeServer(t, wrong)
	err := WarmStartWith(context.Background(), grypeOnlyConfig(srv, testCacheDir(t)))
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
}

func TestGrypeUnverifiableChecksumIsRefusedUnlessOptedIn(t *testing.T) {
	xxh := func(base string, a []byte) string {
		return `{"schemaVersion":"v6.0.0","path":"db.tar.zst","checksum":"xxh64:0011223344556677"}`
	}
	srv := newGrypeServer(t, xxh)

	err := WarmStartWith(context.Background(), grypeOnlyConfig(srv, testCacheDir(t)))
	if !errors.Is(err, ErrUnverifiableChecksum) {
		t.Fatalf("want ErrUnverifiableChecksum, got %v", err)
	}

	dir := testCacheDir(t)
	cfg := grypeOnlyConfig(srv, dir)
	cfg.Grype.AllowUnverifiedArchiveChecksum = true
	if err := WarmStartWith(context.Background(), cfg); err != nil {
		t.Fatalf("explicit opt-in still refused: %v", err)
	}
	rec, _ := readManifestForTest(t, dir).find(SourceGrypeDB)
	if rec.ChecksumVerified {
		t.Fatal("an unverified archive was recorded as verified; the opt-out must be visible on disk")
	}
	if rec.ChecksumAlgorithm != "xxh64" {
		t.Fatalf("manifest does not record which algorithm went unverified: %q", rec.ChecksumAlgorithm)
	}
}

// TestGrypeListingCannotRedirectTheDownloadToAnotherHost — the listing is
// third-party content, and spine S7 forbids following it across hosts.
func TestGrypeListingCannotRedirectTheDownloadToAnotherHost(t *testing.T) {
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the archive was fetched from a host the listing named")
	}))
	t.Cleanup(elsewhere.Close)

	srv := newGrypeServer(t, func(base string, a []byte) string {
		return fmt.Sprintf(`{"schemaVersion":"v6.0.0","url":%q,"checksum":"sha256:00"}`,
			elsewhere.URL+"/db.tar.zst")
	})
	err := WarmStartWith(context.Background(), grypeOnlyConfig(srv, testCacheDir(t)))
	if !errors.Is(err, ErrRegistry) {
		t.Fatalf("want ErrRegistry, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// The client version pin
// ---------------------------------------------------------------------------

// TestClientPinCannotBeLoweredQuietly guards the constants themselves. Anchore
// retired schema v5 on 2026-03-06; a client below v0.88.0 silently stops
// receiving updates, and "silently" is the whole problem.
func TestClientPinCannotBeLoweredQuietly(t *testing.T) {
	if err := CheckClientPins(); err != nil {
		t.Fatalf("CheckClientPins: %v", err)
	}
	if ok, err := versionAtLeast(MinGrypeClientVersion, "v0.88.0"); err != nil || !ok {
		t.Fatalf("MinGrypeClientVersion is %s; research/12 §7 requires at least v0.88.0",
			MinGrypeClientVersion)
	}
	if MinGrypeDBSchemaMajor < 6 {
		t.Fatalf("MinGrypeDBSchemaMajor is %d; schema v5 stopped updating on 2026-03-06",
			MinGrypeDBSchemaMajor)
	}
	if ok, err := versionAtLeast(GrypeClientVersionPin, MinGrypeClientVersion); err != nil || !ok {
		t.Fatalf("GrypeClientVersionPin %s is below the minimum %s",
			GrypeClientVersionPin, MinGrypeClientVersion)
	}
}

func TestVersionComparison(t *testing.T) {
	cases := []struct {
		have, want string
		ok         bool
	}{
		{"v0.88.0", "v0.88.0", true},
		{"v0.88.1", "v0.88.0", true},
		{"v0.87.9", "v0.88.0", false},
		{"v1.0.0", "v0.88.0", true},
		{"0.88.0", "v0.88.0", true},
		{"v0.88.0-rc1", "v0.88.0", true},
	}
	for _, c := range cases {
		got, err := versionAtLeast(c.have, c.want)
		if err != nil {
			t.Fatalf("versionAtLeast(%q,%q): %v", c.have, c.want, err)
		}
		if got != c.ok {
			t.Errorf("versionAtLeast(%q,%q) = %v, want %v", c.have, c.want, got, c.ok)
		}
	}
	if _, err := versionAtLeast("not-a-version", "v0.88.0"); err == nil {
		t.Error("an unparseable version was accepted")
	}
}

// ---------------------------------------------------------------------------
// No path re-serves the artifact
// ---------------------------------------------------------------------------

// TestPackageExposesNoWayToServeOrRepublishTheArtifact is a structural test.
//
// The prohibition is not "do not write a server" — it is "make it impossible
// for a caller to obtain the pulled bytes through this package", because bytes
// that can be obtained are bytes that will eventually be forwarded. So: no
// exported identifier may be named like a server or a publisher, no exported
// function may RETURN artifact bytes or a reader over them, and no source file
// may reference an HTTP server primitive.
func TestPackageExposesNoWayToServeOrRepublishTheArtifact(t *testing.T) {
	forbiddenName := regexp.MustCompile(`(?i)(serve|handler|publish|redistribut|upload|listen|proxy)`)
	forbiddenCall := []string{
		"http.ListenAndServe", "http.Handle", "http.FileServer", "http.Server{",
		"net.Listen", "httptest.NewServer",
	}
	forbiddenResult := map[string]bool{
		"[]byte": true, "io.Reader": true, "io.ReadCloser": true,
		"*os.File": true, "fs.FS": true, "io.ReadSeeker": true,
	}

	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, call := range forbiddenCall {
			if strings.Contains(string(raw), call) {
				t.Errorf("%s references %s; this package pulls and never serves", name, call)
			}
		}
		file, err := parser.ParseFile(fset, name, raw, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() || fn.Recv != nil {
				continue
			}
			if forbiddenName.MatchString(fn.Name.Name) {
				t.Errorf("%s exports %s, which reads as a way to serve the artifact", name, fn.Name.Name)
			}
			if fn.Type.Results == nil {
				continue
			}
			for _, res := range fn.Type.Results.List {
				typ := exprString(fset, res.Type)
				if forbiddenResult[typ] {
					t.Errorf("%s: exported %s returns %s; nothing may hand the pulled bytes out",
						name, fn.Name.Name, typ)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("the structural test scanned no source files; it would pass vacuously")
	}
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var sb strings.Builder
	if err := printNode(&sb, fset, e); err != nil {
		return ""
	}
	return sb.String()
}

func printNode(sb *strings.Builder, fset *token.FileSet, e ast.Expr) error {
	switch v := e.(type) {
	case *ast.Ident:
		sb.WriteString(v.Name)
	case *ast.StarExpr:
		sb.WriteString("*")
		return printNode(sb, fset, v.X)
	case *ast.SelectorExpr:
		if err := printNode(sb, fset, v.X); err != nil {
			return err
		}
		sb.WriteString("." + v.Sel.Name)
	case *ast.ArrayType:
		sb.WriteString("[]")
		return printNode(sb, fset, v.Elt)
	default:
		sb.WriteString("?")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func readManifestForTest(t *testing.T, dir string) *Manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, ManifestFileName))
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	return &m
}
