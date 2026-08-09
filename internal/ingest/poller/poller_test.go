// Tests for A.7, the authenticated conditional-GET poller.
//
// ===========================================================================
// NO TEST HERE TOUCHES THE NETWORK OR A REAL CREDENTIAL
// ===========================================================================
//
// Every exchange runs against an httptest TLS server on the loopback
// interface. The two cases that need a request to CARRY a real provider
// hostname — research/06 Risk #8's unauthenticated-304 penalty is keyed on the
// host, so a fixture that polls 127.0.0.1 cannot exercise it — use a transport
// whose DialContext is redirected to the same httptest listener. The URL, the
// Host header and the TLS handshake are all real; only the dial address is
// substituted, so nothing leaves the machine and the code under test sees
// exactly what it would see in production.
//
// The credential is the string in fixtureToken, invented here. The GitHub PAT
// is ops-provisioned; no test reads a real environment variable, and
// TestNoCredentialValueAppearsInAnyErrorOrResult sweeps every error and every
// rendered result for the fixture value.
//
// ===========================================================================
// WHAT THE PACKET ASKED FOR, AND WHERE IT IS
// ===========================================================================
//
//	(a) 304 reads zero body bytes and feed_state moves only last_ok_at
//	    → TestNotModifiedReadsZeroBodyBytesAndMovesOnlyLastOKAt
//	(b) a redirect to a different host is refused
//	    → TestCrossHostRedirectIsRefusedAndTheOtherHostIsNeverContacted
//	(c) every request to a rate-limited host carries Authorization
//	    → TestRateLimitedHostAuthorizesEveryRequestIncludingThe304
//	    → TestRateLimitedHostWithAuthNoneIsRefusedBeforeAnyRequest
//	 stop condition: every polled sync mechanism in the feed table, in both the
//	 raw-JSON and release-asset URL shapes, with no hard-coded URL or cadence
//	    → TestEveryPolledSyncMechanismRunsAgainstTheFixture
//	    → TestPollerGoNamesNoFeedURLFeedIDHostOrCadence
package poller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
)

// fixtureToken is the invented secret every authenticated fixture uses. It is
// not a credential, it never was one, and its only job is to be searched for in
// error text.
const fixtureToken = "fixture-token-not-a-real-credential"

// fixtureEnv is the environment variable name a fixture row names. The value is
// served by fakeCredentials, never by the process environment.
const fixtureEnv = "ANVIL_TEST_FEED_TOKEN"

// clockStart is the fixed clock every test runs on, so last_ok_at is assertable
// rather than approximately assertable.
var clockStart = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// Licence fixtures — the A.4 gate admits nothing without them
// ---------------------------------------------------------------------------
//
// internal/ingest/license refuses every feed until the publisher's verbatim
// licence text has been acquired into mirror/ and its sha256 pinned. A fresh
// clone therefore admits nothing, and A.7 is inert until an operator acquires
// the bodies. These fixtures are a synthetic mirror in the same shape, so the
// poller's admitted path is reachable in a test without a network fetch and
// without pretending a real pin exists.

const cc0Verbatim = `Creative Commons Legal Code

CC0 1.0 Universal

The person who associated a work with this deed has dedicated the work to the
public domain by waiving all rights to the work worldwide under copyright law.`

const cc0Notes = `SPDX-License-Identifier: CC0-1.0

Anvil's record for the fixture feed: public domain dedication, no obligation.`

// buildMirror renders one admitted feed into an fstest.MapFS shaped exactly
// like the real mirror/ tree.
func buildMirror(t *testing.T, feedID, dir string, tier config.LicenseTier) fs.FS {
	t.Helper()
	if dir == "" {
		dir = feedID
	}
	sum := sha256.Sum256([]byte(cc0Verbatim))

	var man strings.Builder
	man.WriteString("# synthetic manifest, poller_test\n")
	man.WriteString("schema_version = 1\n")
	man.WriteString("generated_utc = \"2026-08-09\"\n")
	man.WriteString("generated_by = \"poller_test\"\n")
	fmt.Fprintf(&man, "\n[[body]]\nfeed_id = %q\ntier = %d\ndir = %q\n"+
		"spdx_id = \"CC0-1.0\"\ntext_url = \"https://example.invalid/LICENSE\"\n"+
		"sha256 = %q\nclaim_source = \"poller_test fixture\"\n",
		feedID, tier.Int(), dir, hex.EncodeToString(sum[:]))

	notes := "# fixture notes\n\nProse outside a block is never classified.\n\n" +
		license.BodyBeginMarker(feedID) + "\n" + cc0Notes + "\n" + license.BodyEndMarker(feedID) + "\n"

	return fstest.MapFS{
		license.ManifestFileName: &fstest.MapFile{Data: []byte(man.String())},
		path.Join(license.TierDir(tier), dir, license.VerbatimFileName): &fstest.MapFile{
			Data: []byte(cc0Verbatim),
		},
		path.Join(license.TierDir(tier), license.NotesFileName): &fstest.MapFile{Data: []byte(notes)},
	}
}

// ---------------------------------------------------------------------------
// Credential fixture
// ---------------------------------------------------------------------------

// fakeCredentials answers from a map. It exists so that no test reads the
// process environment: a suite that could pick up a real ANVIL_GITHUB_TOKEN is
// a suite that behaves differently on the machine that has one.
type fakeCredentials map[string]string

func (f fakeCredentials) Credential(name string) (string, bool) {
	v, ok := f[name]
	return v, ok
}

// ---------------------------------------------------------------------------
// HTTP fixtures
// ---------------------------------------------------------------------------

// recordedRequest is what the fixture server saw.
type recordedRequest struct {
	Method string
	Host   string
	Path   string
	Query  string
	Header http.Header
}

// recorder collects requests across handlers and goroutines.
type recorder struct {
	mu   sync.Mutex
	reqs []recordedRequest
}

func (r *recorder) add(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, recordedRequest{
		Method: req.Method,
		Host:   req.Host,
		Path:   req.URL.Path,
		Query:  req.URL.RawQuery,
		Header: req.Header.Clone(),
	})
}

func (r *recorder) all() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedRequest, len(r.reqs))
	copy(out, r.reqs)
	return out
}

func (r *recorder) count() int { return len(r.all()) }

// newServer starts a TLS httptest server that records every request.
func newServer(t *testing.T, rec *recorder, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// countingBody counts Read calls and bytes on a response body. It is how
// "a 304 reads zero body bytes" is OBSERVED rather than asserted from a field
// the code under test filled in itself.
type countingBody struct {
	rc    io.ReadCloser
	reads *int
	bytes *int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	*c.reads++
	n, err := c.rc.Read(p)
	*c.bytes += int64(n)
	return n, err
}

func (c *countingBody) Close() error { return c.rc.Close() }

type countingTransport struct {
	base  http.RoundTripper
	reads *int
	bytes *int64
}

func (c countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(r)
	if resp != nil && resp.Body != nil {
		resp.Body = &countingBody{rc: resp.Body, reads: c.reads, bytes: c.bytes}
	}
	return resp, err
}

// hostMapTransport keeps the request URL, the Host header and the TLS handshake
// exactly as production would see them while dialling a local fixture.
//
// It exists because two of this package's rules are keyed on the HOSTNAME —
// research/06 Risk #8's unauthenticated-304 penalty, and spine S7's cross-host
// redirect refusal — and a fixture where every server is 127.0.0.1 on a
// different port cannot exercise either of them. Only the dial address is
// substituted; a host with no mapping is a hard failure, so a test that drifted
// toward the real internet fails instead of reaching it.
func hostMapTransport(t *testing.T, mapping map[string]*httptest.Server) *http.Transport {
	t.Helper()
	if len(mapping) == 0 {
		t.Fatal("hostMapTransport needs at least one host")
	}
	var any *httptest.Server
	for _, s := range mapping {
		any = s
		break
	}
	base, ok := any.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("httptest client transport is %T, expected *http.Transport", any.Client().Transport)
	}
	tr := base.Clone()

	cfg := tr.TLSClientConfig.Clone()
	pool := cfg.RootCAs.Clone()
	for _, s := range mapping {
		pool.AddCert(s.Certificate())
	}
	cfg.RootCAs = pool
	// httptest's certificate carries example.com as a SAN and nothing else, so
	// the handshake is verified against that name while the request keeps the
	// hostname the feed row configured.
	cfg.ServerName = "example.com"
	tr.TLSClientConfig = cfg

	addrs := map[string]string{}
	for host, s := range mapping {
		addrs[host] = s.Listener.Addr().String()
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		to, ok := addrs[host]
		if !ok {
			return nil, fmt.Errorf("fixture transport: no mapping for host %q; no test may dial anything else", host)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, to)
	}
	return tr
}

// ---------------------------------------------------------------------------
// Cache fixture
// ---------------------------------------------------------------------------

func openCache(t *testing.T) *sql.DB {
	t.Helper()
	db, err := cache.Open(t.Context(), filepath.Join(t.TempDir(), "ingest-cache.db"))
	if err != nil {
		t.Fatalf("cache.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := cache.Migrate(t.Context(), db); err != nil {
		t.Fatalf("cache.Migrate: %v", err)
	}
	return db
}

// storedState is feed_state as a test reads it back.
type storedState struct {
	found                                  bool
	etag, lastModified, watermark, lastOK  sql.NullString
	consecutiveFailures, licenseTierColumn int
}

func readStoredState(t *testing.T, db *sql.DB, feedID string) storedState {
	t.Helper()
	var s storedState
	err := db.QueryRowContext(t.Context(), cache.SelectFeedStateSQL, feedID).
		Scan(&s.etag, &s.lastModified, &s.watermark, &s.lastOK, &s.consecutiveFailures, &s.licenseTierColumn)
	if errors.Is(err, sql.ErrNoRows) {
		return s
	}
	if err != nil {
		t.Fatalf("reading feed_state for %q: %v", feedID, err)
	}
	s.found = true
	return s
}

func seedState(t *testing.T, db *sql.DB, feedID, etag, lastMod, watermark, lastOK string, failures int, tier config.LicenseTier) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), cache.UpsertFeedStateSQL,
		feedID, etag, lastMod, watermark, lastOK, failures, tier.Int())
	if err != nil {
		t.Fatalf("seeding feed_state for %q: %v", feedID, err)
	}
}

// countRows is how "a 304 leaves advisory/affected/advisory_fts alone" is
// checked from outside the poller.
func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("counting %s: %v", table, err)
	}
	return n
}

// ---------------------------------------------------------------------------
// Feed fixtures
// ---------------------------------------------------------------------------

// fixtureFeed builds a FeedConfig by hand. Every value a real row would carry
// comes from the caller, because the point of A.1 is that none of them is a
// constant in Go — including in a test, where a copied cadence would be the
// first place the two sources of truth diverge.
type fixtureFeed struct {
	id       string
	rawURL   string
	auth     config.AuthMode
	sync     config.SyncMechanism
	interval time.Duration
	slo      time.Duration
	mirrorIn string
}

func (f fixtureFeed) config() config.FeedConfig {
	c := config.FeedConfig{
		ID:                  f.id,
		URL:                 f.rawURL,
		Enabled:             true,
		AuthMode:            f.auth,
		SyncMechanism:       f.sync,
		IntervalSeconds:     int(f.interval / time.Second),
		FreshnessSLOSeconds: int(f.slo / time.Second),
		OnFailure:           config.OnFailureServeStale,
		LicenseTier:         config.LicenseTier0,
		LicenseSPDX:         "CC0-1.0",
		MirrorDir:           f.mirrorIn,
		BootstrapMechanism:  config.BootstrapBulkArchive,
	}
	if c.MirrorDir == "" {
		c.MirrorDir = f.id
	}
	if f.auth != config.AuthNone {
		c.CredentialEnv = fixtureEnv
	}
	return c
}

// newPoller builds a Poller wired to the fixture cache, mirror and clock.
func newPoller(t *testing.T, db *sql.DB, mirror fs.FS, tr http.RoundTripper) *Poller {
	t.Helper()
	p, err := New(Options{
		DB:          db,
		Mirror:      mirror,
		Transport:   tr,
		Credentials: fakeCredentials{fixtureEnv: fixtureToken},
		Now:         func() time.Time { return clockStart },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// (a) The 304 path
// ---------------------------------------------------------------------------

// TestNotModifiedReadsZeroBodyBytesAndMovesOnlyLastOKAt is A.7's first named
// validation and the A.2 cache's exit criterion 3.
//
// The zero-body claim is checked by COUNTING READ CALLS on the response body,
// not by reading PollResult.BodyBytes: the field is filled in by the code under
// test, so trusting it would be asking the poller whether the poller behaved.
func TestNotModifiedReadsZeroBodyBytesAndMovesOnlyLastOKAt(t *testing.T) {
	const feedID = "fixture-etag-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerIfNoneMatch) == "" {
			t.Errorf("no %s header on a conditional_get_etag poll with a stored validator", headerIfNoneMatch)
		}
		w.WriteHeader(http.StatusNotModified)
	})

	db := openCache(t)
	const priorETag = `"prior-etag"`
	const priorLastMod = "Fri, 08 Aug 2026 12:00:00 GMT"
	const priorWatermark = "prior-cursor"
	const priorLastOK = "2026-08-01T00:00:00.000000000Z"
	seedState(t, db, feedID, priorETag, priorLastMod, priorWatermark, priorLastOK, 0, config.LicenseTier0)

	var reads int
	var bytesRead int64
	tr := countingTransport{base: ts.Client().Transport, reads: &reads, bytes: &bytesRead}
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), tr)

	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/known_exploited_vulnerabilities.json",
		auth: config.AuthNone, sync: config.SyncConditionalGetETag,
		interval: 15 * time.Minute, slo: 24 * time.Hour,
	}.config()

	res, err := p.Poll(t.Context(), feed)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if res.Status != StatusNotModified {
		t.Fatalf("status = %q, want %q", res.Status, StatusNotModified)
	}
	if reads != 0 || bytesRead != 0 {
		t.Errorf("the 304 path read the body: %d Read calls, %d bytes; a 304 must not touch it at all", reads, bytesRead)
	}
	if res.BodyBytes != 0 {
		t.Errorf("BodyBytes = %d, want 0", res.BodyBytes)
	}
	if res.Payload != nil {
		t.Error("a 304 produced a payload; there is no body to carry")
	}

	got := readStoredState(t, db, feedID)
	if !got.found {
		t.Fatal("feed_state row is gone after a 304")
	}
	if got.etag.String != priorETag {
		t.Errorf("etag = %q, want the stored %q unchanged", got.etag.String, priorETag)
	}
	if got.lastModified.String != priorLastMod {
		t.Errorf("last_modified = %q, want the stored %q unchanged", got.lastModified.String, priorLastMod)
	}
	if got.watermark.String != priorWatermark {
		t.Errorf("watermark = %q, want the stored %q unchanged", got.watermark.String, priorWatermark)
	}
	if got.consecutiveFailures != 0 {
		t.Errorf("consecutive_failures = %d, want 0 unchanged", got.consecutiveFailures)
	}
	if got.lastOK.String == priorLastOK {
		t.Error("last_ok_at did not move; a 304 is a successful poll and it is the one column that advances")
	}
	if want := clockStart.Format(timeLayout); got.lastOK.String != want {
		t.Errorf("last_ok_at = %q, want %q", got.lastOK.String, want)
	}

	for _, table := range []string{"advisory", "affected", "advisory_fts"} {
		if n := countRows(t, db, table); n != 0 {
			t.Errorf("%s has %d rows after a 304; the poller writes no advisory data at all", table, n)
		}
	}
}

// TestNotModifiedClearsAFailureStreak records the one reading of exit criterion
// 3 this package makes deliberately, so that a reviewer sees the decision
// rather than discovering it.
//
// The criterion's words are "move nothing but last_ok_at". A 304 is a
// SUCCESSFUL poll, and leaving a stale failure streak behind would keep a
// healthy feed looking broken to anything that backs off on that counter. The
// three columns the criterion is actually about — the two validators and the
// watermark — are written back unchanged, as the test above proves.
func TestNotModifiedClearsAFailureStreak(t *testing.T) {
	const feedID = "fixture-recovering-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})
	db := openCache(t)
	seedState(t, db, feedID, `"e"`, "", "", "2026-08-01T00:00:00.000000000Z", 4, config.LicenseTier0)

	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
		sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	res, err := p.Poll(t.Context(), feed)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if res.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d after a successful 304, want 0", res.ConsecutiveFailures)
	}
	if got := readStoredState(t, db, feedID); got.consecutiveFailures != 0 {
		t.Errorf("stored consecutive_failures = %d, want 0", got.consecutiveFailures)
	}
}

// ---------------------------------------------------------------------------
// (b) Redirects — spine S7
// ---------------------------------------------------------------------------

// TestCrossHostRedirectIsRefusedAndTheOtherHostIsNeverContacted is A.7's second
// named validation and spine S7's "never follow cross-host redirects".
//
// The assertion that matters is not only the error: it is that the SECOND
// SERVER RECORDED NOTHING. A poller that followed the redirect and then
// complained about it has already made the request an attacker wanted.
func TestCrossHostRedirectIsRefusedAndTheOtherHostIsNeverContacted(t *testing.T) {
	const feedID = "fixture-redirected-feed"
	const configuredHost = "feeds.example.test"
	const attackerHost = "collector.example.invalid"

	elsewhere := &recorder{}
	other := newServer(t, elsewhere, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"exfiltrated":true}`)
	})

	home := &recorder{}
	ts := newServer(t, home, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+attackerHost+"/collect", http.StatusFound)
	})

	tr := hostMapTransport(t, map[string]*httptest.Server{
		configuredHost: ts,
		attackerHost:   other,
	})

	db := openCache(t)
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), tr)
	feed := fixtureFeed{
		id: feedID, rawURL: "https://" + configuredHost + "/releases/latest", auth: config.AuthGitHubToken,
		sync: config.SyncConditionalGetETag, interval: 15 * time.Minute, slo: 6 * time.Hour,
	}.config()

	res, err := p.Poll(t.Context(), feed)
	if err == nil {
		t.Fatal("Poll followed a cross-host redirect and returned no error")
	}
	if !errors.Is(err, ErrCrossHostRedirect) {
		t.Errorf("error = %v, want ErrCrossHostRedirect", err)
	}
	if !errors.Is(err, ErrPollRefused) {
		t.Errorf("a cross-host redirect refusal does not satisfy ErrPollRefused: %v", err)
	}
	if res.Status != StatusRefused {
		t.Errorf("status = %q, want %q", res.Status, StatusRefused)
	}
	if n := elsewhere.count(); n != 0 {
		t.Fatalf("the off-host server received %d requests; the redirect must never be followed", n)
	}
	if n := home.count(); n != 1 {
		t.Errorf("the configured host received %d requests, want exactly 1", n)
	}
	if res.Requests != 1 {
		t.Errorf("Requests = %d, want 1: the refused hop was never made", res.Requests)
	}
	if got := readStoredState(t, db, feedID); got.consecutiveFailures != 1 {
		t.Errorf("consecutive_failures = %d, want 1: the feed did not deliver", got.consecutiveFailures)
	}
}

// TestSameHostDifferentPortRedirectIsRefused is the rest of the scope rule:
// spine S7 says re-validate SCOPE, and a hop to another port on the same
// hostname is a different service.
func TestSameHostDifferentPortRedirectIsRefused(t *testing.T) {
	const feedID = "fixture-reported-feed"
	rec := &recorder{}
	other := newServer(t, &recorder{}, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "{}")
	})
	ts := newServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/elsewhere", http.StatusFound)
	})
	db := openCache(t)
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
		sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	if _, err := p.Poll(t.Context(), feed); !errors.Is(err, ErrScopeViolation) {
		t.Fatalf("error = %v, want ErrScopeViolation", err)
	}
}

// TestSameHostRedirectIsFollowedAndKeepsTheCredential covers the other half of
// the rule: the release-asset shape in the feed table is a redirect to a
// download path on the SAME host, and a poller that refused every redirect
// would break it.
func TestSameHostRedirectIsFollowedAndKeepsTheCredential(t *testing.T) {
	const feedID = "fixture-release-asset-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/latest" {
			http.Redirect(w, r, "/releases/download/all_CVEs_at_midnight.zip", http.StatusFound)
			return
		}
		w.Header().Set(headerETag, `"asset-v1"`)
		_, _ = io.WriteString(w, "PK\x03\x04fixture-archive")
	})

	db := openCache(t)
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/releases/latest", auth: config.AuthGitHubToken,
		sync: config.SyncConditionalGetETag, interval: 15 * time.Minute, slo: 6 * time.Hour,
	}.config()

	res, err := p.Poll(t.Context(), feed)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if res.Status != StatusUpdated {
		t.Fatalf("status = %q, want %q", res.Status, StatusUpdated)
	}
	if res.Requests != 2 {
		t.Errorf("Requests = %d, want 2 (the redirect was followed)", res.Requests)
	}
	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(got))
	}
	for i, r := range got {
		if r.Header.Get(headerAuthorization) != bearerPrefix+fixtureToken {
			t.Errorf("request %d (%s) carried Authorization %q; every hop must be authorized",
				i, r.Path, r.Header.Get(headerAuthorization))
		}
	}
	body, err := res.Payload.Bytes()
	if err != nil {
		t.Fatalf("Payload.Bytes: %v", err)
	}
	if !strings.HasPrefix(string(body), "PK") {
		t.Errorf("payload = %q, want the asset the redirect pointed at", body)
	}
	if got := readStoredState(t, db, feedID); got.etag.String != `"asset-v1"` {
		t.Errorf("etag = %q, want the value the final response carried", got.etag.String)
	}
}

// TestRedirectChainIsCappedEvenOnTheConfiguredHost keeps a same-host redirect
// loop from being an unbounded request generator against a feed we authenticate
// to.
func TestRedirectChainIsCappedEvenOnTheConfiguredHost(t *testing.T) {
	const feedID = "fixture-looping-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	})
	db := openCache(t)
	p, err := New(Options{
		DB: db, Mirror: buildMirror(t, feedID, "", config.LicenseTier0),
		Transport: ts.Client().Transport, Credentials: fakeCredentials{fixtureEnv: fixtureToken},
		Now: func() time.Time { return clockStart }, MaxRedirects: 2,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/start", auth: config.AuthNone,
		sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	_, pollErr := p.Poll(t.Context(), feed)
	if !errors.Is(pollErr, ErrTooManyRedirects) {
		t.Fatalf("error = %v, want ErrTooManyRedirects", pollErr)
	}
	if n := rec.count(); n > 3 {
		t.Errorf("server saw %d requests with MaxRedirects=2; the cap did not bound the chain", n)
	}
}

// ---------------------------------------------------------------------------
// (c) research/06 Risk #8 — authorize every request, including the 304s
// ---------------------------------------------------------------------------

// TestRateLimitedHostAuthorizesEveryRequestIncludingThe304 is A.7's third named
// validation.
//
// GitHub's exemption is conditional: "Making a conditional request does not
// count against your primary rate limit if a 304 response is returned AND the
// request was made while correctly authorized with an Authorization header."
// An unauthenticated 304 costs one of 60 an hour. So the header has to be on
// the request that is EXPECTED to 304, which is the request a careless
// implementation optimises it off.
func TestRateLimitedHostAuthorizesEveryRequestIncludingThe304(t *testing.T) {
	const feedID = "fixture-provider-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerIfNoneMatch) != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set(headerETag, `"v1"`)
		_, _ = io.WriteString(w, `{"advisories":[]}`)
	})

	db := openCache(t)
	tr := hostMapTransport(t, map[string]*httptest.Server{"raw.githubusercontent.com": ts})
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), tr)

	// The URL names the provider whose rate limiter research/06 Risk #8 is
	// about. The dial lands on the fixture; the Host header, the URL and the
	// TLS handshake are the real ones.
	feed := fixtureFeed{
		id: feedID, rawURL: "https://raw.githubusercontent.com/fixture/data/main/feed.json",
		auth: config.AuthGitHubToken, sync: config.SyncConditionalGetETag,
		interval: 15 * time.Minute, slo: 24 * time.Hour,
	}.config()

	first, err := p.Poll(t.Context(), feed)
	if err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	if first.Status != StatusUpdated {
		t.Fatalf("first status = %q, want %q", first.Status, StatusUpdated)
	}
	second, err := p.Poll(t.Context(), feed)
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if second.Status != StatusNotModified {
		t.Fatalf("second status = %q, want %q; the stored validator should have produced a 304", second.Status, StatusNotModified)
	}

	reqs := rec.all()
	if len(reqs) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(reqs))
	}
	for i, r := range reqs {
		if got := r.Header.Get(headerAuthorization); got != bearerPrefix+fixtureToken {
			t.Errorf("request %d carried Authorization %q, want the bearer credential; an unauthenticated 304 still costs the 60/hour budget", i, got)
		}
		if !strings.Contains(r.Host, "githubusercontent.com") {
			t.Errorf("request %d Host = %q; the fixture must present the real provider host", i, r.Host)
		}
	}
	if reqs[1].Header.Get(headerIfNoneMatch) != `"v1"` {
		t.Errorf("second request If-None-Match = %q, want the stored validator", reqs[1].Header.Get(headerIfNoneMatch))
	}
}

// TestRateLimitedHostWithAuthNoneIsRefusedBeforeAnyRequest is the forbidden
// action stated as a test: the row is the mistake, and the poller must refuse
// rather than spend anonymous budget discovering it.
func TestRateLimitedHostWithAuthNoneIsRefusedBeforeAnyRequest(t *testing.T) {
	const feedID = "fixture-anonymous-provider-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})
	db := openCache(t)
	tr := hostMapTransport(t, map[string]*httptest.Server{"api.github.com": ts})
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), tr)

	feed := fixtureFeed{
		id: feedID, rawURL: "https://api.github.com/repos/fixture/project/releases/latest",
		auth: config.AuthNone, sync: config.SyncConditionalGetETag,
		interval: 15 * time.Minute, slo: 6 * time.Hour,
	}.config()

	res, err := p.Poll(t.Context(), feed)
	if !errors.Is(err, ErrUnauthenticatedGitHub) {
		t.Fatalf("error = %v, want ErrUnauthenticatedGitHub", err)
	}
	if !errors.Is(err, ErrPollRefused) {
		t.Errorf("refusal does not satisfy ErrPollRefused: %v", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("server saw %d requests; the refusal must happen before the request", n)
	}
	if res.Requests != 0 {
		t.Errorf("Requests = %d, want 0", res.Requests)
	}
	if res.StateWritten {
		t.Error("feed_state was written for a request that was never made")
	}
	if got := readStoredState(t, db, feedID); got.found {
		t.Error("a feed_state row exists for a feed that was never polled")
	}
}

// TestRateLimitedHostDetectionCoversSubdomains keeps the predicate honest
// without turning it into a list of feed hosts.
func TestRateLimitedHostDetectionCoversSubdomains(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"github.com", true},
		{"api.github.com", true},
		{"raw.githubusercontent.com", true},
		{"objects.githubusercontent.com", true},
		{"API.GitHub.Com", true},
		{"github.com.", true},
		{"notgithub.com", false},
		{"github.com.evil.example", false},
		{"cwe.mitre.org", false},
		{"", false},
	} {
		if got := gitHubRateLimited(tc.host); got != tc.want {
			t.Errorf("gitHubRateLimited(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

// TestMissingCredentialIsRefusedBeforeTheRequest: a row that names an
// environment variable nobody set must not fall back to an anonymous request,
// because that is the fail-open answer and it is the one Risk #8 punishes.
func TestMissingCredentialIsRefusedBeforeTheRequest(t *testing.T) {
	const feedID = "fixture-uncredentialed-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	db := openCache(t)
	p, err := New(Options{
		DB: db, Mirror: buildMirror(t, feedID, "", config.LicenseTier0),
		Transport: ts.Client().Transport, Credentials: fakeCredentials{},
		Now: func() time.Time { return clockStart },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthGitHubToken,
		sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	if _, err := p.Poll(t.Context(), feed); !errors.Is(err, ErrMissingCredential) {
		t.Fatalf("error = %v, want ErrMissingCredential", err)
	} else if !strings.Contains(err.Error(), fixtureEnv) {
		t.Errorf("the refusal does not name the environment variable an operator must set: %v", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("server saw %d requests; a missing credential must not become an anonymous request", n)
	}
}

// TestNoCredentialValueAppearsInAnyErrorOrResult sweeps every rendered string
// this package can produce on the paths a credential is in scope for.
//
// A token in an error message is a token in a log file, and a log file is the
// one place an ops-provisioned secret is guaranteed to outlive the process.
func TestNoCredentialValueAppearsInAnyErrorOrResult(t *testing.T) {
	const feedID = "fixture-secret-sweep-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Header().Set(headerETag, `"v1"`)
			_, _ = io.WriteString(w, "{}")
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	db := openCache(t)
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)

	var rendered []string
	for _, p2 := range []string{"/ok", "/boom"} {
		feed := fixtureFeed{
			id: feedID, rawURL: ts.URL + p2, auth: config.AuthGitHubToken,
			sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
		}.config()
		res, err := p.Poll(t.Context(), feed)
		if err != nil {
			rendered = append(rendered, err.Error())
		}
		rendered = append(rendered,
			fmt.Sprintf("%+v", res),
			res.Sanitize.String(),
			fmt.Sprintf("%+v", res.Decision),
		)
	}
	// And the refusal paths that read the credential.
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/ok", auth: config.AuthAPIKeyHeader,
		sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
	}.config()
	if _, err := p.Poll(t.Context(), feed); err != nil {
		rendered = append(rendered, err.Error())
	}

	for _, s := range rendered {
		if strings.Contains(s, fixtureToken) {
			t.Fatalf("a rendered value carries the credential: %s", s)
		}
	}
	if len(rendered) == 0 {
		t.Fatal("the sweep rendered nothing, so it proved nothing")
	}
}

// ---------------------------------------------------------------------------
// A.4 — the licence gate runs first
// ---------------------------------------------------------------------------

// TestLicenceRefusalHappensBeforeAnyRequest is the forbidden action about
// writing ungated data, enforced at the strongest point available: the request
// is not made at all.
//
// The fixture is the state of a FRESH CLONE — no acquired licence bodies, no
// pins — which is what internal/ingest/license documents as admitting nothing.
// So this is also the test that says out loud that A.7 is inert until an
// operator has run the acquire step.
func TestLicenceRefusalHappensBeforeAnyRequest(t *testing.T) {
	const feedID = "fixture-unlicensed-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"advisories":[]}`)
	})
	db := openCache(t)
	p := newPoller(t, db, fstest.MapFS{}, ts.Client().Transport)

	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
		sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	res, err := p.Poll(t.Context(), feed)
	if err == nil {
		t.Fatal("Poll fetched a feed the licence gate had not admitted")
	}
	if !errors.Is(err, license.ErrLicenseRefused) {
		t.Errorf("error = %v, want a refusal satisfying license.ErrLicenseRefused", err)
	}
	if !errors.Is(err, ErrPollRefused) {
		t.Errorf("licence refusal does not satisfy ErrPollRefused: %v", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("server saw %d requests; a feed that cannot be kept must not be fetched", n)
	}
	if res.StateWritten || readStoredState(t, db, feedID).found {
		t.Error("feed_state was written for a feed the licence gate refused")
	}
	if !res.Decision.Refused() {
		t.Error("the returned decision does not report itself as a refusal")
	}
	if res.Decision.Tier.Valid() {
		t.Errorf("refused decision carries tier %d; a refusal must never present as a valid tier, least of all 0",
			res.Decision.Tier.Int())
	}
}

// TestAdmittedTierIsWrittenFromTheGateNotTheRow: feed_state.license_tier is a
// conclusion, not a copy of the row's claim.
func TestAdmittedTierIsWrittenFromTheGateNotTheRow(t *testing.T) {
	const feedID = "fixture-tiered-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "{}")
	})
	db := openCache(t)
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
		sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	res, err := p.Poll(t.Context(), feed)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if res.Decision.Refused() {
		t.Fatal("the fixture mirror did not admit the feed")
	}
	got := readStoredState(t, db, feedID)
	if got.licenseTierColumn != res.Decision.Tier.Int() {
		t.Errorf("feed_state.license_tier = %d, want the gate's conclusion %d",
			got.licenseTierColumn, res.Decision.Tier.Int())
	}
	if err := res.Payload.CheckWritePath(res.Decision.Dir + "/data.json"); err != nil {
		t.Errorf("the payload refuses a write inside its own directory: %v", err)
	}
	if err := res.Payload.CheckWritePath(license.TierDir(config.LicenseTier2) + "/somewhere/data.json"); err == nil {
		t.Error("the payload permitted a write into another tier's quarantine")
	}
}

// TestPayloadWithoutAnAdmittedDecisionYieldsNothing is the zero-value defence
// internal/ingest/license makes at Decision.ManifestRow, one layer out: a
// Payload nobody filled in must not present as tier 0 with usable bytes.
func TestPayloadWithoutAnAdmittedDecisionYieldsNothing(t *testing.T) {
	var zero Payload
	if _, err := zero.Bytes(); !errors.Is(err, ErrNoPayload) {
		t.Errorf("zero Payload.Bytes error = %v, want ErrNoPayload", err)
	}
	if err := zero.CheckWritePath("mirror/tier0/anything"); !errors.Is(err, ErrNoPayload) {
		t.Errorf("zero Payload.CheckWritePath error = %v, want ErrNoPayload", err)
	}
	var nilPayload *Payload
	if _, err := nilPayload.Bytes(); !errors.Is(err, ErrNoPayload) {
		t.Errorf("nil Payload.Bytes error = %v, want ErrNoPayload", err)
	}
	if d := nilPayload.Decision(); d.Tier.Valid() {
		t.Errorf("nil Payload.Decision tier = %d, want an invalid tier", d.Tier.Int())
	}
}

// ---------------------------------------------------------------------------
// A.3 — every stored string goes through the sanitizer
// ---------------------------------------------------------------------------

// TestValidatorThatDoesNotSurviveTheSanitizerIsNotStored.
//
// A zero-width space inside an ETag is invisible to a reviewer and changes the
// bytes. Sanitizing it and storing the RESULT would be worse than dropping it:
// the next request would send a validator the server never issued, so the feed
// would answer 200 forever while feed_state recorded that it was tracking one.
// The value is therefore dropped and counted.
func TestValidatorThatDoesNotSurviveTheSanitizerIsNotStored(t *testing.T) {
	const feedID = "fixture-hostile-header-feed"
	const hostileETag = "\"abc​def\""
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerETag, hostileETag)
		w.Header().Set(headerLastModified, "not a date at all")
		_, _ = io.WriteString(w, "{}")
	})
	db := openCache(t)
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
		sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	res, err := p.Poll(t.Context(), feed)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if res.HeaderRejected != 2 {
		t.Errorf("HeaderRejected = %d, want 2 (the mangled validator and the unparseable date)", res.HeaderRejected)
	}
	if res.Sanitize.Removed() == 0 {
		t.Error("the sanitizer reported removing nothing from a header carrying a zero-width space")
	}
	got := readStoredState(t, db, feedID)
	if got.etag.Valid {
		t.Errorf("etag = %q was stored; a validator the sanitizer changed is not the server's validator", got.etag.String)
	}
	if got.lastModified.Valid {
		t.Errorf("last_modified = %q was stored; it does not parse as an HTTP-date", got.lastModified.String)
	}
}

// TestWellFormedValidatorsAreStoredVerbatim is the other direction: the schema
// says "verbatim ETag header value, quotes and W/ prefix included", so a value
// that survives must not be trimmed, unquoted or normalised on the way in.
func TestWellFormedValidatorsAreStoredVerbatim(t *testing.T) {
	const feedID = "fixture-verbatim-feed"
	const weakETag = `W/"33a64df551425fcc55e4d42a148795d9f25f89d4"`
	const httpDate = "Sat, 08 Aug 2026 23:00:00 GMT"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerETag, weakETag)
		w.Header().Set(headerLastModified, httpDate)
		_, _ = io.WriteString(w, "{}")
	})
	db := openCache(t)
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
		sync: config.SyncConditionalGetLastModified, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	res, err := p.Poll(t.Context(), feed)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if res.HeaderRejected != 0 {
		t.Errorf("HeaderRejected = %d over two well-formed headers, want 0", res.HeaderRejected)
	}
	got := readStoredState(t, db, feedID)
	if got.etag.String != weakETag {
		t.Errorf("etag = %q, want the verbatim %q", got.etag.String, weakETag)
	}
	if got.lastModified.String != httpDate {
		t.Errorf("last_modified = %q, want the verbatim %q", got.lastModified.String, httpDate)
	}

	// And the stored Last-Modified is what the next conditional request asks
	// with, which is the only thing storing it was for.
	if _, err := p.Poll(t.Context(), feed); err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	reqs := rec.all()
	if len(reqs) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(reqs))
	}
	if got := reqs[1].Header.Get(headerIfModifiedSince); got != httpDate {
		t.Errorf("second request %s = %q, want %q", headerIfModifiedSince, got, httpDate)
	}
}

// TestETagShapeCheck exercises the validator-shape rule directly, including the
// case the DQUOTE requirement exists for: a value carrying a comma would split
// into two If-None-Match entries when it is sent back.
func TestETagShapeCheck(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want bool
	}{
		{`"abc"`, true},
		{`W/"abc"`, true},
		{`""`, true},
		{`abc`, false},
		{`"abc`, false},
		{`abc"`, false},
		{`"a"b"`, false},
		{`"a, "b"`, false},
		{"\"a\tb\"", false},
		{"", false},
	} {
		if got := validETag(tc.v); got != tc.want {
			t.Errorf("validETag(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// x-poll-interval
// ---------------------------------------------------------------------------

// TestServerPollIntervalIsHonouredButNeverShortensTheConfiguredCadence.
//
// research/06 S2: "If a response includes an x-poll-interval header, wait AT
// LEAST that many seconds before you poll the same endpoint again." At least —
// so the rule is max(configured, requested), and a server can never talk Anvil
// into polling faster than the operator configured.
func TestServerPollIntervalIsHonouredButNeverShortensTheConfiguredCadence(t *testing.T) {
	const feedID = "fixture-paced-feed"
	configured := 15 * time.Minute
	slo := 6 * time.Hour

	for _, tc := range []struct {
		name       string
		header     string
		retryAfter string
		want       time.Duration
		source     IntervalSource
		capped     bool
		rejected   int
	}{
		{"no header at all", "", "", configured, IntervalFromFeedTable, false, 0},
		{"server asks for longer", strconv.Itoa(int((30 * time.Minute).Seconds())), "", 30 * time.Minute, IntervalFromServer, false, 0},
		{"server asks for shorter", strconv.Itoa(int((time.Minute).Seconds())), "", configured, IntervalFromFeedTable, false, 0},
		{"retry-after wins when longer", "", strconv.Itoa(int((45 * time.Minute).Seconds())), 45 * time.Minute, IntervalFromRetryAfter, false, 0},
		{"absurd interval is capped by the feed's own SLO", strconv.Itoa(int((30 * 24 * time.Hour).Seconds())), "", slo, IntervalFromServer, true, 0},
		{"unparseable header is rejected and counted", "soon", "", configured, IntervalFromFeedTable, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
				if tc.header != "" {
					w.Header().Set(headerPollInterval, tc.header)
				}
				if tc.retryAfter != "" {
					w.Header().Set(headerRetryAfter, tc.retryAfter)
				}
				_, _ = io.WriteString(w, "{}")
			})
			db := openCache(t)
			p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
			feed := fixtureFeed{
				id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
				sync: config.SyncConditionalGetETag, interval: configured, slo: slo,
			}.config()

			res, err := p.Poll(t.Context(), feed)
			if err != nil {
				t.Fatalf("Poll: %v", err)
			}
			if res.NextPollAfter != tc.want {
				t.Errorf("NextPollAfter = %v, want %v", res.NextPollAfter, tc.want)
			}
			if res.IntervalSource != tc.source {
				t.Errorf("IntervalSource = %q, want %q", res.IntervalSource, tc.source)
			}
			if res.IntervalCapped != tc.capped {
				t.Errorf("IntervalCapped = %v, want %v", res.IntervalCapped, tc.capped)
			}
			if res.HeaderRejected != tc.rejected {
				t.Errorf("HeaderRejected = %d, want %d", res.HeaderRejected, tc.rejected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The stop condition: every polled sync mechanism, both URL shapes
// ---------------------------------------------------------------------------

// fakeWatermarker is the config.SyncWatermarkAPI hook a test supplies. The real
// one is A.14's, and its shape is per-feed, which is exactly why this package
// takes it as an interface rather than implementing one.
type fakeWatermarker struct {
	param     string
	applied   []string
	next      string
	relocate  string
	failApply bool
}

func (w *fakeWatermarker) Apply(_ config.FeedConfig, watermark string, u *url.URL) (*url.URL, error) {
	if w.failApply {
		return nil, errors.New("fixture hook declines")
	}
	if w.relocate != "" {
		return url.Parse(w.relocate)
	}
	w.applied = append(w.applied, watermark)
	if watermark != "" {
		q := u.Query()
		q.Set(w.param, watermark)
		u.RawQuery = q.Encode()
	}
	return u, nil
}

func (w *fakeWatermarker) Advance(_ config.FeedConfig, _ string, _ Response) (string, error) {
	return w.next, nil
}

// TestEveryPolledSyncMechanismRunsAgainstTheFixture is A.7's stop condition.
//
// Every mechanism in the feed table with SyncMechanism.Polled() true is driven
// against the same fixture, in both URL shapes the table uses — a raw JSON
// document and a release-asset download — and none of them is named in the code
// under test.
func TestEveryPolledSyncMechanismRunsAgainstTheFixture(t *testing.T) {
	shapes := []struct {
		name string
		path string
		body string
	}{
		{"raw json document", "/known_exploited_vulnerabilities.json", `{"vulnerabilities":[]}`},
		{"release asset", "/releases/download/all_CVEs_at_midnight.zip", "PK\x03\x04fixture-archive"},
	}
	mechanisms := []config.SyncMechanism{
		config.SyncConditionalGetETag,
		config.SyncConditionalGetLastModified,
		config.SyncWatermarkAPI,
	}

	for _, shape := range shapes {
		for _, mech := range mechanisms {
			name := shape.name + " / " + string(mech)
			t.Run(name, func(t *testing.T) {
				feedID := "fixture-" + strings.ReplaceAll(string(mech), "_", "-")
				rec := &recorder{}
				ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set(headerETag, `"shape-v1"`)
					w.Header().Set(headerLastModified, "Sat, 08 Aug 2026 23:00:00 GMT")
					_, _ = io.WriteString(w, shape.body)
				})
				db := openCache(t)
				wm := &fakeWatermarker{param: "lastModStartDate", next: "2026-08-09T00:00:00Z"}
				p, err := New(Options{
					DB: db, Mirror: buildMirror(t, feedID, "", config.LicenseTier0),
					Transport: ts.Client().Transport, Credentials: fakeCredentials{fixtureEnv: fixtureToken},
					Now: func() time.Time { return clockStart }, Watermarks: wm,
				})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				feed := fixtureFeed{
					id: feedID, rawURL: ts.URL + shape.path, auth: config.AuthGitHubToken,
					sync: mech, interval: time.Hour, slo: 24 * time.Hour,
				}.config()

				res, err := p.Poll(t.Context(), feed)
				if err != nil {
					t.Fatalf("Poll: %v", err)
				}
				if res.Status != StatusUpdated {
					t.Fatalf("status = %q, want %q", res.Status, StatusUpdated)
				}
				body, err := res.Payload.Bytes()
				if err != nil {
					t.Fatalf("Payload.Bytes: %v", err)
				}
				if string(body) != shape.body {
					t.Errorf("payload = %q, want %q", body, shape.body)
				}
				if res.Payload.SHA256() == "" {
					t.Error("the payload carries no digest")
				}
				got := readStoredState(t, db, feedID)
				if !got.found {
					t.Fatal("no feed_state row was written")
				}
				if mech == config.SyncWatermarkAPI && got.watermark.String != wm.next {
					t.Errorf("watermark = %q, want the advanced cursor %q", got.watermark.String, wm.next)
				}

				// Second poll: the mechanism's own conditional header must be
				// on the wire, built from what the first poll stored.
				if _, err := p.Poll(t.Context(), feed); err != nil {
					t.Fatalf("second Poll: %v", err)
				}
				reqs := rec.all()
				if len(reqs) != 2 {
					t.Fatalf("server saw %d requests, want 2", len(reqs))
				}
				switch mech {
				case config.SyncConditionalGetETag:
					if reqs[1].Header.Get(headerIfNoneMatch) == "" {
						t.Errorf("second request carried no %s", headerIfNoneMatch)
					}
				case config.SyncConditionalGetLastModified:
					if reqs[1].Header.Get(headerIfModifiedSince) == "" {
						t.Errorf("second request carried no %s", headerIfModifiedSince)
					}
				case config.SyncWatermarkAPI:
					if !strings.Contains(reqs[1].Query, wm.param) {
						t.Errorf("second request query = %q, want the cursor the hook applied", reqs[1].Query)
					}
				}
				for i, r := range reqs {
					if r.Header.Get(headerAuthorization) == "" {
						t.Errorf("request %d carried no Authorization header", i)
					}
				}
			})
		}
	}
}

// TestMechanismsThatAreNotHTTPPollsAreRefused covers the rest of the enum. Each
// refusal names the reason, because "nothing happened" is the failure mode a
// silent no-op produces.
func TestMechanismsThatAreNotHTTPPollsAreRefused(t *testing.T) {
	for _, tc := range []struct {
		mech config.SyncMechanism
		want error
	}{
		{config.SyncGitBloblessFetch, ErrMechanismNotHTTP},
		{config.SyncDerived, ErrNotPolled},
		{config.SyncNone, ErrNotPolled},
	} {
		t.Run(string(tc.mech), func(t *testing.T) {
			feedID := "fixture-" + strings.ReplaceAll(string(tc.mech), "_", "-")
			rec := &recorder{}
			ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "{}")
			})
			db := openCache(t)
			p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
			feed := fixtureFeed{
				id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
				sync: tc.mech, interval: time.Hour, slo: 24 * time.Hour,
			}.config()

			_, err := p.Poll(t.Context(), feed)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if n := rec.count(); n != 0 {
				t.Errorf("server saw %d requests for a mechanism that is not an HTTP poll", n)
			}
		})
	}
}

// TestWatermarkHookCannotRelocateTheRequest closes the hole an injected hook
// would otherwise open: the hook builds a URL, so a hook that returned a
// different host would be a way around the redirect rule.
func TestWatermarkHookCannotRelocateTheRequest(t *testing.T) {
	const feedID = "fixture-relocating-hook-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "{}")
	})
	db := openCache(t)
	p, err := New(Options{
		DB: db, Mirror: buildMirror(t, feedID, "", config.LicenseTier0),
		Transport: ts.Client().Transport, Credentials: fakeCredentials{fixtureEnv: fixtureToken},
		Now:        func() time.Time { return clockStart },
		Watermarks: &fakeWatermarker{relocate: "https://elsewhere.example/collect"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
		sync: config.SyncWatermarkAPI, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	if _, err := p.Poll(t.Context(), feed); !errors.Is(err, ErrCrossHostRedirect) {
		t.Fatalf("error = %v, want ErrCrossHostRedirect", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("server saw %d requests", n)
	}
}

// TestWatermarkMechanismWithoutAHookIsRefused: the cursor's shape is a per-feed
// fact, so a missing hook is a refusal and never a request without the cursor.
func TestWatermarkMechanismWithoutAHookIsRefused(t *testing.T) {
	const feedID = "fixture-hookless-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "{}")
	})
	db := openCache(t)
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
		sync: config.SyncWatermarkAPI, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	if _, err := p.Poll(t.Context(), feed); !errors.Is(err, ErrWatermark) {
		t.Fatalf("error = %v, want ErrWatermark", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("server saw %d requests", n)
	}
}

// ---------------------------------------------------------------------------
// The remaining refusals and failures
// ---------------------------------------------------------------------------

func TestDisabledFeedIsNotPolled(t *testing.T) {
	const feedID = "fixture-parked-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "{}")
	})
	db := openCache(t)
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
		sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
	}.config()
	feed.Enabled = false

	if _, err := p.Poll(t.Context(), feed); !errors.Is(err, ErrFeedDisabled) {
		t.Fatalf("error = %v, want ErrFeedDisabled", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("server saw %d requests for a disabled feed", n)
	}
}

func TestNonHTTPSFeedURLIsRefused(t *testing.T) {
	const feedID = "fixture-downgraded-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {})
	db := openCache(t)
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
	feed := fixtureFeed{
		id: feedID, rawURL: strings.Replace(ts.URL, "https", "http", 1) + "/feed.json",
		auth: config.AuthNone, sync: config.SyncConditionalGetETag,
		interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	if _, err := p.Poll(t.Context(), feed); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("error = %v, want ErrInsecureURL", err)
	}
	if n := rec.count(); n != 0 {
		t.Errorf("server saw %d requests", n)
	}
}

func TestBodyOverTheCapIsRefusedAndTheStreakGrows(t *testing.T) {
	const feedID = "fixture-oversized-feed"
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("A", 4096))
	})
	db := openCache(t)
	p, err := New(Options{
		DB: db, Mirror: buildMirror(t, feedID, "", config.LicenseTier0),
		Transport: ts.Client().Transport, Credentials: fakeCredentials{fixtureEnv: fixtureToken},
		Now: func() time.Time { return clockStart }, MaxBodyBytes: 64,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
		sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	res, pollErr := p.Poll(t.Context(), feed)
	if !errors.Is(pollErr, ErrBodyTooLarge) {
		t.Fatalf("error = %v, want ErrBodyTooLarge", pollErr)
	}
	if res.Payload != nil {
		t.Error("an oversized body produced a payload")
	}
	if got := readStoredState(t, db, feedID); got.consecutiveFailures != 1 {
		t.Errorf("consecutive_failures = %d, want 1", got.consecutiveFailures)
	}
}

func TestUnexpectedStatusIsAFailureAndLeavesValidatorsAlone(t *testing.T) {
	const feedID = "fixture-erroring-feed"
	const priorETag = `"still-valid"`
	rec := &recorder{}
	ts := newServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	db := openCache(t)
	seedState(t, db, feedID, priorETag, "", "", "2026-08-01T00:00:00.000000000Z", 1, config.LicenseTier0)
	p := newPoller(t, db, buildMirror(t, feedID, "", config.LicenseTier0), ts.Client().Transport)
	feed := fixtureFeed{
		id: feedID, rawURL: ts.URL + "/feed.json", auth: config.AuthNone,
		sync: config.SyncConditionalGetETag, interval: time.Hour, slo: 24 * time.Hour,
	}.config()

	res, err := p.Poll(t.Context(), feed)
	if !errors.Is(err, ErrUnexpectedStatus) {
		t.Fatalf("error = %v, want ErrUnexpectedStatus", err)
	}
	if !errors.Is(err, ErrPollFailed) {
		t.Errorf("failure does not satisfy ErrPollFailed: %v", err)
	}
	if res.Status != StatusFailed {
		t.Errorf("status = %q, want %q", res.Status, StatusFailed)
	}
	got := readStoredState(t, db, feedID)
	if got.etag.String != priorETag {
		t.Errorf("etag = %q; a failed poll is no evidence about the body the validator describes", got.etag.String)
	}
	if got.consecutiveFailures != 2 {
		t.Errorf("consecutive_failures = %d, want 2", got.consecutiveFailures)
	}
}

func TestNewRefusesAPollerWithNoCache(t *testing.T) {
	if _, err := New(Options{}); !errors.Is(err, ErrNoCache) {
		t.Fatalf("error = %v, want ErrNoCache", err)
	}
}

// ---------------------------------------------------------------------------
// A.1's rule, applied to the consuming side
// ---------------------------------------------------------------------------

// TestPollerGoNamesNoFeedURLFeedIDHostOrCadence is internal/ingest/config's own
// AST assertion turned around and pointed at this package.
//
// research/06 Recommendation item 4: "Every cadence above lives in config,
// never in code." A poller that branched on a feed id, built a URL, or held a
// cadence would move part of the feed table into Go, where an operator cannot
// reach it and where it would drift from the file that claims to own it.
//
// THE ONE EXEMPTION is gitHubRateLimitedDomains, and this test is also what
// bounds it: those literals may appear inside that declaration and nowhere
// else. See the declaration for why a provider's rate-limit domain is not a
// feed fact.
func TestPollerGoNamesNoFeedURLFeedIDHostOrCadence(t *testing.T) {
	set, err := config.Load(filepath.Join("..", "config", config.ExampleFileName))
	if err != nil {
		t.Fatalf("loading the feed table: %v", err)
	}

	feedIDs := map[string]bool{}
	hosts := map[string]bool{}
	cadences := map[int]string{}
	for _, f := range set.Feeds {
		feedIDs[f.ID] = true
		for _, raw := range []string{f.URL, f.BootstrapURL} {
			if raw == "" {
				continue
			}
			u, perr := url.Parse(raw)
			if perr != nil {
				t.Fatalf("feed %q: %v", f.ID, perr)
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
	if len(feedIDs) == 0 || len(hosts) == 0 || len(cadences) == 0 {
		t.Fatal("the feed table yielded no ids, hosts or cadences, so this assertion would pass vacuously")
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "poller.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing poller.go: %v", err)
	}

	exemptLo, exemptHi := exemptionRange(t, file)
	sawExemptLiteral := false

	// Import paths are string literals too, and this module's own path begins
	// with a forge hostname. They are excluded by IDENTITY — the exact literal
	// nodes go/parser recorded as imports — rather than by a pattern, so no
	// other literal can be excluded by looking like one.
	imports := map[*ast.BasicLit]bool{}
	for _, spec := range file.Imports {
		imports[spec.Path] = true
	}

	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || imports[lit] {
			return true
		}
		pos := fset.Position(lit.Pos())
		inExemption := lit.Pos() >= exemptLo && lit.Pos() <= exemptHi
		switch lit.Kind {
		case token.STRING:
			s, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if strings.Contains(s, "://") {
				t.Errorf("%s: poller.go contains a URL literal %q; feed URLs live in %s",
					pos, s, config.ExampleFileName)
			}
			if feedIDs[s] {
				t.Errorf("%s: poller.go contains the feed id %q; a branch on feed identity is a hard-coded feed table",
					pos, s)
			}
			for host := range hosts {
				if !strings.Contains(s, host) {
					continue
				}
				if inExemption {
					sawExemptLiteral = true
					continue
				}
				t.Errorf("%s: poller.go contains the feed host %q outside gitHubRateLimitedDomains", pos, s)
			}
		case token.INT:
			v, cerr := strconv.Atoi(lit.Value)
			if cerr != nil {
				return true
			}
			if what, ok := cadences[v]; ok {
				t.Errorf("%s: poller.go contains the integer %d, which is %s; every cadence lives in %s",
					pos, v, what, config.ExampleFileName)
			}
		}
		return true
	})

	if !sawExemptLiteral {
		t.Error("no literal used the gitHubRateLimitedDomains exemption; if the declaration is gone, delete the exemption from this test rather than leaving it open")
	}
}

// exemptionRange returns the source span of the gitHubRateLimitedDomains
// declaration, which is the only place a provider domain may be written.
func exemptionRange(t *testing.T, file *ast.File) (token.Pos, token.Pos) {
	t.Helper()
	for _, d := range file.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if name.Name == "gitHubRateLimitedDomains" {
					return gen.Pos(), gen.End()
				}
			}
		}
	}
	t.Fatal("gitHubRateLimitedDomains is not declared in poller.go")
	return 0, 0
}

// TestStatusVocabularyIsClosed keeps the typed result a closed set, so a caller
// that switches on it cannot be surprised by a value nobody declared.
func TestStatusVocabularyIsClosed(t *testing.T) {
	seen := map[Status]bool{}
	for _, s := range StatusValues() {
		if seen[s] {
			t.Errorf("Status %q is declared twice", s)
		}
		seen[s] = true
		if !s.Valid() {
			t.Errorf("Status %q is in StatusValues but reports itself invalid", s)
		}
	}
	if Status("published").Valid() {
		t.Error("an undeclared status reports itself valid")
	}
	if len(StatusValues()) != 4 {
		t.Errorf("StatusValues has %d entries; update this test deliberately if a status was added", len(StatusValues()))
	}
}
