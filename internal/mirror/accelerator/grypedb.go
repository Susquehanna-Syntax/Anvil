package accelerator

// grypedb.go is the Grype DB half of the warm-start accelerator, and the home
// of the VERSION GATE.
//
// # WHY THERE IS A GATE AT ALL
//
// Anchore announced that on 2026-03-06 Grype stops publishing vulnerability
// database updates for DB schema v5, and that "You are affected if you are
// running Grype older than v0.88.0" (research/12 §7 [S21]; research/06 records
// the same migration from the DB side [S24]). That date is in the past.
//
// The dangerous shape of this failure is not an error — it is SILENCE. A v5
// listing still parses, still downloads, still loads, and still answers
// queries. It answers them from a database that stopped receiving updates, so
// the accelerator warms the scanner with a frozen view of the world and every
// vulnerability published since the freeze reads as "not vulnerable". A stale
// database that returns CLEAN is worse than no database, because no database
// is visibly no database.
//
// So the gate refuses rather than warns, and it refuses in both directions:
//
//	SCHEMA — a listing that is not provably schema v6 or newer is refused,
//	         including a listing whose schema cannot be determined at all.
//	         "Unknown" is refused, not assumed current: the whole point is
//	         that the stale case looks normal.
//	CLIENT — GrypeClientVersionPin, the client version Anvil pins, is checked
//	         against MinGrypeClientVersion at startup, BEFORE any network
//	         call. A future edit that drops the pin below v0.88.0 fails
//	         immediately rather than at the first pull, and a successful
//	         download can never disguise it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultGrypeListingURL is the schema v6 listing endpoint. The v5
	// endpoint (toolbox-data.anchore.io/grype/databases/listing.json) is
	// deliberately absent from this file: there is no configuration that
	// reaches it, because reaching it is the defect.
	DefaultGrypeListingURL = "https://grype.anchore.io/databases/v6/latest.json"

	// MinGrypeDBSchemaMajor is the oldest DB schema still receiving updates.
	MinGrypeDBSchemaMajor = 6

	// MinGrypeClientVersion is the oldest Grype client that can read schema
	// v6 and therefore the oldest client that receives updates at all.
	MinGrypeClientVersion = "v0.88.0"

	// GrypeClientVersionPin is the Grype client version Anvil pins. It is a
	// constant so that changing it is a reviewed source change, and it is
	// CHECKED against MinGrypeClientVersion so that lowering it cannot be
	// done quietly. Raise it freely; it may never go below the minimum.
	GrypeClientVersionPin = "v0.88.0"
)

var (
	// ErrSchemaTooOld reports a database schema below MinGrypeDBSchemaMajor —
	// in practice, a v5 listing that is no longer being updated.
	ErrSchemaTooOld = errors.New("accelerator: database schema is end-of-life and no longer updated")

	// ErrSchemaUnknown reports a listing whose schema version could not be
	// established. It is a REFUSAL, not a default-to-current: an unreadable
	// listing is exactly what a changed-out-from-under-us channel looks like.
	ErrSchemaUnknown = errors.New("accelerator: database schema version could not be established")

	// ErrClientPin reports a pinned client version below the minimum. It fires
	// at startup, before any network call.
	ErrClientPin = errors.New("accelerator: pinned client version is below the supported minimum")

	// ErrUnverifiableChecksum reports an archive whose stated checksum uses an
	// algorithm this package does not implement. Refusing is the default;
	// GrypeConfig.AllowUnverifiedArchiveChecksum is the operator's explicit,
	// recorded opt-out.
	ErrUnverifiableChecksum = errors.New("accelerator: archive checksum algorithm is not verifiable here")
)

// GrypeConfig configures the Grype DB pull.
type GrypeConfig struct {
	Enabled bool

	// ListingURL is the schema-v6 listing document. An operator self-hosting a
	// mirror points this at their own copy; Anchore's own guidance, like
	// Aqua's, is that heavy users should not hammer the public endpoint.
	// https only — see AllowUnverifiedArchiveChecksum for why that matters
	// here specifically.
	ListingURL string

	// MaxArchiveBytes bounds the archive download. Zero means
	// DefaultMaxBlobBytes. Grype DB v6 is roughly 65 MB compressed.
	MaxArchiveBytes int64

	// AllowUnverifiedArchiveChecksum admits an archive whose checksum this
	// package cannot verify — a v6 listing may state xxh64, which is not
	// implemented here. Setting it means TLS is the only integrity evidence,
	// and the cache manifest records checksum_verified:false so the choice is
	// visible on disk and not only in a config file.
	//
	// That justification is only true because ListingURL is https-only and
	// enforced. Over cleartext there would be no TLS, so the opt-out's entire
	// stated safety basis would be absent while the manifest still recorded
	// checksum_verified:false as though the operator had made the documented
	// trade. The two rules hold each other up; neither may be relaxed alone.
	AllowUnverifiedArchiveChecksum bool
}

// CheckClientPins verifies every compiled-in client version pin against its
// minimum. It runs before any network call in WarmStartWith, and takes no
// arguments so that it can also be called from a process's startup path.
//
// It is a build-time-ish assertion expressed as a runtime check: the constants
// are compiled in, so this can only fail if somebody edited them, and failing
// loudly at startup is how that edit gets noticed.
func CheckClientPins() error {
	ok, err := versionAtLeast(GrypeClientVersionPin, MinGrypeClientVersion)
	if err != nil {
		return refuse(ErrClientPin, "grype: pinned client version %q is unparseable", GrypeClientVersionPin)
	}
	if !ok {
		return refuse(ErrClientPin,
			"grype: pinned client version %s is below %s; clients older than that stopped "+
				"receiving database updates when schema v5 was retired on 2026-03-06, and a "+
				"stale database answers CLEAN rather than answering with an error",
			GrypeClientVersionPin, MinGrypeClientVersion)
	}
	return nil
}

// grypeListing is the subset of the listing document this package reads.
//
// Three shapes are tolerated because the document has already changed once and
// the parse must be able to RECOGNISE the old shape in order to refuse it —
// a parser that simply fails on v5 reports "malformed listing", which reads
// like a transient outage and gets retried forever.
type grypeListing struct {
	Status        string          `json:"status"`
	SchemaVersion json.RawMessage `json:"schemaVersion"`
	Schema        json.RawMessage `json:"schema"`
	Built         string          `json:"built"`
	Path          string          `json:"path"`
	URL           string          `json:"url"`
	Checksum      string          `json:"checksum"`

	// Available is the SCHEMA V5 listing shape: {"available": {"5": [...]}}.
	// It is parsed solely so that a v5 listing is refused as v5.
	Available map[string]json.RawMessage `json:"available"`
}

// schemaMajor establishes the listing's schema major version, or reports that
// it could not be established.
func (l *grypeListing) schemaMajor() (int, error) {
	for _, raw := range []json.RawMessage{l.SchemaVersion, l.Schema} {
		if len(raw) == 0 {
			continue
		}
		if n, ok := majorFromJSON(raw); ok {
			return n, nil
		}
	}
	if len(l.Available) > 0 {
		best := -1
		for k := range l.Available {
			if n, err := strconv.Atoi(strings.TrimPrefix(k, "v")); err == nil && n > best {
				best = n
			}
		}
		if best >= 0 {
			return best, nil
		}
	}
	return 0, refuse(ErrSchemaUnknown,
		"grype: the listing document states no schema version this package recognises; "+
			"refusing rather than assuming it is current, because a stale database is silent")
}

// majorFromJSON reads a schema version out of a number, a string ("v6.0.0",
// "6"), or an object carrying a "model"/"major" field.
func majorFromJSON(raw json.RawMessage) (int, bool) {
	var n int
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if m, ok := majorFromString(s); ok {
			return m, true
		}
		return 0, false
	}
	var obj struct {
		Model *int `json:"model"`
		Major *int `json:"major"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		if obj.Model != nil {
			return *obj.Model, true
		}
		if obj.Major != nil {
			return *obj.Major, true
		}
	}
	return 0, false
}

func majorFromString(s string) (int, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "v"))
	if s == "" {
		return 0, false
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// versionAtLeast compares two vMAJOR.MINOR.PATCH strings.
func versionAtLeast(have, want string) (bool, error) {
	h, err := parseVersion(have)
	if err != nil {
		return false, err
	}
	w, err := parseVersion(want)
	if err != nil {
		return false, err
	}
	for i := range h {
		if h[i] != w[i] {
			return h[i] > w[i], nil
		}
	}
	return true, nil
}

func parseVersion(v string) ([3]int, error) {
	var out [3]int
	s := strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return out, fmt.Errorf("accelerator: %q is not a version", v)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, fmt.Errorf("accelerator: %q is not a version", v)
		}
		out[i] = n
	}
	return out, nil
}

// pullGrypeDB fetches the Grype DB archive into the cache, gating on schema
// first and downloading only if the gate passes.
//
// The order matters: the schema check runs on the LISTING, before ~65 MB moves,
// so an end-of-life channel costs one small GET rather than a full download
// that is then thrown away — or, worse, kept.
func pullGrypeDB(ctx context.Context, cfg Config, root string, now time.Time) (SourceRecord, error) {
	client := httpClient(cfg)

	// https, a host, and no inline credentials — the same scope rule the
	// registry base and every redirect hop go through. It has already run in
	// normalise(); it runs again here because this is the function that opens
	// the socket, and a scope check that lives only at the far end of a
	// configuration path is a scope check somebody will route around.
	listingURL, err := parseEndpoint("grype listing url", cfg.Grype.ListingURL)
	if err != nil {
		return SourceRecord{}, err
	}

	listing, err := fetchGrypeListing(ctx, client, listingURL, cfg.Grype.MaxArchiveBytes)
	if err != nil {
		return SourceRecord{}, err
	}

	major, err := listing.schemaMajor()
	if err != nil {
		return SourceRecord{}, err
	}
	if major < MinGrypeDBSchemaMajor {
		return SourceRecord{}, refuse(ErrSchemaTooOld,
			"grype: listing states database schema v%d, but schema v%d is the oldest still "+
				"published; v5 stopped receiving updates on 2026-03-06 and a client fed a frozen "+
				"database reports CLEAN for everything published since",
			major, MinGrypeDBSchemaMajor)
	}

	archiveURL, err := resolveArchiveURL(listingURL, listing)
	if err != nil {
		return SourceRecord{}, err
	}

	data, err := fetchGrypeArchive(ctx, client, archiveURL, cfg.Grype.MaxArchiveBytes)
	if err != nil {
		return SourceRecord{}, err
	}

	alg, verified, err := verifyGrypeChecksum(listing.Checksum, data, cfg.Grype.AllowUnverifiedArchiveChecksum)
	if err != nil {
		return SourceRecord{}, err
	}

	const fileName = "grype-db.tar.zst"
	if err := writeFileAtomic(root, fileName, data); err != nil {
		return SourceRecord{}, err
	}

	against := ""
	if verified {
		against = verifiedAgainstGrypeListing
	}
	return SourceRecord{
		Name:              SourceGrypeDB,
		Origin:            redactURL(archiveURL.String()),
		Reference:         listing.Built,
		Digest:            listing.Checksum,
		File:              fileName,
		Bytes:             int64(len(data)),
		SchemaVersion:     major,
		ClientPin:         GrypeClientVersionPin,
		ChecksumVerified:  verified,
		ChecksumAlgorithm: alg,
		VerifiedAgainst:   against,
		PulledAt:          now.UTC(),
	}, nil
}

func fetchGrypeListing(ctx context.Context, client *http.Client, u *url.URL, maxBytes int64) (*grypeListing, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, refuse(ErrRegistry, "grype: cannot build listing request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, refuse(ErrRegistry, "grype: listing request failed: %v", redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if err := checkStatus(resp, "grype listing"); err != nil {
		return nil, err
	}
	raw, err := readCapped(resp.Body, min(maxBytes, int64(8<<20)), "grype listing")
	if err != nil {
		return nil, err
	}
	var l grypeListing
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, refuse(ErrSchemaUnknown, "grype: cannot parse the listing document: %v", err)
	}
	return &l, nil
}

// resolveArchiveURL turns the listing's path into an absolute URL.
//
// The result must be on the SAME HOST as the listing. Spine S7 forbids
// following cross-host redirects; a listing document that can send the client
// to an arbitrary host is the same hazard reached one step earlier, and the
// listing is third-party content.
func resolveArchiveURL(listingURL *url.URL, l *grypeListing) (*url.URL, error) {
	ref := strings.TrimSpace(l.URL)
	if ref == "" {
		ref = strings.TrimSpace(l.Path)
	}
	if ref == "" {
		return nil, refuse(ErrRegistry, "grype: the listing names no database archive")
	}
	parsed, err := url.Parse(ref)
	if err != nil {
		return nil, refuse(ErrRegistry, "grype: the listing's archive reference is not a URL")
	}
	abs := listingURL.ResolveReference(parsed)
	if err := sameOrigin("grype: the listing's archive reference", listingURL, abs); err != nil {
		return nil, err
	}
	return abs, nil
}

func fetchGrypeArchive(ctx context.Context, client *http.Client, u *url.URL, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, refuse(ErrRegistry, "grype: cannot build archive request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, refuse(ErrRegistry, "grype: archive request failed: %v", redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if err := checkStatus(resp, "grype archive"); err != nil {
		return nil, err
	}
	return readCapped(resp.Body, maxBytes, "grype db archive")
}

// verifyGrypeChecksum verifies a sha256 checksum, and refuses anything else
// unless the operator has explicitly opted out.
//
// Only sha256 is implemented. A v6 listing may state xxh64; rather than
// pretend, this returns ErrUnverifiableChecksum and the pull does not happen.
// The alternative — accepting silently — would put an unverified 65 MB blob in
// a directory whose whole justification is that it is well-understood.
func verifyGrypeChecksum(checksum string, data []byte, allowUnverified bool) (alg string, verified bool, err error) {
	checksum = strings.TrimSpace(checksum)
	if checksum == "" {
		if allowUnverified {
			return "", false, nil
		}
		return "", false, refuse(ErrUnverifiableChecksum,
			"grype: the listing states no archive checksum; set AllowUnverifiedArchiveChecksum "+
				"to accept TLS as the only integrity evidence")
	}
	parts := strings.SplitN(checksum, ":", 2)
	if len(parts) != 2 {
		return "", false, refuse(ErrUnverifiableChecksum, "grype: malformed archive checksum")
	}
	alg = strings.ToLower(strings.TrimSpace(parts[0]))
	want := strings.ToLower(strings.TrimSpace(parts[1]))
	if alg != "sha256" {
		if allowUnverified {
			return alg, false, nil
		}
		return alg, false, refuse(ErrUnverifiableChecksum,
			"grype: the listing states a %s checksum, which this package does not implement; "+
				"set AllowUnverifiedArchiveChecksum to accept TLS as the only integrity evidence", alg)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return alg, false, refuse(ErrDigestMismatch,
			"grype: archive sha256 is %s but the listing named %s", got, want)
	}
	return alg, true, nil
}
