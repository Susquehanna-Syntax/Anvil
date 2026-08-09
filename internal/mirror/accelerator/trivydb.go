// Package accelerator is Anvil's OPTIONAL warm-start cache for package-range
// matching. This is step A.11 of plan/20-lane-a-ingestion-sca.md.
//
// # ANVIL MUST WORK CORRECTLY WITHOUT THIS PACKAGE. THAT IS THE DESIGN.
//
// Everything here is a performance optimisation. If the accelerator is absent,
// disabled, misconfigured, rate-limited or broken, Lane A's normal ingestion
// path still produces the same findings — only slower and colder. A performance
// optimisation that becomes a correctness dependency is a liability, so the
// structure below makes the dependency impossible rather than merely discouraged:
//
//   - DefaultConfig() is DISABLED. A fresh clone pulls nothing, WarmStart
//     returns nil, and no directory is created. Enabling is a deliberate
//     operator act, exactly as the licence gate admits nothing until an
//     operator acquires evidence.
//   - THIS PACKAGE EXPORTS NO READER. There is no Lookup, no Open, no Query,
//     no matcher, no decoder. Nothing in Anvil can consult the pulled bytes
//     through Go, so no code path can come to depend on them being present.
//     The consumer is an external scanner binary pointed at CacheDir().
//   - Every error returned by WarmStart is advisory. A caller that ignores it
//     entirely is behaving correctly. TestWarmStartFailureIsNotFatal records
//     that contract.
//
// # WHAT IS PULLED, AND WHY IT MAY NOT BE REDISTRIBUTED
//
// Trivy DB and Grype DB are published for public consumption, and consuming
// them is fine. Redistributing them is NOT established: research/06
// §"Prebuilt OCI-distributed databases" records that both builders are
// Apache-2.0 for their CODE and that "neither the trivy-db README nor the Trivy
// contribution docs enumerate the licenses of the aggregated data or state
// whether the built DB may be redistributed", and research/06's Recommendation
// says Anvil "must not redistribute a repackaged Trivy DB or Grype DB" until
// Aqua/Anchore state terms in writing.
//
// Unstated terms are not permissive terms. So the pulled artifact is:
//
//	CONSUME-ONLY  — recorded as consume_only: true in the cache manifest, and
//	                a manifest that says otherwise is refused on read.
//	NEVER SERVED  — no code path re-serves, re-publishes or re-packages it.
//	OUTSIDE THE   — it is written under the operating system's user cache
//	LICENCE MIRROR  directory, which is NOT mirror/tier{0,1,2,3}. See the guard
//	                below.
//	OUTSIDE THE   — and it is outside the git WORK TREE as well. Those are two
//	WORK TREE       independent failure modes: the guard stops Anvil's own code
//	                writing into a licence tier, and it says nothing at all
//	                about `git add -A`. A cache root inside the work tree is one
//	                careless commit away from being redistribution, and
//	                redistribution is unrecoverable once pushed. So the default
//	                root is os.UserCacheDir()-based (DefaultCacheDir), AND
//	                .gitignore rules exist for the old in-tree location. Belt
//	                and braces, because neither one implies the other.
//
// # THE WRITE-PATH GUARD, AND WHY IT ROUTES THROUGH THE LICENCE GATE
//
// mirror/tier2 is the share-alike QUARANTINE — Ubuntu/Alpine CC-BY-SA-4.0,
// Greenbone ODbL — and it exists so those terms cannot propagate into Anvil's
// own findings database. An accelerator that wrote into tier 2, or that wrote
// tier-2-derived bytes into tier 0/1, would defeat the quarantine silently and
// unrecoverably once published. It is silent because nothing about a copied
// file announces the licence it arrived under.
//
// So this package does not merely "avoid" the mirror by convention. Every write
// path is put through license.CheckWritePath for EVERY tier, and a path that
// any tier ACCEPTS is refused here. That inversion is the point: the licence
// gate is the authority on what a tiered path looks like, and the accelerator
// asks it rather than re-deciding. Note that the accelerator's own home
// directory contains a component literally named "mirror"
// (internal/mirror/accelerator/...), so a substring check on "mirror" would be
// both wrong and confidently wrong; asking the gate is neither.
//
// The gate's comparison is byte-exact, and byte-exact is not a PATH comparison
// on a filesystem that resolves MIRROR\Tier2 and mirror/tier2 to one directory.
// The gate is frozen and its exactness may be load-bearing for the admission
// path, so the accelerator — which is the component actually performing the
// filesystem write, and therefore the component asserting a filesystem property
// — does the folding itself before it asks. See foldPathComponent.
//
// # THE SHA-256 HERE IS NOT A FINGERPRINT
//
// This package computes sha256 over downloaded bytes. That is CONTENT
// INTEGRITY — "are these the bytes the publisher's manifest named" — and it is
// not, and must never be read as, a finding fingerprint. Anvil has exactly one
// fingerprint algorithm, anvil-fp/v1, defined once in internal/record with
// FINGERPRINT-SPEC.md as its authority, because two producers emitting
// different digests under one name breaks regression matching forever with
// nothing surfacing it. This package produces no findings, emits no records,
// and never calls the fingerprint. It hashes files.
//
// # KNOWN LIMITS — READ BEFORE YOU TRUST A GREEN RUN
//
//   - The guard proves where THIS package writes. It cannot prove what an
//     external scanner binary does with CacheDir() once it is handed the path.
//
//   - DIGEST VERIFICATION HERE IS TRANSPORT INTEGRITY, NOT PROVENANCE. Say it
//     that way round, because "digest verified" reads like the stronger claim
//     and it is not the claim being made. The Trivy manifest is fetched BY TAG;
//     the layer digest is read out of THAT response; the blob is then checked
//     against that digest. Whoever controlled the manifest response controlled
//     the digest, so what is proved is "the bytes arrived intact from whoever
//     answered", not "the bytes are Aqua's". The same holds for Grype: the
//     archive checksum comes out of the listing document that named the
//     archive. No cosign/sigstore verification is performed, no digest-pinned
//     default reference is shipped, and there is therefore no configuration by
//     which an operator could obtain provenance from this package today. Every
//     SourceRecord carries verified_against saying exactly this, because the
//     manifest is what an operator reads months from now without this file.
//
//   - THE PULLED DATABASE AGGREGATES SHARE-ALIKE SOURCES, AND NOTHING HERE
//     TRACKS THAT. mirror/tier2 quarantines Ubuntu OVAL (CC-BY-SA-4.0), Alpine
//     secdb and Greenbone (ODbL). The Trivy DB aggregates those same upstreams.
//     The guard and outside_licence_mirror:true are DIRECTORY facts — they
//     record that this cache carries no tier — and they say nothing about the
//     licence of the data inside it. Anvil has no DataSourceID → licence-tier
//     mapping anywhere, so a finding derived from this cache can reach the
//     findings database without the quarantine ever being consulted. That is
//     an unresolved cross-area question, not something this package decides,
//     and it may be a reason not to ship the accelerator at all. It is recorded
//     here so it is not discovered after publication.
//
//   - The Grype archive checksum is verified only when the listing states a
//     sha256. A v6 listing may state xxh64, which this package does not
//     implement; that pull is REFUSED unless the operator explicitly opts in
//     via GrypeConfig.AllowUnverifiedArchiveChecksum, in which case TLS is the
//     only integrity evidence and the manifest records checksum_verified:false.
//
//   - Freshness is a cadence guard, not a correctness property. Research/06
//     Risk #6 records Aqua's GHCR TOOMANYREQUESTS outage (44,000 req/min per
//     namespace) and the resulting 6h → 24h cadence cut, which is why
//     DefaultMinRefreshInterval is 24h and why 429 is a first-class outcome.
//
//   - Cross-host redirects are refused outright (spine S7), with no allowlist
//     and no opt-out. Real ghcr.io redirects blob GETs to
//     pkg-containers.githubusercontent.com, so a pull against the real registry
//     is expected to be REFUSED by that rule. That refusal is the rule working
//     rather than a defect, and the operator's route is a pull-through cache
//     that serves its own blobs — which is Aqua's own post-outage advice and
//     what RegistryBase is for. It is stated here because no test can observe
//     it: S7 forbids the network at test time, so the mock registry does not
//     model the redirect the real one issues.
package accelerator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
)

// ---------------------------------------------------------------------------
// Constants — endpoints, layout, pins
// ---------------------------------------------------------------------------

const (
	// DefaultTrivyRegistry is the OCI registry root research/06 names first
	// for the Trivy DB artifact. Aqua also publishes to Docker Hub,
	// public.ecr.aws and a GCR mirror, and Aqua's own advice after the
	// TOOMANYREQUESTS outage was to self-host or run a pull-through cache —
	// which is what RegistryBase is for. It is configuration, not a constant
	// with an override bolted on.
	DefaultTrivyRegistry = "https://ghcr.io"

	// DefaultTrivyRepository is the repository path of the Trivy DB artifact.
	DefaultTrivyRepository = "aquasecurity/trivy-db"

	// TrivyDBSchemaReference is the tag that selects Trivy DB schema 2. The
	// tag IS the schema version for this artifact — `trivy-db:2` — so pinning
	// the reference is pinning the schema, and a bare "latest" would silently
	// follow a schema bump. There is no "latest" default here for that reason.
	TrivyDBSchemaReference = "2"

	// TrivyDBSchemaVersion is the schema TrivyDBSchemaReference denotes. It is
	// the schema of the DEFAULT reference only. It is not written to the cache
	// manifest unless the configured reference actually denotes it — see
	// trivySchemaFromReference — because a manifest field is a claim, and a
	// claim nobody checked is worse than an absent field.
	TrivyDBSchemaVersion = 2
)

const (
	// LegacyInTreeCacheDir is the cache root this package used to default to:
	// inside the git working tree. It is retained ONLY so the gitignore test
	// can name the path it must keep ignored. Nothing writes here.
	//
	// It was wrong for a reason worth keeping written down. The write-path
	// guard proves Anvil's own code never writes into a licence tier; it has
	// nothing to say about `git add -A`, which would have staged ~165 MB of an
	// artifact with no stated redistribution terms into a public repository.
	// That IS redistribution, and it is unrecoverable once pushed. The repo
	// already knew this — mirror/.gitignore says "a file that git cannot carry
	// is a file no Anvil commit can author" — and this package had not applied
	// its own repo's rule to its own directory.
	LegacyInTreeCacheDir = "internal/mirror/accelerator/.cache"

	// CacheDirLeaf is the path appended to the OS user cache directory to form
	// DefaultCacheDir. It keeps CacheDirSuffix intact so the guard's positive
	// assertion survives the relocation out of the work tree.
	CacheDirLeaf = "anvil/mirror/accelerator/.cache"

	// CacheDirSuffix is the trailing path shape every cache root must have,
	// however it is rooted. An operator self-hosting on another volume still
	// ends the path in mirror/accelerator/.cache, so the layout — and the
	// guard's positive assertion — survives relocation.
	CacheDirSuffix = "mirror/accelerator/.cache"

	// ManifestFileName is the cache manifest: what was pulled, from where, at
	// what digest, and the consume_only flag that is this cache's whole legal
	// posture in one field.
	ManifestFileName = "accelerator-manifest.json"

	// DefaultMinRefreshInterval matches the cadence Aqua moved Trivy DB to
	// after the GHCR rate-limit outage (research/06 Risk #6: "Reduced the
	// frequency of Trivy DB updates from every 6 hours to every 24 hours").
	// Pulling more often than the publisher publishes buys nothing and spends
	// a shared rate-limit budget that is not Anvil's alone.
	DefaultMinRefreshInterval = 24 * time.Hour

	// DefaultMaxBlobBytes bounds a single downloaded artifact. Trivy DB is
	// roughly 100 MB compressed and Grype DB v6 about 65 MB, so 1 GiB is
	// generous by an order of magnitude while still refusing to fill a disk
	// because a registry answered with something unexpected.
	DefaultMaxBlobBytes = int64(1) << 30
)

// DefaultCacheDir returns the accelerator's default cache root: the operating
// system's user cache directory, plus CacheDirLeaf.
//
// It is a FUNCTION and not a constant on purpose. The old constant pointed
// inside the repository work tree, and a path that git can see is a path git
// can carry — see LegacyInTreeCacheDir. Resolving through os.UserCacheDir puts
// the artifact where every other tool's downloaded cache lives, outside any
// checkout, so no commit can pick it up however the repo is arranged.
//
// It can fail — os.UserCacheDir needs HOME or LOCALAPPDATA — and it REFUSES
// rather than falling back to a relative path, because every fallback anyone
// would reach for lands somewhere a checkout might be. The accelerator is
// optional, so the correct behaviour when the cache root cannot be located is
// to do nothing and say why.
func DefaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", refuse(ErrBadCacheDir,
			"cannot locate the OS user cache directory (%v); set Config.CacheDir explicitly to a "+
				"path outside any git working tree", err)
	}
	return filepath.Join(base, filepath.FromSlash(CacheDirLeaf)), nil
}

// OCI media types. An index is REFUSED rather than resolved: the Trivy DB
// artifact is a plain manifest, and silently picking a platform out of an index
// would be inventing a selection rule the publisher never stated.
const (
	ociManifestMediaType    = "application/vnd.oci.image.manifest.v1+json"
	dockerManifestMediaType = "application/vnd.docker.distribution.manifest.v2+json"
	ociIndexMediaType       = "application/vnd.oci.image.index.v1+json"
	dockerIndexMediaType    = "application/vnd.docker.distribution.manifest.list.v2+json"
	trivyDBLayerMediaType   = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
)

// consumeOnlyNotice is written into every cache manifest. It is prose on
// purpose: the operator who finds this directory on a disk months from now is
// the person who needs to know they may not republish it.
const consumeOnlyNotice = "CONSUME ONLY. Neither Aqua (Trivy DB) nor Anchore (Grype DB) states " +
	"redistribution terms for the compiled database artifact; unstated terms are not permissive " +
	"terms. Anvil consumes this cache locally and never re-serves, re-publishes or re-packages it. " +
	"It is deliberately outside mirror/tier{0,1,2,3} and carries no licence tier."

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrAccelerator is satisfied by errors.Is for every refusal this package
	// produces, so a caller that only needs "did the warm start work" needs
	// one check. Callers do not NEED that check — the accelerator is optional
	// — but a caller that logs it should be able to classify it.
	ErrAccelerator = errors.New("accelerator: warm start refused")

	// ErrLicenceTierWrite reports an attempt to write anywhere the licence
	// gate recognises as a tiered mirror directory. This is the one that
	// matters: it is the error that stands between an untermed database
	// artifact and mirror/tier0, and between the share-alike quarantine and
	// everything downstream of it.
	ErrLicenceTierWrite = errors.New("accelerator: write path resolves inside the licence-tiered mirror")

	// ErrBadCacheDir reports a cache root that is not shaped like an
	// accelerator cache — the positive half of the guard. "Not in the mirror"
	// is necessary and not sufficient; the cache also has to be where it says
	// it is, or the negative check is guarding a path nobody uses.
	ErrBadCacheDir = errors.New("accelerator: cache directory is not an accelerator cache")

	// ErrBadConfig reports a structurally unusable configuration: no registry,
	// no repository, an http URL where https is required, a credential_env
	// that is not an environment variable NAME.
	ErrBadConfig = errors.New("accelerator: invalid configuration")

	// ErrInsecureTransport reports a cleartext endpoint. There is no opt-out
	// and no loopback exception. This package carries an operator-provisioned
	// registry credential, and over http the 401 challenge that starts the
	// token exchange — challenge, realm, host and all — is written by whoever
	// is on the path.
	ErrInsecureTransport = errors.New("accelerator: endpoint is not https")

	// ErrTokenRealmNotAllowed reports a registry that named a token endpoint
	// which is not on the configured allowlist.
	//
	// This is the error that stands between an ops-provisioned PAT and a host
	// of the registry's choosing. The WWW-Authenticate header is UNTRUSTED
	// INPUT — it is written by the thing being talked to — and "it parses and
	// has a host" is not a check, it is a syntax note. Where a credential may
	// be sent is configuration, never discovery.
	ErrTokenRealmNotAllowed = errors.New("accelerator: registry named a token endpoint that is not allowlisted")

	// ErrRegistry reports an upstream failure: a non-200, an unreadable body,
	// an unexpected media type.
	ErrRegistry = errors.New("accelerator: registry error")

	// ErrRateLimited reports HTTP 429. It is a named error because it is a
	// DOCUMENTED, ALREADY-OBSERVED failure of this exact channel, not a
	// hypothetical: research/06 Risk #6 records Trivy users hitting GHCR's
	// 44,000 requests/minute/namespace cap and receiving TOOMANYREQUESTS.
	// A warm start that fails this way is normal and is not an incident.
	ErrRateLimited = errors.New("accelerator: registry rate limited the pull")

	// ErrDigestMismatch reports content whose sha256 is not the digest the
	// manifest named.
	ErrDigestMismatch = errors.New("accelerator: content digest mismatch")

	// ErrTooLarge reports a body exceeding the configured byte ceiling.
	ErrTooLarge = errors.New("accelerator: artifact exceeds the size ceiling")

	// ErrTamperedManifest reports an existing cache manifest whose
	// consume_only flag is not true. The flag is the cache's legal posture;
	// a cache asserting it may be redistributed is refused rather than
	// corrected, because whoever flipped it may already have acted on it.
	ErrTamperedManifest = errors.New("accelerator: cache manifest is not marked consume_only")
)

// refuse builds an error that satisfies errors.Is for BOTH ErrAccelerator and
// the specific kind, so callers can check at whichever altitude they need.
func refuse(kind error, format string, a ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, a...), errors.Join(ErrAccelerator, kind))
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// Config is the accelerator's whole surface. The zero value is disabled and
// does nothing, which is the safe default for an optional component.
type Config struct {
	// Enabled is the master switch. False — the default — means WarmStart is
	// a no-op that creates no directory and opens no socket.
	Enabled bool

	// CacheDir is the cache root. Empty means DefaultCacheDir(). Whatever it
	// is, it must end in CacheDirSuffix and must not resolve inside the mirror.
	// Point it outside any git working tree; the default already is.
	CacheDir string

	// MinRefreshInterval suppresses a pull whose last success is more recent
	// than this. Zero means DefaultMinRefreshInterval.
	MinRefreshInterval time.Duration

	// HTTPClient lets a test supply httptest's client. Nil means a bounded
	// default. Either way the client is COPIED and given a redirect policy
	// that refuses cross-host hops, per spine S7.
	HTTPClient *http.Client

	// Now is the clock, for freshness tests. Nil means time.Now.
	Now func() time.Time

	// Trivy and Grype are the two sources. Each can be disabled on its own:
	// a warm start of one is still a warm start.
	Trivy TrivyConfig
	Grype GrypeConfig
}

// TrivyConfig configures the Trivy DB OCI pull.
type TrivyConfig struct {
	Enabled bool

	// RegistryBase is the registry root, e.g. https://ghcr.io, or an operator's
	// own pull-through cache — which is Aqua's own post-outage advice. https
	// only: there is no cleartext registry configuration.
	RegistryBase string

	// TokenHosts is the ALLOWLIST of hosts that may receive a token-exchange
	// request, and therefore the allowlist of hosts that may receive the
	// credential named by CredentialEnv.
	//
	// The registry's own host is always allowed and does not need listing. This
	// field exists for the registries that answer with a realm on a DIFFERENT
	// host — Docker Hub's registry-1.docker.io challenges with a realm on
	// auth.docker.io — and it exists as CONFIGURATION because the alternative
	// is letting the registry's own WWW-Authenticate header decide where the
	// operator's credential goes. A compromised registry, a pull-through cache
	// somebody else runs, a typo'd hostname, or anything that can inject that
	// header would otherwise be choosing the destination.
	//
	// Entries are host, host:port, or an https:// URL. A realm that is not on
	// this list is refused with ErrTokenRealmNotAllowed and NO request is made
	// — not "made without the credential". An unexpected realm means the
	// channel is not what the configuration described, and the correct answer
	// to that is to stop.
	TokenHosts []string

	// Repository is the OCI repository path, e.g. aquasecurity/trivy-db.
	Repository string

	// Reference is the tag or digest. Empty means TrivyDBSchemaReference.
	Reference string

	// CredentialEnv NAMES the environment variable holding a registry token.
	// It is a NAME, never a value: a lower-cased, punctuated string is a
	// pasted token and is refused as a name. The value is read at pull time,
	// held only for the length of one request, and never logged, never
	// written to the manifest, and never included in an error message.
	CredentialEnv string

	// MaxBlobBytes bounds the layer download. Zero means DefaultMaxBlobBytes.
	MaxBlobBytes int64
}

// DefaultConfig returns the shipped configuration: DISABLED, pointed at the
// published endpoints, on the publisher's own cadence.
//
// It is disabled because a fresh clone must not open a socket to a third-party
// registry on somebody's laptop because a package's init decided to be helpful.
// Enabling is an operator act.
func DefaultConfig() Config {
	// CacheDir is left empty rather than resolved here: DefaultCacheDir() can
	// fail, and DefaultConfig() must stay a total function that a package
	// variable or a test can call without handling an error. normalise()
	// resolves it, and normalise() already reports errors.
	return Config{
		Enabled:            false,
		MinRefreshInterval: DefaultMinRefreshInterval,
		Trivy: TrivyConfig{
			Enabled:      true,
			RegistryBase: DefaultTrivyRegistry,
			Repository:   DefaultTrivyRepository,
			Reference:    TrivyDBSchemaReference,
			MaxBlobBytes: DefaultMaxBlobBytes,
		},
		Grype: GrypeConfig{
			Enabled:         true,
			ListingURL:      DefaultGrypeListingURL,
			MaxArchiveBytes: DefaultMaxBlobBytes,
		},
	}
}

// normalise fills defaults and validates. It returns a copy; the caller's
// Config is never mutated.
func (c Config) normalise() (Config, error) {
	out := c
	if strings.TrimSpace(out.CacheDir) == "" {
		d, err := DefaultCacheDir()
		if err != nil {
			return Config{}, err
		}
		out.CacheDir = d
	}
	if out.MinRefreshInterval <= 0 {
		out.MinRefreshInterval = DefaultMinRefreshInterval
	}
	if out.Now == nil {
		out.Now = time.Now
	}
	if out.Trivy.MaxBlobBytes <= 0 {
		out.Trivy.MaxBlobBytes = DefaultMaxBlobBytes
	}
	if out.Grype.MaxArchiveBytes <= 0 {
		out.Grype.MaxArchiveBytes = DefaultMaxBlobBytes
	}
	if out.Trivy.Enabled {
		if strings.TrimSpace(out.Trivy.RegistryBase) == "" {
			return Config{}, refuse(ErrBadConfig, "trivy: no registry base")
		}
		if strings.TrimSpace(out.Trivy.Repository) == "" {
			return Config{}, refuse(ErrBadConfig, "trivy: no repository")
		}
		if strings.TrimSpace(out.Trivy.Reference) == "" {
			out.Trivy.Reference = TrivyDBSchemaReference
		}
		if out.Trivy.CredentialEnv != "" && !validEnvName(out.Trivy.CredentialEnv) {
			// The message names the FIELD, never the value: the value of a
			// mis-set credential_env is very often the token itself.
			return Config{}, refuse(ErrBadConfig,
				"trivy: credential_env must be an environment variable NAME, not a value")
		}
		if _, err := parseEndpoint("trivy registry base", out.Trivy.RegistryBase); err != nil {
			return Config{}, err
		}
		if _, err := normaliseTokenHosts(out.Trivy.TokenHosts); err != nil {
			return Config{}, err
		}
	}
	if out.Grype.Enabled {
		if strings.TrimSpace(out.Grype.ListingURL) == "" {
			return Config{}, refuse(ErrBadConfig, "grype: no listing url")
		}
		if _, err := parseEndpoint("grype listing url", out.Grype.ListingURL); err != nil {
			return Config{}, err
		}
	}
	return out, nil
}

// parseEndpoint is the scope rule applied to ONE configured url, and it is the
// same rule internal/ingest/poller applies per S7: https, a host, no inline
// credentials. It runs on the configured endpoint before any socket opens, and
// again on anything third-party content later names.
//
// There is no cleartext exception, not even for loopback. ErrBadConfig's own
// doc has always said this package refuses "an http URL where https is
// required"; it now does. Tests use httptest.NewTLSServer, which is https on
// loopback, so the no-network rule and the https rule do not conflict — and a
// loopback exception would be a hole an operator could configure into.
func parseEndpoint(what, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, refuse(ErrBadConfig, "%s %q is not a URL", what, raw)
	}
	if u.Host == "" {
		return nil, refuse(ErrBadConfig, "%s %q names no host", what, raw)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, refuse(ErrInsecureTransport,
			"%s uses scheme %q; this channel is https only, because over cleartext the 401 "+
				"challenge that starts the credential exchange is written by whoever is on the path",
			what, u.Scheme)
	}
	if u.User != nil {
		// Inline credentials in a URL are a credential literal in
		// configuration. internal/ingest/config refuses feed URLs with a
		// userinfo component for the same reason.
		return nil, refuse(ErrBadConfig, "%s carries inline credentials", what)
	}
	return u, nil
}

// validEnvName accepts the shape of an environment variable name and nothing
// else. This is the same check internal/ingest/config makes on credential_env
// and for the same reason: it is what stops a pasted secret from being accepted
// where a variable name belongs.
func validEnvName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'A' && ch <= 'Z', ch == '_':
		case ch >= '0' && ch <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// The write-path guard
// ---------------------------------------------------------------------------

// slashClean folds a path to the cleaned, slash-separated form the mirror
// layout is expressed in.
//
// Backslashes are folded because Anvil builds on Windows, where filepath.Join
// produces mirror\tier2\ubuntu — and a quarantine a path separator can walk out
// of is not a quarantine. internal/ingest/license makes the same fold for the
// same reason.
func slashClean(p string) string {
	return path.Clean(strings.ReplaceAll(p, `\`, "/"))
}

// caseInsensitivePaths reports whether the platform this binary was built for
// resolves path components without regard to case. runtime.GOOS is a constant,
// so this is decided at compile time.
//
// It is used for the guard's POSITIVE half only. The negative half — "is this
// inside a licence tier" — folds case unconditionally; see foldPathComponent.
const caseInsensitivePaths = runtime.GOOS == "windows" || runtime.GOOS == "darwin"

// foldPathComponent normalises ONE path component to the form the operating
// system will actually resolve, so that two spellings of one directory compare
// equal.
//
// Two folds, both of them things the OS does and a byte comparison does not:
//
//   - CASE. Windows and macOS open mirror/tier2 when handed MIRROR\Tier2. A
//     byte-exact comparison against "mirror/tier2" is not a path comparison on
//     those hosts; it is a string comparison wearing the clothes of one, and
//     the quarantine it is guarding is the one place that must not be guarded
//     by a lookalike.
//   - TRAILING DOTS AND SPACES. Win32 strips them from a component before the
//     path reaches the filesystem, so "tier2." and "tier2 " name the same
//     directory as "tier2".
//
// Both folds are applied UNCONDITIONALLY, on every platform, even though only
// some platforms behave this way. The fold can only ever map MORE spellings
// onto the tier form, so it can only ever refuse more — and refusing a cache
// root that spells itself "Tier2" costs nothing, because no legitimate cache
// root distinguishes Tier2 from tier2. Making it conditional would mean the
// Linux CI run tests different code from the Windows dev host, on exactly the
// question the Windows host got wrong.
func foldPathComponent(c string) string {
	if c == "" || c == "." || c == ".." {
		return c
	}
	if trimmed := strings.TrimRight(c, ". "); trimmed != "" {
		c = trimmed
	}
	return strings.ToLower(c)
}

// foldPath applies foldPathComponent to every component of a cleaned,
// slash-separated path.
func foldPath(cleaned string) string {
	comps := strings.Split(cleaned, "/")
	for i := range comps {
		comps[i] = foldPathComponent(comps[i])
	}
	return strings.Join(comps, "/")
}

// pathComponents splits a path into its non-empty components, cleaned and
// separator-folded, for comparison AS A PATH rather than as a string.
func pathComponents(p string) []string {
	raw := strings.Split(slashClean(p), "/")
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// componentsEqual compares two path components with the platform's own
// sensitivity. Unlike foldPathComponent this one IS conditional, because it
// serves the guard's positive half, where folding would LOOSEN the check
// rather than tighten it.
func componentsEqual(a, b string) bool {
	if caseInsensitivePaths {
		return strings.EqualFold(strings.TrimRight(a, ". "), strings.TrimRight(b, ". "))
	}
	return a == b
}

// hasPathSuffix reports whether p ends in suffix, comparing component by
// component. strings.HasSuffix would accept "…/notmirror/accelerator/.cache"
// for the suffix "mirror/accelerator/.cache"; this does not.
func hasPathSuffix(p, suffix string) bool {
	pc, sc := pathComponents(p), pathComponents(suffix)
	if len(sc) == 0 || len(pc) < len(sc) {
		return false
	}
	off := len(pc) - len(sc)
	for i := range sc {
		if !componentsEqual(pc[off+i], sc[i]) {
			return false
		}
	}
	return true
}

// pathWithin reports whether child is strictly inside parent, comparing
// component by component rather than by string prefix — a prefix test accepts
// "/a/bc" for the parent "/a/b".
func pathWithin(parent, child string) bool {
	pc, cc := pathComponents(parent), pathComponents(child)
	if len(cc) <= len(pc) {
		return false
	}
	for i := range pc {
		if !componentsEqual(pc[i], cc[i]) {
			return false
		}
	}
	return true
}

// guardNotTiered refuses any path the licence gate would accept as a tiered
// mirror location, at any root.
//
// The check is deliberately an INVERSION of license.CheckWritePath rather than
// a rule of its own. license.CheckWritePath is the authority on what a tier's
// directory looks like; asking it four times and refusing on acceptance means
// the accelerator cannot drift away from the mirror layout as that layout
// changes. A hand-rolled `strings.Contains(p, "mirror/tier")` here would pass
// review and rot on the first layout change.
//
// It is applied at every suffix of the path, so an absolute path such as
// C:/build/mirror/tier2/ubuntu is caught by the tail "mirror/tier2/ubuntu"
// even though the whole string is not a mirror-relative path.
//
// EACH TAIL IS OFFERED TO THE GATE TWICE: once verbatim, and once folded by
// foldPathComponent. The verbatim form is what keeps the delegation honest — if
// license.TierDir ever returns something the fold would mangle, the raw form
// still matches and TestGuardAgreesWithTheLicenceGate still holds. The folded
// form is what makes the comparison a PATH comparison on the hosts where
// MIRROR\Tier2 and mirror/tier2 are one directory. The gate is frozen, so the
// fold lives here: the accelerator is the component performing the write, and
// therefore the component asserting the filesystem property.
func guardNotTiered(p string) error {
	clean := slashClean(p)
	if clean == "" || clean == "." {
		return refuse(ErrBadCacheDir, "empty write path")
	}
	comps := strings.Split(clean, "/")
	for i := range comps {
		if comps[i] == "" {
			continue
		}
		tail := strings.Join(comps[i:], "/")
		folded := foldPath(tail)
		for _, tier := range config.LicenseTierValues() {
			for _, form := range [2]string{tail, folded} {
				if license.CheckWritePath(tier, form) != nil {
					continue
				}
				return refuse(ErrLicenceTierWrite,
					"path %q resolves under %s; the accelerator artifact has no stated "+
						"redistribution terms and therefore no licence tier, and tier 2 is a "+
						"share-alike quarantine that must not receive foreign data",
					clean, license.TierDir(tier))
			}
		}
	}
	return nil
}

// guardCacheRoot is the guard's positive half: the cache root must be shaped
// like an accelerator cache, and must not be inside the mirror.
//
// REPARSE POINTS ARE RESOLVED FIRST, on every component that exists. Without
// that, a directory named .cache that merely POINTS at mirror/tier2 passes every
// string check in this file and writes into the quarantine anyway. On Windows
// there are two kinds of such directory and only one of them needs a privilege
// to create; reparse.go explains why both must be followed and why
// filepath.EvalSymlinks follows only one.
func guardCacheRoot(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", refuse(ErrBadCacheDir, "empty cache directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", refuse(ErrBadCacheDir, "cannot resolve %q: %v", dir, err)
	}
	real, err := resolveRealPath(abs)
	if err != nil {
		return "", err
	}
	// BOTH the literal path and its resolved form are guarded. A .cache link
	// pointing at the quarantine passes every check on the literal path and
	// writes into tier 2 anyway, and a resolved path that no longer looks like a
	// cache root means the layout and the guard have stopped describing the same
	// directory.
	for _, candidate := range []string{abs, real} {
		if err := guardNotTiered(candidate); err != nil {
			return "", err
		}
		if !hasPathSuffix(candidate, CacheDirSuffix) {
			return "", refuse(ErrBadCacheDir,
				"cache root %q must end in %q so that the guard and the layout describe the "+
					"same directory", slashClean(candidate), CacheDirSuffix)
		}
	}
	return real, nil
}

// resolveRealPath is resolveReparsePoints with this package's refusal wrapped
// around its errors, so a path the guard cannot resolve is a refusal and never
// an accepted path.
func resolveRealPath(abs string) (string, error) {
	real, err := resolveReparsePoints(abs)
	if err != nil {
		return "", refuse(ErrBadCacheDir, "cannot resolve %q: %v", abs, err)
	}
	return real, nil
}

// cachePath joins names under the guarded cache root and re-guards the result.
//
// Re-guarding after the join is not belt-and-braces. It is the only check that
// sees the FINAL path, and a name carrying "../../mirror/tier2" would otherwise
// escape a root that was itself perfectly legal.
func cachePath(root string, names ...string) (string, error) {
	for _, n := range names {
		if n == "" || n == "." || n == ".." ||
			strings.ContainsAny(n, `/\`) || strings.HasPrefix(n, ".") && n != ".cache" {
			return "", refuse(ErrBadCacheDir, "unsafe cache file name %q", n)
		}
	}
	full := filepath.Join(append([]string{root}, names...)...)
	if err := guardNotTiered(full); err != nil {
		return "", err
	}
	if !pathWithin(root, full) {
		return "", refuse(ErrBadCacheDir, "path %q escapes the cache root", full)
	}
	return full, nil
}

// CacheDir returns the resolved cache root for a configuration, having put it
// through the same guard a write would.
//
// It exists so an external scanner binary can be pointed at the warm cache —
// `trivy --cache-dir`, for instance. It hands out a PATH, not bytes: this
// package still exposes no reader, and handing out a path is not serving the
// artifact.
func CacheDir(cfg Config) (string, error) {
	c, err := cfg.normalise()
	if err != nil {
		return "", err
	}
	return guardCacheRoot(c.CacheDir)
}

// ---------------------------------------------------------------------------
// The cache manifest
// ---------------------------------------------------------------------------

// Manifest is the cache's record of itself.
type Manifest struct {
	// ConsumeOnly is always true when written, and a manifest read back with
	// it false is refused. It is one bool carrying the entire legal posture of
	// this directory, which is why it is checked rather than assumed.
	ConsumeOnly bool `json:"consume_only"`

	// Redistribution is the human-readable form of the same fact, for the
	// operator who finds this directory without this source code.
	Redistribution string `json:"redistribution"`

	// OutsideLicenceMirror records that this cache carries no licence tier.
	OutsideLicenceMirror bool `json:"outside_licence_mirror"`

	// UpdatedAt is when the manifest was last written.
	UpdatedAt time.Time `json:"updated_at"`

	// Sources are the pulled artifacts, keyed by SourceRecord.Name.
	Sources []SourceRecord `json:"sources"`
}

// SourceRecord is one pulled artifact.
//
// Every field here is read by an operator who has this directory and not this
// source file, so every field states only what was actually established. Two
// of them exist because the obvious spelling would have overstated:
//
//   - SchemaVersion is OMITTED when the configured reference does not determine
//     it. Grype records the schema it parsed out of the listing; Trivy can only
//     record a schema when the reference names one, and a constant written into
//     the field regardless would be a claim nobody checked.
//   - VerifiedAgainst says what ChecksumVerified:true was verified AGAINST.
//     "checksum_verified" alone reads as provenance and it is not: it is
//     transport integrity against a digest that came out of the same
//     unauthenticated response as the content.
type SourceRecord struct {
	Name              string    `json:"name"`
	Origin            string    `json:"origin"`
	Reference         string    `json:"reference"`
	Digest            string    `json:"digest"`
	MediaType         string    `json:"media_type,omitempty"`
	File              string    `json:"file"`
	Bytes             int64     `json:"bytes"`
	SchemaVersion     int       `json:"schema_version,omitempty"`
	ClientPin         string    `json:"client_pin,omitempty"`
	ChecksumVerified  bool      `json:"checksum_verified"`
	ChecksumAlgorithm string    `json:"checksum_algorithm,omitempty"`
	VerifiedAgainst   string    `json:"verified_against,omitempty"`
	PulledAt          time.Time `json:"pulled_at"`
}

// verifiedAgainst* say, in the manifest itself, exactly how strong
// checksum_verified is. They are prose because the reader is a person.
const (
	verifiedAgainstTrivyManifest = "the layer digest stated by the registry's own image manifest, " +
		"which was fetched by tag over an unauthenticated channel. TRANSPORT INTEGRITY ONLY: " +
		"whoever answered that request chose the digest. No signature (cosign/sigstore) was checked, " +
		"so this is not provenance."

	verifiedAgainstGrypeListing = "the sha256 stated by the listing document that named this archive. " +
		"TRANSPORT INTEGRITY ONLY: the listing and the archive come from the same unauthenticated " +
		"origin. No signature was checked, so this is not provenance."
)

// SourceTrivyDB and SourceGrypeDB name the two records.
const (
	SourceTrivyDB = "trivy-db"
	SourceGrypeDB = "grype-db"
)

func (m *Manifest) find(name string) (SourceRecord, bool) {
	for _, s := range m.Sources {
		if s.Name == name {
			return s, true
		}
	}
	return SourceRecord{}, false
}

func (m *Manifest) upsert(rec SourceRecord) {
	for i := range m.Sources {
		if m.Sources[i].Name == rec.Name {
			m.Sources[i] = rec
			return
		}
	}
	m.Sources = append(m.Sources, rec)
}

// readManifest loads the cache manifest. A missing manifest is an empty one,
// not an error — a cold cache is the normal first state.
func readManifest(root string) (*Manifest, error) {
	p, err := cachePath(root, ManifestFileName)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return &Manifest{}, nil
	}
	if err != nil {
		return nil, refuse(ErrBadCacheDir, "cannot read %s: %v", ManifestFileName, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, refuse(ErrBadCacheDir, "cannot parse %s: %v", ManifestFileName, err)
	}
	if !m.ConsumeOnly {
		return nil, refuse(ErrTamperedManifest,
			"%s exists with consume_only=false; refusing to reuse a cache that asserts it may "+
				"be redistributed, because whoever set that may already have acted on it", ManifestFileName)
	}
	return &m, nil
}

// writeManifest writes the manifest atomically, always asserting consume_only.
func writeManifest(root string, m *Manifest, now time.Time) error {
	m.ConsumeOnly = true
	m.Redistribution = consumeOnlyNotice
	m.OutsideLicenceMirror = true
	m.UpdatedAt = now.UTC()
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return refuse(ErrBadCacheDir, "cannot encode %s: %v", ManifestFileName, err)
	}
	return writeFileAtomic(root, ManifestFileName, append(raw, '\n'))
}

// guardWriteTarget re-runs the ENTIRE guard against the directory a write is
// about to touch, after that directory exists, and returns the reparse-free
// destination to write to.
//
// It exists because configure time and write time are different moments, and a
// check made only at the first one answers a question about the past. Between
// guardCacheRoot accepting a cache root and pullTrivyDB installing ~100 MB into
// it there is a network round trip — seconds, sometimes minutes — and during it
// an ordinary unprivileged process can `rmdir` the cache directory and `mklink
// /J` a junction of the same name pointing at mirror/tier2. Nothing needs to be
// malicious for this to happen either; a build script that relocates a cache
// does it by accident.
//
// Three things are therefore established HERE and not inherited:
//
//   - The directory is created FIRST, then resolved. A path that does not exist
//     cannot be resolved, so the configure-time check on a first run is
//     necessarily a check on text. This one is a check on a directory.
//   - The resolved root is re-guarded in full — quarantine and cache shape —
//     rather than trusted because it was guarded before.
//   - The write goes to the RESOLVED path, not the path as written. Following
//     the reparse points once and then writing through the original spelling
//     would re-open every link the resolution just walked past.
func guardWriteTarget(root, name string) (dir, final string, err error) {
	lexical, err := cachePath(root, name)
	if err != nil {
		return "", "", err
	}
	parent := filepath.Dir(lexical)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", "", refuse(ErrBadCacheDir, "cannot create cache directory: %v", err)
	}
	realDir, err := guardCacheRoot(parent)
	if err != nil {
		return "", "", err
	}
	realFinal := filepath.Join(realDir, name)
	if err := guardNotTiered(realFinal); err != nil {
		return "", "", err
	}
	if !pathWithin(realDir, realFinal) {
		return "", "", refuse(ErrBadCacheDir, "path %q escapes the cache root", realFinal)
	}
	return realDir, realFinal, nil
}

// writeFileAtomic writes through the guard, via a temp file in the same
// directory, so a crashed pull never leaves a half-written cache that looks
// complete.
//
// The guard it writes through is guardWriteTarget, which re-verifies the
// destination at this moment rather than trusting the moment the cache root was
// configured.
func writeFileAtomic(root, name string, data []byte) error {
	dir, final, err := guardWriteTarget(root, name)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-"+name+"-*")
	if err != nil {
		return refuse(ErrBadCacheDir, "cannot create temp file: %v", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return refuse(ErrBadCacheDir, "cannot write temp file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return refuse(ErrBadCacheDir, "cannot close temp file: %v", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return refuse(ErrBadCacheDir, "cannot install %s: %v", name, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// WarmStart
// ---------------------------------------------------------------------------

// WarmStart is the packet-named entry point. It runs DefaultConfig(), which is
// DISABLED, so out of the box it does nothing and returns nil.
//
// That is not a placeholder. An accelerator that pulls a third-party database
// because a binary started is an accelerator that has decided on the operator's
// behalf to open a socket, spend a shared rate-limit budget and consume ~100 MB
// of disk. The operator decides; WarmStartWith is how they say so.
func WarmStart(ctx context.Context) error {
	return WarmStartWith(ctx, DefaultConfig())
}

// WarmStartWith runs the warm start under an explicit configuration.
//
// THE RETURNED ERROR IS ADVISORY. Every failure here leaves Anvil correct and
// merely cold. Callers should log it and continue; a caller that treats it as
// fatal has converted an optimisation into a dependency, which is the exact
// failure mode this package is shaped to prevent.
//
// Both sources are attempted even if the first fails, and their errors are
// joined: a Grype outage must not suppress a perfectly good Trivy warm start.
func WarmStartWith(ctx context.Context, cfg Config) error {
	if !cfg.Enabled {
		return nil
	}
	c, err := cfg.normalise()
	if err != nil {
		return err
	}

	// The client pin is checked BEFORE any network call. A pin below the
	// minimum is a configuration defect that a successful download would only
	// disguise — see grypedb.go.
	if err := CheckClientPins(); err != nil {
		return err
	}

	root, err := guardCacheRoot(c.CacheDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return refuse(ErrBadCacheDir, "cannot create cache directory: %v", err)
	}
	// Guarded AGAIN, now that the directory exists. The check above ran against
	// a path that on a first run was only text; this one runs against a
	// directory, so reparse points that MkdirAll walked through — or that were
	// put there between the two calls — are resolved and refused. Every
	// subsequent write re-checks as well, in guardWriteTarget.
	root, err = guardCacheRoot(root)
	if err != nil {
		return err
	}
	man, err := readManifest(root)
	if err != nil {
		return err
	}

	now := c.Now()
	var errs []error
	changed := false

	if c.Trivy.Enabled {
		rec, ok := man.find(SourceTrivyDB)
		if ok && now.Sub(rec.PulledAt) < c.MinRefreshInterval {
			// Fresh enough. Research/06 Risk #6: the publisher's own cadence
			// is 24h, and out-pulling it spends a shared budget for nothing.
			_ = rec
		} else if newRec, err := pullTrivyDB(ctx, c, root, now); err != nil {
			errs = append(errs, err)
		} else {
			man.upsert(newRec)
			changed = true
		}
	}

	if c.Grype.Enabled {
		rec, ok := man.find(SourceGrypeDB)
		if ok && now.Sub(rec.PulledAt) < c.MinRefreshInterval {
			_ = rec
		} else if newRec, err := pullGrypeDB(ctx, c, root, now); err != nil {
			errs = append(errs, err)
		} else {
			man.upsert(newRec)
			changed = true
		}
	}

	// The manifest is rewritten whenever anything changed, and also when the
	// cache is brand new, so a cache directory never exists without the
	// consume_only marker beside it.
	if changed || len(man.Sources) == 0 {
		if err := writeManifest(root, man, now); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ---------------------------------------------------------------------------
// Trivy DB — the OCI pull
// ---------------------------------------------------------------------------

// pullTrivyDB fetches the Trivy DB layer from an OCI registry into the cache.
//
// It speaks the OCI distribution API directly over net/http rather than
// linking a registry client, because adding a dependency is a licence decision
// and the subset needed here — one manifest GET, one blob GET, one anonymous
// token exchange — is small and fully exercised by the tests.
func pullTrivyDB(ctx context.Context, cfg Config, root string, now time.Time) (SourceRecord, error) {
	rc, err := newRegistryClient(cfg)
	if err != nil {
		return SourceRecord{}, err
	}
	// The credential NAME travels on the context; the VALUE is materialised
	// inside exchangeToken and nowhere else.
	ctx = withCredentialEnv(ctx, cfg.Trivy.CredentialEnv)

	man, err := rc.fetchManifest(ctx, cfg.Trivy.Reference)
	if err != nil {
		return SourceRecord{}, err
	}
	layer, err := selectTrivyLayer(man)
	if err != nil {
		return SourceRecord{}, err
	}

	blob, err := rc.fetchBlob(ctx, layer.Digest, cfg.Trivy.MaxBlobBytes)
	if err != nil {
		return SourceRecord{}, err
	}

	const fileName = "trivy-db.tar.gz"
	if err := writeFileAtomic(root, fileName, blob); err != nil {
		return SourceRecord{}, err
	}

	// The schema is DERIVED from the reference that was actually used, and
	// omitted when the reference does not determine one. Writing the constant
	// unconditionally would record schema_version:2 beside reference:"3" — a
	// field stating something nobody verified, in the one file a future
	// operator reads to find out what is on this disk.
	schema, _ := trivySchemaFromReference(cfg.Trivy.Reference)

	return SourceRecord{
		Name:              SourceTrivyDB,
		Origin:            rc.origin(),
		Reference:         cfg.Trivy.Reference,
		Digest:            layer.Digest,
		MediaType:         layer.MediaType,
		File:              fileName,
		Bytes:             int64(len(blob)),
		SchemaVersion:     schema,
		ChecksumVerified:  true,
		ChecksumAlgorithm: "sha256",
		VerifiedAgainst:   verifiedAgainstTrivyManifest,
		PulledAt:          now.UTC(),
	}, nil
}

// trivySchemaFromReference reports the DB schema a reference denotes, and
// whether it denotes one at all.
//
// For this artifact the tag IS the schema — `trivy-db:2` is schema 2 — so a
// bare integer tag determines it. A digest, or any other tag, does not: the
// only way to learn the schema would be to open the database, and this package
// deliberately cannot read the artifact it pulls. So it reports "unknown" and
// the field is omitted, which is the honest answer.
func trivySchemaFromReference(ref string) (int, bool) {
	s := strings.TrimSpace(ref)
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// ociDescriptor is the subset of an OCI descriptor this package reads.
type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// ociManifest is the subset of an OCI image manifest this package reads.
type ociManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Layers        []ociDescriptor `json:"layers"`
	Manifests     []ociDescriptor `json:"manifests"`
}

// selectTrivyLayer picks the DB layer.
//
// The Trivy DB media type is preferred. A single-layer manifest with some other
// media type is accepted, because the artifact's media type is the publisher's
// to change. Anything ambiguous is REFUSED rather than guessed: picking one of
// several layers by position would be inventing a rule the publisher never
// stated, and the failure would be a silently wrong database.
func selectTrivyLayer(m *ociManifest) (ociDescriptor, error) {
	if len(m.Manifests) > 0 || m.MediaType == ociIndexMediaType || m.MediaType == dockerIndexMediaType {
		return ociDescriptor{}, refuse(ErrRegistry,
			"reference resolved to an image index (%s); the Trivy DB artifact is a plain "+
				"manifest and selecting a platform out of an index would be a rule Anvil invented",
			m.MediaType)
	}
	for _, l := range m.Layers {
		if l.MediaType == trivyDBLayerMediaType {
			return l, nil
		}
	}
	if len(m.Layers) == 1 {
		return m.Layers[0], nil
	}
	return ociDescriptor{}, refuse(ErrRegistry,
		"manifest has %d layers and none carries %s; refusing to guess which one is the database",
		len(m.Layers), trivyDBLayerMediaType)
}

// ---------------------------------------------------------------------------
// A minimal OCI distribution client
// ---------------------------------------------------------------------------

type registryClient struct {
	base  *url.URL
	repo  string
	httpc *http.Client

	// tokenHosts is the resolved allowlist of "hostname:port" endpoints that
	// may receive a token exchange, and therefore the credential. It is built
	// from CONFIGURATION — the registry base plus TrivyConfig.TokenHosts — and
	// nothing the registry says can add to it.
	tokenHosts []string

	// token is a registry bearer token held for the life of one warm start.
	// It is never logged, never written to the manifest, and never placed in
	// an error message. Nothing in this file formats it.
	token string
}

func newRegistryClient(cfg Config) (*registryClient, error) {
	u, err := parseEndpoint("trivy registry base", strings.TrimSuffix(cfg.Trivy.RegistryBase, "/"))
	if err != nil {
		return nil, err
	}
	extra, err := normaliseTokenHosts(cfg.Trivy.TokenHosts)
	if err != nil {
		return nil, err
	}
	return &registryClient{
		base:       u,
		repo:       strings.Trim(cfg.Trivy.Repository, "/"),
		httpc:      httpClient(cfg),
		tokenHosts: append([]string{hostPort(u)}, extra...),
	}, nil
}

// hostPort renders a URL's authority as the lower-cased "hostname:port" the
// request will actually connect to, filling in the scheme's default port so
// that an explicit :443 and an absent port compare equal. It is the same
// normalisation internal/ingest/poller's effectivePort performs, for the same
// reason: two spellings of one endpoint must not compare unequal.
func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if p, err := net.LookupPort("tcp", u.Scheme); err == nil {
			port = strconv.Itoa(p)
		}
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

// normaliseTokenHosts turns configured allowlist entries into "hostname:port".
//
// Entries may be written as a bare host, host:port, or an https:// URL. A bare
// host means the default https port, because that is what an operator writing
// "auth.docker.io" means and silently accepting any port would widen the
// allowlist past what they wrote.
func normaliseTokenHosts(entries []string) ([]string, error) {
	out := make([]string, 0, len(entries))
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			return nil, refuse(ErrBadConfig, "trivy: token_hosts contains an empty entry")
		}
		if !strings.Contains(e, "://") {
			e = "https://" + e
		}
		u, err := parseEndpoint("trivy token host", e)
		if err != nil {
			return nil, err
		}
		if u.Path != "" && u.Path != "/" {
			return nil, refuse(ErrBadConfig,
				"trivy: token_hosts entry %q names a path; the allowlist is of HOSTS, and a path "+
					"in it reads as a restriction that is not enforced", raw)
		}
		out = append(out, hostPort(u))
	}
	return out, nil
}

func (rc *registryClient) origin() string {
	return rc.base.String() + "/" + rc.repo
}

// httpClient copies the caller's client and installs the S7 redirect policy.
// http.Client has no unexported state, so the copy is safe, and copying means
// the caller's client is not mutated by having been passed in.
//
// EVERY HOP IS RE-VALIDATED AGAINST THE ORIGINAL REQUEST, not against the
// previous hop. Checking against the previous hop accepts a chain of
// individually-legal steps that ends somewhere the configuration never named,
// and "each step looked fine" is how a redirect chain becomes an SSRF. This is
// the same rule internal/ingest/poller.sameOrigin applies, deliberately spelled
// the same way: host, scheme, effective port, and no inline credentials.
func httpClient(cfg Config) *http.Client {
	var c http.Client
	if cfg.HTTPClient != nil {
		c = *cfg.HTTPClient
	} else {
		c.Timeout = 15 * time.Minute
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return refuse(ErrRegistry, "too many redirects")
		}
		if len(via) == 0 {
			return nil
		}
		return sameOrigin("redirect", via[0].URL, req.URL)
	}
	return &c
}

// sameOrigin refuses any move off the origin the request started from: a
// different hostname, a different scheme, a different effective port, or a
// target carrying inline credentials.
func sameOrigin(what string, configured, next *url.URL) error {
	if !strings.EqualFold(next.Hostname(), configured.Hostname()) {
		return refuse(ErrRegistry,
			"%s: request started at host %q and the response points at %q; a cross-host hop is "+
				"never followed", what, configured.Hostname(), next.Hostname())
	}
	if !strings.EqualFold(next.Scheme, configured.Scheme) {
		return refuse(ErrInsecureTransport,
			"%s: request started on scheme %q and the response points at %q",
			what, configured.Scheme, next.Scheme)
	}
	if hostPort(next) != hostPort(configured) {
		return refuse(ErrRegistry,
			"%s: request started at %q and the response points at %q",
			what, hostPort(configured), hostPort(next))
	}
	if next.User != nil {
		return refuse(ErrRegistry, "%s: the response points at a url carrying inline credentials", what)
	}
	return nil
}

func (rc *registryClient) do(ctx context.Context, u string, accept []string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, refuse(ErrRegistry, "cannot build request: %v", err)
	}
	for _, a := range accept {
		req.Header.Add("Accept", a)
	}
	if rc.token != "" {
		req.Header.Set("Authorization", "Bearer "+rc.token)
	}
	resp, err := rc.httpc.Do(req)
	if err != nil {
		return nil, refuse(ErrRegistry, "request failed: %v", redactURLError(err))
	}
	return resp, nil
}

// fetchManifest gets the image manifest, performing one anonymous-or-credentialed
// token exchange if the registry challenges.
func (rc *registryClient) fetchManifest(ctx context.Context, ref string) (*ociManifest, error) {
	accept := []string{ociManifestMediaType, dockerManifestMediaType}
	u := fmt.Sprintf("%s/v2/%s/manifests/%s", rc.base.String(), rc.repo, url.PathEscape(ref))

	resp, err := rc.do(ctx, u, accept)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		_ = resp.Body.Close()
		if err := rc.exchangeToken(ctx, challenge); err != nil {
			return nil, err
		}
		if resp, err = rc.do(ctx, u, accept); err != nil {
			return nil, err
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if err := checkStatus(resp, "manifest"); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, refuse(ErrRegistry, "cannot read manifest: %v", err)
	}
	var m ociManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, refuse(ErrRegistry, "cannot parse manifest: %v", err)
	}
	return &m, nil
}

// exchangeToken performs the registry token dance. It is the ONLY place a
// credential is read, and the value never leaves this function except as an
// Authorization header.
//
// THE REALM IS UNTRUSTED INPUT AND IS PINNED TO CONFIGURATION BEFORE ANYTHING
// ELSE HAPPENS. It arrives in a WWW-Authenticate header written by the thing
// being talked to. "It parses and has a host" is a syntax note, not a check,
// and the request that follows carries the operator's registry credential — so
// a registry that is compromised, mistyped, or merely someone else's
// pull-through cache would otherwise be choosing where an ops-provisioned PAT
// is sent. That is credential exfiltration driven by untrusted input, in a tool
// whose entire job is to be pointed at untrusted things.
//
// The check runs BEFORE the request is built, so nothing is sent anywhere the
// allowlist does not name — not the credential, and not the request either. A
// realm that is not on the list means the channel is not what the
// configuration described; the answer to that is to stop, loudly, rather than
// to proceed anonymously and hope.
func (rc *registryClient) exchangeToken(ctx context.Context, challenge string) error {
	realm, params := parseBearerChallenge(challenge)
	if realm == "" {
		return refuse(ErrRegistry, "registry returned 401 with no usable Bearer challenge")
	}
	tu, err := rc.checkTokenRealm(realm)
	if err != nil {
		return err
	}
	q := tu.Query()
	if svc := params["service"]; svc != "" {
		q.Set("service", svc)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + rc.repo + ":pull"
	}
	q.Set("scope", scope)
	tu.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tu.String(), nil)
	if err != nil {
		return refuse(ErrRegistry, "cannot build token request: %v", err)
	}
	// The credential is read here and nowhere else. It is not stored on the
	// client, not compared, not logged, and not written anywhere.
	if secret := readCredential(ctx); secret != "" {
		req.SetBasicAuth("x-access-token", secret)
	}
	resp, err := rc.httpc.Do(req)
	if err != nil {
		return refuse(ErrRegistry, "token request failed: %v", redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if err := checkStatus(resp, "token"); err != nil {
		return err
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return refuse(ErrRegistry, "cannot read token response: %v", err)
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return refuse(ErrRegistry, "cannot parse token response")
	}
	rc.token = body.Token
	if rc.token == "" {
		rc.token = body.AccessToken
	}
	if rc.token == "" {
		return refuse(ErrRegistry, "token response carried no token")
	}
	return nil
}

// checkTokenRealm validates a realm the registry named against the allowlist
// that was configured alongside the registry.
//
// The refusals are attributed to the REGISTRY, not to the configuration: an
// unexpected realm is the remote end behaving unexpectedly, and an error that
// blames the operator sends them to fix the wrong file.
func (rc *registryClient) checkTokenRealm(realm string) (*url.URL, error) {
	tu, err := url.Parse(strings.TrimSpace(realm))
	if err != nil || tu.Host == "" {
		return nil, refuse(ErrTokenRealmNotAllowed, "registry token realm is not a URL")
	}
	if !strings.EqualFold(tu.Scheme, "https") {
		return nil, refuse(ErrInsecureTransport,
			"registry named a token realm on scheme %q; the credential exchange is https only", tu.Scheme)
	}
	if tu.User != nil {
		return nil, refuse(ErrTokenRealmNotAllowed, "registry named a token realm carrying inline credentials")
	}
	want := hostPort(tu)
	for _, allowed := range rc.tokenHosts {
		if want == allowed {
			return tu, nil
		}
	}
	// The refused host IS named, because an operator adding a legitimate
	// second auth host needs to know what to allowlist, and because a stolen
	// credential's destination is exactly what an incident responder needs. No
	// part of the credential appears here.
	return nil, refuse(ErrTokenRealmNotAllowed,
		"registry challenged with a token realm on %q, which is not the registry host and is not "+
			"listed in trivy.token_hosts %v; refusing to send a token exchange — and therefore the "+
			"operator's credential — to a host chosen by the thing being talked to",
		want, rc.tokenHosts)
}

// credentialEnvKey is the context key carrying the configured credential
// variable NAME into the token exchange. Passing the NAME rather than the value
// keeps the secret out of every struct field and every log line: the value is
// materialised at the moment it is used and is never assigned to anything that
// outlives the request.
type credentialEnvKey struct{}

func withCredentialEnv(ctx context.Context, envName string) context.Context {
	if envName == "" {
		return ctx
	}
	return context.WithValue(ctx, credentialEnvKey{}, envName)
}

func readCredential(ctx context.Context) string {
	name, _ := ctx.Value(credentialEnvKey{}).(string)
	if name == "" || !validEnvName(name) {
		return ""
	}
	return os.Getenv(name)
}

// parseBearerChallenge pulls realm and the other parameters out of a
// WWW-Authenticate header.
func parseBearerChallenge(h string) (realm string, params map[string]string) {
	params = map[string]string{}
	h = strings.TrimSpace(h)
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return "", params
	}
	for _, part := range splitChallenge(h[len("bearer "):]) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		if key == "realm" {
			realm = val
			continue
		}
		params[key] = val
	}
	return realm, params
}

// splitChallenge splits on commas that are not inside a quoted string.
func splitChallenge(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}

// fetchBlob downloads and digest-verifies a blob.
func (rc *registryClient) fetchBlob(ctx context.Context, digest string, maxBytes int64) ([]byte, error) {
	alg, want, err := splitDigest(digest)
	if err != nil {
		return nil, err
	}
	if alg != "sha256" {
		return nil, refuse(ErrRegistry, "unsupported digest algorithm %q", alg)
	}
	u := fmt.Sprintf("%s/v2/%s/blobs/%s", rc.base.String(), rc.repo, url.PathEscape(digest))
	resp, err := rc.do(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := checkStatus(resp, "blob"); err != nil {
		return nil, err
	}
	data, err := readCapped(resp.Body, maxBytes, "trivy db layer")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, refuse(ErrDigestMismatch,
			"blob sha256 is %s but the manifest named %s", got, want)
	}
	return data, nil
}

func splitDigest(d string) (alg, hexdigest string, err error) {
	parts := strings.SplitN(strings.TrimSpace(d), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", refuse(ErrRegistry, "malformed digest %q", d)
	}
	return strings.ToLower(parts[0]), strings.ToLower(parts[1]), nil
}

// readCapped reads at most maxBytes, and refuses a body that would exceed it
// rather than silently truncating. A truncated database that parses is worse
// than no database.
func readCapped(r io.Reader, maxBytes int64, what string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, refuse(ErrRegistry, "cannot read %s: %v", what, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, refuse(ErrTooLarge, "%s exceeds the %d byte ceiling", what, maxBytes)
	}
	return data, nil
}

// checkStatus turns an HTTP status into this package's vocabulary. 429 is
// named separately because it is the failure this channel is already known to
// produce under load (research/06 Risk #6).
func checkStatus(resp *http.Response, what string) error {
	switch {
	case resp.StatusCode == http.StatusOK:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		retry := resp.Header.Get("Retry-After")
		if retry == "" {
			retry = "unspecified"
		}
		return refuse(ErrRateLimited,
			"%s: HTTP 429 (retry-after %s); this is the documented TOOMANYREQUESTS behaviour of "+
				"the published DB channel, not an Anvil fault — the warm start is skipped and "+
				"ingestion proceeds cold", what, retry)
	default:
		return refuse(ErrRegistry, "%s: HTTP %d", what, resp.StatusCode)
	}
}

// redactURLError strips the URL from a *url.Error before it reaches a log.
// A registry URL can carry a token in its query string after a token exchange,
// and an error string is the easiest place in a program for a secret to leak.
func redactURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + " " + redactURL(ue.URL) + ": " + ue.Err.Error()
	}
	return err.Error()
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparseable url]"
	}
	u.RawQuery = ""
	u.User = nil
	return u.String()
}
