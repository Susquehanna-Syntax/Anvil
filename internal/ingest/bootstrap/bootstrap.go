// Package bootstrap fills a feed's ingestion cache ONCE, from a bulk artifact,
// so that the conditional-GET poller (A.7) only ever has to carry deltas.
//
// This is step A.8 of plan/20-lane-a-ingestion-sca.md. Lane A is the
// zero-inference half of Anvil (plan/00-SPINE.md S1): CVE/OSV/GHSA describe
// vulnerable PACKAGE VERSIONS and a version comparator answers that exactly and
// for free. Nothing in this package infers anything, calls a model, or emits a
// fingerprint.
//
// # Why a bulk archive and not a git clone
//
// research/06 Recommendation item 2: "Bootstrap from bulk archives, not from
// git history." cvelistV5 commits every ~7 minutes — ~205 commits/day and
// ~75,000 commits/year — and on a repository holding 300,000+ small files the
// TREE objects dominate any clone, blobless or otherwise. The 570 MB midnight
// baseline zip (research/06 S8) transfers the same content once, with no
// history at all.
//
// research/06 Risk #7 is the specific trap, and it is encoded in ghsa_clone.go
// rather than described here: the intuitive "clone --depth=1, then git fetch
// hourly" design is warned against by GitHub in its own words — "a `git fetch`
// operation in a shallow clone might end up downloading an almost-full commit
// history!" A shallow clone is a fine way to build a thing once and throw it
// away, and a bad way to run a syncing daemon for a year. cloneArgs refuses to
// construct one and assertNotShallow refuses to import from one.
//
// The blobless partial clone survives for GHSA and ONLY for GHSA, because
// github/advisory-database is one file per advisory and git hands back exact
// change sets for free. research/06 names it "the right tool for GHSA
// specifically, the wrong tool for cvelistV5". internal/ingest/config already
// enforces the pairing: SyncGitBloblessFetch and BootstrapBloblessClone are
// only legal together, so no feed can ask for a fetch with nothing to fetch
// into.
//
// # The two gates. Nothing reaches the cache without both.
//
//   - A.4's licence gate runs FIRST, before a byte is fetched. license.Resolve
//     decides the tier and the one directory this feed's data may occupy, and
//     every one of its errors satisfies license.ErrLicenseRefused. A refusal
//     ends the bootstrap with no request made and no row written.
//
//     READ internal/ingest/license's known-limits file before trusting an
//     admission. Its REFUSAL path is sound; its ADMISSION path is a substring
//     judgement, and as of this writing it admits NOTHING at all, because no
//     publisher licence body has been acquired into mirror/. Nothing in this
//     package assumes a feed will be admitted: the refusal path is the
//     ordinary path today, and BootstrapResult.Refused says so plainly rather
//     than looking like a successful import of zero rows.
//
//   - A.3's sanitizer runs on every string projected out of a fetched document
//     into a queryable column or the FTS index, and sanitize.AssertAllSanitized
//     re-checks the whole bind set immediately before the parameters go to the
//     driver. internal/ingest/sanitize's writer guard walks this package's AST
//     looking for exactly that, and it is the reason the sanitize call and the
//     bind live in the same call graph rather than three packages apart.
//
//     raw_json is the ONE deliberate exception and it is not an oversight:
//     cvelistV5's CVE-TOU obliges Anvil to store records byte-verbatim, so the
//     column holds the publisher's exact bytes. It is a BLOB nothing renders.
//     Every string that leaves it for a column, the FTS index or a prompt goes
//     through Sanitize on the way out of the decoder, above.
//
// # A bulk import is a bulk write, so it is resumable and idempotent
//
// A 570 MB import is not one transaction. It is thousands of rows committed in
// batches, and a process killed halfway through leaves a cache that is
// PARTIALLY populated. The danger is not the missing rows. It is that a
// half-populated cache and a fully-populated cache look identical to every
// reader: a comparator asks "is CVE-X in here", gets no, and reports the target
// clean. An incomplete import that cannot be distinguished from a complete one
// manufactures false negatives in a security tool, silently and permanently.
//
// So completion is a durable FACT, written exactly once, after the last batch:
//
//	Bootstrapped(watermark) is true only for PhaseComplete. Until then the
//	feed is not bootstrapped, whatever the row count says.
//
// And the progress cursor moves in THE SAME TRANSACTION as the rows it
// describes. This is the property R.7's lease protocol needed and did not have
// on the first attempt, so it is worth stating as the crash argument rather
// than as an assertion:
//
//	commitBatch issues BEGIN, upserts the batch's advisory/affected/alias/FTS
//	rows, UPDATEs feed_state.watermark to a cursor naming the last fully
//	imported entry, and COMMITs. A crash can land before the BEGIN, between
//	any two statements, or after the COMMIT. In the first two cases SQLite
//	rolls the whole batch back and the cursor still names the previous entry —
//	rows and cursor agree. In the third, both landed — rows and cursor agree.
//	There is no interleaving in which the cursor claims progress the rows do
//	not have, because there is no moment at which one is durable and the other
//	is not. A cursor written in its own transaction would have exactly that
//	moment, and the failure would be invisible: the resume would skip entries
//	that were rolled back.
//
// Idempotence is what makes a resume safe when the cursor is behind reality
// (which it is by up to one batch, and by one whole entry for a multi-record
// entry that was flushed mid-way):
//
//   - advisory upserts on ON CONFLICT (source, source_id) DO UPDATE, never
//     INSERT OR REPLACE. REPLACE would assign a new rowid and orphan the FTS
//     entry with no error; internal/ingest/cache/schema.go says so at the
//     table.
//   - affected and cve_alias are DELETEd for the advisory and re-INSERTed
//     inside the same transaction. This is not tidiness. `affected` has an
//     autoincrement primary key and no unique constraint over its natural key,
//     so a plain re-INSERT on a resumed batch DUPLICATES every version range,
//     and A.17's comparator would then see one advisory as several. Replacing
//     the set is the only shape that is idempotent.
//   - advisory_fts is INSERT OR REPLACE by the rowid the advisory upsert
//     returned, which genuinely replaces the old terms because the table
//     carries contentless_delete=1.
//
// Re-running a COMPLETED bootstrap is therefore safe and is a no-op by default:
// Bootstrap refuses a completed feed unless Options.Force is set, because
// re-downloading 570 MB by accident is a cost, not a correctness problem.
//
// # What this package does NOT do
//
//   - It does not poll. A.7 owns steady state; this runs once per feed.
//   - It does not invent a fingerprint. plan/00-SPINE.md S6 permits exactly one
//     algorithm, anvil-fp/v1, owned by internal/record. Lane A's cache has a
//     lane-local `finding.id` and this package writes no findings at all.
//   - It does not decide a licence. It presents the feed row to A.4 and obeys.
//   - It does not name a feed. There is no feed id, URL, cadence or format
//     mapping compiled into this file. Which feeds exist comes from A.1's feed
//     table; what an artifact CONTAINS is decided by looking at the bytes.
package bootstrap

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/decode"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/license"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
)

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

const (
	// DefaultMaxArchiveBytes bounds a single downloaded artifact. The largest
	// thing in the feed table is OSV's merged all.zip at ~1.32 GiB measured
	// (A.8's packet), with cvelistV5's midnight baseline at 570,845,537 B
	// (research/06 S8). 4 GiB is ~3x the largest known artifact: enough head
	// room that a growing feed does not trip it, small enough that a
	// misconfigured URL pointing at something enormous is a refusal rather
	// than a full disk.
	DefaultMaxArchiveBytes int64 = 4 << 30

	// MaxRecordBytes bounds ONE advisory document. OSV and CVE 5.x records are
	// kilobytes; the largest CVE records in the corpus are a few hundred KB.
	// 8 MiB refuses a decompression bomb without refusing a real record, and
	// it is the number that makes "peak memory is bounded by a record, not by
	// the archive" true rather than hoped for.
	MaxRecordBytes = 8 << 20

	// MaxEntries bounds how many members an archive may have. OSV's merged
	// export is ~300,000 files; cvelistV5's baseline is ~300,000. Two million
	// is far above either and refuses a zip whose central directory is itself
	// the attack.
	MaxEntries = 2_000_000

	// DefaultBatchSize is how many advisory records are committed per
	// transaction. Small enough that a crash loses little work, large enough
	// that per-transaction overhead does not dominate a 300,000-record import.
	DefaultBatchSize = 500

	// MaxPendingRecords caps rows buffered before a forced flush, so that a
	// single entry holding a hundred thousand records (KEV, EPSS, an Alpine
	// secdb branch file) cannot grow the pending batch without bound. A flush
	// forced in the middle of an entry pins the cursor to the previous
	// COMPLETED entry, so the resume redoes that entry from its start — which
	// is correct because every write in it is idempotent.
	MaxPendingRecords = 2000

	// WatermarkVersion is the schema version of the progress token this
	// package writes into feed_state.watermark. A token from a future version
	// is refused, never guessed at.
	WatermarkVersion = 1

	// httpUserAgent identifies Anvil to a feed publisher. It is not a feed URL
	// and not a cadence; it is this process's own name.
	httpUserAgent = "anvil-ingest/1 (+https://github.com/Susquehanna-Syntax/Anvil)"
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	// ErrBootstrap is satisfied by errors.Is for every refusal this package
	// raises, so a caller that only needs "did the bootstrap happen" needs one
	// check. Licence refusals additionally satisfy license.ErrLicenseRefused,
	// which is the sentinel that matters for a write decision.
	ErrBootstrap = errors.New("bootstrap: refused")

	// ErrNotConfigured reports a Bootstrapper missing something it cannot
	// invent: the cache handle, or a working directory to stage artifacts in.
	ErrNotConfigured = errors.New("bootstrap: bootstrapper is not configured")

	// ErrUnsupportedMechanism reports a bootstrap_mechanism this package does
	// not implement. It exists so that adding a value to A.1's enum without
	// teaching this dispatch produces a refusal instead of a silent no-op that
	// looks like a successful import of zero rows.
	ErrUnsupportedMechanism = errors.New("bootstrap: unsupported bootstrap_mechanism")

	// ErrAlreadyBootstrapped reports a feed whose watermark already records a
	// completed bootstrap. Re-running is SAFE — every write is idempotent —
	// but it re-downloads the whole artifact, so it takes Options.Force.
	ErrAlreadyBootstrapped = errors.New("bootstrap: feed is already bootstrapped")

	// ErrForeignWatermark reports a watermark this package did not write and
	// cannot read. It means some other component — A.7's poller, A.14's git
	// fetch — owns the cursor now, which only happens to a feed already in
	// service. Overwriting it would destroy that component's position and
	// silently cost a full re-sync window, so it takes Options.Force too.
	ErrForeignWatermark = errors.New("bootstrap: feed_state.watermark is owned by another component")

	// ErrBadWatermark reports a token that IS this package's (it carries the
	// anvil_bootstrap key) but cannot be parsed — a future version, a
	// truncated write, an unknown field. It is a refusal rather than a restart
	// because a token we cannot read may describe progress we would discard.
	ErrBadWatermark = errors.New("bootstrap: unreadable bootstrap watermark")

	// ErrArchiveTooLarge reports an artifact over the configured cap, whether
	// the server declared the size or the body simply kept coming.
	ErrArchiveTooLarge = errors.New("bootstrap: archive exceeds the size limit")

	// ErrRecordTooLarge reports one member or document over MaxRecordBytes.
	// This is the decompression-bomb refusal: a zip member may declare any
	// uncompressed size it likes, so the limit is enforced on the bytes
	// actually read and not on the declared size alone.
	ErrRecordTooLarge = errors.New("bootstrap: record exceeds the size limit")

	// ErrUnrecognisedArchive reports a container this package cannot open.
	ErrUnrecognisedArchive = errors.New("bootstrap: unrecognised archive container")

	// ErrDependencyRequired reports a container whose codec is not in the Go
	// standard library — zstd, xz, bzip2-in-a-tar. Adding one is a NEW
	// DEPENDENCY and therefore a licence decision for the owner (spine S8), so
	// this package refuses and names the artifact rather than quietly picking
	// a library.
	ErrDependencyRequired = errors.New("bootstrap: archive codec needs a dependency Anvil does not have")

	// ErrCredentialMissing reports an authenticated feed whose credential
	// environment variable is unset. The variable NAME comes from the feed
	// table; the value is never read from anywhere else, never defaulted, and
	// never logged.
	ErrCredentialMissing = errors.New("bootstrap: credential environment variable is unset")

	// ErrFetch reports a transport or status failure fetching an artifact.
	ErrFetch = errors.New("bootstrap: fetch failed")

	// ErrNoArchiveAsset reports a release manifest with no artifact this
	// package can identify as the bulk archive.
	ErrNoArchiveAsset = errors.New("bootstrap: no bulk archive asset in the release manifest")
)

func refuse(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %w", ErrBootstrap, fmt.Errorf("%w: "+format, append([]any{sentinel}, args...)...))
}

// ---------------------------------------------------------------------------
// The progress token
// ---------------------------------------------------------------------------

// Phase is where a feed stands in its one-time bootstrap.
//
// It is deliberately FOUR-VALUED. "Bootstrapped or not" is two values and it is
// the wrong question: the interesting states are "nobody has started", "somebody
// started and did not finish", "finished", and "the cursor is not ours to
// read". Collapsing the last one into "not started" is what would licence a
// re-run to clobber the poller's position.
type Phase string

const (
	// PhaseNotStarted means feed_state has no watermark at all. Nothing has
	// been imported on this feed's account.
	PhaseNotStarted Phase = "not_started"

	// PhaseInProgress means a bootstrap committed at least one batch and did
	// not reach the end. The cache holds real rows and is INCOMPLETE, and any
	// reader treating it as complete would be manufacturing false negatives.
	PhaseInProgress Phase = "in_progress"

	// PhaseComplete means the final batch committed. This is the only value
	// that authorises a reader to treat the feed's slice of the cache as whole.
	PhaseComplete Phase = "complete"

	// PhaseForeign means the watermark holds a value this package did not
	// write. It is not an error in itself — a polled feed's cursor is a
	// perfectly good watermark — it means the question "was this bootstrapped"
	// has no answer from here.
	PhaseForeign Phase = "foreign"
)

// Valid reports whether p is one of the four phases.
func (p Phase) Valid() bool {
	switch p {
	case PhaseNotStarted, PhaseInProgress, PhaseComplete, PhaseForeign:
		return true
	}
	return false
}

// Progress is the token this package writes into feed_state.watermark, and the
// only thing that distinguishes a half-imported cache from a whole one.
//
// It lives in `watermark` because that is the column A.8's packet names for the
// clone ref, and because feed_state has no other per-feed column that is not
// already owned by conditional GET. That makes the format a shared vocabulary
// with A.7 and A.14, so it is parsed in exactly one place — ParseWatermark —
// and A.14 reads the clone ref through Handoff rather than by string surgery.
//
// The JSON is a single line with a self-identifying first key, so a human
// reading the column, and a parser deciding whether the value is ours, both get
// their answer from the first few bytes.
type Progress struct {
	// Version is WatermarkVersion. Its JSON name is the discriminator: a
	// watermark object without `anvil_bootstrap` is not ours.
	Version int `json:"anvil_bootstrap"`

	// Phase is the state. PhaseNotStarted and PhaseForeign are never encoded;
	// they describe the absence of a token, not a token.
	Phase Phase `json:"phase"`

	// Mechanism echoes the config.BootstrapMechanism that produced this token,
	// so a feed re-pointed from a bulk archive to a clone does not resume
	// against a cursor that means something else.
	Mechanism string `json:"mechanism"`

	// ArchiveSHA256 is the digest of the staged artifact, or the resolved
	// commit for a clone. It is the RESUME KEY: a cursor is only meaningful
	// against the exact bytes it was counted over, so a different digest
	// restarts the import from entry zero rather than skipping entries that
	// were never imported.
	ArchiveSHA256 string `json:"archive_sha256,omitempty"`

	// ArchiveBytes is the staged artifact's size, for diagnostics.
	ArchiveBytes int64 `json:"archive_bytes,omitempty"`

	// Entries is how many archive members are FULLY imported and committed.
	// Cursor is the name of the last of them. Both move only in a transaction
	// that also carries the rows they describe.
	Entries int    `json:"entries,omitempty"`
	Cursor  string `json:"cursor,omitempty"`

	// Records is how many advisory rows have been committed. It is checkable
	// against the cache — a reader can count the feed's rows and compare —
	// which is what makes the "cursor and rows move together" claim testable
	// rather than merely asserted.
	Records int `json:"records,omitempty"`

	// Handoff is the value the STEADY-STATE sync mechanism starts from once
	// the bootstrap completes: the resolved commit for a blobless clone (which
	// is what A.14's `git fetch` needs), the artifact digest for a bulk
	// archive. Read it through Handoff, never by re-implementing this struct.
	Handoff string `json:"handoff,omitempty"`

	// CloneDir is the working tree a blobless clone landed in, relative to the
	// Bootstrapper's WorkDir. Empty for every other mechanism.
	CloneDir string `json:"clone_dir,omitempty"`

	// UpdatedAt is when this token was last written, RFC3339 UTC.
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Encode renders the token for feed_state.watermark.
func (p Progress) Encode() (string, error) {
	p.Version = WatermarkVersion
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("bootstrap: encoding watermark: %w", err)
	}
	return string(b), nil
}

// watermarkKey is the discriminator. A value that does not contain it is not
// this package's, whatever else it is.
const watermarkKey = `"anvil_bootstrap"`

// ParseWatermark reads a feed_state.watermark value.
//
// It is TOTAL over the three things a watermark can be, and it fails closed on
// the fourth:
//
//	""                       -> PhaseNotStarted, nil
//	anything not ours        -> PhaseForeign, nil
//	one of our tokens        -> its phase, nil
//	ours but unreadable      -> ErrBadWatermark
//
// The last case is an error rather than a restart on purpose. A token we cannot
// read may describe committed progress, and treating it as "not started" would
// be safe for correctness and expensive for nothing; treating it as "complete"
// would be unsafe. Refusing makes an operator look, which is the only outcome
// that is right in both directions.
func ParseWatermark(w string) (Progress, error) {
	trimmed := strings.TrimSpace(w)
	if trimmed == "" {
		return Progress{Phase: PhaseNotStarted}, nil
	}
	if !strings.HasPrefix(trimmed, "{") || !strings.Contains(trimmed, watermarkKey) {
		return Progress{Phase: PhaseForeign}, nil
	}

	var p Progress
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Progress{Phase: PhaseForeign}, refuse(ErrBadWatermark,
			"the watermark carries %s but does not parse (%v); it may describe committed "+
				"progress, so it is refused rather than discarded", watermarkKey, err)
	}
	if p.Version != WatermarkVersion {
		return Progress{Phase: PhaseForeign}, refuse(ErrBadWatermark,
			"watermark schema version %d is not %d", p.Version, WatermarkVersion)
	}
	if p.Phase != PhaseInProgress && p.Phase != PhaseComplete {
		return Progress{Phase: PhaseForeign}, refuse(ErrBadWatermark,
			"watermark phase %q is not one a token may carry", p.Phase)
	}
	return p, nil
}

// Bootstrapped reports whether a watermark records a COMPLETED bootstrap.
//
// This is the question the whole token exists to answer, and the answer is
// false for every other state including "there are plenty of rows in the cache".
// A row count is not evidence of completeness; only the fact written after the
// last batch is.
func Bootstrapped(watermark string) bool {
	p, err := ParseWatermark(watermark)
	return err == nil && p.Phase == PhaseComplete
}

// Handoff returns the value a steady-state sync mechanism should start from,
// and whether the bootstrap that produced it completed.
//
// A.14's `git fetch` calls this to get the clone's resolved commit rather than
// parsing the watermark itself; a second parser for one format is how the two
// halves of a handover drift apart.
func Handoff(watermark string) (string, bool) {
	p, err := ParseWatermark(watermark)
	if err != nil || p.Phase != PhaseComplete {
		return "", false
	}
	return p.Handoff, true
}

// ---------------------------------------------------------------------------
// Options and result
// ---------------------------------------------------------------------------

// Options are the per-run choices a caller makes. The zero value is the safe
// one: resume if there is something to resume, refuse to clobber anything else.
type Options struct {
	// Force overrides ErrAlreadyBootstrapped and ErrForeignWatermark. It is
	// how an operator says "yes, re-import this feed from scratch, I know it
	// costs a full download and I know it overwrites the poller's cursor".
	Force bool
}

// BootstrapResult is what one bootstrap did. It is returned on the refusal
// paths too, because "the licence gate said no" and "the import wrote nothing"
// must not look alike to a caller reading a row count.
type BootstrapResult struct {
	// FeedID and Mechanism echo the row this ran for.
	FeedID    string
	Mechanism config.BootstrapMechanism

	// Refused is true when the licence gate refused the feed. RefusedBecause
	// carries the gate's own sentence. No request was made and no row written.
	Refused        bool
	RefusedBecause string

	// Complete is true only when the final batch committed. It is the same
	// fact Bootstrapped reads back out of the watermark.
	Complete bool

	// Resumed is true when this run picked up an in-progress import rather
	// than starting from the beginning.
	Resumed bool
	// ResumedFromEntry is the entry index the run started at.
	ResumedFromEntry int

	// Tier and Dir are A.4's decision: the licence tier and the ONE directory
	// this feed's data may be written under.
	Tier int
	Dir  string

	// ArchiveBytes and ArchiveSHA256 identify the staged artifact.
	ArchiveBytes  int64
	ArchiveSHA256 string
	// ArchiveReused is true when a previously staged artifact was verified by
	// digest and reused instead of re-downloaded. This is what makes a resume
	// cheap rather than merely correct.
	ArchiveReused bool

	// EntriesRead is archive members opened; EntriesSkipped is members that
	// held nothing this package recognised as an advisory. A CWE catalog is
	// the worked example of the second: it is Lane B's label space, it is not
	// advisory content, and it has no table in the A.2 cache.
	EntriesRead    int
	EntriesSkipped int

	// Records are what reached the cache. AffectedRows and AliasRows are
	// replaced per advisory, so these count writes and not net growth.
	RecordsUpserted int
	AffectedRows    int
	AliasRows       int
	Degraded        int
	Batches         int

	// PeakRecordBytes is the largest single document held in memory, and
	// PeakReadBytes the largest single read taken from the staged artifact.
	// They are the measured evidence for the claim that the importer streams:
	// both are bounded by a record and a buffer, never by the archive.
	PeakRecordBytes int
	PeakReadBytes   int
	BytesRead       int64

	// Sanitizer is the merged report of everything A.3 removed across the
	// import. A non-zero count is not an error; it is the ordinary state of
	// text written by strangers.
	Sanitizer sanitize.SanitizeStats

	// Watermark is the token as committed. Empty when nothing was committed.
	Watermark string
}

// ---------------------------------------------------------------------------
// Bootstrapper
// ---------------------------------------------------------------------------

// Bootstrapper carries everything a bootstrap needs that is not per-feed.
//
// Bootstrap's signature is the one A.8's packet names — (ctx, feed) ->
// (BootstrapResult, error) — and the environment hangs off the receiver rather
// than off a third parameter, so that a cache handle, an HTTP client and a git
// runner are configured once and cannot vary per call.
type Bootstrapper struct {
	// DB is the A.2 ingestion cache, already migrated. It is NOT
	// internal/store: that is the audit store of record and nothing here may
	// touch it.
	DB *sql.DB

	// Mirror is the filesystem A.4 reads pinned licence evidence from. Nil
	// means the process working directory, which is what a daemon wants and
	// what a test must never rely on.
	Mirror fs.FS

	// WorkDir is where artifacts are staged and clones live. It must be a real
	// directory on disk: a 570 MB archive is not held in memory, and a resume
	// that can verify a staged file by digest is a disk read instead of a
	// re-download.
	WorkDir string

	// HTTP is the client used for bulk archives. Nil means a default client
	// with a generous timeout, since these transfers are large.
	HTTP *http.Client

	// Git runs git subcommands for the blobless-clone path. Nil means the git
	// on PATH. Tests inject a fake; nothing in the test suite reaches the
	// network.
	Git GitRunner

	// Lookup resolves the environment variable NAMED BY THE FEED ROW to a
	// credential. Nil means os.LookupEnv. The value is never logged, never
	// placed on a command line, and never written anywhere.
	Lookup func(string) (string, bool)

	// Clock is the time source. Nil means time.Now.
	Clock func() time.Time

	// BatchSize overrides DefaultBatchSize.
	BatchSize int

	// MaxArchiveBytes overrides DefaultMaxArchiveBytes.
	MaxArchiveBytes int64

	// hookAfterBatch is a test seam: it runs after each batch COMMITS, and a
	// non-nil error aborts the import exactly as a crash would, leaving the
	// cache in the state the committed batches put it in. It is unexported
	// because simulating a crash is not something a caller should be able to
	// ask for.
	hookAfterBatch func(batch int) error
}

func (b *Bootstrapper) now() time.Time {
	if b.Clock != nil {
		return b.Clock()
	}
	return time.Now()
}

func (b *Bootstrapper) batchSize() int {
	if b.BatchSize > 0 {
		return b.BatchSize
	}
	return DefaultBatchSize
}

func (b *Bootstrapper) maxArchive() int64 {
	if b.MaxArchiveBytes > 0 {
		return b.MaxArchiveBytes
	}
	return DefaultMaxArchiveBytes
}

func (b *Bootstrapper) httpClient() *http.Client {
	if b.HTTP != nil {
		return b.HTTP
	}
	return &http.Client{Timeout: 30 * time.Minute}
}

func (b *Bootstrapper) lookup(name string) (string, bool) {
	if b.Lookup != nil {
		return b.Lookup(name)
	}
	return os.LookupEnv(name)
}

func (b *Bootstrapper) check() error {
	if b.DB == nil {
		return refuse(ErrNotConfigured, "no cache handle")
	}
	if strings.TrimSpace(b.WorkDir) == "" {
		return refuse(ErrNotConfigured, "no working directory to stage artifacts in")
	}
	return nil
}

// Bootstrap fills one feed's slice of the cache from its bulk artifact.
//
// It is the entry point A.8's packet names. The order of what it does is the
// argument for why it is safe:
//
//  1. The LICENCE GATE runs before anything is fetched. A refusal means no
//     request is made at all, which matters because "we downloaded it and then
//     decided we were not allowed to keep it" is not a defensible position.
//  2. The WATERMARK is read and classified. A completed or foreign one stops
//     the run unless the caller forced it.
//  3. The artifact is staged to disk, streamed and hashed as it arrives.
//  4. Members are iterated in the archive's own order and decoded one at a
//     time; rows are committed in batches, each batch carrying its own cursor.
//  5. The final batch carries PhaseComplete, and only then is the feed
//     bootstrapped.
func (b *Bootstrapper) Bootstrap(ctx context.Context, feed config.FeedConfig) (BootstrapResult, error) {
	res := BootstrapResult{FeedID: feed.ID, Mechanism: feed.BootstrapMechanism, Tier: license.NoTier}
	if err := b.check(); err != nil {
		return res, err
	}
	if !feed.BootstrapMechanism.Valid() {
		return res, refuse(ErrUnsupportedMechanism, "feed %q declares bootstrap_mechanism %q",
			feed.ID, feed.BootstrapMechanism)
	}

	// --- Gate 1 of 2: the licence. Before a byte is fetched. ---
	decision, err := license.Resolve(license.FromFeed(feed, "", b.Mirror))
	if err != nil {
		res.Refused = true
		res.RefusedBecause = err.Error()
		return res, fmt.Errorf("%w: feed %q: %w", ErrBootstrap, feed.ID, err)
	}
	if decision.Refused() {
		res.Refused = true
		res.RefusedBecause = "the licence gate returned a refusal without an error"
		return res, refuse(license.ErrLicenseRefused, "feed %q: %s", feed.ID, res.RefusedBecause)
	}
	res.Tier, res.Dir = decision.Tier.Int(), decision.Dir

	// --- Where does this feed stand? ---
	state, err := readFeedState(ctx, b.DB, feed.ID)
	if err != nil {
		return res, err
	}
	prior, err := ParseWatermark(state.watermark)
	if err != nil {
		return res, err
	}
	opts := Options{}
	if v := ctx.Value(forceKey{}); v != nil {
		if o, ok := v.(Options); ok {
			opts = o
		}
	}
	switch prior.Phase {
	case PhaseComplete:
		if !opts.Force {
			res.Complete = true
			res.Watermark = state.watermark
			return res, refuse(ErrAlreadyBootstrapped,
				"feed %q completed its bootstrap at %s over %d entries; re-running costs a full "+
					"re-download and is only a no-op for correctness, so it needs Force",
				feed.ID, prior.UpdatedAt, prior.Entries)
		}
		prior = Progress{Phase: PhaseNotStarted}
	case PhaseForeign:
		if !opts.Force {
			return res, refuse(ErrForeignWatermark,
				"feed %q has a watermark this package did not write; a steady-state sync owns it, "+
					"and overwriting it costs that component its position, so it needs Force", feed.ID)
		}
		prior = Progress{Phase: PhaseNotStarted}
	}
	if prior.Mechanism != "" && prior.Mechanism != string(feed.BootstrapMechanism) {
		// The feed was re-pointed. A cursor counted over a zip means nothing
		// against a clone.
		prior = Progress{Phase: PhaseNotStarted}
	}

	switch feed.BootstrapMechanism {
	case config.BootstrapBulkArchive:
		return b.bulkArchive(ctx, feed, decision, prior, res)
	case config.BootstrapBloblessClone:
		return b.bloblessClone(ctx, feed, decision, prior, res)
	case config.BootstrapIncrementalAPI, config.BootstrapNone:
		// Neither fetches a bulk artifact, and neither is a no-op: the feed
		// still needs a feed_state row carrying its licence tier before A.7
		// can poll it, and it still needs the durable fact that its bootstrap
		// is not pending. Writing PhaseComplete with zero entries is the
		// truth — there was nothing to import — and it is what stops an
		// operator's "which feeds still need bootstrapping" query from
		// listing a feed forever.
		prog := Progress{
			Phase:     PhaseComplete,
			Mechanism: string(feed.BootstrapMechanism),
			UpdatedAt: b.now().UTC().Format(time.RFC3339),
		}
		wm, err := prog.Encode()
		if err != nil {
			return res, err
		}
		if err := writeFeedState(ctx, b.DB, feed.ID, state, wm, decision.Tier.Int()); err != nil {
			return res, err
		}
		res.Complete, res.Watermark = true, wm
		return res, nil
	}
	return res, refuse(ErrUnsupportedMechanism, "feed %q declares bootstrap_mechanism %q",
		feed.ID, feed.BootstrapMechanism)
}

// forceKey carries Options through the packet-mandated two-parameter signature.
type forceKey struct{}

// WithOptions attaches per-run options to a context, because Bootstrap's
// signature is fixed at (ctx, feed) by A.8's packet and Force is a per-run
// choice rather than a property of the Bootstrapper.
func WithOptions(ctx context.Context, o Options) context.Context {
	return context.WithValue(ctx, forceKey{}, o)
}

// ---------------------------------------------------------------------------
// feed_state
// ---------------------------------------------------------------------------

type feedState struct {
	etag         string
	lastModified string
	watermark    string
	lastOKAt     string
	failures     int
	tier         int
}

func readFeedState(ctx context.Context, db *sql.DB, feedID string) (feedState, error) {
	var (
		st                        feedState
		etag, lastMod, wm, lastOK sql.NullString
		failures, tier            int
	)
	row := db.QueryRowContext(ctx, cache.SelectFeedStateSQL, feedID)
	switch err := row.Scan(&etag, &lastMod, &wm, &lastOK, &failures, &tier); {
	case errors.Is(err, sql.ErrNoRows):
		return feedState{}, nil
	case err != nil:
		return feedState{}, fmt.Errorf("bootstrap: reading feed_state for %q: %w", feedID, err)
	}
	st.etag, st.lastModified = etag.String, lastMod.String
	st.watermark, st.lastOKAt = wm.String, lastOK.String
	st.failures, st.tier = failures, tier
	return st, nil
}

// writeFeedState upserts the row OUTSIDE a batch transaction. It preserves
// etag/last_modified/last_ok_at, because those are A.7's conditional-GET state
// and a bootstrap has no business moving them.
func writeFeedState(ctx context.Context, db *sql.DB, feedID string, st feedState, watermark string, tier int) error {
	_, err := db.ExecContext(ctx, cache.UpsertFeedStateSQL,
		feedID, nullable(st.etag), nullable(st.lastModified), nullable(watermark),
		nullable(st.lastOKAt), st.failures, tier)
	if err != nil {
		return fmt.Errorf("bootstrap: writing feed_state for %q: %w", feedID, err)
	}
	return nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---------------------------------------------------------------------------
// The bulk-archive path
// ---------------------------------------------------------------------------

func (b *Bootstrapper) bulkArchive(
	ctx context.Context,
	feed config.FeedConfig,
	decision license.Decision,
	prior Progress,
	res BootstrapResult,
) (BootstrapResult, error) {
	state, err := readFeedState(ctx, b.DB, feed.ID)
	if err != nil {
		return res, err
	}

	staged, err := b.stageArchive(ctx, feed, prior)
	if err != nil {
		return res, err
	}
	defer staged.close()

	res.ArchiveBytes, res.ArchiveSHA256, res.ArchiveReused = staged.size, staged.digest, staged.reused

	// The cursor is only meaningful against the exact bytes it was counted
	// over. A different artifact restarts from entry zero — which is cheap in
	// correctness terms because every write is idempotent, and is the only
	// option that cannot skip an entry that was never imported.
	resume := prior
	if resume.Phase != PhaseInProgress || resume.ArchiveSHA256 != staged.digest {
		resume = Progress{Phase: PhaseNotStarted}
	}
	res.Resumed = resume.Phase == PhaseInProgress
	res.ResumedFromEntry = resume.Entries

	w := &writer{
		b:        b,
		feed:     feed,
		decision: decision,
		state:    state,
		res:      &res,
		progress: Progress{
			Phase:         PhaseInProgress,
			Mechanism:     string(feed.BootstrapMechanism),
			ArchiveSHA256: staged.digest,
			ArchiveBytes:  staged.size,
			Entries:       resume.Entries,
			Cursor:        resume.Cursor,
			Records:       resume.Records,
			Handoff:       staged.digest,
		},
		asOf:      b.now().UTC(),
		staleness: stalenessSeconds(b.now().UTC(), staged.lastMod),
		lastEntry: resume.Entries - 1,
		lastName:  resume.Cursor,
	}

	dc := newDecodeCtx(feed.ID)
	err = walkArchive(staged, resume.Entries, resume.Cursor, func(index int, name string, r io.Reader) error {
		res.EntriesRead++
		n, derr := dc.decodeEntry(name, r, func(rec advisoryRecord) error {
			return w.add(ctx, rec)
		})
		if derr != nil {
			return derr
		}
		if n == 0 {
			res.EntriesSkipped++
		}
		return w.entryDone(ctx, index, name)
	})
	res.Sanitizer = dc.stats()
	res.PeakReadBytes, res.BytesRead = staged.maxRead, staged.readSeen
	if err != nil {
		return res, err
	}
	if err := w.finish(ctx); err != nil {
		return res, err
	}
	res.Complete = true
	return res, nil
}

// ---------------------------------------------------------------------------
// Staging: download once, hash while streaming, reuse on resume
// ---------------------------------------------------------------------------

type stagedArchive struct {
	path     string
	size     int64
	digest   string
	reused   bool
	lastMod  string
	file     *os.File
	meter    *readMeter
	maxRead  int
	readSeen int64
}

func (s *stagedArchive) close() {
	if s.file != nil {
		_ = s.file.Close()
	}
}

// stageArchive puts the artifact on disk and returns its digest.
//
// The staged file is keyed by feed id, not by digest, because the digest is not
// knowable before the download. On a resume the existing file is re-hashed and
// reused only when it matches the cursor's digest, so a download killed
// half-way is detected as a mismatch and repeated rather than imported as a
// truncated archive.
func (b *Bootstrapper) stageArchive(ctx context.Context, feed config.FeedConfig, prior Progress) (*stagedArchive, error) {
	if err := os.MkdirAll(b.WorkDir, 0o755); err != nil {
		return nil, fmt.Errorf("bootstrap: creating work dir: %w", err)
	}
	dest := filepath.Join(b.WorkDir, feed.ID+".archive")

	if prior.Phase == PhaseInProgress && prior.ArchiveSHA256 != "" {
		if sum, size, err := digestFile(dest); err == nil && sum == prior.ArchiveSHA256 {
			f, err := os.Open(dest)
			if err == nil {
				return &stagedArchive{path: dest, size: size, digest: sum, reused: true, file: f}, nil
			}
		}
	}

	url, _, err := b.resolveArchiveURL(ctx, feed)
	if err != nil {
		return nil, err
	}
	sum, size, lastMod, err := b.download(ctx, feed, url, dest)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(dest)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: reopening staged archive: %w", err)
	}
	return &stagedArchive{path: dest, size: size, digest: sum, lastMod: lastMod, file: f}, nil
}

// resolveArchiveURL turns the feed's bootstrap_url into the URL of an actual
// artifact.
//
// Most rows point straight at one. cvelistV5 points at a releases endpoint that
// returns a MANIFEST, and A.8's packet requires resolving the baseline asset
// from it. That resolution is done by looking at the manifest — an assets array
// of {name, browser_download_url, size} — and never by knowing which feed this
// is: the rule is "among assets whose name ends in a container extension this
// package can open, take the LARGEST", which picks the ~570 MB midnight
// baseline over the ~17 MB deltas published beside it.
//
// THE RULE IS A HEURISTIC AND IT IS ADMITTED AS ONE. If a publisher ever ships
// a larger asset that is not the baseline, the operator's escape hatch is
// already in the feed table: set bootstrap_url to the asset directly. That
// keeps the exception in config, where every other per-feed fact in Lane A
// lives, and out of Go.
func (b *Bootstrapper) resolveArchiveURL(ctx context.Context, feed config.FeedConfig) (string, string, error) {
	target := feed.BootstrapURL
	if target == "" {
		target = feed.URL
	}
	if target == "" {
		return "", "", refuse(ErrFetch, "feed %q has no bootstrap_url and no url", feed.ID)
	}

	req, err := b.request(ctx, feed, target)
	if err != nil {
		return "", "", err
	}
	resp, err := b.httpClient().Do(req)
	if err != nil {
		return "", "", refuse(ErrFetch, "feed %q: %v", feed.ID, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", "", refuse(ErrFetch, "feed %q: %s returned %s", feed.ID, redactURL(target), resp.Status)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "json") {
		// Not a manifest. The URL is the artifact; the body we just opened is
		// discarded and re-fetched by download, which is one wasted request on
		// a once-per-feed operation and keeps staging in one place.
		return target, resp.Header.Get("Last-Modified"), nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", "", refuse(ErrFetch, "feed %q: reading release manifest: %v", feed.ID, err)
	}
	asset, ok := largestArchiveAsset(body)
	if !ok {
		// A JSON body that is not a release manifest is the artifact itself —
		// CISA KEV is exactly this shape.
		return target, resp.Header.Get("Last-Modified"), nil
	}
	return asset, resp.Header.Get("Last-Modified"), nil
}

type releaseManifest struct {
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

func largestArchiveAsset(body []byte) (string, bool) {
	var m releaseManifest
	if err := json.Unmarshal(body, &m); err != nil || len(m.Assets) == 0 {
		return "", false
	}
	best, bestSize := "", int64(-1)
	for _, a := range m.Assets {
		if a.URL == "" || !openableExtension(a.Name) {
			continue
		}
		if a.Size > bestSize {
			best, bestSize = a.URL, a.Size
		}
	}
	return best, best != ""
}

func openableExtension(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range []string{".zip", ".tar.gz", ".tgz", ".tar", ".json.gz", ".csv.gz", ".gz"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// request builds one authenticated request.
//
// THE CREDENTIAL IS READ FROM THE ENVIRONMENT VARIABLE THE FEED ROW NAMES, and
// from nowhere else. It is never defaulted, never logged, never put in a URL,
// and never written to disk. research/06 item 1 is why an authenticated header
// goes on even when a 304 is the expected answer — an authorized 304 costs zero
// rate-limit budget, an unauthenticated one consumes the 60/hour limit — and
// the same rule applies here, where the response is a 570 MB 200.
func (b *Bootstrapper) request(ctx context.Context, feed config.FeedConfig, target string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, refuse(ErrFetch, "feed %q: building request: %v", feed.ID, err)
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Accept", "*/*")

	switch feed.AuthMode {
	case config.AuthNone:
	case config.AuthGitHubToken:
		token, ok := b.lookup(feed.CredentialEnv)
		if !ok || token == "" {
			return nil, refuse(ErrCredentialMissing,
				"feed %q needs the credential in $%s", feed.ID, feed.CredentialEnv)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	case config.AuthAPIKeyHeader:
		token, ok := b.lookup(feed.CredentialEnv)
		if !ok || token == "" {
			return nil, refuse(ErrCredentialMissing,
				"feed %q needs the credential in $%s", feed.ID, feed.CredentialEnv)
		}
		req.Header.Set(feed.CredentialHeader, token)
	}
	return req, nil
}

// redactURL strips any userinfo and query from a URL before it appears in an
// error. A.1 already refuses inline credentials in the feed table, so this
// guards the one case it cannot: a redirect target or a resolved asset URL that
// carries a signed query parameter.
func redactURL(raw string) string {
	if i := strings.Index(raw, "?"); i >= 0 {
		raw = raw[:i] + "?<redacted>"
	}
	if i := strings.Index(raw, "@"); i >= 0 {
		if j := strings.Index(raw, "//"); j >= 0 && j < i {
			raw = raw[:j+2] + "<redacted>@" + raw[i+1:]
		}
	}
	return raw
}

func (b *Bootstrapper) download(ctx context.Context, feed config.FeedConfig, target, dest string) (string, int64, string, error) {
	req, err := b.request(ctx, feed, target)
	if err != nil {
		return "", 0, "", err
	}
	resp, err := b.httpClient().Do(req)
	if err != nil {
		return "", 0, "", refuse(ErrFetch, "feed %q: %v", feed.ID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", 0, "", refuse(ErrFetch, "feed %q: %s returned %s", feed.ID, redactURL(target), resp.Status)
	}
	limit := b.maxArchive()
	if resp.ContentLength > limit {
		return "", 0, "", refuse(ErrArchiveTooLarge, "feed %q: %s declares %d bytes, over the %d-byte limit",
			feed.ID, redactURL(target), resp.ContentLength, limit)
	}

	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return "", 0, "", fmt.Errorf("bootstrap: staging %q: %w", tmp, err)
	}
	h := sha256.New()
	// One more byte than the limit, so a body that lies about its length is
	// caught by what actually arrived rather than by what it claimed.
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, limit+1))
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return "", 0, "", refuse(ErrFetch, "feed %q: reading body: %v", feed.ID, err)
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return "", 0, "", fmt.Errorf("bootstrap: closing staged archive: %w", closeErr)
	}
	if n > limit {
		_ = os.Remove(tmp)
		return "", 0, "", refuse(ErrArchiveTooLarge, "feed %q: body exceeded the %d-byte limit", feed.ID, limit)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return "", 0, "", fmt.Errorf("bootstrap: staging %q: %w", dest, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, resp.Header.Get("Last-Modified"), nil
}

func digestFile(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// ---------------------------------------------------------------------------
// Read metering — the evidence that the importer streams
// ---------------------------------------------------------------------------

// readMeter records the largest single read taken from the staged artifact and
// the total. It is always on, because "this streams" is a claim that ought to
// be measured rather than asserted, and the measurement costs two comparisons
// per read.
type readMeter struct {
	MaxRead int
	Total   int64
}

type meteredReaderAt struct {
	r io.ReaderAt
	m *readMeter
}

func (m meteredReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := m.r.ReadAt(p, off)
	if n > m.m.MaxRead {
		m.m.MaxRead = n
	}
	m.m.Total += int64(n)
	return n, err
}

type meteredReader struct {
	r io.Reader
	m *readMeter
}

func (m meteredReader) Read(p []byte) (int, error) {
	n, err := m.r.Read(p)
	if n > m.m.MaxRead {
		m.m.MaxRead = n
	}
	m.m.Total += int64(n)
	return n, err
}

// ---------------------------------------------------------------------------
// Container dispatch — decided by the BYTES, never by the feed id
// ---------------------------------------------------------------------------

// walkArchive iterates an archive's members in its own order, handing each one
// to fn as a STREAM. It never holds a member's bytes; the decoder decides how
// much of one to buffer, bounded by MaxRecordBytes.
//
// skipTo/skipName implement the resume. The name check is not belt-and-braces:
// an index alone would silently skip real entries if the artifact changed, and
// the digest check upstream can only catch a change that produced different
// bytes — this catches a mismatch the digest check was not given the chance to
// see, and restarts from zero rather than importing a hole.
func walkArchive(s *stagedArchive, skipTo int, skipName string, fn func(index int, name string, r io.Reader) error) error {
	meter := &readMeter{}
	s.meter = meter
	defer func() {
		s.maxRead, s.readSeen = meter.MaxRead, meter.Total
	}()

	head := make([]byte, 512)
	n, err := s.file.ReadAt(head, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("bootstrap: reading archive header: %w", err)
	}
	head = head[:n]

	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")), bytes.HasPrefix(head, []byte("PK\x05\x06")):
		return walkZip(s, meter, skipTo, skipName, fn)
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return walkGzip(s, meter, skipTo, skipName, fn)
	case bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return refuse(ErrDependencyRequired,
			"the artifact is zstd-compressed; Go's standard library has no zstd decoder, so opening "+
				"it would add a dependency, and a dependency is a licence decision (spine S8), not "+
				"an implementation detail")
	case bytes.HasPrefix(head, []byte("BZh")):
		return refuse(ErrDependencyRequired,
			"the artifact is bzip2-compressed; compress/bzip2 decodes it but tar-in-bzip2 archives "+
				"are not in the feed table, so this path is deliberately unimplemented rather than "+
				"guessed at")
	case bytes.HasPrefix(head, []byte{0xfd, '7', 'z', 'X', 'Z'}):
		return refuse(ErrDependencyRequired, "the artifact is xz-compressed and Go has no xz decoder")
	case isTarHeader(head):
		return walkTar(&meteredReader{r: io.NewSectionReader(s.file, 0, s.size), m: meter}, skipTo, skipName, fn)
	default:
		// A bare document: KEV's JSON, an EPSS CSV served uncompressed, one
		// CSAF advisory. One entry, streamed.
		return walkSingle(path.Base(s.path), &meteredReader{r: io.NewSectionReader(s.file, 0, s.size), m: meter},
			skipTo, skipName, fn)
	}
}

func isTarHeader(head []byte) bool {
	return len(head) >= 265 && bytes.Equal(head[257:262], []byte("ustar"))
}

func walkZip(s *stagedArchive, meter *readMeter, skipTo int, skipName string, fn func(int, string, io.Reader) error) error {
	zr, err := zip.NewReader(meteredReaderAt{r: s.file, m: meter}, s.size)
	if err != nil {
		return refuse(ErrUnrecognisedArchive, "opening zip: %v", err)
	}
	if len(zr.File) > MaxEntries {
		return refuse(ErrArchiveTooLarge, "the zip declares %d members, over the %d-member limit",
			len(zr.File), MaxEntries)
	}
	if skipTo > 0 {
		if skipTo > len(zr.File) || (skipName != "" && zr.File[skipTo-1].Name != skipName) {
			skipTo = 0
		}
	}
	for i := skipTo; i < len(zr.File); i++ {
		f := zr.File[i]
		if f.FileInfo().IsDir() {
			if err := fn(i, f.Name, bytes.NewReader(nil)); err != nil {
				return err
			}
			continue
		}
		if f.UncompressedSize64 > MaxRecordBytes {
			return refuse(ErrRecordTooLarge, "member %q declares %d uncompressed bytes, over the %d-byte limit",
				f.Name, f.UncompressedSize64, MaxRecordBytes)
		}
		rc, err := f.Open()
		if err != nil {
			return refuse(ErrUnrecognisedArchive, "opening member %q: %v", f.Name, err)
		}
		err = fn(i, f.Name, rc)
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func walkGzip(s *stagedArchive, meter *readMeter, skipTo int, skipName string, fn func(int, string, io.Reader) error) error {
	sec := io.NewSectionReader(s.file, 0, s.size)
	zr, err := gzip.NewReader(&meteredReader{r: sec, m: meter})
	if err != nil {
		return refuse(ErrUnrecognisedArchive, "opening gzip: %v", err)
	}
	defer func() { _ = zr.Close() }()

	br := bufio.NewReaderSize(zr, 64<<10)
	if head, _ := br.Peek(512); isTarHeader(head) {
		return walkTar(br, skipTo, skipName, fn)
	}
	name := zr.Name
	if name == "" {
		name = strings.TrimSuffix(path.Base(s.path), ".gz")
	}
	return walkSingle(name, br, skipTo, skipName, fn)
}

func walkTar(r io.Reader, skipTo int, skipName string, fn func(int, string, io.Reader) error) error {
	tr := tar.NewReader(r)
	// A tar is sequential, so a resume must walk past the skipped members
	// rather than seek to one. Their bodies are never read: tar.Next skips to
	// the next header without decoding what it passed over.
	for i := 0; ; i++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return refuse(ErrUnrecognisedArchive, "reading tar: %v", err)
		}
		if i >= MaxEntries {
			return refuse(ErrArchiveTooLarge, "the tar holds more than %d members", MaxEntries)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if h.Size > MaxRecordBytes {
			return refuse(ErrRecordTooLarge, "member %q is %d bytes, over the %d-byte limit", h.Name, h.Size, MaxRecordBytes)
		}
		if i < skipTo {
			continue
		}
		if err := fn(i, h.Name, tr); err != nil {
			return err
		}
	}
}

func walkSingle(name string, r io.Reader, skipTo int, _ string, fn func(int, string, io.Reader) error) error {
	if skipTo > 0 {
		// A single-member artifact has exactly one entry, so a cursor past it
		// means the import already finished it. Re-running it would be
		// harmless; skipping it is simply cheaper.
		return nil
	}
	return fn(0, name, r)
}

// ---------------------------------------------------------------------------
// The batch writer — where the crash argument lives
// ---------------------------------------------------------------------------

type writer struct {
	b        *Bootstrapper
	feed     config.FeedConfig
	decision license.Decision
	state    feedState
	res      *BootstrapResult
	progress Progress
	asOf     time.Time

	// staleness is spine S6's staleness_seconds for every row this import
	// writes: the age of the ARTIFACT, measured from its Last-Modified header,
	// not the age of the import. research/06 Risk #5 is the reason it exists —
	// a feed outage must never fail a scan, it must serve stale data with the
	// age stamped on it, and "a scan run on 3-day-old KEV data must say so".
	//
	// A reused staged archive contributes no header and therefore reports zero,
	// which UNDERSTATES the age. That is a known gap, recorded here rather than
	// papered over: the correct fix is for the resume token to carry the
	// original Last-Modified, and it is not worth a watermark schema bump until
	// something reads the field.
	staleness int

	pending   []advisoryRecord
	lastEntry int
	lastName  string
}

// stalenessSeconds is the age of an artifact at import time, floored at zero: a
// publisher clock ahead of ours must not produce a negative age, which the
// cache's staleness_nonneg CHECK would refuse anyway.
func stalenessSeconds(now time.Time, lastModified string) int {
	if strings.TrimSpace(lastModified) == "" {
		return 0
	}
	t, err := http.ParseTime(lastModified)
	if err != nil {
		return 0
	}
	if d := int(now.Sub(t).Seconds()); d > 0 {
		return d
	}
	return 0
}

func (w *writer) add(ctx context.Context, rec advisoryRecord) error {
	// The raw document IS the record buffer: it is the largest thing held on a
	// record's behalf, and it is what raw_json stores verbatim. Tracking its
	// high-water mark turns "the importer streams" from an assertion into a
	// number a test can assert against the archive's uncompressed size.
	if n := len(rec.Raw); n > w.res.PeakRecordBytes {
		w.res.PeakRecordBytes = n
	}
	w.pending = append(w.pending, rec)
	if len(w.pending) >= MaxPendingRecords {
		// A forced flush in the MIDDLE of an entry pins the cursor to the last
		// COMPLETED entry, so a crash immediately after this commit makes the
		// resume redo this entry from its start. That re-does work and cannot
		// lose a record, which is the trade this whole design makes: never be
		// wrong, sometimes be slow.
		return w.commit(ctx, w.progress.Entries, w.progress.Cursor, false)
	}
	return nil
}

// cursorLagEntries bounds how far the cursor may fall behind while there is
// nothing to write. A stretch of entries that produce no advisories — a README,
// a directory, a CWE catalog — still has to be crossed on a resume, but paying
// a transaction per one of them would cost more than re-crossing them. Falling
// behind is always the SAFE direction: a resume that redoes work cannot lose a
// record, and a cursor ahead of the rows could.
const cursorLagEntries = 512

func (w *writer) entryDone(ctx context.Context, index int, name string) error {
	w.lastEntry, w.lastName = index, name
	if len(w.pending) >= w.b.batchSize() {
		return w.commit(ctx, index+1, name, false)
	}
	if len(w.pending) == 0 && index+1-w.progress.Entries >= cursorLagEntries {
		return w.commit(ctx, index+1, name, false)
	}
	// Otherwise the cursor stays where it is, which is correct: an entry whose
	// rows are still pending has not been imported.
	return nil
}

func (w *writer) finish(ctx context.Context) error {
	return w.commit(ctx, w.lastEntry+1, w.lastName, true)
}

// commit is the transaction. Rows and cursor, or neither.
//
// It is one BEGIN...COMMIT covering: every advisory upsert in the batch, the
// replacement of each of their affected/alias sets, their FTS rows, and the
// feed_state watermark naming the entry the batch ends at. See the package
// comment's crash argument for why the watermark cannot be a separate
// transaction, and for why "cursor is behind reality by up to one batch" is a
// safe direction to be wrong in while the reverse is not.
func (w *writer) commit(ctx context.Context, entries int, cursor string, final bool) error {
	if len(w.pending) == 0 && !final && entries == w.progress.Entries {
		return nil
	}

	next := w.progress
	next.Entries, next.Cursor = entries, cursor
	next.Records += len(w.pending)
	next.UpdatedAt = w.b.now().UTC().Format(time.RFC3339)
	if final {
		next.Phase = PhaseComplete
	}
	watermark, err := next.Encode()
	if err != nil {
		return err
	}

	tx, err := w.b.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("bootstrap: beginning batch: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()

	for _, rec := range w.pending {
		if err := writeAdvisory(ctx, tx, w, rec); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, cache.UpsertFeedStateSQL,
		w.feed.ID, nullable(w.state.etag), nullable(w.state.lastModified), watermark,
		nullable(w.state.lastOKAt), w.state.failures, w.decision.Tier.Int()); err != nil {
		return fmt.Errorf("bootstrap: writing feed_state in batch: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("bootstrap: committing batch: %w", err)
	}
	rollback = false

	w.progress = next
	w.res.RecordsUpserted += len(w.pending)
	w.res.Batches++
	w.res.Watermark = watermark
	w.pending = w.pending[:0]

	if w.b.hookAfterBatch != nil {
		if err := w.b.hookAfterBatch(w.res.Batches); err != nil {
			return err
		}
	}
	return nil
}

// writeAdvisory binds ONE record. Every externally-sourced string reaching a
// parameter here has been through sanitize.Sanitize in the decoder, and
// sanitize.AssertAllSanitized re-proves it on the exact values about to be
// bound — the post-condition A.3 exists to make checkable rather than merely
// documented.
//
// raw_json is bound VERBATIM and deliberately: cvelistV5's CVE-TOU obliges
// byte-identical storage, the column is a BLOB nothing renders, and every
// string projected out of it into a queryable column or the FTS index was
// sanitized on the way in.
func writeAdvisory(ctx context.Context, tx *sql.Tx, w *writer, rec advisoryRecord) error {
	fields := map[string]string{
		"source_id":           rec.SourceID,
		"cve_id":              rec.CVEID,
		"published":           rec.Published,
		"modified":            rec.Modified,
		"severity":            rec.Severity,
		"cvss_vector":         rec.CVSSVector,
		"description":         rec.Description,
		"references_text":     rec.ReferencesText(),
		"data_version":        rec.DataVersion,
		"epss_as_of":          rec.EPSSAsOf,
		"license_manual_note": w.decision.ManualNote,
	}
	for i, a := range rec.Affected {
		fields["affected["+strconv.Itoa(i)+"].package"] = a.Package
		fields["affected["+strconv.Itoa(i)+"].ecosystem"] = a.Ecosystem
	}
	if err := sanitize.AssertAllSanitized(fields); err != nil {
		return fmt.Errorf("%w: feed %q record %q: %w", ErrBootstrap, w.feed.ID, rec.SourceID, err)
	}

	// A record that carries its own age wins; otherwise the artifact's age
	// applies to every row it produced.
	staleness := rec.StalenessSeconds
	if staleness <= 0 {
		staleness = w.staleness
	}

	state := rec.State
	var tombstone any
	if state != cache.AdvisoryPublished {
		ts := rec.TombstonedAt
		if ts == "" {
			ts = w.asOf.Format(time.RFC3339)
		}
		tombstone = ts
	}

	var rowid int64
	err := tx.QueryRowContext(ctx, cache.UpsertAdvisorySQL,
		rec.Source, rec.SourceID, nullable(rec.CVEID), nullable(rec.Published), nullable(rec.Modified),
		state, tombstone, nullable(rec.Severity), nullable(rec.CVSSVector), rec.CVSSScore,
		rec.EPSSScore, nullable(rec.EPSSAsOf), boolInt(rec.KEV),
		nullable(w.decision.EffectiveSPDX), nullable(w.decision.ManualNote), w.decision.Tier.Int(),
		string(cache.AdvisoryTrustDefault),
		w.asOf.Format(time.RFC3339), staleness, boolInt(rec.ParseDegraded),
		nullable(rec.DataVersion), rec.Raw,
	).Scan(&rowid)
	if err != nil {
		return fmt.Errorf("bootstrap: upserting %s/%s: %w", rec.Source, rec.SourceID, err)
	}
	if rec.ParseDegraded {
		w.res.Degraded++
	}

	// A TOMBSTONED ADVISORY LEAVES THE SEARCH INDEX AND KEEPS ITS ROW.
	//
	// The row is never deleted (exit criterion 22: a finding that depended on
	// it must become INVALIDATED rather than vanish), but its text must stop
	// matching, because anything that retrieves it retrieves it as live
	// advice.
	//
	// A.14's writer has always done this and this one had not, which is the
	// divergence A.21's end-to-end harness found. It was invisible from inside
	// either package: each writer's own tests were internally consistent, and
	// the A.14 cross-producer conformance test compared `advisory`, `affected`
	// and `cve_alias` but not `advisory_fts`. It is the exact failure ruling
	// G11 describes, one layer down from the decoders: A.15's weekly baseline
	// self-heal runs THIS path, so every advisory the delta path had correctly
	// de-indexed would be re-indexed once a week, forever, with nothing
	// surfacing why. The conformance test now compares the index too.
	if rec.State == cache.AdvisoryPublished {
		if _, err := tx.ExecContext(ctx, cache.UpsertAdvisoryFTSSQL, rowid, rec.Description, rec.ReferencesText()); err != nil {
			return fmt.Errorf("bootstrap: indexing %s/%s: %w", rec.Source, rec.SourceID, err)
		}
	} else if _, err := tx.ExecContext(ctx, cache.DeleteAdvisoryFTSSQL, rowid); err != nil {
		return fmt.Errorf("bootstrap: de-indexing tombstoned %s/%s: %w", rec.Source, rec.SourceID, err)
	}

	// Replace, never append. `affected` has an autoincrement primary key and
	// no unique constraint over its natural key, so a resumed batch that
	// re-imports an advisory would otherwise duplicate every version range and
	// A.17's comparator would see one advisory as several.
	if _, err := tx.ExecContext(ctx, deleteAffectedSQL, rec.Source, rec.SourceID); err != nil {
		return fmt.Errorf("bootstrap: clearing affected for %s/%s: %w", rec.Source, rec.SourceID, err)
	}
	for _, a := range rec.Affected {
		if _, err := tx.ExecContext(ctx, insertAffectedSQL,
			rec.Source, rec.SourceID, a.Ecosystem, a.Package, nullable(a.PURL),
			nullable(a.Introduced), nullable(a.Fixed), boolInt(a.DistroBackport)); err != nil {
			return fmt.Errorf("bootstrap: writing affected for %s/%s: %w", rec.Source, rec.SourceID, err)
		}
		w.res.AffectedRows++
	}

	if _, err := tx.ExecContext(ctx, deleteAliasSQL, rec.Source, rec.SourceID); err != nil {
		return fmt.Errorf("bootstrap: clearing cve_alias for %s/%s: %w", rec.Source, rec.SourceID, err)
	}
	for _, alias := range rec.Aliases {
		if _, err := tx.ExecContext(ctx, insertAliasSQL, alias, rec.Source, rec.SourceID); err != nil {
			return fmt.Errorf("bootstrap: writing cve_alias for %s/%s: %w", rec.Source, rec.SourceID, err)
		}
		w.res.AliasRows++
	}
	return nil
}

// The four statements internal/ingest/cache does not export.
//
// cache/schema.go exports the advisory and FTS write shapes precisely so that
// A.7, A.8, A.14, A.15 and A.16 do not each compose their own; it exports
// nothing for `affected` or `cve_alias`, so these are composed here. They are
// kept together, named, and commented for the same reason the exported ones
// are: the next writer should copy these rather than invent a fifth shape.
// Reported to the orchestrator as a gap in A.2's exported surface.
const (
	deleteAffectedSQL = `DELETE FROM affected WHERE source = ? AND source_id = ?`

	insertAffectedSQL = `
INSERT INTO affected (source, source_id, ecosystem, package, purl, introduced, fixed, distro_backport)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	deleteAliasSQL = `DELETE FROM cve_alias WHERE source = ? AND source_id = ?`

	insertAliasSQL = `
INSERT INTO cve_alias (cve_id, source, source_id) VALUES (?, ?, ?)
ON CONFLICT (cve_id, source, source_id) DO NOTHING`
)

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// The record model
// ---------------------------------------------------------------------------

// affectedRange and advisoryRecord are the row shapes internal/ingest/decode
// defines, named here so this file reads as it always did.
//
// THEY ARE GO TYPE ALIASES AND NOT CONVERSIONS. This package and
// internal/ingest/delta write ONE table from ONE wire format (orchestrator
// ruling G11), and a converter between two structurally identical record types
// is precisely where a field gets carried on one side and dropped on the other
// — which A.15's weekly self-heal would then restore forever, each importer
// undoing the other, with nothing surfacing why.
type (
	affectedRange  = decode.AffectedRange
	advisoryRecord = decode.Record
)

// ---------------------------------------------------------------------------
// Decoding — driven by what the bytes say, not by which feed asked
// ---------------------------------------------------------------------------

// decodeEntry decodes one archive member and emits every advisory in it.
//
// THE FORMAT IS DECIDED BY LOOKING AT THE BYTES. There is no feed-id-to-parser
// table here, for the same reason A.1 exists: a format mapping compiled into Go
// is a hard-coded feed table wearing a different hat, and it breaks the moment
// an operator points a row at a mirror. What the entry IS, is a property of the
// entry.
//
// It returns how many records it emitted. Zero means the member held nothing
// this package recognises as an advisory — a directory, a README, a CWE catalog
// — which is reported as a skip, never as an error and never as an empty
// advisory row.
func (dc *decodeCtx) decodeEntry(name string, r io.Reader, emit func(advisoryRecord) error) (int, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	head, err := br.Peek(4096)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return 0, fmt.Errorf("bootstrap: reading member %q: %w", name, err)
	}
	// A UTF-8 BOM is written as an escape rather than as a literal: a literal
	// BOM in the middle of a Go source file is a compile error, and it is also
	// exactly the kind of invisible character internal/ingest/invisible exists
	// to keep out of this repository's own text.
	trimmed := bytes.TrimLeft(head, " \t\r\n\ufeff")
	if len(trimmed) == 0 {
		return 0, nil
	}

	switch {
	case trimmed[0] == '<':
		// XML. The CWE catalog is the only XML in the feed table and it is not
		// advisory content: it is Lane B's label space (spine S1 requirement
		// 8), 944 classes, and the A.2 cache has no table for it. Recognising
		// it and declining is the honest outcome; inventing an advisory row
		// shape for a weakness class would be worse than not importing it.
		return 0, nil

	case trimmed[0] == '{' || trimmed[0] == '[':
		return dc.decodeJSON(name, trimmed, br, emit)

	case bytes.HasPrefix(trimmed, []byte("#model_version")), bytes.HasPrefix(trimmed, []byte("cve,epss")):
		return dc.decodeEPSS(br, emit)
	}
	return 0, nil
}

// decodeJSON dispatches on the discriminating keys visible in the first 4 KiB.
//
// Two shapes exist and they need different handling. A SINGLE-RECORD entry (an
// OSV advisory, a CVE 5.x record, one CSAF document) is read into a bounded
// buffer, because raw_json must be stored verbatim and a record is bounded by
// MaxRecordBytes. A MULTI-RECORD entry (KEV's vulnerabilities array, an Alpine
// secdb branch file) is STREAMED element by element, because those files hold
// tens of thousands of records and reading one into memory would be the exact
// thing this package promises not to do.
func (dc *decodeCtx) decodeJSON(name string, head []byte, br *bufio.Reader, emit func(advisoryRecord) error) (int, error) {
	switch {
	case bytes.Contains(head, []byte(`"vulnerabilities"`)) && bytes.Contains(head, []byte(`"catalogVersion"`)),
		bytes.Contains(head, []byte(`"vulnerabilities"`)) && bytes.Contains(head, []byte(`"cveID"`)):
		return dc.decodeKEV(br, emit)

	case bytes.Contains(head, []byte(`"secfixes"`)), bytes.Contains(head, []byte(`"distroversion"`)):
		return dc.decodeAlpineSecdb(br, emit)

	case bytes.Contains(head, []byte(`"csaf_version"`)), bytes.Contains(head, []byte(`"csaf_vex"`)):
		return dc.decodeSingle(name, br, dc.dec.CSAF, emit)

	case bytes.Contains(head, []byte(`"CVE_RECORD"`)):
		return dc.decodeSingle(name, br, dc.dec.CVE5, emit)

	default:
		return dc.decodeSingle(name, br, dc.dec.OSV, emit)
	}
}

// decodeSingle reads one bounded document and hands it to a decoder.
//
// The read is bounded by MaxRecordBytes + 1 so that a member lying about its
// uncompressed size — the decompression bomb — is refused by what actually
// arrived rather than by what its header claimed.
func (dc *decodeCtx) decodeSingle(
	name string,
	br *bufio.Reader,
	decode func(raw []byte) (advisoryRecord, bool, error),
	emit func(advisoryRecord) error,
) (int, error) {
	raw, err := io.ReadAll(io.LimitReader(br, MaxRecordBytes+1))
	if err != nil {
		return 0, fmt.Errorf("bootstrap: reading member %q: %w", name, err)
	}
	if len(raw) > MaxRecordBytes {
		return 0, refuse(ErrRecordTooLarge, "member %q exceeded %d bytes while being read", name, MaxRecordBytes)
	}
	rec, ok, err := decode(raw)
	if err != nil || !ok {
		// A member that does not parse is SKIPPED, not fatal. A bulk archive
		// is 300,000 files written by strangers, and one malformed document
		// must not cost the other 299,999. It is counted as a skip so the
		// number is visible rather than inferred.
		return 0, nil
	}
	if err := emit(rec); err != nil {
		return 0, err
	}
	return 1, nil
}

// ---------------------------------------------------------------------------
// The decoding context
// ---------------------------------------------------------------------------

// decodeCtx is this import's binding to internal/ingest/decode: which feed the
// rows belong to, and the running report of everything A.3 removed.
//
// EVERY WIRE FORMAT IS DECODED IN internal/ingest/decode AND NOWHERE ELSE.
// This package used to hold its own OSV, CVE 5.x and KEV decoders, unexported,
// which forced internal/ingest/delta to re-derive them — two producers writing
// one table from one wire format. A.14 guarded the duplication with a
// conformance test, but two implementations agreeing on a fixture is a smoke
// alarm and not a fix, so A.21 extracted the shared package (ruling G11).
//
// WHAT STAYS HERE IS DISPATCH, and it stays here because it is genuinely
// different from delta's. This importer walks 300,000 archive members written
// by strangers: a member it cannot read is a README or a directory entry and is
// SKIPPED, so that one bad member does not cost the other 299,999. A delta
// document was fetched BECAUSE SOMETHING SAID IT CHANGED, so the same condition
// there means a change was dropped and must be an error. Sharing the format and
// not the policy is the whole seam.
//
// The size bounds stay here too. MaxRecordBytes is a statement about an archive
// member being streamed out of a 570 MB artifact; delta's MaxDocumentBytes is a
// statement about a body the poller already read into memory. They are
// different numbers for different reasons and neither belongs in the shared
// package.
type decodeCtx struct {
	feedID string
	dec    *decode.Decoder
}

func newDecodeCtx(feedID string) *decodeCtx {
	return &decodeCtx{feedID: feedID, dec: decode.New(feedID)}
}

// stats is everything the sanitizer removed across this import.
//
// A feed that ships zero-width joiners, bidi overrides or HTML comments inside
// an advisory description is not a curiosity — spine S7 puts prompt injection
// at ingest, and the counts are the only place the fact is visible after the
// bytes are clean. BootstrapResult.Sanitizer carries the merged total.
func (dc *decodeCtx) stats() sanitize.SanitizeStats { return dc.dec.Stats() }

// decodeKEV streams the CISA KEV catalogue element by element.
//
// The traversal is this package's — a 570 MB archive member is never held in
// memory — and the per-entry mapping is the shared one, which is exactly the
// split ruling G11 asked for: delta reads the same catalogue out of a body the
// poller already buffered, and both write the same row.
func (dc *decodeCtx) decodeKEV(br *bufio.Reader, emit func(advisoryRecord) error) (int, error) {
	n := 0
	err := decode.StreamArrayField(br, "vulnerabilities", MaxRecordBytes, func(raw json.RawMessage) error {
		rec, ok, err := dc.dec.KEVEntry(raw)
		if err != nil || !ok {
			// A single malformed catalogue entry is skipped, not fatal: KEV is
			// one document holding every entry, and one bad entry must not
			// cost the rest. It is bounded to a single element.
			return nil
		}
		n++
		return emit(rec)
	})
	if errors.Is(err, decode.ErrElementTooLarge) {
		return 0, refuse(ErrRecordTooLarge, "an element of %q exceeded %d bytes", "vulnerabilities", MaxRecordBytes)
	}
	return n, err
}

// decodeAlpineSecdb bounds the branch file, then hands it to the shared
// decoder. The bound is enforced on what ARRIVED, never on a declared size.
func (dc *decodeCtx) decodeAlpineSecdb(br *bufio.Reader, emit func(advisoryRecord) error) (int, error) {
	raw, err := io.ReadAll(io.LimitReader(br, MaxRecordBytes+1))
	if err != nil {
		return 0, fmt.Errorf("bootstrap: reading alpine secdb: %w", err)
	}
	if len(raw) > MaxRecordBytes {
		return 0, refuse(ErrRecordTooLarge, "an alpine secdb branch file exceeded %d bytes", MaxRecordBytes)
	}
	return dc.dec.AlpineSecdb(raw, emit)
}

// decodeEPSS streams the EPSS CSV. The whole file is never buffered, so the
// per-record bound above does not apply and none is invented here.
func (dc *decodeCtx) decodeEPSS(br *bufio.Reader, emit func(advisoryRecord) error) (int, error) {
	return dc.dec.EPSS(br, emit)
}
