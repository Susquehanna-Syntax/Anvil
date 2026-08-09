// Package repo is Lane A's repository SCA collector (plan/20-lane-a-ingestion-sca.md
// step A.10): it runs Trivy over a repository that is already on disk and
// turns Trivy's JSON report into Lane A findings.
//
// # No model, ever
//
// plan/00-SPINE.md S1: Lane A is "deterministic, zero inference — SBOM/host
// package matching by version comparator". CVE/OSV/GHSA describe vulnerable
// PACKAGE VERSIONS, and a comparator answers that exactly and for free. There
// is no inference in this package and none may be added to it.
//
// # One fingerprint, and it is not this package's
//
// plan/00-SPINE.md S6 permits exactly one fingerprint algorithm, anvil-fp/v1,
// owned by internal/record and specified in internal/record/FINGERPRINT-SPEC.md.
// This package computes NO digest of its own: Finding.Fingerprint delegates
// to record.Sca and there is no other hashing anywhere in these files. Two
// producers emitting different digests under one name is a named cross-area
// failure — it breaks regression matching forever with nothing surfacing it —
// so trivy_test.go asserts the delegation rather than trusting the comment.
//
// The same rule applies to vocabulary: every enum value emitted here is a Go
// constant from internal/record (record.DetectorKindSCA, record.EvidenceClassSCA,
// record.Trust*, record.Level*) or from internal/ingest/cache
// (cache.CollectorRepoSCA), never a bare string literal.
//
// # A missing tool is never a clean repository
//
// Every failure mode is loud and typed. There is no path through this package
// that returns a nil error with no findings because something was absent:
//
//	tool binary absent          -> *BinaryMissingError (ExitCodeArtefactAbsent)
//	tool ran but exited non-zero-> *RunError with Trivy's stderr attached
//	report unparseable          -> *ReportError
//	report schema version unknown-> *ReportError, never a best-effort parse
//	report parsed, no target found-> ScanResult.AssertNotSilentlyEmpty fails
//
// The last one matters as much as the first. `Findings == nil` means exactly
// one thing here: the scanner ran over at least one detected manifest and
// matched nothing. If no manifest was detected at all, Coverage says so and
// AssertNotSilentlyEmpty refuses to let the caller read it as clean.
//
// # Licence
//
// Trivy is Apache-2.0 (research/13 row C25, verified from the LICENSE body;
// research/12 S6). This package INVOKES it as a subprocess and vendors none
// of its code, so no §4 NOTICE duty attaches at source checkout. The duty
// attaches when a release artifact bakes the binary in — that is step O.17's
// call, not this package's, and this comment exists so O.17 finds the fact
// rather than re-deriving it.
package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// DetectionPriority is Trivy's documented false-positive / false-negative
// knob. This is TRIVY'S vocabulary, not an Anvil enum: plan/IMPLEMENTATION-PLAN.md
// §6 reserves enum ownership to internal/record for values that cross Anvil's
// areas, and these three literals never leave this package's argument vector.
// They are declared as constants for the same reason internal/ingest/cache
// declares CollectorRepoSCA — so a caller writes a constant, not a literal.
//
// research/12 §"The mitigation has a cost" [S15]: `comprehensive` "aims to
// detect more vulnerabilities, potentially including some that might be false
// positives. It provides broader coverage but may increase the noise in the
// results". There is no setting that is simultaneously low-FP and low-FN, so
// research/12 Recommendation item 5 puts the level in CONFIG with a documented
// default and nothing compiled in. DetectionPriorityUnset is that default: the
// flag is omitted entirely and Trivy's own default applies, so Anvil does not
// silently pick a side of a trade-off its operator owns.
type DetectionPriority string

const (
	// DetectionPriorityUnset omits --detection-priority from the argument
	// vector. The default.
	DetectionPriorityUnset DetectionPriority = ""
	// DetectionPriorityPrecise favours fewer false positives.
	DetectionPriorityPrecise DetectionPriority = "precise"
	// DetectionPriorityComprehensive favours fewer false negatives, at the
	// cost of noise (research/12 [S15]).
	DetectionPriorityComprehensive DetectionPriority = "comprehensive"
)

// DetectionPriorityValues returns every value BuildArgs will emit.
func DetectionPriorityValues() []DetectionPriority {
	return []DetectionPriority{
		DetectionPriorityUnset, DetectionPriorityPrecise, DetectionPriorityComprehensive,
	}
}

// Valid reports whether p is one of the values this collector will pass.
func (p DetectionPriority) Valid() bool {
	for _, v := range DetectionPriorityValues() {
		if p == v {
			return true
		}
	}
	return false
}

// DefaultTimeout bounds one scan. A repository SCA pass over a large monorepo
// is minutes, not hours; a scan still running after this is wedged.
const DefaultTimeout = 15 * time.Minute

// Config is everything an operator may change about how Trivy is invoked.
// What it deliberately does NOT contain is as important as what it does: no
// subcommand, no scanner selection, no arbitrary extra-argument slice. Each of
// those would let configuration reach past the safety boundary this collector
// is supposed to hold. See ScannersVuln and AllowedSubcommands.
type Config struct {
	// Binary is an absolute path to the pinned Trivy executable. Empty means
	// BinaryName resolved on PATH.
	Binary string

	// DetectionPriority is the research/12 FP/FN passthrough. Never
	// hard-coded; see the type.
	DetectionPriority DetectionPriority

	// SkipDBUpdate stops Trivy from fetching its vulnerability database as a
	// side effect of scanning. TRUE BY DEFAULT, and that default is the A.11
	// routing rule: plan/20's A.10 Forbidden actions bar invoking Trivy "in
	// any mode that fetches its DB from a redistributable-unclear mirror
	// without going through A.11's consume-only accelerator", and
	// research/06 records that neither the Trivy-DB nor the Grype-DB
	// publisher states redistribution terms. A.11 populates CacheDir; this
	// package only reads it.
	SkipDBUpdate bool

	// OfflineScan stops Trivy from issuing its own API requests to resolve
	// dependencies (its Java/Maven path does this). True by default: a
	// collector that silently reaches the internet mid-scan is a collector
	// whose egress cannot be reasoned about.
	OfflineScan bool

	// DBRepository names the OCI repository a DB update may pull from. It is
	// REQUIRED whenever SkipDBUpdate is false — an update with no named
	// source is exactly the unrouted fetch A.10 forbids, so Validate refuses
	// it with ErrDBUpdateUnrouted rather than defaulting to Aqua's registry.
	DBRepository string

	// CacheDir is the Trivy cache directory, normally the one A.11's
	// accelerator warmed. Empty means Trivy's own default location.
	CacheDir string

	// RequiredVersion, when set, is the exact release tag the resolved binary
	// must report; a mismatch is ErrVersionMismatch before any scan runs.
	//
	// There is deliberately NO DEFAULT LITERAL here. plan/20's Pinned
	// Versions table requires pinning "the exact release tag used by
	// internal/collector/repo", and spine S8's compliance mechanics require
	// reading artefact bodies rather than trusting metadata. No Trivy release
	// was available to verify on the host that wrote this file, so writing a
	// version literal here would be a fabricated pin — worse than an absent
	// one, because it would look verified. Ops sets this from the release
	// they actually acquired.
	RequiredVersion string

	// Timeout bounds one scan. Zero means DefaultTimeout.
	Timeout time.Duration

	// MaxOutputBytes caps the captured report. Zero means
	// DefaultMaxOutputBytes.
	MaxOutputBytes int
}

// DefaultConfig is the configuration ScanRepo uses: no DB fetch, no network
// dependency resolution, no detection-priority opinion.
func DefaultConfig() Config {
	return Config{
		DetectionPriority: DetectionPriorityUnset,
		SkipDBUpdate:      true,
		OfflineScan:       true,
		Timeout:           DefaultTimeout,
	}
}

// Validate reports whether c is admissible. It runs before any process is
// started, so a bad configuration can never become a half-completed scan.
func (c Config) Validate() error {
	if !c.DetectionPriority.Valid() {
		return fmt.Errorf("%w: detection priority %q is not one of %v",
			ErrBadConfig, c.DetectionPriority, DetectionPriorityValues())
	}
	// Every configured string reaches Trivy's argument vector. A value
	// beginning with '-' would be parsed as a flag, which is how a config key
	// becomes flag injection; no path, URL or version legitimately starts
	// with one.
	//
	// Checked in a fixed order, not over a map: two bad values must produce
	// the same first error on every run, or a config bug becomes a flaky one.
	for _, f := range []struct{ name, value string }{
		{"binary", c.Binary},
		{"cache directory", c.CacheDir},
		{"db repository", c.DBRepository},
		{"required version", c.RequiredVersion},
	} {
		if strings.HasPrefix(f.value, "-") {
			return fmt.Errorf("%w: %s %q begins with '-' and would be read as a flag",
				ErrBadConfig, f.name, f.value)
		}
	}
	if !c.SkipDBUpdate && strings.TrimSpace(c.DBRepository) == "" {
		return fmt.Errorf(
			"%w: SkipDBUpdate is false but no DBRepository is configured. A.11's consume-only "+
				"accelerator is the only sanctioned source, and research/06 records that the "+
				"Trivy-DB publisher states no redistribution terms",
			ErrDBUpdateUnrouted)
	}
	if c.Timeout < 0 {
		return fmt.Errorf("%w: timeout must not be negative", ErrBadConfig)
	}
	return nil
}

func (c Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultTimeout
	}
	return c.Timeout
}

// Runner returns the CLI runner this configuration describes. It is the
// fallback path S12 requires stay reachable; see the Runner interface.
func (c Config) Runner() Runner {
	return CLIRunner{Binary: c.Binary, MaxOutputBytes: c.MaxOutputBytes}
}

// ---------------------------------------------------------------------------
// Trivy's JSON report — the only place its wire shape is known
// ---------------------------------------------------------------------------

// SupportedReportSchemaVersion is the Trivy JSON report schema this parser
// understands. Trivy stamps `SchemaVersion` on every report.
//
// An unrecognised version is a HARD FAILURE, not a best-effort parse. The
// failure mode of best-effort here is precise and awful: field names move, the
// decoder finds nothing, and the collector reports zero findings over a
// vulnerable repository with no error anywhere. A loud refusal costs an
// operator one upgrade note; a silent mis-parse costs them the scan.
const SupportedReportSchemaVersion = 2

// ReportError is a report that could not be turned into findings.
type ReportError struct {
	Reason string
	Err    error
}

func (e *ReportError) Error() string {
	if e.Err != nil {
		return "repo: trivy report is unusable: " + e.Reason + ": " + e.Err.Error()
	}
	return "repo: trivy report is unusable: " + e.Reason
}

func (e *ReportError) Unwrap() error { return ErrUnusableReport }

// ErrUnusableReport is the sentinel behind every *ReportError.
var ErrUnusableReport = errors.New("repo: trivy report is unusable")

// trivyReport is the subset of Trivy's JSON report this collector reads.
// Fields absent here are ignored by encoding/json, which is intended: this
// struct is a contract with a tool that has no API stability guarantee (spine
// S12), so it names only what it needs and gates on SchemaVersion for the
// rest.
type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	CreatedAt     string        `json:"CreatedAt"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Results       []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Packages        []trivyPackage  `json:"Packages"`
	Vulnerabilities []trivyVulnItem `json:"Vulnerabilities"`
}

// trivyPackage is one enumerated dependency. Only the COUNT is read — it is
// Coverage's denominator, the thing that makes "no findings" mean something —
// so the fields here exist to document the shape --list-all-pkgs produces,
// not because a value is consumed.
type trivyPackage struct {
	Name    string `json:"Name"`
	Version string `json:"Version"`
}

type trivyPkgIdentifier struct {
	PURL string `json:"PURL"`
}

type trivyVulnItem struct {
	VulnerabilityID  string             `json:"VulnerabilityID"`
	PkgName          string             `json:"PkgName"`
	PkgIdentifier    trivyPkgIdentifier `json:"PkgIdentifier"`
	InstalledVersion string             `json:"InstalledVersion"`
	FixedVersion     string             `json:"FixedVersion"`
	Severity         string             `json:"Severity"`
	PrimaryURL       string             `json:"PrimaryURL"`
	Title            string             `json:"Title"`
	Description      string             `json:"Description"`
	References       []string           `json:"References"`
	DataSource       *trivyDataSource   `json:"DataSource"`
	PublishedDate    string             `json:"PublishedDate"`
	LastModifiedDate string             `json:"LastModifiedDate"`
}

type trivyDataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

// Trivy's `Class` values this collector recognises.
const (
	// classLangPkgs is a language dependency manifest or lockfile: the only
	// class this collector emits findings from.
	classLangPkgs = "lang-pkgs"
	// classOSPkgs is an operating-system package database. A repository scan
	// should not produce one, and if it does the row belongs to A.9's host
	// collector — internal/ingest/cache's `finding` table CHECKs that a
	// `host` row is never remediable_by_agent, and emitting an OS package as
	// `repo-sca` would launder exactly that constraint. Counted, never
	// emitted, never silently dropped.
	classOSPkgs = "os-pkgs"
)

// ---------------------------------------------------------------------------
// Lane A's finding shape
// ---------------------------------------------------------------------------

// Finding is one repository dependency that matched a vulnerable version
// range. Its fields line up one-for-one with the `finding` table
// internal/ingest/cache/schema.go declares (collector, source, source_id,
// package, installed_version, ecosystem, remediable_by_agent, anvil_trust)
// plus the three the anvil-fp/v1 SCA tier hashes (advisory id, purl, manifest
// path). It is NOT a second record format: A.19 owns emission into the
// canonical SARIF-shaped record, and the fields here exist so A.19 has
// something to emit FROM.
type Finding struct {
	// Collector is always cache.CollectorRepoSCA. Present as a field rather
	// than implied so a row written from this struct carries the constant,
	// not a literal spelled at the call site.
	Collector string

	// AdvisoryID is Trivy's VulnerabilityID: "CVE-2021-44228",
	// "GHSA-jfh8-c2jp-5v3q". Hashed VERBATIM by record.Sca — GHSA
	// identifiers mix case meaningfully — so it is never folded here.
	AdvisoryID string

	// DataSourceID and DataSourceName are Trivy's own attribution for where
	// the advisory came from ("ghsa", "osv", "redhat"). They map onto the
	// cache `finding.source` column, and A.17's comparator is what reconciles
	// them against the advisory rows Lane A ingested itself.
	DataSourceID   string
	DataSourceName string

	// PackageName is the dependency as its ecosystem names it.
	PackageName string

	// Purl is the package URL. record.PurlBase strips version, qualifiers
	// and subpath before hashing, which is why bumping a dependency INSIDE
	// the vulnerable range does not mint a new finding.
	Purl string

	// InstalledVersion is the version present in the repository. It is
	// reported, stored and shown — and it is NEVER hashed. See
	// FINGERPRINT-SPEC.md's "THE VERSION STRING IS NEVER HASHED".
	InstalledVersion string

	// FixedVersion is the version that resolves it, empty when the publisher
	// names none.
	FixedVersion string

	// ManifestRelPath is the repo-relative manifest or lockfile that declared
	// the dependency, canonicalised by record.CanonicalRepoRelPath. It is
	// part of the fingerprint: the same vulnerable package pulled in by two
	// manifests in a monorepo is two findings with two owners and two fixes.
	ManifestRelPath string

	// Ecosystem is Trivy's `Type` for the target ("gomod", "npm", "pip").
	Ecosystem string

	// Detector and EvidenceClass are the frozen record enums. Both are fixed
	// for this collector; they are fields so that a consumer reads a typed
	// value rather than re-deriving one.
	Detector      record.DetectorKind
	EvidenceClass record.EvidenceClass

	// RemediableByAgent is true only when a fixed version is known.
	//
	// plan/00-SPINE.md S6 makes this field required and S7 makes it false for
	// every host finding; a repository dependency is the one class the coding
	// agent CAN act on — by bumping a version. When the publisher names no
	// fixed version there is no bump to make, and claiming otherwise sends
	// the agent after a patch that does not exist. Reported, not silently
	// implied: Coverage.NoFixedVersion counts these.
	//
	// Trivy's own `Status` field ("fixed", "affected", "will_not_fix",
	// "fix_deferred", "end_of_life") is deliberately NOT consulted. It is a
	// vendor vocabulary with no stability contract, and the question here has
	// a directly observable answer: is there a version to move to. Reading
	// Status would put a second, drifting source of truth behind the one flag
	// that decides whether a coding agent is dispatched.
	RemediableByAgent bool

	// Severity is Trivy's severity string, verbatim and untrusted.
	Severity string

	// Level is the SARIF severity Anvil DERIVES from Severity. The record
	// contract requires that rank on ingested third-party output be treated
	// as untrusted and re-derived rather than adopted; this is that
	// derivation, and severityToLevel is where the mapping is stated.
	Level record.Level

	// Trust classifies the strings in this finding. It is
	// record.TrustUntrusted, and that is a deliberate call — see the comment
	// on findingTrust.
	Trust record.Trust

	// Title, Description and References are external prose, sanitised at
	// ingest (plan/00-SPINE.md S7: "sanitize at ingest, not at prompt time")
	// and carrying their trust level inline.
	Title       record.TrustedString
	Description record.TrustedString
	References  []record.TrustedString

	// PrimaryURL is Trivy's advisory link.
	PrimaryURL string

	// PublishedDate and LastModifiedDate are Trivy's verbatim strings, kept
	// unparsed: A.19 owns the record's time fields and a second date parser
	// here would be a second source of truth for staleness.
	PublishedDate    string
	LastModifiedDate string
}

// findingTrust is the trust level stamped on every finding this collector
// produces, and the reasoning is the part worth keeping.
//
// internal/ingest/cache declares FindingTrustDefault = record.TrustAnvilGenerated,
// because A.17's comparator output is Anvil's own conclusion. A TRIVY finding
// is not: the conclusion, the severity, the title and the description were all
// written outside Anvil, by a third-party tool over third-party advisory data.
// record.Trust's own documentation settles it — "the question TrustLevel
// answers is 'who wrote these bytes', never 'who assigned this field'" — and
// the record contract separately requires that `rank` on ingested third-party
// output be treated as untrusted and re-derived.
//
// The cache's `finding.anvil_trust` CHECK admits all three literals, so this
// is storable as-is. It is reported to the orchestrator as a deviation from
// the column's DEFAULT rather than applied quietly.
const findingTrust = record.TrustUntrusted

// ScaInput returns the anvil-fp/v1 SCA-tier input for this finding under the
// given target. It exists so the field mapping is stated once and testable,
// and so no caller assembles a record.ScaInput by hand.
func (f Finding) ScaInput(targetID string) record.ScaInput {
	return record.ScaInput{
		TargetID:        targetID,
		AdvisoryID:      f.AdvisoryID,
		Purl:            f.Purl,
		ManifestRelPath: f.ManifestRelPath,
	}
}

// Fingerprint returns the canonical anvil-fp/v1 digest for this finding.
//
// It is one line, and that is the point: this package computes no digest of
// its own and must never gain one (plan/00-SPINE.md S6, one fingerprint).
// Every error comes from record's own field validation — an empty target id, a
// missing advisory id, a purl that is not a purl — and is returned rather than
// papered over, because a finding that cannot be identified cannot be tracked
// across scans and must not be presented as if it could.
func (f Finding) Fingerprint(targetID string) (string, error) {
	return record.Sca(f.ScaInput(targetID))
}

// ---------------------------------------------------------------------------
// Coverage — the answer to "was that a clean repo, or did nothing run?"
// ---------------------------------------------------------------------------

// Coverage reports what the scan actually covered. plan/20 exit criterion 20
// requires that "every match run reports coverage, never silent 'clean'",
// including the zero-findings case; this is that report for the collector
// half, and it is populated on every successful parse.
type Coverage struct {
	// TargetsDetected is how many manifests/lockfiles Trivy found. Zero means
	// NOTHING WAS SCANNED, which is not the same as "nothing was found".
	TargetsDetected int
	// TargetsWithFindings is how many of those carried at least one
	// vulnerability.
	TargetsWithFindings int
	// PackagesEnumerated is the total dependency count across every detected
	// target — the denominator that makes a zero-finding result meaningful.
	PackagesEnumerated int

	// VulnerabilitiesReported is how many entries Trivy reported;
	// FindingsEmitted is how many became Findings. The two differ by exactly
	// the anomaly counts below, and trivy_test.go asserts that identity so a
	// future edit cannot drop a row without the arithmetic noticing.
	VulnerabilitiesReported int
	FindingsEmitted         int

	// SkippedOSPackages counts os-pkgs-class entries: A.9's territory, never
	// emitted here. See classOSPkgs.
	SkippedOSPackages int
	// SkippedOtherClass counts entries from any class this collector does not
	// recognise at all.
	SkippedOtherClass int
	// NoFixedVersion counts findings the publisher names no fix for; those
	// carry RemediableByAgent=false.
	NoFixedVersion int
	// UnmappedSeverity counts severities outside Trivy's documented set.
	UnmappedSeverity int

	// Anomalies are entries that could not become well-formed findings. They
	// are RETAINED, not discarded: a dropped row with no record of the drop
	// is the failure this package is built to refuse.
	Anomalies []Anomaly

	// Targets is the per-target breakdown, in report order.
	Targets []TargetCoverage
}

// TargetCoverage is one manifest's contribution.
type TargetCoverage struct {
	Target          string
	CanonicalPath   string
	Class           string
	Type            string
	Packages        int
	Vulnerabilities int
}

// AnomalyKind names why an entry could not become a finding.
type AnomalyKind string

const (
	// AnomalyMissingAdvisoryID: no VulnerabilityID, so nothing to match or
	// fingerprint against.
	AnomalyMissingAdvisoryID AnomalyKind = "missing_advisory_id"
	// AnomalyMissingPurl: no package URL, so record.Sca cannot identify it.
	// Trivy emits PkgIdentifier.PURL for every ecosystem it supports; an
	// entry without one is a shape change worth seeing.
	AnomalyMissingPurl AnomalyKind = "missing_purl"
	// AnomalyMissingTarget: no manifest path, which the SCA fingerprint tier
	// requires — the same package pulled in by two manifests is two findings.
	AnomalyMissingTarget AnomalyKind = "missing_manifest_path"
	// AnomalyUnsanitizedIdentity: an identity field (package name, purl,
	// version, manifest path) carries characters Sanitize would remove.
	//
	// These fields are NOT rewritten. Rewriting an identity field silently
	// changes the identity it produces, and a zero-width character inside a
	// package name is a supply-chain signal, not a formatting nit. The entry
	// is held here with its reason instead.
	AnomalyUnsanitizedIdentity AnomalyKind = "unsanitized_identity_field"
)

// Anomaly is one retained entry that did not become a Finding.
type Anomaly struct {
	Kind AnomalyKind
	// AdvisoryID, PackageName and Target are best-effort identification of
	// the entry, for an operator reading a log. They are the raw values, and
	// carry the same untrusted status as everything else Trivy reports.
	AdvisoryID  string
	PackageName string
	Target      string
	Detail      string
}

func (a Anomaly) String() string {
	s := fmt.Sprintf("%s: advisory=%q package=%q target=%q", a.Kind, a.AdvisoryID, a.PackageName, a.Target)
	if a.Detail != "" {
		s += ": " + a.Detail
	}
	return s
}

// ScannedNothing reports whether the scan detected no manifest at all.
//
// This is the predicate that separates "clean" from "nothing ran". Trivy
// omits a target from its Results when it has no vulnerabilities, so without
// --list-all-pkgs an empty report would be ambiguous; BuildArgs always passes
// it, which is what makes TargetsDetected meaningful.
func (c Coverage) ScannedNothing() bool { return c.TargetsDetected == 0 }

// ---------------------------------------------------------------------------
// ScanResult
// ---------------------------------------------------------------------------

// ScanResult is one collector run.
type ScanResult struct {
	// Findings is Lane A's output. Empty means the scanner ran over at least
	// TargetsDetected manifests and matched nothing — and only that, provided
	// AssertNotSilentlyEmpty returns nil.
	Findings []Finding

	// Coverage is populated on every successful parse, including the
	// zero-findings case (plan/20 exit criterion 20).
	Coverage Coverage

	// SchemaVersion, ArtifactName, ArtifactType and CreatedAt are Trivy's own
	// report envelope, retained so a stored result records what produced it.
	SchemaVersion int
	ArtifactName  string
	ArtifactType  string
	CreatedAt     string

	// TrivyVersion is filled in only when Config.RequiredVersion is set and
	// the pin was therefore checked.
	TrivyVersion string

	// Args is the exact argument vector that ran. It contains no credential:
	// nothing in this package reads one. Retained because a scan whose
	// argument vector is unknown is a scan whose result cannot be reproduced.
	Args []string

	// Sanitization is the merged report from every external string this run
	// passed through sanitize.Sanitize. Non-zero counts mean advisory prose
	// carried invisible or hidden-markup characters — worth surfacing, since
	// plan/00-SPINE.md S7 puts prompt-injection defence at ingest.
	Sanitization sanitize.SanitizeStats
}

// ErrNothingScanned is the sentinel behind AssertNotSilentlyEmpty's refusal.
var ErrNothingScanned = errors.New("repo: no manifest was scanned; this is not a clean repository")

// AssertNotSilentlyEmpty refuses to let a caller read "no findings" as "no
// vulnerabilities" when in fact nothing was scanned.
//
// Call it before reporting a clean result. It returns nil when at least one
// target was detected — at which point an empty Findings slice means exactly
// what it appears to mean.
func (r ScanResult) AssertNotSilentlyEmpty() error {
	if r.Coverage.ScannedNothing() {
		return fmt.Errorf(
			"%w: trivy detected 0 dependency manifests under %q (artifact type %q). "+
				"A repository with no lockfile Trivy recognises produces the same empty "+
				"finding list as a repository with no vulnerabilities, and the two must not be reported alike",
			ErrNothingScanned, r.ArtifactName, r.ArtifactType)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------

// ScanRepo scans the repository rooted at path with DefaultConfig and returns
// Lane A findings. It is the signature plan/20 A.10 names.
//
// It shells out to the Trivy binary. It does not link Trivy's `pkg/`
// packages, and per spine S12 no future version may make a native path the
// sole one — see the Runner interface.
func ScanRepo(ctx context.Context, path string) (ScanResult, error) {
	return DefaultConfig().ScanRepo(ctx, path)
}

// ScanRepo runs the configured collector over path.
func (c Config) ScanRepo(ctx context.Context, path string) (ScanResult, error) {
	return c.ScanRepoWith(ctx, path, c.Runner())
}

// ScanRepoWith runs the collector over path using an explicit Runner.
//
// This is the seam a native Trivy path would attach to, and the seam tests use
// to exercise parsing without a binary on the host. Both matter: spine S12
// requires the CLI path stay available under a native one, and a collector
// whose parser can only be tested by installing a scanner is a collector whose
// parser does not get tested.
func (c Config) ScanRepoWith(ctx context.Context, path string, runner Runner) (ScanResult, error) {
	args, err := BuildArgs(c, path)
	if err != nil {
		return ScanResult{}, err
	}

	var pinned string
	if c.RequiredVersion != "" {
		vctx, cancel := context.WithTimeout(ctx, DefaultVersionTimeout)
		v, err := checkVersionPin(vctx, runner, c.RequiredVersion)
		cancel()
		if err != nil {
			return ScanResult{}, err
		}
		pinned = v
	}

	rctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	raw, err := runner.Run(rctx, args)
	if err != nil {
		return ScanResult{}, err
	}

	res, err := ParseReportRelativeTo(raw, path)
	if err != nil {
		return ScanResult{}, err
	}
	res.Args = args
	res.TrivyVersion = pinned
	return res, nil
}

// ParseReport turns a Trivy JSON report into a ScanResult.
//
// Exported so a stored report can be re-parsed without re-running the scanner
// and so the parse is testable with no binary present. It never returns a
// partial result: any structural problem is a *ReportError.
func ParseReport(raw []byte) (ScanResult, error) {
	return ParseReportRelativeTo(raw, "")
}

// ParseReportRelativeTo is ParseReport with the scanned root known, so that an
// absolute manifest target can be made repo-relative before it reaches the
// fingerprint. See RelativeManifestPath for why that matters.
func ParseReportRelativeTo(raw []byte, root string) (ScanResult, error) {
	if len(raw) == 0 {
		return ScanResult{}, &ReportError{Reason: "report is empty"}
	}

	var rep trivyReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return ScanResult{}, &ReportError{Reason: "report is not valid JSON", Err: err}
	}
	if rep.SchemaVersion != SupportedReportSchemaVersion {
		return ScanResult{}, &ReportError{Reason: fmt.Sprintf(
			"report SchemaVersion is %d, this parser understands %d only. Refusing to parse: a report "+
				"whose field names have moved decodes to zero findings with no error, which is "+
				"indistinguishable from a clean repository. Re-pin the Trivy release "+
				"(Config.RequiredVersion) or extend this parser deliberately",
			rep.SchemaVersion, SupportedReportSchemaVersion)}
	}

	out := ScanResult{
		SchemaVersion: rep.SchemaVersion,
		ArtifactName:  rep.ArtifactName,
		ArtifactType:  rep.ArtifactType,
		CreatedAt:     rep.CreatedAt,
	}

	for _, r := range rep.Results {
		canonical := RelativeManifestPath(root, r.Target)
		tc := TargetCoverage{
			Target:          r.Target,
			CanonicalPath:   canonical,
			Class:           r.Class,
			Type:            r.Type,
			Packages:        len(r.Packages),
			Vulnerabilities: len(r.Vulnerabilities),
		}

		switch r.Class {
		case classLangPkgs:
			// The only class this collector emits from.
		case classOSPkgs:
			out.Coverage.SkippedOSPackages += len(r.Vulnerabilities)
			out.Coverage.VulnerabilitiesReported += len(r.Vulnerabilities)
			out.Coverage.TargetsDetected++
			out.Coverage.PackagesEnumerated += len(r.Packages)
			out.Coverage.Targets = append(out.Coverage.Targets, tc)
			continue
		default:
			out.Coverage.SkippedOtherClass += len(r.Vulnerabilities)
			out.Coverage.VulnerabilitiesReported += len(r.Vulnerabilities)
			out.Coverage.TargetsDetected++
			out.Coverage.PackagesEnumerated += len(r.Packages)
			out.Coverage.Targets = append(out.Coverage.Targets, tc)
			continue
		}

		out.Coverage.TargetsDetected++
		out.Coverage.PackagesEnumerated += len(r.Packages)
		out.Coverage.VulnerabilitiesReported += len(r.Vulnerabilities)
		if len(r.Vulnerabilities) > 0 {
			out.Coverage.TargetsWithFindings++
		}
		out.Coverage.Targets = append(out.Coverage.Targets, tc)

		for _, v := range r.Vulnerabilities {
			f, stats, anomaly := toFinding(v, r, canonical)
			out.Sanitization.Merge(stats)
			if anomaly != nil {
				out.Coverage.Anomalies = append(out.Coverage.Anomalies, *anomaly)
				continue
			}
			if !f.RemediableByAgent {
				out.Coverage.NoFixedVersion++
			}
			if !knownSeverity(v.Severity) {
				out.Coverage.UnmappedSeverity++
			}
			out.Findings = append(out.Findings, f)
			out.Coverage.FindingsEmitted++
		}
	}

	return out, nil
}

// toFinding maps one Trivy vulnerability entry onto a Finding, or explains
// why it could not. It returns exactly one of (finding, nil) or (zero,
// anomaly) — never a partially populated finding.
func toFinding(v trivyVulnItem, r trivyResult, canonicalTarget string) (Finding, sanitize.SanitizeStats, *Anomaly) {
	var stats sanitize.SanitizeStats

	anomaly := func(kind AnomalyKind, detail string) (Finding, sanitize.SanitizeStats, *Anomaly) {
		return Finding{}, stats, &Anomaly{
			Kind:        kind,
			AdvisoryID:  v.VulnerabilityID,
			PackageName: v.PkgName,
			Target:      r.Target,
			Detail:      detail,
		}
	}

	if strings.TrimSpace(v.VulnerabilityID) == "" {
		return anomaly(AnomalyMissingAdvisoryID, "entry carries no VulnerabilityID")
	}
	purl := strings.TrimSpace(v.PkgIdentifier.PURL)
	if purl == "" {
		return anomaly(AnomalyMissingPurl,
			"entry carries no PkgIdentifier.PURL, so record.Sca cannot identify the package")
	}
	if canonicalTarget == "" {
		return anomaly(AnomalyMissingTarget,
			"result Target canonicalises to the empty string, and the SCA fingerprint tier requires a manifest path")
	}

	// Identity fields are ASSERTED, never rewritten. See
	// AnomalyUnsanitizedIdentity.
	identity := map[string]string{
		"advisory id":       v.VulnerabilityID,
		"package name":      v.PkgName,
		"purl":              purl,
		"installed version": v.InstalledVersion,
		"manifest path":     canonicalTarget,
	}
	if err := sanitize.AssertAllSanitized(identity); err != nil {
		return anomaly(AnomalyUnsanitizedIdentity, err.Error())
	}

	// Prose is sanitised. plan/00-SPINE.md S7: "sanitize at ingest, not at
	// prompt time." sanitize.Ingest is the entry point that also stamps the
	// trust level, so a caller cannot sanitise and then forget to classify.
	title, s := sanitize.Ingest(v.Title)
	stats.Merge(s)
	desc, s := sanitize.Ingest(v.Description)
	stats.Merge(s)
	refs, s := sanitize.IngestSlice(v.References)
	stats.Merge(s)

	severity, s := sanitize.Sanitize(v.Severity)
	stats.Merge(s)
	primaryURL, s := sanitize.Sanitize(v.PrimaryURL)
	stats.Merge(s)

	var dsID, dsName string
	if v.DataSource != nil {
		dsID, s = sanitize.Sanitize(v.DataSource.ID)
		stats.Merge(s)
		dsName, s = sanitize.Sanitize(v.DataSource.Name)
		stats.Merge(s)
	}

	fixed := strings.TrimSpace(v.FixedVersion)

	return Finding{
		Collector:        cache.CollectorRepoSCA,
		AdvisoryID:       v.VulnerabilityID,
		DataSourceID:     dsID,
		DataSourceName:   dsName,
		PackageName:      v.PkgName,
		Purl:             purl,
		InstalledVersion: v.InstalledVersion,
		FixedVersion:     fixed,
		ManifestRelPath:  canonicalTarget,
		Ecosystem:        r.Type,
		Detector:         record.DetectorKindSCA,
		EvidenceClass:    record.EvidenceClassSCA,
		// See the field comment: no fixed version, no bump to propose.
		RemediableByAgent: fixed != "",
		Severity:          severity,
		Level:             severityToLevel(severity),
		Trust:             findingTrust,
		Title:             title,
		Description:       desc,
		References:        refs,
		PrimaryURL:        primaryURL,
		PublishedDate:     v.PublishedDate,
		LastModifiedDate:  v.LastModifiedDate,
	}, stats, nil
}

// Trivy's documented severity vocabulary.
const (
	severityUnknown  = "UNKNOWN"
	severityLow      = "LOW"
	severityMedium   = "MEDIUM"
	severityHigh     = "HIGH"
	severityCritical = "CRITICAL"
)

func knownSeverity(s string) bool {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case severityUnknown, severityLow, severityMedium, severityHigh, severityCritical:
		return true
	}
	return false
}

// severityToLevel derives the SARIF level from Trivy's severity.
//
// SARIF's `level` is severity, not confidence, and the record contract
// requires third-party ranking be re-derived rather than adopted — so this
// mapping is Anvil's, stated once, in one place:
//
//	CRITICAL, HIGH -> error
//	MEDIUM         -> warning
//	LOW            -> note
//	UNKNOWN, and anything unrecognised -> warning
//
// The last row is the one with a judgement in it. An unrecognised severity
// could be mapped to `none`, which reads as "nothing here" and hides the
// finding in every consumer that filters by level — turning a vocabulary
// change upstream into silently dropped output. Mapping it to `warning`
// over-reports instead, and over-reporting is the recoverable direction.
// Coverage.UnmappedSeverity counts every one, so the inflation is visible.
func severityToLevel(severity string) record.Level {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case severityCritical, severityHigh:
		return record.LevelError
	case severityMedium:
		return record.LevelWarning
	case severityLow:
		return record.LevelNote
	default:
		return record.LevelWarning
	}
}

// RelativeManifestPath canonicalises a Trivy target that may be absolute
// against the scanned root, then hands it to record.CanonicalRepoRelPath.
//
// Trivy reports lockfile targets relative to the scanned directory, but an
// absolute path has been observed for some target types; a caller that stored
// one would fingerprint the same finding differently on a machine with a
// different checkout path. Exported because A.19 may need to re-derive it from
// a stored report.
func RelativeManifestPath(root, target string) string {
	t := target
	if filepath.IsAbs(t) && root != "" {
		if rel, err := filepath.Rel(root, t); err == nil {
			t = rel
		}
	}
	return record.CanonicalRepoRelPath(t)
}
