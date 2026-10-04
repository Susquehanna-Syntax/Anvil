// This file is the scan itself: trigger policy, controller, collection,
// comparison, emission, seal, assembly, masking, the store and the SARIF
// output, in that order (plan node cli).
//
// A repository scan runs two lanes into the one SAST half: Lane A's
// repository SCA (Trivy, when the operator enables its database) and Lane B's
// recall tier (when the operator configures its rule pack and tools). Each
// lane runs only if the configuration enables it and the trigger policy's
// detectors allow it. A lane the configuration leaves off is stated in
// Result.NotRun, and a scan with a lane not run and nothing found exits
// refused, never clean: no scan reports a repository clean on the strength of
// half its lanes.

package scan

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/collector/host"
	"github.com/Susquehanna-Syntax/Anvil/internal/collector/repo"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/laneb"
	"github.com/Susquehanna-Syntax/Anvil/internal/match"
	"github.com/Susquehanna-Syntax/Anvil/internal/policy"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/record/lanea"
	"github.com/Susquehanna-Syntax/Anvil/internal/scanctl"
	"github.com/Susquehanna-Syntax/Anvil/internal/store"
)

// Kind is what a scan looks at.
type Kind string

// The two Lane A scan kinds.
const (
	KindRepo Kind = "repo"
	KindHost Kind = "host"
)

// RulesetVersion is scan_run.ruleset_version for a Lane A scan. Lane A has no
// rules of its own; the version names the matching logic, and moves when a
// change to it can change a verdict.
const RulesetVersion = "lanea/v1"

// Request is one scan.
type Request struct {
	Kind Kind

	// RepoPath is the repository to scan (KindRepo).
	RepoPath string
	// TargetName overrides the repository's identity, which is otherwise its
	// absolute path. It names the target; it does not change what is read.
	TargetName string

	// Inventory is the host collector's output (KindHost). The scan never
	// collects a host itself: the collector runs under its systemd unit.
	Inventory *host.Inventory

	// Event is the trigger event the policy is evaluated against, e.g.
	// "manual" or "schedule". Full marks a scheduled full scan.
	Event string
	Full  bool

	// PolicyPath is the policy file. Empty means policy.Locate under the
	// repository for a repo scan, and no policy for a host scan.
	PolicyPath string

	Cache *sql.DB
	Feeds config.FeedSet
	Store *sql.DB

	TrivyDB TrivyDB
	Trivy   repo.Config

	// LaneB configures Lane B's recall tier for repository scans. Nil means
	// the operator's configuration leaves Lane B off.
	LaneB *laneb.Config

	AnvilVersion string
	Now          func() time.Time
}

// Outcome classifies a finished scan for the command's exit status.
type Outcome string

// The outcomes. Missing and Refused never describe a clean scan.
const (
	OutcomeClean    Outcome = "clean"    // sealed, complete, no findings
	OutcomeFindings Outcome = "findings" // at least one finding
	OutcomeRefused  Outcome = "refused"  // the scan did not see everything it was asked to
	OutcomeMissing  Outcome = "missing"  // a tool or its data is absent
)

// Result is one finished scan.
type Result struct {
	Outcome   Outcome
	AuditID   string
	Log       *record.SARIFLog
	Write     store.WriteResult
	Emitted   int
	Complete  bool
	Problems  []string
	PolicyHit []string

	// NotRun names each lane the operator's configuration left off. It keeps
	// a scan with nothing found from reading clean.
	NotRun []string
	// Notes are informational: Lane B's candidate count and its budget flag.
	Notes []string
	// RecallCandidates is Lane B's candidates-per-scan count; nil when Lane B
	// did not run.
	RecallCandidates *int
}

// ErrPolicyRefused means the trigger policy resolved to a rule whose
// detectors exclude this scan's lane, or (for a scheduled scan) no rule
// matched at all.
var ErrPolicyRefused = errors.New("scan: the trigger policy does not run this scan")

// ErrMissingTool wraps a missing scanner or its data.
var ErrMissingTool = errors.New("scan: a required tool or its data is missing")

// The two NotRun statements.
const (
	notRunSCA   = "repository SCA did not run: the operator's configuration does not enable the Trivy database (trivyDB: {enabled: true})"
	notRunLaneB = "Lane B did not run: the operator's configuration does not enable it (recall: {enabled: true})"
)

// Run performs one scan. A returned error with ErrMissingTool, ErrPolicyRefused
// or ErrRepoSCANotEnabled happened BEFORE anything was recorded; any other
// failure after the audit began is recorded as a failed half and returned in
// Result.Problems with Outcome refused.
func Run(ctx context.Context, req Request) (Result, error) {
	now := req.Now
	if now == nil {
		now = time.Now
	}
	if req.Store == nil || req.Cache == nil {
		return Result{}, errors.New("scan: a scan needs the store and the advisory cache")
	}

	if req.Kind != KindRepo && req.Kind != KindHost {
		return Result{}, fmt.Errorf("scan: unknown scan kind %q", req.Kind)
	}
	rule, polRef, err := resolvePolicy(req)
	if err != nil {
		return Result{}, err
	}

	// Everything that can stop a scan before it starts is checked first, so
	// a refusal leaves no audit behind.
	var (
		locator  string
		trivyDB  repo.DatabaseInfo
		lane     *laneb.Lane
		runSCA   bool
		detected []record.DetectorKind
		notRun   []string
	)
	switch req.Kind {
	case KindRepo:
		if !req.TrivyDB.Enabled && req.LaneB == nil {
			return Result{}, fmt.Errorf("%w, and Lane B is not enabled either, so a repository scan has no lane to run", ErrRepoSCANotEnabled)
		}
		runSCA = req.TrivyDB.Enabled && policyAllows(rule, record.DetectorKindSCA)
		runLaneB := req.LaneB != nil && policyAllows(rule, record.DetectorKindSast)
		if !runSCA && !runLaneB {
			return Result{}, fmt.Errorf("%w: the resolved rule's detectors are %v, which exclude every enabled repository lane",
				ErrPolicyRefused, rule.Detectors)
		}
		if !req.TrivyDB.Enabled {
			notRun = append(notRun, notRunSCA)
		}
		if req.LaneB == nil {
			notRun = append(notRun, notRunLaneB)
		}
		abs, err := filepath.Abs(req.RepoPath)
		if err != nil {
			return Result{}, err
		}
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			return Result{}, fmt.Errorf("scan: %q is not a directory", req.RepoPath)
		}
		req.RepoPath = abs
		locator = "repo:" + abs
		if req.TargetName != "" {
			locator = "repo:" + req.TargetName
		}
		if runSCA {
			if _, err := repo.ResolveBinary(binaryOf(req.Trivy)); err != nil {
				return Result{}, fmt.Errorf("%w: %v", ErrMissingTool, err)
			}
			trivyDB, err = repo.Database(ctx, req.Trivy.Runner())
			if err != nil {
				return Result{}, fmt.Errorf("%w: %v", ErrMissingTool, err)
			}
			detected = append(detected, record.DetectorKindSCA)
		}
		if runLaneB {
			// A refused rule pack, an absent tool and a tool at the wrong
			// version all stop the scan here, before any audit exists.
			if lane, err = laneb.Prepare(ctx, *req.LaneB, abs); err != nil {
				return Result{}, fmt.Errorf("%w: %v", ErrMissingTool, err)
			}
			detected = append(detected, record.DetectorKindSast)
		}
	case KindHost:
		if !policyAllows(rule, record.DetectorKindHost) {
			return Result{}, fmt.Errorf("%w: the resolved rule's detectors are %v, which exclude %q",
				ErrPolicyRefused, rule.Detectors, record.DetectorKindHost)
		}
		detected = []record.DetectorKind{record.DetectorKindHost}
		if req.Inventory == nil {
			return Result{}, errors.New("scan: a host scan needs the collector's inventory")
		}
		h := strings.TrimSpace(req.Inventory.Provenance.Hostname)
		if h == "" {
			return Result{}, fmt.Errorf("%w: the inventory names no host, so its findings would have no target", ErrPolicyRefused)
		}
		locator = "host:" + h
	}

	ctl, err := scanctl.NewController(scanctl.DeadlinePolicy{}, scanctl.WatermarkPolicy{})
	if err != nil {
		return Result{}, err
	}
	ctl.SetClock(now)
	auditID, err := newAuditID()
	if err != nil {
		return Result{}, err
	}
	started := now().UTC()
	rec, err := ctl.Begin(auditID, started)
	if err != nil {
		return Result{}, err
	}

	res := Result{AuditID: auditID, Complete: true, PolicyHit: rule.MatchedNames(), NotRun: notRun}
	emitter := lanea.Emitter{TargetID: locator, AssembledAt: started}
	var (
		emissions []lanea.Emission
		snapshot  *record.AdvisorySnapshot
		engineVer []string
		ruleset   = []string{RulesetVersion}
		half      = record.HalfStatusSealed
		lbOut     laneb.Output
	)
	incomplete := func(format string, args ...any) {
		res.Complete = false
		res.Problems = append(res.Problems, fmt.Sprintf(format, args...))
	}

	switch req.Kind {
	case KindHost:
		emissions, snapshot, err = hostLane(ctx, req, emitter, incomplete)
		if err != nil {
			half = record.HalfStatusFailed
			incomplete("%v", err)
		}
	case KindRepo:
		if runSCA {
			engineVer = append(engineVer, "trivy "+trivyDB.TrivyVersion)
			emissions, err = repoLane(ctx, req, trivyDB, emitter, incomplete)
			if err != nil {
				half = record.HalfStatusFailed
				incomplete("%v", err)
			}
			snapshot = &record.AdvisorySnapshot{
				FeedIDs:        []string{TrivyDBSource},
				SnapshotDigest: TrivyDBSource + "@" + trivyDB.UpdatedAt.UTC().Format(time.RFC3339),
				ScrapedAt:      trivyDB.UpdatedAt.UTC(),
			}
		}
		if lane != nil {
			engineVer = append(engineVer, lane.EngineVersion())
			ruleset = append(ruleset, lane.RulesetVersion())
			lbOut, err = lane.Run(ctx, locator)
			if err != nil {
				half = record.HalfStatusFailed
				incomplete("%v", err)
			} else {
				for _, p := range lbOut.Problems {
					incomplete("%s", p)
				}
				res.Notes = append(res.Notes, lbOut.Notes...)
				n := lbOut.Recall.Count
				res.RecallCandidates = &n
			}
			if snapshot == nil {
				// The SAST run names the corpus it read; with no advisory
				// feed in this scan, that corpus is the rule pack.
				snapshot = lane.Snapshot()
			}
		}
	}
	results := lanea.Results(emissions)
	results = append(results, lbOut.Results...)
	res.Emitted = len(results)

	if len(results) > 0 {
		if rec, err = ctl.Transition(rec, scanctl.FindingsEvent(record.HalfSast, results...)); err != nil {
			return res, err
		}
	}
	if rec, err = ctl.Transition(rec, scanctl.SealHalfEvent(record.HalfSast, half)); err != nil {
		return res, err
	}
	seal, ok := ctl.Sealer().Inspect(auditID)
	if !ok {
		return res, errors.New("scan: the sealer lost the audit it just sealed")
	}

	actor := os.Getenv("USER")
	l, err := record.Assemble(record.Assembly{
		Seal:    seal,
		Version: rec.Version,
		Target: record.Target{
			RepoURL:    repoURL(req),
			Provenance: record.TargetProvenanceNoTargetDeclared,
		},
		Trigger: record.Trigger{
			Kind: req.Event, PolicyID: strings.Join(rule.MatchedNames(), ","), PolicyRef: polRef,
			ConfigSource: polRef, Actor: actor, ResolvedAt: started,
		},
		SastTool:         record.ToolComponent{Name: "anvil", Version: req.AnvilVersion},
		SastExtensions:   lbOut.Extensions,
		SastTaxonomies:   lbOut.Taxonomies,
		SastResults:      results,
		AdvisorySnapshot: snapshot,
		SpecHarvest:      lbOut.SpecHarvest,
	})
	if err != nil {
		return res, err
	}
	if err := record.MaskRecord(l); err != nil {
		return res, err
	}
	if err := record.AssertMasked(l); err != nil {
		return res, err
	}
	res.Log = l

	var commit string
	if req.Kind == KindRepo {
		var note string
		commit, note = BaseCommit(ctx, req.RepoPath)
		if note != "" {
			res.Notes = append(res.Notes, note)
		}
	}
	w, err := store.WriteScan(ctx, req.Store, store.ScanWrite{
		TargetKind:        string(req.Kind),
		TargetLocator:     locator,
		TriggerRef:        req.Event,
		CommitSHA:         commit,
		RulesetVersion:    strings.Join(ruleset, "+"),
		SastEngineVersion: strings.Join(engineVer, "; "),
		AdvisorySnapshot:  snapshotDigest(snapshot),
		FinishedAt:        now().UTC(),
		Seal:              seal,
		AuditVersion:      rec.Version,
		Complete:          res.Complete,
		DetectorsRun:      detectorsRun(detected, lane, res.RecallCandidates),
		RecallCandidates:  res.RecallCandidates,
		Log:               l,
	})
	if err != nil {
		return res, err
	}
	res.Write = w

	switch {
	case len(results) > 0:
		res.Outcome = OutcomeFindings
	case half != record.HalfStatusSealed || !res.Complete || len(res.NotRun) > 0:
		res.Outcome = OutcomeRefused
	default:
		res.Outcome = OutcomeClean
	}
	return res, nil
}

// BaseCommit is the commit a repository scan read: HEAD of the checkout, when
// root is the top of a git working tree with nothing uncommitted. Otherwise it
// is empty and the note says why; the remediation tier withdraws an audit's
// findings to report-only when no base commit names the blobs it scanned.
//
// git runs in the scanned repository, so it runs as the remediation tier runs
// it: hooks and fsmonitor off, no system or global configuration.
func BaseCommit(ctx context.Context, root string) (commit, note string) {
	gitc := func(args ...string) (string, error) {
		full := append([]string{"--no-optional-locks", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
			"-c", "core.untrackedCache=false", "-c", "diff.external=", "-c", "credential.helper=",
			"-c", "protocol.allow=never", "-C", root}, args...)
		cmd := exec.CommandContext(ctx, "git", full...)
		cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C"}
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	top, err := gitc("rev-parse", "--show-toplevel")
	if err != nil {
		return "", ""
	}
	if abs, aerr := filepath.EvalSymlinks(root); aerr != nil || filepath.Clean(top) != filepath.Clean(abs) {
		return "", ""
	}
	head, err := gitc("rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return "", "the checkout has no commit, so no base commit is recorded"
	}
	if dirty, err := gitc("status", "--porcelain", "--untracked-files=no"); err != nil || dirty != "" {
		return "", "the checkout has uncommitted changes, so no base commit is recorded and the remediation tier will not propose fixes from this scan"
	}
	return head, ""
}

// detectorsRun is what the store may resolve findings for: every lane that
// ran, except a Lane B run that failed before it counted anything, whose
// absent findings prove nothing.
func detectorsRun(detected []record.DetectorKind, lane *laneb.Lane, count *int) []record.DetectorKind {
	var out []record.DetectorKind
	for _, d := range detected {
		if d == record.DetectorKindSast && (lane == nil || count == nil) {
			continue
		}
		out = append(out, d)
	}
	return out
}

// policyAllows reports whether the resolved rule lets a detector run. A rule
// that names no detectors allows every one.
func policyAllows(rule policy.ResolvedRule, d record.DetectorKind) bool {
	return len(rule.Detectors) == 0 || rule.HasDetector(d)
}

// resolvePolicy evaluates the trigger policy for this scan. A repository with
// no policy file runs a manual scan with every enabled detector; a scheduled
// scan runs only when a rule matched, because "a timer fired" is not on its
// own a reason to scan.
func resolvePolicy(req Request) (policy.ResolvedRule, string, error) {
	path := req.PolicyPath
	if path == "" && req.Kind == KindRepo {
		p, err := policy.Locate(req.RepoPath)
		switch {
		case errors.Is(err, policy.ErrNoPolicyFound):
		case err != nil:
			return policy.ResolvedRule{}, "", err
		default:
			path = p
		}
	}
	if path == "" {
		if req.Full || req.Event == "schedule" {
			return policy.ResolvedRule{}, "", fmt.Errorf("%w: a scheduled scan needs a policy, and none was found", ErrPolicyRefused)
		}
		return policy.ResolvedRule{}, "", nil
	}
	p, err := policy.Load(path)
	if err != nil {
		return policy.ResolvedRule{}, path, err
	}
	rule, err := policy.Evaluate(p, policy.TriggerContext{Event: req.Event})
	if err != nil {
		return policy.ResolvedRule{}, path, err
	}
	if (req.Full || req.Event == "schedule") && len(rule.Matched) == 0 {
		return rule, path, fmt.Errorf("%w: no rule in %s matches event %q", ErrPolicyRefused, path, req.Event)
	}
	return rule, path, nil
}

// hostLane matches a host inventory against the cache.
func hostLane(ctx context.Context, req Request, e lanea.Emitter, incomplete func(string, ...any)) ([]lanea.Emission, *record.AdvisorySnapshot, error) {
	inv := req.Inventory
	for _, c := range inv.Coverage {
		if c.Status == host.FamilyFailed {
			incomplete("package family %s failed to enumerate", c.Ecosystem)
		}
	}
	if inv.ParseDegraded {
		incomplete("the inventory reports parse_degraded")
	}
	records, rel, err := HostRecords(inv)
	if err != nil {
		return nil, nil, err
	}
	snap, err := cacheSnapshot(ctx, req.Cache, rel.Key)
	if err != nil {
		return nil, nil, err
	}
	if snap == nil {
		return nil, nil, fmt.Errorf("the advisory cache holds no range for %s, so no package on this host could be decided", rel.Key)
	}
	m, err := match.NewMatcher(&CacheSource{DB: req.Cache, Release: rel.Key})
	if err != nil {
		return nil, nil, err
	}
	results, cov, err := m.Match(ctx, records)
	if err != nil {
		return nil, snap, err
	}
	if !cov.Complete {
		incomplete("the comparator's coverage is incomplete: %d refused scheme, %d refused version, %d unidentifiable, ecosystems refused %v",
			cov.PackagesRefusedScheme, cov.PackagesRefusedVersion, cov.PackagesUnidentifiable, cov.EcosystemsRefused)
	}
	if err := cov.AssertNotSilentlyClean(results); err != nil {
		incomplete("%v", err)
	}
	rows := &AdvisoryRows{DB: req.Cache, Feeds: req.Feeds}
	var out []lanea.Emission
	for _, r := range results {
		row, err := rows.Read(ctx, r.Source, r.SourceID)
		if err != nil {
			incomplete("%v", err)
			continue
		}
		em, err := e.Emit(r, row)
		if err != nil {
			incomplete("emission refused %s/%s for %s: %v", r.Source, r.SourceID, r.Package, err)
			continue
		}
		out = append(out, em)
	}
	return out, snap, nil
}

// repoLane runs Trivy over the repository and emits what it decided.
func repoLane(ctx context.Context, req Request, db repo.DatabaseInfo, e lanea.Emitter, incomplete func(string, ...any)) ([]lanea.Emission, error) {
	res, err := req.Trivy.ScanRepo(ctx, req.RepoPath)
	if err != nil {
		return nil, err
	}
	if err := res.AssertNotSilentlyEmpty(); err != nil {
		incomplete("%v", err)
	}
	matches, rows := RepoMatches(res, db)
	var out []lanea.Emission
	for _, m := range matches {
		em, err := e.Emit(m, rows[[2]string{m.Source, m.SourceID}])
		if err != nil {
			incomplete("emission refused %s/%s for %s: %v", m.Source, m.SourceID, m.Package, err)
			continue
		}
		out = append(out, em)
	}
	return out, nil
}

// cacheSnapshot names the advisory corpus a host scan reads: the feeds with a
// published range for the release, and the newest as_of among them. It
// returns nil when the cache holds no range for the release at all.
func cacheSnapshot(ctx context.Context, db *sql.DB, release string) (*record.AdvisorySnapshot, error) {
	rows, err := db.QueryContext(ctx, `
SELECT DISTINCT a.source, a.as_of, ifnull(af.purl,'')
FROM affected af JOIN advisory a ON a.source = af.source AND a.source_id = af.source_id
WHERE a.state = ?`, cache.AdvisoryPublished)
	if err != nil {
		return nil, fmt.Errorf("scan: reading the advisory snapshot: %w", err)
	}
	defer func() { _ = rows.Close() }()
	feeds := map[string]bool{}
	var newest time.Time
	for rows.Next() {
		var source, asOf, purl string
		if err := rows.Scan(&source, &asOf, &purl); err != nil {
			return nil, err
		}
		if !strings.Contains(purl, "distro="+release) {
			continue
		}
		feeds[source] = true
		if t, err := time.Parse(time.RFC3339, asOf); err == nil && t.After(newest) {
			newest = t
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(feeds) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(feeds))
	for f := range feeds {
		ids = append(ids, f)
	}
	sort.Strings(ids)
	return &record.AdvisorySnapshot{
		FeedIDs:        ids,
		SnapshotDigest: "cache@" + cache.SchemaSHA256() + "/" + release,
		ScrapedAt:      newest.UTC(),
	}, nil
}

func snapshotDigest(s *record.AdvisorySnapshot) string {
	if s == nil {
		return ""
	}
	return s.SnapshotDigest
}

func repoURL(req Request) string {
	if req.Kind != KindRepo {
		return ""
	}
	if req.TargetName != "" {
		return req.TargetName
	}
	return "file://" + filepath.ToSlash(req.RepoPath)
}

func binaryOf(c repo.Config) string {
	if c.Binary != "" {
		return c.Binary
	}
	return repo.BinaryName
}

// newAuditID is a random RFC 4122 version-4 UUID, the shape anvil/auditId
// takes everywhere else in the record.
func newAuditID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
