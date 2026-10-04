package remediation

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/handoff"
	"github.com/Susquehanna-Syntax/Anvil/internal/laneb"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/scanctl"
	"github.com/Susquehanna-Syntax/Anvil/internal/settings"
)

// ErrNotEnabled means the operator's file leaves the remediation tier off.
var ErrNotEnabled = errors.New("remediation: the remediation tier is not enabled in the operator's configuration")

// FromSettings builds the controller an installation runs, and returns the
// warnings its endpoint earns (only a public endpoint the operator allowed
// earns one). exe is the anvil binary, which runs each generation as
// `anvil generate-isolated`; laneB is Lane B's configuration, for the
// diff-aware rescan.
func FromSettings(db *sql.DB, s settings.Settings, exe string, laneB *laneb.Config) (*Controller, []string, error) {
	r := s.Remediation
	if !r.Enabled {
		return nil, nil, ErrNotEnabled
	}
	ep := Endpoint{URL: r.EndpointURL, Model: r.Model, Tier: Tier(r.Tier), AllowPublic: r.AllowPublic, APIKeyFile: r.APIKeyFile}
	warnings, err := ep.Check()
	if err != nil {
		return nil, nil, err
	}
	q, err := handoff.New(db, handoff.Options{})
	if err != nil {
		return nil, nil, err
	}
	cons, err := scanctl.NewConsumer(q, scanctl.DeadlinePolicy{})
	if err != nil {
		return nil, nil, err
	}
	host, _ := os.Hostname()
	c := &Controller{
		DB: db, Consumer: cons, Triage: TriageMode(r.Triage), WorkDir: r.WorkDir, BudgetTokens: r.BudgetTokens,
		WorkerID: fmt.Sprintf("anvil-remediate@%s/%d", host, os.Getpid()),
		Gen:      IsolatedGenerator{Exe: exe, Args: []string{"generate-isolated"}, Endpoint: ep},
		Targets:  map[string]Target{},
	}
	forkRemote := map[string]string{}
	// The build sandbox shows /etc read-only; the directories holding the
	// operator's secrets are hidden from it.
	for _, f := range []string{r.APIKeyFile, r.ForgeTokenFile} {
		if f != "" {
			c.Hide = append(c.Hide, filepath.Dir(f))
		}
	}
	for _, t := range r.Targets {
		c.Targets[t.Locator] = Target{Locator: t.Locator, Source: t.Source, Build: t.Build, Test: t.Test, SandboxEnv: t.Env,
			SandboxReadOnly: t.ReadOnly, Repository: t.Repository, Fork: t.Fork, BaseBranch: t.BaseBranch}
		forkRemote[t.Locator] = t.ForkRemote
	}
	if laneB != nil {
		c.Rescan = func(locator string) func(context.Context, string, []string) (map[string]bool, error) {
			return LaneBRescan(*laneB, locator)
		}
	}
	if r.ForgeTokenFile != "" {
		raw, err := os.ReadFile(r.ForgeTokenFile)
		if err != nil {
			return nil, nil, fmt.Errorf("remediation: reading the forge token: %w", err)
		}
		token := strings.TrimSpace(string(raw))
		c.Forge = GitHubREST{API: r.ForgeAPI, Token: token}
		c.Pusher = func(t Target) Pusher { return GitPusher{Remote: forkRemote[t.Locator], Token: token} }
	}
	return c, warnings, nil
}

// LaneBRescan is the ladder's diff-aware rescan: Lane B over the named files,
// returning the fingerprints of its results in those files. A rescan with a
// coverage problem is an error: an incomplete rescan cannot clear a finding.
func LaneBRescan(cfg laneb.Config, locator string) func(context.Context, string, []string) (map[string]bool, error) {
	return func(ctx context.Context, root string, files []string) (map[string]bool, error) {
		lane, err := laneb.Prepare(ctx, cfg, root)
		if err != nil {
			return nil, err
		}
		out, err := lane.Only(files).Run(ctx, locator)
		if err != nil {
			return nil, err
		}
		want := map[string]bool{}
		for _, f := range files {
			want[f] = true
		}
		// A narrowed plan that reads none of the touched files would report
		// nothing, and nothing would read as "the rule no longer matches".
		if len(out.Problems) > 0 && strings.HasPrefix(out.Problems[0], "Lane B found no source file") || out.Recall.Files == 0 {
			return nil, fmt.Errorf("the rescan read none of the touched files %v", files)
		}
		var problems []string
		problems = append(problems, out.Problems...)
		if len(problems) > 0 {
			return nil, fmt.Errorf("the rescan's coverage is incomplete: %s", strings.Join(problems, "; "))
		}
		found := map[string]bool{}
		for _, r := range out.Results {
			if len(r.Locations) == 0 || r.Locations[0].PhysicalLocation == nil {
				continue
			}
			if want[r.Locations[0].PhysicalLocation.ArtifactLocation.URI] {
				found[r.PartialFingerprints[record.PartialFingerprintAnvilFindingID]] = true
			}
		}
		return found, nil
	}
}

// EnqueuePending enqueues every SAST-sealed audit still inside its claim
// window that has no handoff row yet. It is what `anvil remediate` runs first,
// so audits sealed by the daemon or by `anvil scan` reach the queue whichever
// process sealed them.
func (c *Controller) EnqueuePending(ctx context.Context) (EnqueueReport, error) {
	total := EnqueueReport{Disposed: map[record.HandoffState]int{}}
	rows, err := c.DB.QueryContext(ctx, `SELECT a.audit_record_id, a.deadline_at FROM audit_record a
		WHERE a.sast_status = 'sealed' AND a.payload IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM handoff h WHERE h.audit_record_id = a.audit_record_id)
		ORDER BY a.audit_record_id`)
	if err != nil {
		return total, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		var deadline string
		if err := rows.Scan(&id, &deadline); err != nil {
			_ = rows.Close()
			return total, err
		}
		if d, err := time.Parse(time.RFC3339, deadline); err == nil && d.After(c.now()) {
			ids = append(ids, id)
		}
	}
	_ = rows.Close()
	for _, id := range ids {
		rep, err := c.EnqueueAudit(ctx, c.Consumer.Queue(), id)
		if err != nil {
			return total, err
		}
		total.Enqueued += rep.Enqueued
		total.Superseded += rep.Superseded
		for k, v := range rep.Disposed {
			total.Disposed[k] += v
		}
	}
	return total, nil
}
