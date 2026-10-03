package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/collector/host"
	"github.com/Susquehanna-Syntax/Anvil/internal/collector/repo"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/delta"
	"github.com/Susquehanna-Syntax/Anvil/internal/scan"
)

// Request is one dispatched scan, as a spool file holds it.
type Request struct {
	Kind      scan.Kind `json:"kind"`
	Repo      string    `json:"repo,omitempty"`
	Target    string    `json:"target,omitempty"`
	Inventory string    `json:"inventory,omitempty"` // a host collector's output, on disk
	Event     string    `json:"event"`
	Full      bool      `json:"full,omitempty"`
	Policy    string    `json:"policy,omitempty"`
}

// Answer is what the daemon writes back for one request.
type Answer struct {
	Request  Request        `json:"request"`
	Outcome  scan.Outcome   `json:"outcome,omitempty"`
	AuditID  string         `json:"auditId,omitempty"`
	Findings int            `json:"findings"`
	Marks    map[string]int `json:"marks,omitempty"`
	Problems []string       `json:"problems,omitempty"`
	Error    string         `json:"error,omitempty"`
	At       time.Time      `json:"at"`
}

// Spool file suffixes. A request is <name>.json; claimed, it is
// <name>.running; answered, <name>.done.json.
const (
	requestSuffix = ".json"
	runningSuffix = ".running"
	answerSuffix  = ".done.json"
)

// MaxRequestBytes bounds one spool file.
const MaxRequestBytes = 64 << 10

// Config is one daemon.
type Config struct {
	Cache, Store *sql.DB
	Feeds        config.FeedSet
	Syncer       *delta.Syncer // nil: no feed is refreshed
	SpoolDir     string
	Policy       string // the trigger policy for host requests
	TrivyDB      scan.TrivyDB
	Trivy        repo.Config
	Version      string
	Tick         time.Duration
	Log          io.Writer
	Now          func() time.Time
}

// log is where the daemon reports, io.Discard when the caller gave nothing.
func (c Config) log() io.Writer {
	if c.Log == nil {
		return io.Discard
	}
	return c.Log
}

// Run serves until ctx is cancelled. With once, it does one feed pass and one
// spool pass and returns.
func Run(ctx context.Context, cfg Config, once bool) error {
	if cfg.Tick <= 0 {
		cfg.Tick = time.Minute
	}
	if err := os.MkdirAll(cfg.SpoolDir, 0o700); err != nil {
		return fmt.Errorf("daemon: spool directory: %w", err)
	}
	t := time.NewTicker(cfg.Tick)
	defer t.Stop()
	for {
		SyncFeeds(ctx, cfg)
		if err := DrainSpool(ctx, cfg); err != nil {
			fmt.Fprintf(cfg.log(), "daemon: spool: %v\n", err)
		}
		if once {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// SyncFeeds asks the syncer to sync every enabled feed once.
func SyncFeeds(ctx context.Context, cfg Config) {
	if cfg.Syncer == nil {
		return
	}
	for _, f := range cfg.Feeds.Feeds {
		if !f.Enabled {
			continue
		}
		st, err := cfg.Syncer.SyncDelta(ctx, f)
		switch {
		case err != nil:
			fmt.Fprintf(cfg.log(), "daemon: feed %s: %v\n", f.ID, err)
		case st.Refused:
			fmt.Fprintf(cfg.log(), "daemon: feed %s refused: %s\n", f.ID, st.RefusedBecause)
		case st.Skipped:
		default:
			fmt.Fprintf(cfg.log(), "daemon: feed %s synced (%s)\n", f.ID, st.PollStatus)
		}
	}
}

// DrainSpool runs every pending request in the spool, oldest name first.
func DrainSpool(ctx context.Context, cfg Config) error {
	entries, err := os.ReadDir(cfg.SpoolDir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && strings.HasSuffix(n, requestSuffix) && !strings.HasSuffix(n, answerSuffix) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		base := strings.TrimSuffix(n, requestSuffix)
		claimed := filepath.Join(cfg.SpoolDir, base+runningSuffix)
		// The rename is the claim: a second daemon loses it and moves on.
		if err := os.Rename(filepath.Join(cfg.SpoolDir, n), claimed); err != nil {
			continue
		}
		ans := handle(ctx, cfg, claimed)
		out, _ := json.MarshalIndent(ans, "", "  ")
		if err := os.WriteFile(filepath.Join(cfg.SpoolDir, base+answerSuffix), append(out, '\n'), 0o600); err != nil {
			return err
		}
		_ = os.Remove(claimed)
		fmt.Fprintf(cfg.log(), "daemon: %s: %s %s\n", base, ans.Outcome, ans.Error)
	}
	return nil
}

func handle(ctx context.Context, cfg Config, path string) Answer {
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	ans := Answer{At: now().UTC()}
	req, err := readRequest(path)
	ans.Request = req
	if err != nil {
		ans.Error = err.Error()
		return ans
	}
	sr := scan.Request{
		Kind: req.Kind, RepoPath: req.Repo, TargetName: req.Target,
		Event: req.Event, Full: req.Full, PolicyPath: req.Policy,
		Cache: cfg.Cache, Store: cfg.Store, Feeds: cfg.Feeds,
		TrivyDB: cfg.TrivyDB, Trivy: cfg.Trivy, AnvilVersion: cfg.Version, Now: cfg.Now,
	}
	if req.Kind == scan.KindHost {
		if sr.PolicyPath == "" {
			sr.PolicyPath = cfg.Policy
		}
		inv, err := ReadInventory(req.Inventory)
		if err != nil {
			ans.Error = err.Error()
			return ans
		}
		sr.Inventory = inv
	}
	res, err := scan.Run(ctx, sr)
	if err != nil {
		ans.Error = err.Error()
		return ans
	}
	ans.Outcome, ans.AuditID, ans.Findings, ans.Problems = res.Outcome, res.AuditID, res.Emitted, res.Problems
	ans.Marks = map[string]int{}
	for _, m := range res.Write.Marks {
		ans.Marks[string(m.Kind)]++
	}
	return ans
}

func readRequest(path string) (Request, error) {
	f, err := os.Open(path)
	if err != nil {
		return Request{}, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, MaxRequestBytes))
	dec.DisallowUnknownFields()
	var r Request
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("daemon: %s is not a scan request: %w", filepath.Base(path), err)
	}
	if strings.TrimSpace(r.Event) == "" {
		return r, errors.New("daemon: a request names its trigger event")
	}
	return r, nil
}

// MaxInventoryBytes bounds a host inventory read from disk or stdin. A host
// with 50,000 packages writes a few megabytes.
const MaxInventoryBytes = 64 << 20

// ReadInventory reads a host collector's output from a file, or from stdin
// when path is "-".
func ReadInventory(path string) (*host.Inventory, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxInventoryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxInventoryBytes {
		return nil, fmt.Errorf("the inventory is over %d bytes", MaxInventoryBytes)
	}
	var inv host.Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		return nil, fmt.Errorf("the inventory is not the host collector's JSON: %w", err)
	}
	if inv.Collector != host.Collector || inv.SchemaVersion != host.InventorySchemaVersion {
		return nil, fmt.Errorf("the inventory names collector %q schema %d, want %q schema %d",
			inv.Collector, inv.SchemaVersion, host.Collector, host.InventorySchemaVersion)
	}
	return &inv, nil
}

// Enqueue writes a request into the spool, atomically: it is written under a
// temporary name and renamed, so the daemon never reads half a request.
func Enqueue(spoolDir string, r Request) (string, error) {
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(spoolDir, ".enqueue-*")
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	name := filepath.Join(spoolDir, time.Now().UTC().Format("20060102T150405.000000000Z")+"-"+string(r.Kind)+requestSuffix)
	if err := os.Rename(tmp.Name(), name); err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return name, nil
}
