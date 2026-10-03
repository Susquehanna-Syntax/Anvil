// This file is the whole command line. Every decision lives in a tested
// package: internal/scan runs a scan, internal/daemon serves, internal/store
// reads findings back, internal/ingest/offline imports a feed snapshot. This
// file parses flags, opens the two databases, calls one of those, and turns
// the answer into an exit status.
//
// # Exit status
//
//	0  clean: the SAST half sealed, coverage was complete, nothing was found
//	1  findings: at least one finding
//	2  usage: the command line was wrong
//	3  refused: the scan did not see everything it was asked to (the trigger
//	   policy declined it, repository SCA is not enabled, the host's release
//	   cannot be matched, a half failed, coverage was incomplete)
//	4  missing tool: a scanner or its data is absent
//	5  error: anything else
//
// A refusal and a missing tool are never 0. No flag widens what a scan may
// touch: what a scan reads is the repository or inventory it is named, and
// whether Trivy-decided findings are admitted is the operator's configuration
// file, not a flag.
//
// THIS BINARY HAS NO NETWORK-PROBING CAPABILITY. The dynamic tier is
// cmd/anvil-dast, a separate artifact; TestSplit in split_test.go fails if
// any internal/dast package becomes reachable from here.

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/collector/repo"
	"github.com/Susquehanna-Syntax/Anvil/internal/daemon"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/delta"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/offline"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/poller"
	"github.com/Susquehanna-Syntax/Anvil/internal/scan"
	"github.com/Susquehanna-Syntax/Anvil/internal/settings"
	"github.com/Susquehanna-Syntax/Anvil/internal/store"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "0.0.0-dev"

// Exit statuses, documented at the top of this file.
const (
	exitClean    = 0
	exitFindings = 1
	exitUsage    = 2
	exitRefused  = 3
	exitMissing  = 4
	exitError    = 5
)

const usage = `usage:
  anvil scan --repo PATH [--target NAME] [--out FILE] [--event EVENT] [--full] [--policy FILE]
  anvil scan --host --inventory FILE|- [--out FILE] [--event EVENT] [--full] [--policy FILE]
  anvil findings [--target LOCATOR] [--all]
  anvil feeds import DIR
  anvil dispatch (--repo PATH | --host --inventory FILE) --event EVENT [--full]
  anvil daemon [--once]
  anvil version

Every command takes --config FILE (default $ANVIL_CONFIG, then /etc/anvil/anvil.yml).
anvil scan --host does not collect: it reads the inventory the host collector
(cmd/anvil-host-collector) writes when it runs under its systemd unit.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, version)
		return exitClean
	case "scan":
		return cmdScan(ctx, args[1:], stdout, stderr)
	case "findings":
		return cmdFindings(ctx, args[1:], stdout, stderr)
	case "feeds":
		return cmdFeeds(ctx, args[1:], stdout, stderr)
	case "dispatch":
		return cmdDispatch(args[1:], stdout, stderr)
	case "daemon":
		return cmdDaemon(ctx, args[1:], stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitClean
	}
	fmt.Fprintf(stderr, "anvil: unknown command %q\n\n%s", args[0], usage)
	return exitUsage
}

func newFlags(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("anvil "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	def := os.Getenv("ANVIL_CONFIG")
	if def == "" {
		def = settings.DefaultPath
	}
	return fs, fs.String("config", def, "operator configuration file")
}

// state is an opened installation: its settings and its two databases.
type state struct {
	cfg   settings.Settings
	cache *sql.DB
	store *sql.DB
	feeds config.FeedSet
}

func (s *state) close() {
	if s.cache != nil {
		_ = s.cache.Close()
	}
	if s.store != nil {
		_ = s.store.Close()
	}
}

func open(ctx context.Context, configPath string) (*state, error) {
	cfg, err := settings.Load(configPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	s := &state{cfg: cfg}
	if s.cache, err = cache.Open(ctx, cfg.CachePath()); err != nil {
		return nil, err
	}
	if _, err := cache.Migrate(ctx, s.cache); err != nil {
		s.close()
		return nil, err
	}
	if s.store, err = store.Open(ctx, cfg.StorePath(), filepath.Join(cfg.StateDir, "snapshots")); err != nil {
		s.close()
		return nil, err
	}
	if cfg.Feeds != "" {
		if s.feeds, err = config.Load(cfg.Feeds); err != nil {
			s.close()
			return nil, err
		}
	}
	return s, nil
}

func cmdScan(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs, configPath := newFlags("scan", stderr)
	repoPath := fs.String("repo", "", "scan the repository at PATH")
	hostScan := fs.Bool("host", false, "scan a host from its collector's inventory")
	inventory := fs.String("inventory", "", "the host collector's output, a file or - for stdin")
	target := fs.String("target", "", "name the repository target (its identity), instead of its absolute path")
	out := fs.String("out", "", "write the sealed record (SARIF 2.1.0) to FILE")
	event := fs.String("event", "manual", "the trigger event the policy is evaluated against")
	full := fs.Bool("full", false, "a scheduled full scan: runs only when the policy has a rule for the event")
	policyPath := fs.String("policy", "", "the trigger policy file")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 || (*repoPath == "") == !*hostScan {
		fmt.Fprintf(stderr, "anvil scan: give exactly one of --repo PATH or --host\n\n%s", usage)
		return exitUsage
	}
	if *hostScan && *inventory == "" {
		fmt.Fprint(stderr, "anvil scan --host: refusing to collect a host inventory itself.\n"+
			"The host collector runs read-only under deploy/systemd/anvil-host-collector.service\n"+
			"(DynamicUser, ProtectSystem=strict); pass its output with --inventory FILE or --inventory -.\n")
		return exitRefused
	}
	if !*hostScan && *inventory != "" {
		fmt.Fprint(stderr, "anvil scan: --inventory belongs to --host\n")
		return exitUsage
	}

	st, err := open(ctx, *configPath)
	if err != nil {
		fmt.Fprintf(stderr, "anvil scan: %v\n", err)
		return exitError
	}
	defer st.close()

	req := scan.Request{
		Kind: scan.KindRepo, RepoPath: *repoPath, TargetName: *target,
		Event: *event, Full: *full, PolicyPath: *policyPath,
		Cache: st.cache, Store: st.store, Feeds: st.feeds,
		TrivyDB: scan.TrivyDB{Enabled: st.cfg.TrivyDB}, Trivy: repo.DefaultConfig(),
		AnvilVersion: version,
	}
	if *hostScan {
		req.Kind = scan.KindHost
		if req.PolicyPath == "" {
			req.PolicyPath = st.cfg.Policy
		}
		if req.Inventory, err = daemon.ReadInventory(*inventory); err != nil {
			fmt.Fprintf(stderr, "anvil scan --host: %v\n", err)
			return exitError
		}
	}
	res, err := scan.Run(ctx, req)
	switch {
	case errors.Is(err, scan.ErrMissingTool):
		fmt.Fprintf(stderr, "anvil scan: %v\n", err)
		return exitMissing
	case errors.Is(err, scan.ErrRepoSCANotEnabled), errors.Is(err, scan.ErrPolicyRefused):
		fmt.Fprintf(stderr, "anvil scan: %v\n", err)
		return exitRefused
	case err != nil:
		fmt.Fprintf(stderr, "anvil scan: %v\n", err)
		return exitError
	}
	if *out != "" {
		if err := writeRecord(*out, res); err != nil {
			fmt.Fprintf(stderr, "anvil scan: writing %s: %v\n", *out, err)
			return exitError
		}
	}
	report(stdout, res)
	for _, p := range res.Problems {
		fmt.Fprintf(stderr, "anvil scan: %s\n", p)
	}
	switch res.Outcome {
	case scan.OutcomeFindings:
		return exitFindings
	case scan.OutcomeClean:
		return exitClean
	case scan.OutcomeMissing:
		return exitMissing
	}
	return exitRefused
}

func writeRecord(path string, res scan.Result) error {
	b, err := json.MarshalIndent(res.Log, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func report(w io.Writer, res scan.Result) {
	counts := map[store.MarkKind]int{}
	for _, m := range res.Write.Marks {
		counts[m.Kind]++
	}
	fmt.Fprintf(w, "audit %s: %s, %d finding(s); scan_run %d %s; new %d, persisting %d, regressed %d, fixed %d\n",
		res.AuditID, res.Outcome, res.Emitted, res.Write.ScanRunID, res.Write.Status,
		counts[store.MarkNew], counts[store.MarkPersisting], counts[store.MarkRegressed], counts[store.MarkFixed])
	for _, m := range res.Write.Marks {
		fmt.Fprintf(w, "  %-10s %s  %s\n", m.Kind, m.RuleID, m.Fingerprint[:16])
	}
}

func cmdFindings(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs, configPath := newFlags("findings", stderr)
	target := fs.String("target", "", "only this target's findings (its locator, e.g. host:NAME)")
	all := fs.Bool("all", false, "include resolved findings")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return exitUsage
	}
	st, err := open(ctx, *configPath)
	if err != nil {
		fmt.Fprintf(stderr, "anvil findings: %v\n", err)
		return exitError
	}
	defer st.close()
	fds, err := store.ListFindings(ctx, st.store, *target, *all)
	if err != nil {
		fmt.Fprintf(stderr, "anvil findings: %v\n", err)
		return exitError
	}
	for _, f := range fds {
		fmt.Fprintf(stdout, "%-9s %-9s %-16s %-8s %s  %s\n", f.State, f.Severity, f.RuleID, f.Detector, f.Target, f.Title)
	}
	if len(fds) == 0 {
		return exitClean
	}
	return exitFindings
}

func cmdFeeds(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "import" {
		fmt.Fprintf(stderr, "anvil feeds: the one subcommand is import\n\n%s", usage)
		return exitUsage
	}
	fs, configPath := newFlags("feeds import", stderr)
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
		fmt.Fprintf(stderr, "anvil feeds import: give one snapshot directory\n")
		return exitUsage
	}
	st, err := open(ctx, *configPath)
	if err != nil {
		fmt.Fprintf(stderr, "anvil feeds import: %v\n", err)
		return exitError
	}
	defer st.close()
	rep, err := offline.Import(ctx, st.cache, fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "anvil feeds import: %v\n", err)
		return exitError
	}
	code := exitClean
	for _, f := range rep.Feeds {
		if f.Refused != "" {
			fmt.Fprintf(stderr, "anvil feeds import: %s\n", f.Refused)
			code = exitRefused
			continue
		}
		fmt.Fprintf(stdout, "%s: %d document(s), %d advisory upsert(s), %d affected row(s), as of %s\n",
			f.FeedID, f.Documents, f.Stats.Upserts, f.Stats.AffectedRows, rep.AsOf.Format(time.RFC3339))
	}
	return code
}

func cmdDispatch(args []string, stdout, stderr io.Writer) int {
	fs, configPath := newFlags("dispatch", stderr)
	repoPath := fs.String("repo", "", "the repository to scan")
	hostScan := fs.Bool("host", false, "a host scan")
	inventory := fs.String("inventory", "", "the host collector's output on disk")
	target := fs.String("target", "", "name the repository target")
	event := fs.String("event", "", "the trigger event")
	full := fs.Bool("full", false, "a scheduled full scan")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *event == "" || (*repoPath == "") == !*hostScan {
		fmt.Fprintf(stderr, "anvil dispatch: give --event and exactly one of --repo or --host\n")
		return exitUsage
	}
	cfg, err := settings.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "anvil dispatch: %v\n", err)
		return exitError
	}
	req := daemon.Request{Kind: scan.KindRepo, Repo: *repoPath, Target: *target, Event: *event, Full: *full}
	if *hostScan {
		abs, err := filepath.Abs(*inventory)
		if err != nil || *inventory == "" || *inventory == "-" {
			fmt.Fprintf(stderr, "anvil dispatch --host: --inventory must name a file the daemon can read\n")
			return exitUsage
		}
		req.Kind, req.Inventory = scan.KindHost, abs
	} else if abs, err := filepath.Abs(*repoPath); err == nil {
		req.Repo = abs
	}
	path, err := daemon.Enqueue(cfg.SpoolDir, req)
	if err != nil {
		fmt.Fprintf(stderr, "anvil dispatch: %v\n", err)
		return exitError
	}
	fmt.Fprintln(stdout, path)
	return exitClean
}

func cmdDaemon(ctx context.Context, args []string, stderr io.Writer) int {
	fs, configPath := newFlags("daemon", stderr)
	once := fs.Bool("once", false, "one feed pass and one spool pass, then exit")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return exitUsage
	}
	st, err := open(ctx, *configPath)
	if err != nil {
		fmt.Fprintf(stderr, "anvil daemon: %v\n", err)
		return exitError
	}
	defer st.close()
	dc := daemon.Config{
		Cache: st.cache, Store: st.store, Feeds: st.feeds,
		SpoolDir: st.cfg.SpoolDir, Policy: st.cfg.Policy,
		TrivyDB: scan.TrivyDB{Enabled: st.cfg.TrivyDB}, Trivy: repo.DefaultConfig(),
		Version: version, Log: stderr,
	}
	if len(st.feeds.Feeds) > 0 {
		p, err := poller.New(poller.Options{DB: st.cache, Mirror: os.DirFS(st.cfg.MirrorRoot)})
		if err != nil {
			fmt.Fprintf(stderr, "anvil daemon: %v\n", err)
			return exitError
		}
		if dc.Syncer, err = delta.New(delta.Options{DB: st.cache, Poller: p}); err != nil {
			fmt.Fprintf(stderr, "anvil daemon: %v\n", err)
			return exitError
		}
	}
	if err := daemon.Run(ctx, dc, *once); err != nil {
		fmt.Fprintf(stderr, "anvil daemon: %v\n", err)
		return exitError
	}
	return exitClean
}
