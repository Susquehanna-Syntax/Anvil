package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/daemon"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

const fixture = "../../testdata/lanea-fixture"

// installation is a configuration file and an imported fixture snapshot in a
// temporary state directory.
func installation(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "anvil.yml")
	body := "version: 1\nstateDir: state\n" + extra
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := anvil(t, "feeds", "import", "--config", cfg, fixture); code != exitClean {
		t.Fatalf("feeds import exited %d: %s", code, stderr)
	}
	return cfg
}

func anvil(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestExitStatuses(t *testing.T) {
	cfg := installation(t, "")
	noLanes := installation(t, "recall:\n  enabled: false\n")
	inv := filepath.Join(fixture, "host", "inventory-1.json")
	sarif := filepath.Join(t.TempDir(), "host.sarif")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"version", []string{"version"}, exitClean},
		{"no command", nil, exitUsage},
		{"unknown command", []string{"frobnicate"}, exitUsage},
		{"scan with no target", []string{"scan", "--config", cfg}, exitUsage},
		{"scan with both targets", []string{"scan", "--config", cfg, "--repo", ".", "--host"}, exitUsage},
		{"a host scan never collects itself", []string{"scan", "--config", cfg, "--host"}, exitRefused},
		{"a host with findings", []string{"scan", "--config", cfg, "--host", "--inventory", inv, "--out", sarif}, exitFindings},
		{"a repository scan with both lanes off is refused", []string{"scan", "--config", noLanes, "--repo", filepath.Join(fixture, "repo")}, exitRefused},
		{"Lane B is on by default, and its absent rule pack is a missing tool", []string{"scan", "--config", cfg, "--repo", filepath.Join(fixture, "repo")}, exitMissing},
		{"anvil recall with Lane B off is refused", []string{"recall", "--config", noLanes, "."}, exitRefused},
		{"anvil recall with no rule pack is a missing tool", []string{"recall", "--config", cfg, "."}, exitMissing},
		{"anvil recall with no path", []string{"recall", "--config", cfg}, exitUsage},
		{"a scheduled scan with no policy is refused", []string{"scan", "--config", cfg, "--host", "--inventory", inv, "--full", "--event", "schedule"}, exitRefused},
		{"findings in the store", []string{"findings", "--config", cfg}, exitFindings},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, stderr := anvil(t, c.args...)
			if code != c.want {
				t.Errorf("exit %d, want %d; stderr: %s", code, c.want, stderr)
			}
		})
	}

	raw, err := os.ReadFile(sarif)
	if err != nil {
		t.Fatal(err)
	}
	var l record.SARIFLog
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	if err := l.Validate(); err != nil {
		t.Errorf("the SARIF file does not validate: %v", err)
	}
	if l.Runs[0].Properties.Status != record.HalfStatusSealed || len(l.Runs[0].Results) != 3 {
		t.Errorf("SARIF: SAST status %q with %d results", l.Runs[0].Properties.Status, len(l.Runs[0].Results))
	}
	// The wire schema types these as an object and an array; null is a defect
	// the Go validator cannot see. The full schema check runs in CI's
	// end-to-end job.
	for _, needle := range []string{`"byCluster": null`, `"byCwe": null`, `"byPath": null`, `"cveIds": null`} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Errorf("the SARIF file carries %s", needle)
		}
	}
}

// A missing Trivy is exit 4, never clean, once the operator has enabled the
// Trivy database.
func TestAMissingTrivyExitsMissingTool(t *testing.T) {
	cfg := installation(t, "trivyDB:\n  enabled: true\n")
	t.Setenv("PATH", t.TempDir())
	code, _, stderr := anvil(t, "scan", "--config", cfg, "--repo", filepath.Join(fixture, "repo"))
	if code != exitMissing {
		t.Fatalf("exit %d, want %d; stderr: %s", code, exitMissing, stderr)
	}
}

// TestTheDaemonRunsAPolicyDrivenScheduledScan is the daemon criterion of
// Phase 4's exit gate: a dispatched scheduled scan runs only through a policy
// rule for the schedule event, and the daemon records it.
func TestTheDaemonRunsAPolicyDrivenScheduledScan(t *testing.T) {
	policy, err := filepath.Abs(filepath.Join(fixture, "policy.yml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := installation(t, "policy: "+policy+"\n")
	inv, err := filepath.Abs(filepath.Join(fixture, "host", "inventory-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := anvil(t, "dispatch", "--config", cfg, "--host", "--inventory", inv, "--event", "schedule", "--full"); code != exitClean {
		t.Fatalf("dispatch exited %d: %s", code, stderr)
	}
	// A schedule event the policy has no rule for is refused, not run.
	if code, _, stderr := anvil(t, "dispatch", "--config", cfg, "--host", "--inventory", inv, "--event", "nightly", "--full"); code != exitClean {
		t.Fatalf("dispatch exited %d: %s", code, stderr)
	}
	code, _, stderr := anvil(t, "daemon", "--config", cfg, "--once")
	if code != exitClean {
		t.Fatalf("daemon exited %d: %s", code, stderr)
	}

	spool := filepath.Join(filepath.Dir(cfg), "state", "dispatch")
	answers, _ := filepath.Glob(filepath.Join(spool, "*.done.json"))
	if len(answers) != 2 {
		t.Fatalf("%d answers in the spool, want 2; daemon log: %s", len(answers), stderr)
	}
	byEvent := map[string]daemon.Answer{}
	for _, p := range answers {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var a daemon.Answer
		if err := json.Unmarshal(raw, &a); err != nil {
			t.Fatal(err)
		}
		byEvent[a.Request.Event] = a
	}
	if a := byEvent["schedule"]; a.Outcome != "findings" || a.Findings != 3 || a.Marks["new"] != 3 {
		t.Errorf("the scheduled scan: %+v", a)
	}
	if a := byEvent["nightly"]; a.Outcome != "" || !strings.Contains(a.Error, "no rule") {
		t.Errorf("an event the policy has no rule for: %+v", a)
	}
	if left, _ := filepath.Glob(filepath.Join(spool, "*.running")); len(left) != 0 {
		t.Errorf("claimed requests left behind: %v", left)
	}
}

// TestTheFullScanTimerIsTheMapsDesign holds the shipped units to plan node
// daemon: full scans are one-shot `anvil scan --full` runs woken by a weekly,
// persistent timer with a randomized delay, and nothing restarts them.
func TestTheFullScanTimerIsTheMapsDesign(t *testing.T) {
	read := func(name string) map[string][]string {
		raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", name))
		if err != nil {
			t.Fatal(err)
		}
		keys := map[string][]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("%s: unparseable line %q", name, line)
			}
			keys[k] = append(keys[k], v)
		}
		return keys
	}
	svc := read("anvil-full-scan@.service")
	if got := svc["Type"]; len(got) != 1 || got[0] != "oneshot" {
		t.Errorf("Type = %v, want oneshot", got)
	}
	if _, ok := svc["Restart"]; ok {
		t.Error("the full-scan service has a Restart= directive; the timer is the only thing that runs it")
	}
	exec := svc["ExecStart"]
	if len(exec) != 1 || !strings.HasPrefix(exec[0], "/usr/bin/anvil scan --full --event schedule ") {
		t.Errorf("ExecStart = %v, want one `anvil scan --full --event schedule` line", exec)
	}
	for k := range svc {
		if strings.HasPrefix(k, "Exec") && k != "ExecStart" {
			t.Errorf("%s= in the full-scan service: the scan is the only command it runs", k)
		}
	}
	if got := svc["SuccessExitStatus"]; len(got) != 1 || got[0] != "1" {
		t.Errorf("SuccessExitStatus = %v; exit 1 (findings) is a successful scan", got)
	}
	tim := read("anvil-full-scan@.timer")
	for k, want := range map[string]string{"OnCalendar": "weekly", "RandomizedDelaySec": "6h", "Persistent": "true"} {
		if got := tim[k]; len(got) != 1 || got[0] != want {
			t.Errorf("timer %s = %v, want %s", k, got, want)
		}
	}
}
