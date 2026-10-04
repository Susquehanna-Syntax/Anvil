package settings

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "anvil.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTheTrivyDatabaseIsOffUnlessTheFileTurnsItOn(t *testing.T) {
	s, err := Load(write(t, "version: 1\nstateDir: state\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.TrivyDB {
		t.Fatal("a configuration that does not mention trivyDB enabled it")
	}
	if !filepath.IsAbs(s.StateDir) || filepath.Base(s.StateDir) != "state" {
		t.Errorf("a relative stateDir resolves against the file: %q", s.StateDir)
	}
	on, err := Load(write(t, "version: 1\ntrivyDB:\n  enabled: true\n"))
	if err != nil || !on.TrivyDB {
		t.Fatalf("trivyDB.enabled: true -> %+v, %v", on, err)
	}
}

func TestLaneBIsOnUnlessTheFileTurnsItOff(t *testing.T) {
	s, err := Load(write(t, "version: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Recall.Enabled || s.Recall.Rules != "/usr/share/anvil/rules" {
		t.Fatalf("default recall settings %+v", s.Recall)
	}
	p := write(t, "version: 1\nrecall:\n  rules: data/rules\n  opengrep: /opt/opengrep\n")
	s, err = Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Recall.Enabled || s.Recall.Rules != filepath.Join(filepath.Dir(p), "data/rules") || s.Recall.Opengrep != "/opt/opengrep" {
		t.Fatalf("recall settings %+v", s.Recall)
	}
	off, err := Load(write(t, "version: 1\nrecall:\n  enabled: false\n"))
	if err != nil || off.Recall.Enabled {
		t.Fatalf("recall.enabled: false -> %+v, %v", off.Recall, err)
	}
}

func TestLoadRefuses(t *testing.T) {
	for name, body := range map[string]string{
		"unknown key":        "version: 1\ntrivyDb:\n  enabled: true\n",
		"unknown nested key": "version: 1\ntrivyDB:\n  enable: true\n",
		"string boolean":     "version: 1\ntrivyDB:\n  enabled: \"true\"\n",
		"no version":         "stateDir: /x\n",
		"wrong version":      "version: 2\n",
		"empty path":         "version: 1\nfeeds: \"\"\n",
		"unknown recall key": "version: 1\nrecall:\n  rule: x\n",
		"recall not a map":   "version: 1\nrecall: on\n",
		"recall string bool": "version: 1\nrecall:\n  enabled: \"false\"\n",
		"recall empty path":  "version: 1\nrecall:\n  gosec: \"\"\n",
	} {
		if _, err := Load(write(t, body)); !errors.Is(err, ErrSettings) {
			t.Errorf("%s: err = %v, want ErrSettings", name, err)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yml")); err == nil {
		t.Error("a named configuration file that does not exist loaded")
	}
}

// TestRemediationIsOffAndNamesNoModel: the remediation tier is off unless the
// file turns it on, triage is off by default, and turning the tier on without
// naming an endpoint, a model and a tier is refused: there is no default.
func TestRemediationIsOffAndNamesNoModel(t *testing.T) {
	s, err := Load(write(t, "version: 1\nstateDir: state\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Remediation.Enabled || s.Remediation.Model != "" || s.Remediation.EndpointURL != "" {
		t.Fatalf("a file that does not mention remediation: %+v", s.Remediation)
	}
	on, err := Load(write(t, `version: 1
stateDir: state
remediation:
  enabled: true
  endpoint:
    url: http://127.0.0.1:8080/v1
    model: qwen3-coder
    tier: local
  targets:
    - locator: "repo:anvil"
      source: ../anvil
      build: [go, build, ./...]
      test: [go, test, ./...]
      repository: owner/anvil
      fork: anvil-bot/anvil
`))
	if err != nil {
		t.Fatal(err)
	}
	r := on.Remediation
	if !r.Enabled || r.Triage != "off" || r.Model != "qwen3-coder" || len(r.Targets) != 1 || r.StaleAfterDays != 30 ||
		!filepath.IsAbs(r.Targets[0].Source) || len(r.Targets[0].Test) != 3 || filepath.Base(r.WorkDir) != "remediation" {
		t.Fatalf("%+v", r)
	}
	for _, bad := range []string{
		"remediation:\n  enabled: true\n",
		"remediation:\n  enabled: true\n  endpoint:\n    url: http://x/v1\n    tier: own\n",
		"remediation:\n  triage: always\n",
		"remediation:\n  merge: true\n",
		"remediation:\n  endpoint:\n    token: x\n",
		"remediation:\n  targets:\n    - locator: x\n      source: y\n      build: go build ./...\n",
		"remediation:\n  targets:\n    - locator: x\n",
	} {
		if _, err := Load(write(t, "version: 1\n"+bad)); !errors.Is(err, ErrSettings) {
			t.Errorf("%q was accepted: %v", bad, err)
		}
	}
}
