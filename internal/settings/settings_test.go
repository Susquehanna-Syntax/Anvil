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

func TestLoadRefuses(t *testing.T) {
	for name, body := range map[string]string{
		"unknown key":        "version: 1\ntrivyDb:\n  enabled: true\n",
		"unknown nested key": "version: 1\ntrivyDB:\n  enable: true\n",
		"string boolean":     "version: 1\ntrivyDB:\n  enabled: \"true\"\n",
		"no version":         "stateDir: /x\n",
		"wrong version":      "version: 2\n",
		"empty path":         "version: 1\nfeeds: \"\"\n",
	} {
		if _, err := Load(write(t, body)); !errors.Is(err, ErrSettings) {
			t.Errorf("%s: err = %v, want ErrSettings", name, err)
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "absent.yml")); err == nil {
		t.Error("a named configuration file that does not exist loaded")
	}
}
