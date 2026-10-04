package settings

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/Susquehanna-Syntax/Anvil/internal/policy"
)

// DefaultPath is where an installation keeps its configuration.
const DefaultPath = "/etc/anvil/anvil.yml"

// Settings is an operator configuration file.
type Settings struct {
	// StateDir holds the store (anvil.db) and the advisory cache
	// (anvil-cache.sqlite).
	StateDir string
	// Feeds is the live feed table the daemon keeps fresh. Empty means no
	// feed is refreshed.
	Feeds string
	// Policy is the trigger policy for host scans, which have no repository
	// to locate one in.
	Policy string
	// SpoolDir is where the daemon picks up dispatched scans.
	SpoolDir string
	// MirrorRoot is the directory holding mirror/, the licence evidence the
	// licence gate reads before any feed is fetched.
	MirrorRoot string
	// TrivyDB admits findings decided by Trivy's own database, with tier-2
	// attribution. False unless the file says true.
	TrivyDB bool
	// Recall is Lane B's recall tier.
	Recall Recall
	// Remediation is the coding agent's tier; off unless the file says so.
	Remediation Remediation
}

// Recall configures Lane B's recall tier: the rule pack and the three tools
// it runs as subprocesses. It is on unless the file says enabled: false. Its
// rules are MIT and Apache-2.0 (data/rules/MANIFEST.json), so nothing like
// the Trivy database's licence question keeps it off by default; an absent
// rule pack or tool makes a repository scan exit as a missing tool, never
// clean.
type Recall struct {
	Enabled bool
	// Rules is the rule pack directory.
	Rules string
	// Opengrep, Gosec and Bandit are the executables; empty means the tool's
	// name on PATH.
	Opengrep, Gosec, Bandit string
	// GoBin is the directory holding the go command gosec loads packages
	// with; empty means the go on PATH.
	GoBin string
}

// Default is an installation with nothing configured but a state directory.
func Default() Settings {
	return Settings{StateDir: "/var/lib/anvil", SpoolDir: "/var/lib/anvil/dispatch", MirrorRoot: "/usr/share/anvil",
		Recall: Recall{Enabled: true, Rules: "/usr/share/anvil/rules"}}
}

// StorePath and CachePath are the two databases under StateDir.
func (s Settings) StorePath() string { return filepath.Join(s.StateDir, "anvil.db") }

// CachePath is the advisory cache under StateDir.
func (s Settings) CachePath() string { return filepath.Join(s.StateDir, "anvil-cache.sqlite") }

// ErrSettings reports an unreadable or invalid configuration file.
var ErrSettings = errors.New("settings: invalid configuration")

var keys = map[string]bool{"version": true, "stateDir": true, "feeds": true, "policy": true, "spoolDir": true, "mirrorRoot": true, "trivyDB": true, "recall": true, "remediation": true}

var recallKeys = map[string]bool{"enabled": true, "rules": true, "opengrep": true, "gosec": true, "bandit": true, "goBin": true}

// Load reads a configuration file. A missing file at DefaultPath is the
// default configuration; a missing file anywhere else was named on purpose and
// is an error. Unknown keys are refused, like the policy file's: a misspelt
// key that parsed and did nothing would be a setting nobody can see is off.
func Load(path string) (Settings, error) {
	s := Default()
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) && path == DefaultPath {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("%w: %w", ErrSettings, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, policy.MaxPolicyBytes+1))
	if err != nil {
		return s, fmt.Errorf("%w: %w", ErrSettings, err)
	}
	doc, err := policy.DecodeYAML(raw)
	if err != nil {
		return s, fmt.Errorf("%w: %s: %w", ErrSettings, path, err)
	}
	m, ok := doc.(map[string]any)
	if !ok {
		return s, fmt.Errorf("%w: %s is not a mapping", ErrSettings, path)
	}
	var unknown []string
	for k := range m {
		if !keys[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return s, fmt.Errorf("%w: %s: unknown key(s) %v", ErrSettings, path, unknown)
	}
	if v, ok := m["version"].(int64); !ok || v != 1 {
		return s, fmt.Errorf("%w: %s: version must be 1", ErrSettings, path)
	}
	base := filepath.Dir(path)
	str := func(key string, dst *string) error {
		v, present := m[key]
		if !present || v == nil {
			return nil
		}
		sv, ok := v.(string)
		if !ok || sv == "" {
			return fmt.Errorf("%w: %s: %s must be a non-empty path", ErrSettings, path, key)
		}
		if !filepath.IsAbs(sv) {
			sv = filepath.Join(base, sv)
		}
		*dst = sv
		return nil
	}
	for key, dst := range map[string]*string{"stateDir": &s.StateDir, "feeds": &s.Feeds, "policy": &s.Policy, "spoolDir": &s.SpoolDir, "mirrorRoot": &s.MirrorRoot} {
		if err := str(key, dst); err != nil {
			return s, err
		}
	}
	// The spool lives in the state directory unless the file says otherwise.
	if _, set := m["spoolDir"]; !set {
		s.SpoolDir = filepath.Join(s.StateDir, "dispatch")
	}
	if v, present := m["trivyDB"]; present {
		mm, ok := v.(map[string]any)
		if !ok {
			return s, fmt.Errorf("%w: %s: trivyDB must be a mapping with one key, enabled", ErrSettings, path)
		}
		for k := range mm {
			if k != "enabled" {
				return s, fmt.Errorf("%w: %s: trivyDB has an unknown key %q", ErrSettings, path, k)
			}
		}
		b, ok := mm["enabled"].(bool)
		if !ok {
			return s, fmt.Errorf("%w: %s: trivyDB.enabled must be true or false", ErrSettings, path)
		}
		s.TrivyDB = b
	}
	if v, present := m["recall"]; present {
		mm, ok := v.(map[string]any)
		if !ok {
			return s, fmt.Errorf("%w: %s: recall must be a mapping", ErrSettings, path)
		}
		for k := range mm {
			if !recallKeys[k] {
				return s, fmt.Errorf("%w: %s: recall has an unknown key %q", ErrSettings, path, k)
			}
		}
		if e, present := mm["enabled"]; present {
			b, ok := e.(bool)
			if !ok {
				return s, fmt.Errorf("%w: %s: recall.enabled must be true or false", ErrSettings, path)
			}
			s.Recall.Enabled = b
		}
		for key, dst := range map[string]*string{"rules": &s.Recall.Rules, "opengrep": &s.Recall.Opengrep,
			"gosec": &s.Recall.Gosec, "bandit": &s.Recall.Bandit, "goBin": &s.Recall.GoBin} {
			v, present := mm[key]
			if !present || v == nil {
				continue
			}
			sv, ok := v.(string)
			if !ok || sv == "" {
				return s, fmt.Errorf("%w: %s: recall.%s must be a non-empty path", ErrSettings, path, key)
			}
			if !filepath.IsAbs(sv) {
				sv = filepath.Join(base, sv)
			}
			*dst = sv
		}
	}
	if v, present := m["remediation"]; present {
		if err := parseRemediation(v, path, base, &s); err != nil {
			return s, err
		}
	}
	return s, nil
}
