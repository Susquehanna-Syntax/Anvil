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
}

// Default is an installation with nothing configured but a state directory.
func Default() Settings {
	return Settings{StateDir: "/var/lib/anvil", SpoolDir: "/var/lib/anvil/dispatch", MirrorRoot: "/usr/share/anvil"}
}

// StorePath and CachePath are the two databases under StateDir.
func (s Settings) StorePath() string { return filepath.Join(s.StateDir, "anvil.db") }

// CachePath is the advisory cache under StateDir.
func (s Settings) CachePath() string { return filepath.Join(s.StateDir, "anvil-cache.sqlite") }

// ErrSettings reports an unreadable or invalid configuration file.
var ErrSettings = errors.New("settings: invalid configuration")

var keys = map[string]bool{"version": true, "stateDir": true, "feeds": true, "policy": true, "spoolDir": true, "mirrorRoot": true, "trivyDB": true}

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
	return s, nil
}
