package settings

import (
	"fmt"
	"path/filepath"
)

// Remediation configures the remediation tier. It is off unless the file
// says enabled: true, and it names no model or endpoint of its own: the
// operator chooses both.
type Remediation struct {
	Enabled bool
	// Endpoint is the OpenAI-compatible model endpoint and its trust tier
	// (local, own or public).
	EndpointURL, Model, Tier string
	AllowPublic              bool
	APIKeyFile               string
	// Triage is off, record or gate. Off is the default: the triage gate's
	// precision is unmeasured, so its verdicts gate nothing unless the
	// operator chooses gate.
	Triage string
	// WorkDir holds the controller's clones; default StateDir/remediation.
	WorkDir string
	// StaleAfterDays closes a draft nobody answered; 0 never does.
	StaleAfterDays int
	// BudgetTokens is the prompt-token budget of one cycle per audit; the
	// queue cut defers what does not fit. 0 leaves the queue uncut.
	BudgetTokens int
	// ForgeAPI and ForgeTokenFile reach the pull-request host. The token must
	// not be able to write to any upstream repository (it pushes to forks).
	ForgeAPI, ForgeTokenFile string
	Targets                  []RemediationTarget
}

// RemediationTarget is one repository the agent may propose fixes for.
type RemediationTarget struct {
	Locator, Source  string
	Build, Test, Env []string
	// ReadOnly are directories the build sandbox may read (a toolchain). The
	// target's code can read everything in them, so they must hold no secret.
	ReadOnly                                 []string
	Repository, Fork, ForkRemote, BaseBranch string
}

var remediationKeys = map[string]bool{"enabled": true, "endpoint": true, "triage": true, "workDir": true,
	"staleAfterDays": true, "budgetTokens": true, "forge": true, "targets": true}
var endpointKeys = map[string]bool{"url": true, "model": true, "tier": true, "allowPublic": true, "apiKeyFile": true}
var forgeKeys = map[string]bool{"api": true, "tokenFile": true}
var targetKeys = map[string]bool{"locator": true, "source": true, "build": true, "test": true, "env": true, "readOnly": true,
	"repository": true, "fork": true, "forkRemote": true, "baseBranch": true}

func parseRemediation(v any, path, base string, s *Settings) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s: remediation: %s", ErrSettings, path, fmt.Sprintf(format, args...))
	}
	m, ok := v.(map[string]any)
	if !ok {
		return fail("must be a mapping")
	}
	if err := onlyKeys(m, remediationKeys, "remediation", path); err != nil {
		return err
	}
	r := Remediation{Triage: "off", WorkDir: filepath.Join(s.StateDir, "remediation"), StaleAfterDays: 30, ForgeAPI: "https://api.github.com"}
	if e, present := m["enabled"]; present {
		b, ok := e.(bool)
		if !ok {
			return fail("enabled must be true or false")
		}
		r.Enabled = b
	}
	str := func(mm map[string]any, key string, dst *string, isPath bool) error {
		v, present := mm[key]
		if !present || v == nil {
			return nil
		}
		sv, ok := v.(string)
		if !ok || sv == "" {
			return fail("%s must be a non-empty string", key)
		}
		if isPath && !filepath.IsAbs(sv) {
			sv = filepath.Join(base, sv)
		}
		*dst = sv
		return nil
	}
	if err := str(m, "triage", &r.Triage, false); err != nil {
		return err
	}
	if r.Triage != "off" && r.Triage != "record" && r.Triage != "gate" {
		return fail("triage must be off, record or gate")
	}
	if err := str(m, "workDir", &r.WorkDir, true); err != nil {
		return err
	}
	if v, present := m["staleAfterDays"]; present {
		n, ok := v.(int64)
		if !ok || n < 0 {
			return fail("staleAfterDays must be a whole number of days, 0 or more")
		}
		r.StaleAfterDays = int(n)
	}
	if v, present := m["budgetTokens"]; present {
		n, ok := v.(int64)
		if !ok || n < 0 {
			return fail("budgetTokens must be a whole number of tokens, 0 or more")
		}
		r.BudgetTokens = int(n)
	}
	if v, present := m["endpoint"]; present {
		em, ok := v.(map[string]any)
		if !ok {
			return fail("endpoint must be a mapping")
		}
		if err := onlyKeys(em, endpointKeys, "remediation.endpoint", path); err != nil {
			return err
		}
		for key, dst := range map[string]*string{"url": &r.EndpointURL, "model": &r.Model, "tier": &r.Tier} {
			if err := str(em, key, dst, false); err != nil {
				return err
			}
		}
		if err := str(em, "apiKeyFile", &r.APIKeyFile, true); err != nil {
			return err
		}
		if a, present := em["allowPublic"]; present {
			b, ok := a.(bool)
			if !ok {
				return fail("endpoint.allowPublic must be true or false")
			}
			r.AllowPublic = b
		}
	}
	if v, present := m["forge"]; present {
		fm, ok := v.(map[string]any)
		if !ok {
			return fail("forge must be a mapping")
		}
		if err := onlyKeys(fm, forgeKeys, "remediation.forge", path); err != nil {
			return err
		}
		if err := str(fm, "api", &r.ForgeAPI, false); err != nil {
			return err
		}
		if err := str(fm, "tokenFile", &r.ForgeTokenFile, true); err != nil {
			return err
		}
	}
	if v, present := m["targets"]; present {
		list, ok := v.([]any)
		if !ok {
			return fail("targets must be a list")
		}
		for i, item := range list {
			tm, ok := item.(map[string]any)
			if !ok {
				return fail("targets[%d] must be a mapping", i)
			}
			if err := onlyKeys(tm, targetKeys, fmt.Sprintf("remediation.targets[%d]", i), path); err != nil {
				return err
			}
			var t RemediationTarget
			for key, dst := range map[string]*string{"locator": &t.Locator, "repository": &t.Repository, "fork": &t.Fork,
				"forkRemote": &t.ForkRemote, "baseBranch": &t.BaseBranch} {
				if err := str(tm, key, dst, false); err != nil {
					return err
				}
			}
			if err := str(tm, "source", &t.Source, true); err != nil {
				return err
			}
			for key, dst := range map[string]*[]string{"build": &t.Build, "test": &t.Test, "env": &t.Env, "readOnly": &t.ReadOnly} {
				lv, present := tm[key]
				if !present {
					continue
				}
				items, ok := lv.([]any)
				if !ok {
					return fail("targets[%d].%s must be a list of strings (an argument vector, never a shell line)", i, key)
				}
				for _, it := range items {
					sv, ok := it.(string)
					if !ok {
						return fail("targets[%d].%s must be a list of strings", i, key)
					}
					*dst = append(*dst, sv)
				}
			}
			if t.Locator == "" || t.Source == "" {
				return fail("targets[%d] needs a locator and a source", i)
			}
			r.Targets = append(r.Targets, t)
		}
	}
	if r.Enabled && (r.EndpointURL == "" || r.Model == "" || r.Tier == "") {
		return fail("enabled needs endpoint.url, endpoint.model and endpoint.tier; Anvil has no default model or endpoint")
	}
	s.Remediation = r
	return nil
}

func onlyKeys(m map[string]any, allowed map[string]bool, where, path string) error {
	for k := range m {
		if !allowed[k] {
			return fmt.Errorf("%w: %s: %s has an unknown key %q", ErrSettings, path, where, k)
		}
	}
	return nil
}
