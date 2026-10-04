// This file loads and verifies the vendored rule pack, data/rules: the owner's
// selection (selection.json), the generated manifest (MANIFEST.json), the
// rule files and the licence bodies.
//
// THE PACK IS VERIFIED ON EVERY LOAD, NOT TRUSTED. Every rule file and licence
// body must hash to the manifest, the manifest must name the selection it was
// generated from by digest, and no rule file may sit in a corpus directory
// unlisted: opengrep is only ever handed listed files, but an unlisted file is
// a selection nobody reviewed. A pack that fails any check is refused, and a
// refused pack is a missing tool, never an empty rule set.
//
// THE LICENCE GUARDS ARE ALLOWLISTS. A corpus is admitted only if its
// repository is in admittedCorpora, a GitLab directory only if it is in
// GitLabDirectoryAllowlist, and a rule only if its licence is in
// AdmittedLicences. GitLab's sast-rules LICENSE puts doc/ under CC BY-SA 4.0
// and keeps third-party components under their own licences, and its c/
// directory turned out to be one of them: every rule there is headed
// "License: GPL 2.0" (generated from flawfinder). The owner excluded it on
// 2026-10-03. Semgrep's own rules, the archived opengrep/opengrep-rules and
// lambdasec/autogrep are not in admittedCorpora, so none of them can be
// vendored by adding a line to selection.json.

package recall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// ErrRulePack reports a rule pack that is absent, unreadable or fails
// verification. It is always a refusal: Lane B never runs a partial pack.
var ErrRulePack = errors.New("recall: the rule pack is missing or fails verification")

// AdmittedLicences are the licences a vendored rule may carry. Both are
// permissive and flow into Apache-2.0.
var AdmittedLicences = []string{"MIT", "Apache-2.0"}

// GitLabDirectoryAllowlist is every directory of GitLab's sast-rules Lane B
// may vendor from. c/ is absent on purpose (GPL-2.0 rule headers); doc/, ee/,
// jh/, rules/ (the lgpl and lgpl-cc trees), qa/, mappings/ and ci/ were never
// in it.
var GitLabDirectoryAllowlist = []string{"csharp", "go", "java", "javascript", "python", "scala"}

// admittedCorpora maps each corpus name to the only repository it may come
// from, and the directories it may contribute.
var admittedCorpora = map[string]struct {
	repository  string
	directories []string
}{
	"gitlab-sast-rules":   {"https://gitlab.com/gitlab-org/security-products/sast-rules", GitLabDirectoryAllowlist},
	"0xdea-semgrep-rules": {"https://github.com/0xdea/semgrep-rules", []string{"rules/c"}},
}

// Selection is data/rules/selection.json.
type Selection struct {
	Version             int      `json:"version"`
	DecidedBy           string   `json:"decided_by"`
	DecidedOn           string   `json:"decided_on"`
	About               string   `json:"about"`
	Tools               []Tool   `json:"tools"`
	Corpora             []Corpus `json:"corpora"`
	ExcludedDirectories []struct {
		Corpus    string `json:"corpus"`
		Directory string `json:"directory"`
		Reason    string `json:"reason"`
	} `json:"excluded_directories"`
	ExcludedRuleFiles []struct {
		Corpus string `json:"corpus"`
		Path   string `json:"path"`
		Reason string `json:"reason"`
	} `json:"excluded_rule_files"`
	ExcludedToolRules []struct {
		Tool   string `json:"tool"`
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
	} `json:"excluded_tool_rules"`
	ExcludedPaths struct {
		Reason      string   `json:"reason"`
		Directories []string `json:"directories"`
		FileGlobs   []string `json:"file_globs"`
	} `json:"excluded_paths"`
}

// Corpus is one pinned rule corpus in the selection.
type Corpus struct {
	Name        string   `json:"name"`
	Repository  string   `json:"repository"`
	Commit      string   `json:"commit"`
	LicenceFile string   `json:"licence_file"`
	RuleSuffix  string   `json:"rule_suffix"`
	Directories []string `json:"directories"`
}

// Rule is one vendored rule file, as the manifest records it.
type Rule struct {
	Corpus          string   `json:"corpus"`
	Repository      string   `json:"repository"`
	Commit          string   `json:"commit"`
	Path            string   `json:"path"` // relative to the pack root
	BlobSHA1        string   `json:"blob_sha1"`
	SHA256          string   `json:"sha256"`
	IDs             []string `json:"ids"`
	CWEs            []string `json:"cwes"`
	Languages       []string `json:"languages"`
	Licence         string   `json:"licence"`
	LicenceEvidence string   `json:"licence_evidence"`
	LicenceFile     string   `json:"licence_file"`
}

// Manifest is data/rules/MANIFEST.json.
type Manifest struct {
	Version         int    `json:"version"`
	GeneratedBy     string `json:"generated_by"`
	SelectionSHA256 string `json:"selection_sha256"`
	Licences        []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"licences"`
	Rules []Rule `json:"rules"`
}

// Pack is a verified rule pack.
type Pack struct {
	Root      string
	Selection Selection
	Manifest  Manifest
	// SelectionSHA256 is the digest of selection.json, which the manifest
	// names; it identifies the whole selection in scan_run.ruleset_version.
	SelectionSHA256 string

	byID          map[string]*Rule
	excludedTools map[string]bool // "tool/rule"
}

// Rules returns the vendored rules in manifest order.
func (p *Pack) Rules() []Rule { return p.Manifest.Rules }

// RuleByID resolves a rule id that opengrep reported to the rule and the id
// as the rule file states it. Under --experimental, opengrep 1.26.0 reports
// the id as the rule file states it. Without it, opengrep prefixes the id with
// a dotted form of the rule file's directory, so a reported
// "...gitlab-sast-rules.python.eval.python_eval_rule-eval" is the rule whose
// id is "python_eval_rule-eval" in gitlab-sast-rules/python/eval. Ids may
// themselves contain dots ("python_crypto_rule-crypto.hazmat-hash-md5"), so
// the match is the id the report ends with, after a dot, whose rule file's
// directory also appears dotted just before it. More than one such rule is
// refused rather than guessed.
func (p *Pack) RuleByID(reported string) (*Rule, string, bool) {
	if r, ok := p.byID[reported]; ok {
		return r, reported, true
	}
	var found *Rule
	var foundID string
	for id, r := range p.byID {
		prefix, ok := strings.CutSuffix(reported, "."+id)
		if !ok {
			continue
		}
		dir := strings.ReplaceAll(path.Dir(r.Path), "/", ".")
		if !strings.HasSuffix(prefix, dir) {
			continue
		}
		if found != nil && found != r {
			return nil, "", false
		}
		found, foundID = r, id
	}
	return found, foundID, found != nil
}

// ToolRuleExcluded reports whether the selection drops a native analyser's
// rule (bandit's B101, for one).
func (p *Pack) ToolRuleExcluded(tool, rule string) bool { return p.excludedTools[tool+"/"+rule] }

// LoadPack reads and verifies the rule pack rooted at dir.
func LoadPack(dir string) (*Pack, error) {
	refuse := func(format string, args ...any) (*Pack, error) {
		return nil, fmt.Errorf("%w: %s: %s", ErrRulePack, dir, fmt.Sprintf(format, args...))
	}
	selRaw, err := os.ReadFile(filepath.Join(dir, "selection.json"))
	if err != nil {
		return refuse("%v", err)
	}
	manRaw, err := os.ReadFile(filepath.Join(dir, "MANIFEST.json"))
	if err != nil {
		return refuse("%v", err)
	}
	p := &Pack{Root: dir, SelectionSHA256: sha256Hex(selRaw), byID: map[string]*Rule{}, excludedTools: map[string]bool{}}
	if err := strictJSON(selRaw, &p.Selection); err != nil {
		return refuse("selection.json: %v", err)
	}
	if err := strictJSON(manRaw, &p.Manifest); err != nil {
		return refuse("MANIFEST.json: %v", err)
	}
	if p.Selection.Version != 1 || p.Manifest.Version != 1 {
		return refuse("selection version %d and manifest version %d; this build reads version 1", p.Selection.Version, p.Manifest.Version)
	}
	if p.Manifest.SelectionSHA256 != p.SelectionSHA256 {
		return refuse("MANIFEST.json was generated from a different selection.json (%s, the file on disk is %s); regenerate it with python -m anvil_eval.vendor_rules",
			p.Manifest.SelectionSHA256, p.SelectionSHA256)
	}
	if err := p.checkCorpora(); err != nil {
		return refuse("%v", err)
	}
	for _, t := range p.Selection.ExcludedToolRules {
		p.excludedTools[t.Tool+"/"+t.Rule] = true
	}
	for _, g := range p.Selection.ExcludedPaths.FileGlobs {
		if _, err := path.Match(g, ""); err != nil {
			return refuse("excluded file glob %q: %v", g, err)
		}
	}

	listed := map[string]bool{}
	for _, l := range p.Manifest.Licences {
		if err := checkFile(dir, l.Path, l.SHA256); err != nil {
			return refuse("licence body: %v", err)
		}
		listed[l.Path] = true
	}
	for i := range p.Manifest.Rules {
		r := &p.Manifest.Rules[i]
		if err := p.checkRule(r, listed); err != nil {
			return refuse("%s: %v", r.Path, err)
		}
		if err := checkFile(dir, r.Path, r.SHA256); err != nil {
			return refuse("%v", err)
		}
		for _, id := range r.IDs {
			if strings.TrimSpace(id) == "" {
				return refuse("%s: a rule has an empty id", r.Path)
			}
			if prev, dup := p.byID[id]; dup {
				return refuse("rule id %q is defined by both %s and %s", id, prev.Path, r.Path)
			}
			p.byID[id] = r
		}
		listed[r.Path] = true
	}
	if len(p.Manifest.Rules) == 0 {
		return refuse("the manifest lists no rules")
	}
	// Nothing unlisted may sit beside the vendored rules.
	for _, c := range p.Selection.Corpora {
		err := filepath.WalkDir(filepath.Join(dir, c.Name), func(full string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(dir, full)
			if !listed[filepath.ToSlash(rel)] {
				return fmt.Errorf("%s is not in MANIFEST.json", filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			return refuse("%v", err)
		}
	}
	return p, nil
}

func (p *Pack) checkCorpora() error {
	seen := map[string]bool{}
	for _, c := range p.Selection.Corpora {
		adm, ok := admittedCorpora[c.Name]
		if !ok {
			return fmt.Errorf("corpus %q is not an admitted corpus", c.Name)
		}
		if c.Repository != adm.repository {
			return fmt.Errorf("corpus %q names repository %q; it may only come from %q", c.Name, c.Repository, adm.repository)
		}
		if len(c.Commit) != 40 || strings.Trim(c.Commit, "0123456789abcdef") != "" {
			return fmt.Errorf("corpus %q is pinned to %q, which is not a full commit SHA", c.Name, c.Commit)
		}
		for _, d := range c.Directories {
			if !slices.Contains(adm.directories, d) {
				return fmt.Errorf("corpus %q directory %q is not on its directory allowlist %v", c.Name, d, adm.directories)
			}
		}
		seen[c.Name] = true
	}
	if len(seen) != len(p.Selection.Corpora) {
		return errors.New("a corpus is listed twice")
	}
	return nil
}

func (p *Pack) checkRule(r *Rule, licences map[string]bool) error {
	var corpus *Corpus
	for i := range p.Selection.Corpora {
		if p.Selection.Corpora[i].Name == r.Corpus {
			corpus = &p.Selection.Corpora[i]
		}
	}
	switch {
	case corpus == nil:
		return fmt.Errorf("corpus %q is not in the selection", r.Corpus)
	case r.Repository != corpus.Repository || r.Commit != corpus.Commit:
		return fmt.Errorf("provenance %s@%s disagrees with the selection's %s@%s", r.Repository, r.Commit, corpus.Repository, corpus.Commit)
	case !slices.Contains(AdmittedLicences, r.Licence):
		return fmt.Errorf("licence %q is not admitted (%v)", r.Licence, AdmittedLicences)
	case strings.TrimSpace(r.LicenceEvidence) == "":
		return errors.New("no licence evidence: a licence is read from a body, never assumed")
	case !licences[r.LicenceFile]:
		return fmt.Errorf("licence body %q is not archived in the manifest", r.LicenceFile)
	case len(r.IDs) == 0 || len(r.CWEs) == 0 || len(r.Languages) == 0:
		return errors.New("a rule needs an id, a CWE and a language")
	case len(r.BlobSHA1) != 40:
		return errors.New("no git blob id")
	}
	inCorpus := strings.TrimPrefix(r.Path, r.Corpus+"/")
	if inCorpus == r.Path {
		return errors.New("path is outside its corpus directory")
	}
	ok := false
	for _, d := range corpus.Directories {
		if strings.HasPrefix(inCorpus, d+"/") {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("path is in none of the corpus's selected directories %v", corpus.Directories)
	}
	for _, ex := range p.Selection.ExcludedRuleFiles {
		if ex.Corpus == r.Corpus && ex.Path == inCorpus {
			return errors.New("the selection excludes this rule file")
		}
	}
	for _, ex := range p.Selection.ExcludedDirectories {
		if ex.Corpus == r.Corpus && strings.HasPrefix(inCorpus, ex.Directory+"/") {
			return fmt.Errorf("the selection excludes directory %q", ex.Directory)
		}
	}
	return nil
}

// checkFile verifies that rel (a slash path under root) exists, is a regular
// file inside root and hashes to want.
func checkFile(root, rel, want string) error {
	clean := path.Clean(rel)
	if clean != rel || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean == ".." {
		return fmt.Errorf("%q is not a clean relative path", rel)
	}
	full := filepath.Join(root, filepath.FromSlash(clean))
	st, err := os.Lstat(full)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", rel)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return err
	}
	if got := sha256Hex(b); got != want {
		return fmt.Errorf("%s hashes to %s, the manifest pins %s", rel, got, want)
	}
	return nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// Excluded reports whether a repository-relative slash path is outside what
// Lane B reports on: a test, test-data, documentation or example tree, or a
// test file by name (the selection's excluded_paths).
func (p *Pack) Excluded(rel string) bool {
	segs := strings.Split(rel, "/")
	for _, s := range segs[:len(segs)-1] {
		if slices.Contains(p.Selection.ExcludedPaths.Directories, s) {
			return true
		}
	}
	base := segs[len(segs)-1]
	for _, g := range p.Selection.ExcludedPaths.FileGlobs {
		if ok, _ := path.Match(g, base); ok {
			return true
		}
	}
	return false
}

// Languages returns every rule language in the pack, sorted.
func (p *Pack) Languages() []string {
	set := map[string]bool{}
	for _, r := range p.Manifest.Rules {
		for _, l := range r.Languages {
			set[l] = true
		}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// Tool is a native analyser or engine the selection pins: its exact version,
// where it comes from, and its licence as read from its body. A tool's own
// rules carry this as their provenance.
type Tool struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Repository      string `json:"repository"`
	Licence         string `json:"licence"`
	LicenceEvidence string `json:"licence_evidence"`
	Role            string `json:"role"`
}

// Tool returns the pinned tool called name.
func (p *Pack) Tool(name string) (Tool, bool) {
	for _, t := range p.Selection.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}
