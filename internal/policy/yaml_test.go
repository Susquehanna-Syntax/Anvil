package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The decoder reads a file from the repository under scan, so every bound
// below is a refusal a crafted .anvil/policy.yml must hit.
func TestDecodeYAMLRefusesWhatItDoesNotUnderstand(t *testing.T) {
	deepBlock := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(strings.Repeat("  ", i) + "k:\n")
		}
		b.WriteString(strings.Repeat("  ", n) + "k: v\n")
		return b.String()
	}
	cases := map[string]string{
		"anchor":               "version: 1\ndefaults: &d\n",
		"alias":                "version: 1\ndefaults: *d\n",
		"tag":                  "version: !!int 1\n",
		"literal block scalar": "version: 1\nname: |\n  text\n",
		"folded block scalar":  "name: >\n  text\n",
		"directive":            "%YAML 1.2\n",
		"tab indentation":      "defaults:\n\tdepth: full\n",
		"document marker":      "---\nversion: 1\n",
		"duplicate key":        "version: 1\nversion: 1\n",
		"deep block nesting":   deepBlock(MaxPolicyNesting + 2),
		"deep flow nesting":    "k: " + strings.Repeat("[", MaxPolicyNesting+2) + strings.Repeat("]", MaxPolicyNesting+2) + "\n",
		"oversized":            "version: 1\n# " + strings.Repeat("x", MaxPolicyBytes) + "\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeYAML([]byte(src)); !errors.Is(err, ErrPolicyFile) {
				t.Errorf("accepted, or refused without ErrPolicyFile: %v", err)
			}
		})
	}
}

// The positive controls: the refusals above must not reach legitimate text.
func TestDecodeYAMLAcceptsTheSubset(t *testing.T) {
	src := `version: 1
defaults:
  detectors: [sca, host]
  depth: full
scanRules:
  - name: "nightly"     # a comment
    matchEvents: [schedule]
    matchPaths: ['**/go.mod', "src/*!x"]
    detectors:
      - sca
`
	doc, err := DecodeYAML([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromDocument(doc); err != nil {
		t.Fatalf("a legal policy decoded but FromDocument refused it: %v", err)
	}
	// Indicators are legal inside a quoted scalar and after its first byte.
	if _, err := DecodeYAML([]byte("k: '&anchor-looking text'\nj: a*b\n")); err != nil {
		t.Errorf("quoted or mid-scalar indicator refused: %v", err)
	}
	// Exactly at the nesting bound is legal.
	if _, err := DecodeYAML([]byte("k: " + strings.Repeat("[", MaxPolicyNesting) + strings.Repeat("]", MaxPolicyNesting) + "\n")); err != nil {
		t.Errorf("flow nesting at the bound refused: %v", err)
	}
}

func TestLoadReadsAndValidatesAPolicyFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "policy.yml")
	if err := os.WriteFile(good, []byte("version: 1\ndefaults:\n  depth: full\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(good)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != SchemaVersion || p.Defaults == nil || p.Defaults.Depth != DepthFull {
		t.Fatalf("loaded %+v", p)
	}

	typo := filepath.Join(dir, "typo.yml")
	if err := os.WriteFile(typo, []byte("version: 1\ndefault:\n  depth: full\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(typo); !errors.Is(err, ErrInvalidDocument) {
		t.Errorf("an unknown key loaded: %v", err)
	}

	big := filepath.Join(dir, "big.yml")
	if err := os.WriteFile(big, []byte("version: 1\n#"+strings.Repeat("x", MaxPolicyBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(big); !errors.Is(err, ErrPolicyFile) {
		t.Errorf("an oversized file loaded: %v", err)
	}
	if _, err := Load(filepath.Join(dir, "absent.yml")); !errors.Is(err, ErrPolicyFile) {
		t.Errorf("a missing file: %v", err)
	}
}
