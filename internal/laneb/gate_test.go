package laneb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTheGateFileCitesWhatExists holds docs/gates/lane-b.json to its own
// rule: every row names evidence, every cited path exists, and every cited
// test is defined in the file the row names.
func TestTheGateFileCitesWhatExists(t *testing.T) {
	root := filepath.Join("..", "..")
	raw, err := os.ReadFile(filepath.Join(root, "docs", "gates", "lane-b.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gate struct {
		Rows []struct {
			Criterion string `json:"criterion"`
			Status    string `json:"status"`
			Evidence  []struct {
				Test string `json:"test"`
				Path string `json:"path"`
			} `json:"evidence"`
		} `json:"rows"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&gate); err != nil {
		t.Fatal(err)
	}
	if len(gate.Rows) == 0 {
		t.Fatal("the gate file has no rows")
	}
	for _, row := range gate.Rows {
		if row.Criterion == "" || row.Status == "" || len(row.Evidence) == 0 {
			t.Errorf("row %q names no evidence or no status", row.Criterion)
		}
		for _, ev := range row.Evidence {
			src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ev.Path)))
			if err != nil {
				t.Errorf("row %q cites %s: %v", row.Criterion, ev.Path, err)
				continue
			}
			if ev.Test == "" {
				continue
			}
			def := regexp.MustCompile(`(?m)^(func|def) ` + regexp.QuoteMeta(ev.Test) + `\(`)
			if !def.Match(src) {
				t.Errorf("row %q cites %s in %s, which does not define it", row.Criterion, ev.Test, ev.Path)
			}
		}
	}
}
