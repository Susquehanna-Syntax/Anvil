package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A request the daemon cannot read is answered, not run and not dropped, and
// the spool is left with no claimed request behind.
func TestAMalformedRequestIsAnsweredWithItsError(t *testing.T) {
	spool := t.TempDir()
	if err := os.WriteFile(filepath.Join(spool, "a.json"), []byte(`{"kind":"host","event":"schedule","surprise":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spool, "b.json"), []byte(`{"kind":"repo"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := DrainSpool(context.Background(), Config{SpoolDir: spool}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"a": "unknown field", "b": "names its trigger event"} {
		raw, err := os.ReadFile(filepath.Join(spool, name+answerSuffix))
		if err != nil {
			t.Fatalf("%s: no answer: %v", name, err)
		}
		var a Answer
		if err := json.Unmarshal(raw, &a); err != nil {
			t.Fatal(err)
		}
		if a.Outcome != "" || !strings.Contains(a.Error, want) {
			t.Errorf("%s: answer %+v, want an error containing %q", name, a, want)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(spool, "*"+runningSuffix)); len(left) != 0 {
		t.Errorf("claimed requests left behind: %v", left)
	}
}

func TestEnqueueWritesAWholeRequest(t *testing.T) {
	spool := t.TempDir()
	path, err := Enqueue(spool, Request{Kind: "repo", Repo: "/srv/app", Event: "schedule", Full: true})
	if err != nil {
		t.Fatal(err)
	}
	r, err := readRequest(path)
	if err != nil || r.Repo != "/srv/app" || !r.Full {
		t.Fatalf("read back %+v, %v", r, err)
	}
	if tmp, _ := filepath.Glob(filepath.Join(spool, ".enqueue-*")); len(tmp) != 0 {
		t.Errorf("temporary files left behind: %v", tmp)
	}
}
