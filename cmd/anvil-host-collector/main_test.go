package main

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

// TestTheBinaryRefusesEveryArgument. S7's "not behind a flag" is a statement
// about what may exist, and the process boundary is the last place an argv
// surface could be reintroduced after internal/collector/host has closed every
// other one. `flag` is not imported, and these are the shapes somebody would
// reach for anyway.
func TestTheBinaryRefusesEveryArgument(t *testing.T) {
	for _, args := range [][]string{
		{"--remediate"},
		{"-v"},
		{"--timeout=30s"},
		{"upgrade"},
		{"/var/lib/rpm"},
		{"--help"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != exitUsage {
			t.Errorf("run(%q) = %d, want %d (the binary must refuse every argument)", args, code, exitUsage)
		}
		if stdout.Len() != 0 {
			t.Errorf("run(%q) wrote to stdout: %q", args, stdout.String())
		}
		if !strings.Contains(stderr.String(), "takes NO arguments") {
			t.Errorf("run(%q) did not explain itself: %q", args, stderr.String())
		}
	}
}

// TestTheBinaryEmitsAnInventoryAndTheRightStatus runs the real collection.
//
// On a Linux host with a package manager this is A.9's stop condition and
// A.12's "confirmation the binary runs successfully as a non-root user in the
// test fixture" — the thing that could not be given before, because there was
// no binary. Everywhere else (a Windows development host, a Linux container
// with no package manager) the collector reports no package manager, which is
// exit status 3 WITH an inventory: the coverage report is the point, and this
// asserts it is emitted rather than swallowed.
func TestTheBinaryEmitsAnInventoryAndTheRightStatus(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr)

	if code != exitCollected && code != exitNoPackageManager {
		t.Fatalf("run() = %d (stderr: %s)", code, stderr.String())
	}
	var inv map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &inv); err != nil {
		t.Fatalf("stdout is not a JSON inventory: %v\n%s", err, stdout.String())
	}
	if inv["collector"] != "host" {
		t.Errorf("inventory collector = %v, want host", inv["collector"])
	}
	if inv["remediable_by_agent"] != false {
		t.Errorf("inventory remediable_by_agent = %v, want false", inv["remediable_by_agent"])
	}
	cov, ok := inv["coverage"].([]any)
	if !ok || len(cov) != 3 {
		t.Fatalf("the emitted inventory has no per-family coverage report: %v", inv["coverage"])
	}
	if code == exitNoPackageManager && !strings.Contains(stderr.String(), "coverage report") {
		t.Errorf("exit %d did not say where to look: %q", code, stderr.String())
	}
	t.Logf("goos=%s exit=%d coverage=%v", runtime.GOOS, code, inv["coverage"])
}
