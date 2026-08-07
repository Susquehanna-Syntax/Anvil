package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestSplit_CoreBinaryHasNoDASTCapability fails if any internal/dast package
// becomes reachable from cmd/anvil's import graph.
//
// plan/00-SPINE.md S9-AMENDED splits Anvil into two distribution artifacts:
// anvil (core, no network-probing capability compiled in) and anvil-dast. The
// reasoning in plan/IMPLEMENTATION-PLAN.md 2.2 is that a config flag inside a
// single shipped binary still supplies the probing capability to everyone who
// installs it, so the split has to be real. An unenforced convention is the
// same thing as a boolean: it holds until someone adds an import.
//
// This mirrors the mechanism S7 already mandates for the authorization kernel,
// which is "compiled separately from the model runtime, with a build-time test
// that fails if the dependency graph inverts".
//
// Seeded during Phase 0 bootstrap so the guard exists before the packages it
// guards do. Plan step O.16 owns its final form and must demonstrate the
// negative control: add a temporary internal/dast import, watch this fail,
// revert. A guard that has never failed has not been tested.
//
// ALWAYS RUN THIS WITH -count=1.
//
// This test's verdict comes from the output of an external `go list` process,
// and Go's test-result cache does not track that. Against a warm build cache it
// will replay a previous PASS for a package whose import graph has since
// changed -- reporting "ok (cached)" while never looking at the new import.
// That is precisely the stale-pass this guard exists to prevent, and it is not
// hypothetical: it defeated the CI negative control on its first run against a
// restored cache. -count=1 forces the run.
func TestSplit_CoreBinaryHasNoDASTCapability(t *testing.T) {
	const forbidden = "/internal/dast"

	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("go list -deps .: %v\n%s", err, stderr)
	}

	var violations []string
	for _, pkg := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		if strings.Contains(pkg, forbidden) {
			violations = append(violations, pkg)
		}
	}

	if len(violations) > 0 {
		t.Fatalf(
			"cmd/anvil reaches %d DAST package(s) through its import graph, which breaks the "+
				"two-artifact split required by plan/00-SPINE.md S9-AMENDED:\n  %s\n\n"+
				"The core binary must ship with no network-probing capability compiled in. Move this "+
				"code to cmd/anvil-dast/ rather than gating it behind a flag or a build tag.",
			len(violations), strings.Join(violations, "\n  "),
		)
	}
}
