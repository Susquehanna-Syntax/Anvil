// D.9, gate 2: the kernel's dependency graph, measured.
//
// ===========================================================================
// WHAT MAKES THIS GUARD DIFFERENT FROM A CONVENTION
// ===========================================================================
//
// plan/00-SPINE.md S7: "The authorization kernel is a pure function of
// (target, scope, attestation, clock), compiled separately from the model
// runtime, with a build-time test that fails if the dependency graph inverts.
// No model ever holds a network handle."
//
// Every other part of the kernel is code that can be edited. This file is the
// thing that notices. It fails the build -- non-zero exit, not a logged
// warning -- when the kernel reaches something it must not reach.
//
// The judgment lives in CheckGate2KernelCompiledSeparately (phase0_build.go,
// D.2), which holds kernelImportAllowlist. This file only MEASURES, by
// shelling out to `go list -deps`. That split is why the gate cannot be handed
// a convenient graph by the code it judges.
//
// ===========================================================================
// IT RESOLVES BY IMPORT PATH, WHICH IS THE WHOLE POINT
// ===========================================================================
//
// A sibling guard in internal/collector/host was defeated earlier in this
// build by an import ALIAS, and it did not go red -- it reported pass. An
// alias-defeatable guard is worse than no guard, because the green tick is
// read as an answer.
//
// `go list -deps` emits import PATHS. A local name -- alias, dot-import, blank
// import -- exists only in the importing file's namespace and never appears in
// the output. TestGate2WalkIsNotDefeatedByImportSyntax proves that against a
// throwaway module rather than asserting it, and it proves the transitive case
// too: the offending package is reported even when the kernel reaches it
// through an intermediary that has no forbidden name at all.
//
// ===========================================================================
// THIS GUARD IS NOT VACUOUS, AND GATE 1's POSITIVE HALF STILL IS
// ===========================================================================
//
// MEASURED 2026-08-22. `go list -deps ./internal/dast/authz` returns 189
// packages. The kernel's closure is a real thing this test really walks, so
// gate 2 passes because the closure was inspected and found clean, not because
// there was nothing to inspect.
//
// Gate 1's positive half is a different story and is NOT fixed here.
// `go list -deps ./cmd/anvil-dast | grep internal/dast` returns NOTHING:
// neither shipped binary links the kernel, because cmd/anvil-dast is still the
// bootstrap placeholder plan step O.16 owns. So "anvil does not reach the DAST
// tree" is currently satisfied by the DAST tree appearing in no binary at all,
// and it would keep passing if the kernel were deleted.
//
// That is a KNOWN LIMIT with a named settling condition, recorded in
// TestGate1CoreArtifactSplitAndTheVacuityOfItsPositiveHalf, which prints which
// half it PROVED and which it could not, and which becomes a real two-sided
// measurement the moment cmd/anvil-dast links the kernel. It is not fixed by
// fabricating a consumer: a consumer invented to make a gate green is the
// exact shape internal/SKIPPED-CONTROLS.md records this repository shipping
// twice.
package authz

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// goListDeps walks a package's transitive import closure with the go tool and
// records it as an ImportGraph.
//
// It fails rather than skips when the toolchain is unavailable.
// internal/SKIPPED-CONTROLS.md names the failure this avoids: a dependency
// shape guard in this repository skipped whenever `go list` could not run,
// "i.e. in exactly the hermetic environments it mattered in".
//
// ALWAYS RUN THE TESTS IN THIS FILE WITH -count=1. Their verdict comes from an
// external process, and Go's test cache does not track that: against a warm
// build cache it will replay a previous PASS for a package whose import graph
// has since changed. That is not hypothetical -- it defeated the CI negative
// control for cmd/anvil/split_test.go on its first run.
func goListDeps(t *testing.T, root, pkg string) ImportGraph {
	t.Helper()

	cmd := exec.Command("go", "list", "-deps", pkg)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("go list -deps %s (in %s): %v\n%s", pkg, root, err, stderr)
	}

	var deps []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			deps = append(deps, line)
		}
	}

	// The package's own import path is what the graph is rooted at; go list
	// prints it last. NewImportGraph refuses an empty closure, which is the
	// anti-vacuity floor this whole file rests on.
	full := pkg
	if strings.HasPrefix(pkg, "./") {
		full = modulePath + "/" + strings.TrimPrefix(pkg, "./")
	}
	g, err := NewImportGraph(full, deps)
	if err != nil {
		t.Fatalf("recording the import graph of %s: %v", pkg, err)
	}
	return g
}

// ---------------------------------------------------------------------------
// GATE 2 -- the real measurement
// ---------------------------------------------------------------------------

// TestGate2KernelClosureIsStdlibPlusTheAllowlist is gate 2's build-time test,
// run against the real kernel.
func TestGate2KernelClosureIsStdlibPlusTheAllowlist(t *testing.T) {
	root := repoRootForGuards(t)
	g := goListDeps(t, root, "./internal/dast/authz")

	res := CheckGate2KernelCompiledSeparately(g)
	if !res.Passed() {
		t.Fatalf("gate 2 FAILED over a %d-package closure: %v\n\n"+
			"The kernel is the one component in Anvil whose dependency surface is "+
			"enumerated rather than inferred. If the new import belongs in it, add it "+
			"to kernelImportAllowlist in phase0_build.go with a justification -- that "+
			"edit is the review this gate exists to force. If it does not, the kernel "+
			"is not where the code goes.",
			len(g.Deps()), res.Err())
	}

	nonStdlib := 0
	for _, d := range g.Deps() {
		if !isStdlibPackage(d) && d != KernelPackage {
			nonStdlib++
		}
	}
	t.Logf("gate 2: %d packages in the kernel's closure, %d of them non-stdlib and on "+
		"the allowlist", len(g.Deps()), nonStdlib)
}

// TestGate2NoDastPackageReachesTheInferenceLayer widens gate 2 from the kernel
// to the whole dynamic tier.
//
// S7's sentence is about the kernel, but its reason -- "no model ever holds a
// network handle" -- is about the tier. A crawler or a request layer that
// linked the model runtime would satisfy gate 2 as written and defeat what it
// is for, because the kernel would still be clean while the process holding
// the sockets was not.
//
// Its allowlist is the kernel's, plus the DAST tree itself. It is deliberately
// no looser than that: a DAST package that needs something the kernel may not
// have is a decision, and it should be made in a diff that says so.
func TestGate2NoDastPackageReachesTheInferenceLayer(t *testing.T) {
	root := repoRootForGuards(t)

	cmd := exec.Command("go", "list", "./internal/dast/...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("go list ./internal/dast/...: %v\n%s", err, stderr)
	}

	var pkgs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			pkgs = append(pkgs, line)
		}
	}
	// Anti-vacuity. If the pattern ever stops matching -- a moved tree, a
	// build-tag mistake, a typo -- this loop runs zero times and reports a
	// clean dynamic tier it never looked at.
	if len(pkgs) < 2 {
		t.Fatalf("go list ./internal/dast/... returned %d package(s): %v. This check "+
			"would otherwise pass by finding nothing, which is the silent-clean "+
			"failure it exists to prevent.", len(pkgs), pkgs)
	}

	for _, pkg := range pkgs {
		t.Run(strings.TrimPrefix(pkg, modulePath+"/"), func(t *testing.T) {
			g := goListDeps(t, root, pkg)
			var bad []string
			for _, dep := range g.Deps() {
				if isStdlibPackage(dep) {
					continue
				}
				if dep == dastPackageRoot || strings.HasPrefix(dep, dastPackagePrefix) {
					continue
				}
				allowed := false
				for _, e := range kernelImportAllowlist {
					if e.covers(dep) {
						allowed = true
						break
					}
				}
				if !allowed {
					bad = append(bad, dep)
				}
			}
			if len(bad) > 0 {
				sort.Strings(bad)
				t.Fatalf("%s reaches %d package(s) outside the standard library, the "+
					"DAST tree and the kernel's import allowlist:\n  %s\n\n"+
					"plan/00-SPINE.md S7 keeps the model runtime out of the tier that "+
					"holds the sockets. A DAST package that links something the KERNEL "+
					"may not link puts it in the same process as the network handles.",
					pkg, len(bad), strings.Join(bad, "\n  "))
			}
		})
	}
	t.Logf("gate 2 (tier-wide): %d DAST package(s) walked", len(pkgs))
}

// ---------------------------------------------------------------------------
// The evasion suite
// ---------------------------------------------------------------------------

// TestGate2WalkIsNotDefeatedByImportSyntax is the negative control for the
// mechanism, run against a throwaway module so it needs no mutation of this
// repository and can be run by anyone at any time.
//
// Every row is a way somebody could hide an import from a guard that matched
// source text or local identifiers. The walk sees none of that: it sees the
// import graph the compiler will build.
//
// The last row is the one that matters most. A guard reading THIS package's
// files would see the kernel importing a package called "helper" and stop; the
// forbidden package is two hops away and is still named in the output.
func TestGate2WalkIsNotDefeatedByImportSyntax(t *testing.T) {
	dir := t.TempDir()
	const fixtureModule = "anvil.test/depgraph"
	const forbidden = fixtureModule + "/internal/inference/runtime"

	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", rel, err)
		}
	}

	write("go.mod", "module "+fixtureModule+"\n\ngo 1.26\n")
	write("internal/inference/runtime/runtime.go",
		"package runtime\n\nfunc Infer(s string) string { return s }\n")
	write("helper/helper.go",
		"package helper\n\nimport \"anvil.test/depgraph/internal/inference/runtime\"\n\n"+
			"func H(s string) string { return runtime.Infer(s) }\n")

	cases := []struct {
		name string
		pkg  string
		src  string
	}{
		{
			name: "plain",
			pkg:  "plain",
			src: "package plain\n\nimport \"" + forbidden + "\"\n\n" +
				"func F(s string) string { return runtime.Infer(s) }\n",
		},
		{
			name: "alias",
			pkg:  "aliased",
			src: "package aliased\n\nimport rt \"" + forbidden + "\"\n\n" +
				"func F(s string) string { return rt.Infer(s) }\n",
		},
		{
			name: "dot import",
			pkg:  "dotted",
			src: "package dotted\n\nimport . \"" + forbidden + "\"\n\n" +
				"func F(s string) string { return Infer(s) }\n",
		},
		{
			name: "blank import",
			pkg:  "blanked",
			src:  "package blanked\n\nimport _ \"" + forbidden + "\"\n",
		},
		{
			name: "transitive, through an innocently named intermediary",
			pkg:  "indirect",
			src: "package indirect\n\nimport \"anvil.test/depgraph/helper\"\n\n" +
				"func F(s string) string { return helper.H(s) }\n",
		},
	}
	for _, tc := range cases {
		write(tc.pkg+"/"+tc.pkg+".go", tc.src)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", "./"+tc.pkg)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off")
			out, err := cmd.Output()
			if err != nil {
				var stderr string
				if ee, ok := err.(*exec.ExitError); ok {
					stderr = string(ee.Stderr)
				}
				t.Fatalf("go list -deps ./%s: %v\n%s", tc.pkg, err, stderr)
			}
			deps := strings.Split(strings.TrimSpace(string(out)), "\n")

			found := false
			for _, d := range deps {
				if strings.TrimSpace(d) == forbidden {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("the walk did not report %q for a package that imports it as %q.\n"+
					"This is the alias-defeat that beat a sibling guard in "+
					"internal/collector/host, and it must not work here.\ngo list said:\n  %s",
					forbidden, tc.name, strings.Join(deps, "\n  "))
			}

			// The walk found it; now prove the GATE refuses it and NAMES it.
			// The two halves are tested together because either one alone is
			// satisfiable without the other: a walk nobody judges, or a
			// judgment over a graph nobody measured.
			g, err := NewImportGraph(KernelPackage, append([]string{forbidden}, deps...))
			if err != nil {
				t.Fatalf("recording the fixture graph: %v", err)
			}
			res := CheckGate2KernelCompiledSeparately(g)
			if res.Passed() {
				t.Fatalf("gate 2 PASSED on a closure containing %q", forbidden)
			}
			msg := fmt.Sprint(res.Err())
			if !strings.Contains(msg, forbidden) {
				t.Fatalf("gate 2 refused but did not NAME the offending import path.\n"+
					"got: %s\nwant it to contain: %s\nA guard that fails without saying "+
					"what it caught sends the reader looking in the wrong place.",
					msg, forbidden)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GATE 1 -- the artifact split, and an honest note about half of it
// ---------------------------------------------------------------------------

// TestGate1CoreArtifactSplitAndTheVacuityOfItsPositiveHalf runs gate 1 against
// the real cmd/anvil closure and reports, in the ledger style this repository
// uses elsewhere, which half of the split it actually proved.
//
// The NEGATIVE half -- cmd/anvil must not reach internal/dast -- is enforced,
// and is also enforced independently by cmd/anvil/split_test.go and by the
// artifact-split job in CI, negative control included.
//
// The POSITIVE half -- cmd/anvil-dast must reach the kernel, so that the split
// is proved by a DIFFERENCE between two measurements rather than by the
// absence of one -- is UNPROVEN today, and this test says so out loud rather
// than counting it. It becomes a real assertion automatically the moment
// cmd/anvil-dast links the kernel: the check below is written as an invariant
// over both graphs, so it starts enforcing on its own without anybody
// remembering to come back.
//
// The zero-value half of gate 1 -- "no default target, no default scope, no
// bundled example that resolves to a real host" -- IS proven here, and it is
// not vacuous: zeroValuesThatWouldAuthorize exercises every zero value in the
// kernel's vocabulary against the shipped code.
func TestGate1CoreArtifactSplitAndTheVacuityOfItsPositiveHalf(t *testing.T) {
	root := repoRootForGuards(t)

	core := goListDeps(t, root, "./cmd/anvil")
	if res := CheckGate1DastShipsDisabled(core); !res.Passed() {
		t.Fatalf("gate 1 FAILED over a %d-package closure: %v", len(core.Deps()), res.Err())
	}

	dast := goListDeps(t, root, "./cmd/anvil-dast")
	linksKernel := false
	for _, d := range dast.Deps() {
		if d == dastPackageRoot || strings.HasPrefix(d, dastPackagePrefix) {
			linksKernel = true
			break
		}
	}

	if linksKernel {
		// The settled state. cmd/anvil reaching the tree is already fatal
		// above; the remaining invariant is that the DAST artifact really
		// contains the kernel, which is what makes the two measurements a
		// difference rather than two absences.
		found := false
		for _, d := range dast.Deps() {
			if d == KernelPackage {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("cmd/anvil-dast reaches the DAST tree but not %s. The dynamic "+
				"artifact must link the authorization kernel: a DAST binary that "+
				"reaches the probing code without reaching the kernel has the "+
				"capability and not the gate.", KernelPackage)
		}
		t.Logf("gate 1 ledger: PROVEN negative half (cmd/anvil reaches no DAST package) " +
			"and PROVEN positive half (cmd/anvil-dast links the kernel). The split is " +
			"a measured difference.")
		return
	}

	t.Logf("gate 1 ledger: PROVEN negative half -- cmd/anvil's %d-package closure "+
		"reaches no DAST package, and the zero-value survey found nothing that "+
		"authorizes.\n"+
		"gate 1 ledger: UNPROVEN positive half -- cmd/anvil-dast's %d-package closure "+
		"also reaches no DAST package, so the split is currently satisfied by "+
		"EMPTINESS rather than by separation, and would keep passing if the kernel "+
		"were deleted.\n"+
		"SETTLING CONDITION: plan step O.16 wires cmd/anvil-dast to the kernel. On "+
		"that day this test's positive branch starts enforcing by itself; nothing "+
		"here needs to be remembered.",
		len(core.Deps()), len(dast.Deps()))
}
