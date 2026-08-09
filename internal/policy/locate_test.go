package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// o5writeCandidate creates a candidate policy file (and its parent directory)
// under root, using the repository-relative slash form the search order is
// written in.
func o5writeCandidate(t *testing.T, root, candidate string) string {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(candidate))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll for %q: %v", candidate, err)
	}
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatalf("WriteFile %q: %v", candidate, err)
	}
	return path
}

// TestLocateFindsEachCandidateInIsolation covers all five search paths: each
// one, alone in an otherwise empty tree, must be found.
func TestLocateFindsEachCandidateInIsolation(t *testing.T) {
	for _, candidate := range SearchOrder() {
		t.Run(candidate, func(t *testing.T) {
			root := t.TempDir()
			want := o5writeCandidate(t, root, candidate)

			got, err := Locate(root)
			if err != nil {
				t.Fatalf("Locate: unexpected error: %v", err)
			}
			if got != want {
				t.Errorf("Locate = %q, want %q", got, want)
			}
			if _, err := os.ReadFile(got); err != nil {
				t.Errorf("returned path is not openable: %v", err)
			}
		})
	}
}

// TestLocatePrecedenceStopsAtFirstMatch is the search-order test proper. It
// starts with every candidate present and removes them from the front, so each
// step asserts both "this one wins" and "the ones behind it are inert".
func TestLocatePrecedenceStopsAtFirstMatch(t *testing.T) {
	order := SearchOrder()

	for removed := range order {
		remaining := order[removed:]

		t.Run("winner="+remaining[0], func(t *testing.T) {
			root := t.TempDir()
			var want string
			for i, candidate := range remaining {
				path := o5writeCandidate(t, root, candidate)
				if i == 0 {
					want = path
				}
			}

			got, err := Locate(root)
			if err != nil {
				t.Fatalf("Locate: unexpected error: %v", err)
			}
			if got != want {
				t.Errorf("Locate = %q, want %q (candidates present: %v)", got, want, remaining)
			}
		})
	}
}

func TestLocateNotFound(t *testing.T) {
	root := t.TempDir()

	got, err := Locate(root)
	if err == nil {
		t.Fatalf("Locate on an empty tree returned %q, want an error", got)
	}
	if !errors.Is(err, ErrNoPolicyFound) {
		t.Fatalf("Locate error = %v, want errors.Is(err, ErrNoPolicyFound)", err)
	}
	if got != "" {
		t.Errorf("Locate returned path %q alongside an error, want empty", got)
	}
	// The message has to name what was searched: "no policy file found" with
	// no list is the kind of diagnostic that sends a user reading source.
	for _, candidate := range SearchOrder() {
		if !strings.Contains(err.Error(), candidate) {
			t.Errorf("error message %q does not mention candidate %q", err, candidate)
		}
	}
}

// TestLocateSkipsNonRegularFile: a DIRECTORY named .anvil/policy.yml is not a
// policy file. Matching it would defer the failure to the parser, with a
// confusing error; skipping it lets the next candidate win.
func TestLocateSkipsNonRegularFile(t *testing.T) {
	root := t.TempDir()
	order := SearchOrder()

	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(order[0])), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	want := o5writeCandidate(t, root, order[1])

	got, err := Locate(root)
	if err != nil {
		t.Fatalf("Locate: unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("Locate = %q, want %q (a directory shadowing %q must be skipped)", got, want, order[0])
	}
}

// TestLocateSkipsNonRegularFileEverywhere runs the same check for every
// position in the order, and for the last one asserts the not-found path: a
// tree whose only candidate is a directory has no policy.
func TestLocateSkipsNonRegularFileEverywhere(t *testing.T) {
	for _, candidate := range SearchOrder() {
		t.Run(candidate, func(t *testing.T) {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(candidate)), 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}

			_, err := Locate(root)
			if !errors.Is(err, ErrNoPolicyFound) {
				t.Fatalf("Locate error = %v, want ErrNoPolicyFound", err)
			}
		})
	}
}

// TestLocateEmptyRootMeansWorkingDirectory pins the documented behaviour of
// root == "", which is what a caller running inside the checkout passes.
func TestLocateEmptyRootMeansWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	candidate := SearchOrder()[0]
	o5writeCandidate(t, root, candidate)

	t.Chdir(root)

	got, err := Locate("")
	if err != nil {
		t.Fatalf("Locate(\"\"): unexpected error: %v", err)
	}
	if want := filepath.FromSlash(candidate); got != want {
		t.Errorf("Locate(\"\") = %q, want %q", got, want)
	}
}

func TestLocateEmptyRootNotFoundNamesCurrentDirectory(t *testing.T) {
	t.Chdir(t.TempDir())

	_, err := Locate("")
	if !errors.Is(err, ErrNoPolicyFound) {
		t.Fatalf("Locate error = %v, want ErrNoPolicyFound", err)
	}
	if !strings.Contains(err.Error(), `"."`) {
		t.Errorf("error message %q should name the current directory as %q", err, ".")
	}
}

// TestSearchOrderIsTheDocumentedOrder pins the list itself. The order is a
// published contract (research/09 Recommendation 2, and the O.8 Action
// re-implements the lookup on the runner), so reordering it must break a test,
// not just a habit.
func TestSearchOrderIsTheDocumentedOrder(t *testing.T) {
	want := []string{
		".anvil/policy.yml",
		".anvil/policy.yaml",
		".anvil/policy.toml",
		"anvil.toml",
		".github/anvil.yml",
	}

	got := SearchOrder()
	if len(got) != len(want) {
		t.Fatalf("SearchOrder() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SearchOrder()[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

// TestSearchOrderReturnsACopy: the whole point of exporting the order is that
// several consumers share one definition. A caller that mutates the returned
// slice must not be able to change where anyone else looks.
func TestSearchOrderReturnsACopy(t *testing.T) {
	first := SearchOrder()
	first[0] = "attacker/controlled.yml"

	second := SearchOrder()
	if second[0] == first[0] {
		t.Fatalf("SearchOrder() exposed shared backing storage: mutation leaked (%q)", second[0])
	}
	if second[0] != ".anvil/policy.yml" {
		t.Fatalf("SearchOrder()[0] = %q after a caller mutated an earlier result", second[0])
	}
}

// TestSchemaIdentifiersAreStable guards the constants other areas consume. If
// the schema's $id or path changes, the Action (O.8) and area D must change
// with it, so the change should be deliberate.
func TestSchemaIdentifiersAreStable(t *testing.T) {
	if SchemaPath != "schemas/policy.schema.json" {
		t.Errorf("SchemaPath = %q, want schemas/policy.schema.json", SchemaPath)
	}
	if SchemaID != "https://anvil.invalid/schemas/policy.schema.json" {
		t.Errorf("SchemaID = %q", SchemaID)
	}
}
