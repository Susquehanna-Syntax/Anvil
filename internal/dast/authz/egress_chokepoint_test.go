// D.9, gate 3: the egress choke point, measured.
//
// ===========================================================================
// WHY THIS IS AN ALLOWLIST OF INERT IMPORTS AND NOT A LIST OF BANNED CALLS
// ===========================================================================
//
// The obvious shape for this guard is a list of forbidden call sites:
// net.Dial, http.Client, http.Get, tls.Dial. That shape loses, and it loses
// quietly. It does not know about net.Dialer.DialContext, http.Transport,
// net.ListenPacket, golang.org/x/net/proxy, a vendored HTTP client, or the
// networking API that ships in Go 1.28. Each of those is caught only if
// somebody remembered to add it, and the failure mode of forgetting is a
// PASSING BUILD. A denylist's silence is indistinguishable from cleanliness.
//
// So the question is inverted. A Go file cannot open a socket without
// importing something that can open a socket. This guard therefore enumerates
// the packages that are INERT — that provably cannot construct a connection —
// and treats an import of anything else as egress capability. A new networking
// API is caught the first time it appears, by default, because it is not on
// the inert list and nobody has to have heard of it.
//
// The cost is real and is accepted deliberately: adding an ordinary new stdlib
// import to Anvil means adding one line to inertImports below. That edit is
// the review this gate exists to force, and it is a one-line edit with a
// stated reason, in a diff whose subject is exactly that widening.
//
// The judgment itself lives in CheckGate3EgressChokePoint (phase0_build.go,
// D.2). This file only MEASURES. The split is deliberate: the gate cannot lie
// about its own inputs, and this file cannot decide what its findings mean.
//
// ===========================================================================
// WHAT THIS GUARD CATCHES, AND WHAT IT DOES NOT
// ===========================================================================
//
// CAUGHT (each demonstrated by a fixture in
// TestGate3ScannerIsNotDefeatedByImportSyntax, which is where the claims below
// are proved rather than asserted):
//
//	import "net"                     plain import
//	import n "net"                   ALIAS -- resolved by PATH, never by local
//	                                 name. A sibling guard in
//	                                 internal/collector/host was defeated by an
//	                                 import alias earlier in this build, and an
//	                                 alias-defeatable guard is worse than none
//	                                 because it reports pass.
//	import . "net"                   dot-import
//	import _ "net"                   blank import
//	type c = http.Client             type alias
//	var dial = net.Dial              a call indirected through a variable
//	f := net.Dial; f(...)            a function value assigned then called
//	golang.org/x/net/proxy           an API nobody put on any denylist
//	syscall.Socket                   a raw socket under a package that is on
//	                                 the inert list only for named constants
//
// NOT CAUGHT, stated rather than papered over. Each of these is a laundering
// of a capability that this guard has ALREADY caught somewhere else, which is
// why they are limits rather than holes:
//
//  1. RE-EXPORT FROM AN ALLOWLISTED PACKAGE. internal/ingest/poller is on
//     nonKernelEgressAllowlist. If it grew an exported Fetch(url) and a new
//     package called it, the new package is not flagged. The socket is still
//     constructed in a reviewed package; what is not reviewed is the widening
//     of that package's blast radius.
//  2. A CAPABILITY PASSED AS A FUNCTION VALUE ACROSS A PACKAGE BOUNDARY.
//     func Fetch(do func(string) ([]byte, error)) imports nothing. Whoever
//     supplies `do` imports net and IS flagged.
//  3. os/exec. It is on the inert list (a subprocess is not a Go-level socket
//     construction) so `exec.Command("curl", url)` passes this gate. That
//     containment is D.11's network namespace with default-deny egress, not
//     this scanner, and D.11 is the reason it is acceptable to leave here.
//  4. SHADOWING. A local variable named `net` in a file that imports "net"
//     would make the selector analysis attribute the wrong package. This
//     applies only to packages with an inert-symbol allowlist (today: syscall
//     alone); every other non-inert import is flagged at the import line
//     without looking at selectors at all.
//  5. A vendor/ DIRECTORY. The walk skips it. Anvil does not vendor today
//     (go.mod has one direct requirement and no vendor tree), and scanning
//     third-party source would flag the whole dependency graph and make this
//     guard unusable within a week. `go mod vendor` therefore reopens this;
//     the S5 dependency gate in CI is what watches what enters the graph.
//  6. THE KERNEL'S OWN TEST FILES. internal/dast/authz is the choke point, so
//     it is exempt from both tiers, tests included. That exemption is the
//     definition of a choke point rather than a gap in it, but it does mean
//     this scanner says nothing about what the kernel's own tests dial.
//
// ===========================================================================
// WHAT THE MEASUREMENT PROVES TODAY, AND WHAT IT DOES NOT
// ===========================================================================
//
// Tier 2 (the whole repository outside internal/dast) is NON-VACUOUS: the scan
// finds real socket construction in internal/ingest/bootstrap,
// internal/ingest/poller and internal/mirror/accelerator, and
// TestGate3ScanFindsTheKnownFetchers asserts it finds all three. A scanner
// that silently stopped matching would fail that test rather than report a
// clean repository.
//
// Tier 1 (inside internal/dast, outside the kernel) currently finds ZERO
// sites, because no DAST code dials yet -- D.6's request layer is the first
// that will. That half of the measurement is therefore satisfied by emptiness
// today, and it is the fixture tests, not the repository scan, that prove the
// scanner can see a violation at all.
package authz

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The inert allowlist
// ---------------------------------------------------------------------------

// inertImports is every import path that provably cannot construct an outbound
// connection. Anything not listed here confers egress capability on the file
// that imports it.
//
// The values are not decoration: they are printed nowhere, but an entry a
// reviewer cannot justify in a phrase is an entry that should not be added, and
// requiring the phrase is what stops this list drifting into "everything we
// happened to import".
//
// net/netip and net/url are here on purpose despite their prefix. Both are
// pure value/parsing packages with no dialer, no listener and no transport;
// netip in particular is what the kernel uses to hold a PINNED address, which
// is the opposite of a capability.
var inertImports = map[string]string{
	"archive/tar":         "byte-stream archive format",
	"archive/zip":         "byte-stream archive format",
	"bufio":               "buffering over an io.Reader/Writer it is handed",
	"bytes":               "in-memory buffers",
	"cmp":                 "ordering helpers",
	"compress/gzip":       "byte-stream codec",
	"context":             "cancellation and deadlines; carries no connection",
	"crypto/sha256":       "hashing",
	"database/sql":        "SQL over a driver; the only driver in this module is file-backed",
	"database/sql/driver": "the driver interface types",
	"embed":               "compile-time file embedding",
	"encoding/binary":     "byte encoding",
	"encoding/csv":        "byte encoding",
	"encoding/hex":        "byte encoding",
	"encoding/json":       "byte encoding",
	// Go's XML decoder does NOT resolve external entities and does not fetch
	// DTDs -- it has no XXE, which is why D.19 can point it at a spec file
	// harvested from an untrusted repository at all. The one route to a socket
	// is Decoder.CharsetReader, which is CALLER-SUPPLIED: a caller that set it
	// to something fetching would have that fetch in its OWN code, where this
	// scanner sees it. Verified: nothing under internal/ sets CharsetReader.
	"encoding/xml":         "byte encoding; no external-entity resolution",
	"errors":               "error values",
	"flag":                 "command-line parsing",
	"fmt":                  "formatting",
	"go/ast":               "Go syntax trees",
	"go/format":            "Go source formatting",
	"go/parser":            "Go source parsing",
	"go/printer":           "Go source printing",
	"go/scanner":           "Go source lexing",
	"go/token":             "Go source positions",
	"hash/fnv":             "hashing",
	"io":                   "stream interfaces over whatever it is handed",
	"io/fs":                "filesystem interfaces",
	"log":                  "writes to an io.Writer it is handed",
	"maps":                 "map helpers",
	"math":                 "arithmetic",
	"math/rand/v2":         "pseudorandom numbers",
	"net/netip":            "an address VALUE type; no dialer, listener or resolver",
	"net/url":              "URL parsing; no dialer",
	"os":                   "files, environment and process state; cannot create a socket",
	"os/exec":              "subprocesses -- see limit 3 in this file's header, and D.11",
	"path":                 "slash-path string manipulation",
	"path/filepath":        "filesystem path string manipulation",
	"reflect":              "reflection over values it is handed",
	"regexp":               "pattern matching",
	"runtime":              "runtime introspection",
	"slices":               "slice helpers",
	"sort":                 "sorting",
	"strconv":              "string/number conversion",
	"strings":              "string manipulation",
	"sync":                 "mutexes and once",
	"sync/atomic":          "atomic scalars",
	"testing":              "the test driver",
	"testing/fstest":       "in-memory filesystems",
	"text/tabwriter":       "column alignment over an io.Writer",
	"time":                 "clocks and durations",
	"unicode":              "rune classification",
	"unicode/utf8":         "rune encoding",
	"modernc.org/sqlite":   "the pure-Go, file-backed SQLite driver S12 mandates; no network protocol",
	"golang.org/x/sys/cpu": "CPU feature detection",
}

// inertSymbols is the single, narrow escape hatch: a package that is NOT inert
// as a whole, but whose use in this repository is confined to identifiers that
// are inert.
//
// A package appears here only when the alternative is putting a genuinely
// socket-capable package on inertImports, which would be a lie. Every
// identifier is listed by name. A reference to any other identifier of the
// package -- syscall.Socket, syscall.Connect -- is a violation, and
// TestGate3ScannerIsNotDefeatedByImportSyntax proves it.
//
// Reaching this map is the ONLY case in which the scanner looks at selectors
// rather than stopping at the import line, which is why limit 4 (shadowing) is
// scoped to exactly these packages.
var inertSymbols = map[string]map[string]string{
	"syscall": {
		"Errno":   "the errno TYPE, for errors.Is comparisons",
		"ENOTDIR": "an errno CONSTANT. internal/policy/locate.go:124 compares against it when a path component turns out to be a file",
		"ENOENT":  "an errno CONSTANT",
		"EEXIST":  "an errno CONSTANT",
		"EACCES":  "an errno CONSTANT",
	},
}

// isInertImport reports whether importing p confers no egress capability.
//
// First-party packages are inert HERE because this scan attributes a socket to
// whoever holds the socket-capable import, not to everyone downstream of them.
// A first-party package that dials is caught in its own file; making its
// importers guilty too would flag every consumer of the kernel and the list
// would be weakened until it meant nothing. Limit 1 in this file's header is
// the price.
func isInertImport(p string) bool {
	if p == modulePath || strings.HasPrefix(p, modulePath+"/") {
		return true
	}
	_, ok := inertImports[p]
	return ok
}

// ---------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------

// scanGoFileForEgress returns every egress capability the file at absPath
// confers, attributed to pkg and reported against relPath.
//
// The two-stage rule, in order:
//
//  1. Every import that is not inert is a finding AT THE IMPORT LINE, unless
//     the imported package has an entry in inertSymbols. A dot-import or a
//     blank import of a non-inert package is always a finding, because there
//     is no qualified selector left to analyse and a guard with nothing to
//     look at must refuse rather than pass.
//  2. For the packages that DO have an inertSymbols entry, every selector on
//     them is checked against that entry by name. An import that survives
//     stage 1 but produces no selectors at all is ALSO a finding: either the
//     import is unused (which does not compile) or this function failed to
//     work out its local name, and both of those mean the analysis did not
//     happen. "We looked and found nothing" and "we could not look" must not
//     produce the same output.
func scanGoFileForEgress(fset *token.FileSet, absPath, relPath, pkg string) ([]EgressCallSite, error) {
	f, err := parser.ParseFile(fset, absPath, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", relPath, err)
	}

	var sites []EgressCallSite
	add := func(line int, symbol string) {
		sites = append(sites, EgressCallSite{
			Package: pkg,
			File:    filepath.ToSlash(relPath),
			Line:    line,
			Symbol:  symbol,
		})
	}

	// local name -> import path, for the inertSymbols packages only.
	watched := map[string]string{}
	// import path -> how many selectors we resolved onto it.
	seen := map[string]int{}
	// import path -> the line it was imported on.
	importLine := map[string]int{}

	for _, spec := range f.Imports {
		p, uerr := strconv.Unquote(spec.Path.Value)
		if uerr != nil {
			return nil, fmt.Errorf("%s: unquotable import path %s", relPath, spec.Path.Value)
		}
		if isInertImport(p) {
			continue
		}
		line := fset.Position(spec.Pos()).Line

		if spec.Name != nil && spec.Name.Name == "." {
			add(line, fmt.Sprintf("dot-import of %q", p))
			continue
		}
		if spec.Name != nil && spec.Name.Name == "_" {
			add(line, fmt.Sprintf("blank import of %q", p))
			continue
		}

		allowed, hasAllowlist := inertSymbols[p]
		if !hasAllowlist || len(allowed) == 0 {
			add(line, fmt.Sprintf("import %q", p))
			continue
		}

		local := p
		if i := strings.LastIndexByte(local, '/'); i >= 0 {
			local = local[i+1:]
		}
		if spec.Name != nil {
			local = spec.Name.Name
		}
		watched[local] = p
		importLine[p] = line
		seen[p] = 0
	}

	if len(watched) > 0 {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			p, ok := watched[ident.Name]
			if !ok {
				return true
			}
			seen[p]++
			if _, allowed := inertSymbols[p][sel.Sel.Name]; !allowed {
				add(fset.Position(sel.Pos()).Line, ident.Name+"."+sel.Sel.Name)
			}
			return true
		})
	}

	for p, n := range seen {
		if n == 0 {
			add(importLine[p], fmt.Sprintf(
				"import %q, whose uses this scan could not resolve", p))
		}
	}

	sort.Slice(sites, func(i, j int) bool { return sites[i].Line < sites[j].Line })
	return sites, nil
}

// scanRepoForEgress walks the repository and returns a completed EgressScan.
//
// # Which files are in scope, and why
//
// Every non-test .go file in the module, plus every _test.go file underneath
// internal/dast. Test files elsewhere are excluded because they are not linked
// into either shipped artifact, so they cannot bypass the kernel at runtime in
// anything a user installs. Test files inside the DAST tree are INCLUDED
// anyway, because a test there that dials probes a real host on whatever
// machine runs `go test`, and tier 1's claim -- that the kernel is the only
// place in the dynamic tier that opens a socket -- is not restricted to
// shipped code.
func scanRepoForEgress(t *testing.T, root string) EgressScan {
	t.Helper()

	fset := token.NewFileSet()
	var sites []EgressCallSite
	files := 0

	dastRel := filepath.Join("internal", "dast")

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		if d.IsDir() {
			name := d.Name()
			if p == root {
				return nil
			}
			// testdata and _-prefixed directories are invisible to the go
			// tool, so nothing in them is ever compiled.
			if name == ".git" || name == "testdata" || name == "vendor" ||
				strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		if strings.HasSuffix(p, "_test.go") &&
			!(rel == dastRel || strings.HasPrefix(rel, dastRel+string(filepath.Separator))) {
			return nil
		}

		dir := filepath.Dir(rel)
		pkg := modulePath
		if dir != "." {
			pkg = modulePath + "/" + filepath.ToSlash(dir)
		}
		found, serr := scanGoFileForEgress(fset, p, rel, pkg)
		if serr != nil {
			return serr
		}
		files++
		sites = append(sites, found...)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	scan, err := NewEgressScan(files, sites)
	if err != nil {
		t.Fatalf("recording the egress scan: %v", err)
	}
	return scan
}

// repoRootForGuards returns the module root, or fails.
//
// It does not skip when it cannot find the root. internal/SKIPPED-CONTROLS.md
// records this repository shipping two guards that vanished silently when they
// could not run; a build-time invariant that cannot locate the tree it guards
// has not passed, it has not run.
func repoRootForGuards(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		gomod := filepath.Join(dir, "go.mod")
		if b, rerr := os.ReadFile(gomod); rerr == nil {
			if strings.Contains(string(b), "module "+modulePath) {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod declaring module %s above %s. This guard refuses to "+
				"report a pass it did not measure.", modulePath, dir)
		}
		dir = parent
	}
}

// ---------------------------------------------------------------------------
// GATE 3 -- the repository measurement
// ---------------------------------------------------------------------------

// TestGate3NoSocketIsConstructedOutsideTheKernel is gate 3's build-time half,
// run against the real tree.
//
// ALWAYS RUN WITH -count=1. The verdict depends on the contents of files this
// package does not import, and Go's test cache does not track those.
func TestGate3NoSocketIsConstructedOutsideTheKernel(t *testing.T) {
	root := repoRootForGuards(t)
	scan := scanRepoForEgress(t, root)

	res := CheckGate3EgressChokePoint(scan)
	if !res.Passed() {
		var b strings.Builder
		fmt.Fprintf(&b, "gate 3 FAILED over %d file(s): %v", scan.FilesScanned(), res.Err())
		b.WriteString("\n\nIf the finding is a package that legitimately fetches something " +
			"and does not probe a target, add it to nonKernelEgressAllowlist in " +
			"phase0_build.go with a justification. If the finding is an ordinary new " +
			"import that cannot open a socket, add it to inertImports in this file. " +
			"If the finding is inside internal/dast, there is no list to add it to: " +
			"route it through Adjudicate and PinnedDialAddress.")
		t.Fatal(b.String())
	}
	t.Logf("gate 3: %d files scanned, %d egress site(s), all inside the kernel or on the allowlist",
		scan.FilesScanned(), len(scan.Sites()))
}

// TestGate3ScanFindsTheKnownFetchers is the positive control, and it is the
// reason the test above is evidence rather than an empty query.
//
// A scanner that matched nothing would satisfy gate 3 perfectly. These three
// packages really do construct HTTP clients -- an independent fact, readable by
// grepping for http.Client in the tree, not derived from this scanner -- so a
// scan that fails to see them is broken, whatever verdict it returned.
func TestGate3ScanFindsTheKnownFetchers(t *testing.T) {
	root := repoRootForGuards(t)
	scan := scanRepoForEgress(t, root)

	want := []string{
		modulePath + "/internal/ingest/bootstrap",
		modulePath + "/internal/ingest/poller",
		modulePath + "/internal/mirror/accelerator",
	}
	got := map[string]int{}
	for _, s := range scan.Sites() {
		got[s.Package]++
	}
	for _, w := range want {
		if got[w] == 0 {
			t.Errorf("the scan found no egress capability in %s, which constructs an "+
				"http.Client. A scan that cannot see a known fetcher cannot be trusted "+
				"to have seen an unknown one, and gate 3 would pass on its silence.", w)
		}
	}
	if scan.FilesScanned() < 20 {
		t.Errorf("the scan examined %d files. The module has far more than that, so the "+
			"walk is not reaching the tree it is supposed to judge.", scan.FilesScanned())
	}
}

// TestGate3ScannerIsNotDefeatedByImportSyntax is the evasion suite.
//
// A sibling guard in internal/collector/host was defeated by an import alias
// earlier in this build. It reported pass. Every row below is one way somebody
// could try the same thing here, plus the negative controls that stop the
// scanner from passing this suite by flagging everything.
//
// The fixtures are written to a temp dir and parsed, not compiled: the point is
// what the scanner sees, and several rows are deliberately not valid programs.
func TestGate3ScannerIsNotDefeatedByImportSyntax(t *testing.T) {
	cases := []struct {
		name   string
		src    string
		want   int
		expect string
	}{
		{
			name: "plain import",
			src: `package p
import "net"
func f() { net.Dial("tcp", "x") }`,
			want: 1, expect: `import "net"`,
		},
		{
			name: "import alias",
			src: `package p
import n "net"
func f() { n.Dial("tcp", "x") }`,
			want: 1, expect: `import "net"`,
		},
		{
			name: "dot import",
			src: `package p
import . "net"
func f() { Dial("tcp", "x") }`,
			want: 1, expect: `dot-import of "net"`,
		},
		{
			name: "blank import",
			src: `package p
import _ "net/http/pprof"`,
			want: 1, expect: `blank import of "net/http/pprof"`,
		},
		{
			name: "type alias",
			src: `package p
import "net/http"
type c = http.Client`,
			want: 1, expect: `import "net/http"`,
		},
		{
			name: "indirection through a package-level variable",
			src: `package p
import "net"
var dial = net.Dial
func f() { dial("tcp", "x") }`,
			want: 1, expect: `import "net"`,
		},
		{
			name: "a function value assigned then called",
			src: `package p
import "net"
func f() {
	g := net.Dial
	g("tcp", "x")
}`,
			want: 1, expect: `import "net"`,
		},
		{
			// Written as an interpreted string rather than a raw one so the
			// import path can carry quotes: this row is the whole argument
			// for the allowlist, and it must name a real API that no
			// denylist in this repository has ever mentioned.
			name:   "a networking API on no denylist anywhere",
			src:    "package p\n\nimport \"golang.org/x/net/proxy\"\n\nfunc f() { _, _ = proxy.SOCKS5(\"tcp\", \"x\", nil, nil) }\n",
			want:   1,
			expect: "golang.org/x/net/proxy",
		},
		{
			name: "net.Dialer rather than net.Dial",
			src: `package p
import "net"
var d net.Dialer`,
			want: 1, expect: `import "net"`,
		},
		{
			name: "crypto/tls",
			src: `package p
import "crypto/tls"
func f() { tls.Dial("tcp", "x", nil) }`,
			want: 1, expect: `import "crypto/tls"`,
		},
		{
			name: "a raw socket under an inert-symbol package",
			src: `package p
import "syscall"
func f() { syscall.Socket(2, 1, 0) }`,
			want: 1, expect: "syscall.Socket",
		},
		{
			name: "an aliased raw socket under an inert-symbol package",
			src: `package p
import sc "syscall"
func f() { sc.Socket(2, 1, 0) }`,
			want: 1, expect: "sc.Socket",
		},
		// ---- negative controls ----
		//
		// Without these the suite is satisfied by a scanner that returns a
		// finding for every file it is handed, which would be useless and
		// would still pass every row above.
		{
			name: "an inert-symbol package used only for an errno",
			src: `package p
import (
	"errors"
	"io/fs"
	"syscall"
)
func f(err error) bool { return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) }`,
			want: 0,
		},
		{
			name: "net/netip and net/url are values and parsers, not dialers",
			src: `package p
import (
	"net/netip"
	"net/url"
)
func f(s string) (netip.Addr, error) { _, _ = url.Parse(s); return netip.ParseAddr(s) }`,
			want: 0,
		},
		{
			name: "an ordinary inert file",
			src: `package p
import (
	"fmt"
	"strings"
)
func f(s string) string { return fmt.Sprint(strings.TrimSpace(s)) }`,
			want: 0,
		},
		{
			name: "a first-party import is attributed to whoever holds the socket",
			src: `package p
import "github.com/Susquehanna-Syntax/Anvil/internal/ingest/poller"
func f() { _ = poller.Config{} }`,
			want: 0,
		},
	}

	dir := t.TempDir()
	fset := token.NewFileSet()

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.src
			p := filepath.Join(dir, fmt.Sprintf("case%02d.go", i))
			if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
				t.Fatalf("writing fixture: %v", err)
			}
			sites, err := scanGoFileForEgress(fset, p, filepath.Base(p), "fixture/pkg")
			if err != nil {
				t.Fatalf("scanning fixture: %v", err)
			}
			if len(sites) != tc.want {
				t.Fatalf("scanner found %d site(s), want %d.\nsites: %v\nsource:\n%s",
					len(sites), tc.want, sites, src)
			}
			if tc.want == 0 {
				return
			}
			joined := fmt.Sprint(sites)
			if !strings.Contains(joined, tc.expect) {
				t.Fatalf("the scanner flagged the file but did not NAME the offending "+
					"import: got %q, want it to contain %q. A guard that fails without "+
					"saying what it caught sends the reader looking in the wrong place.",
					joined, tc.expect)
			}
		})
	}
}

// TestGate3ScanRefusesToReportAnEmptyMeasurement pins the anti-vacuity floor
// this file depends on.
//
// scanRepoForEgress hands NewEgressScan a file count. If the walk ever matched
// zero files -- a bad root, a stray SkipDir, a changed suffix -- the sites list
// would also be empty and gate 3 would return PASS on a repository nobody
// looked at. That is the silent-clean failure this project keeps catching.
func TestGate3ScanRefusesToReportAnEmptyMeasurement(t *testing.T) {
	if _, err := NewEgressScan(0, nil); err == nil {
		t.Fatal("NewEgressScan accepted a scan that examined zero files, so a walk that " +
			"matched nothing would be indistinguishable from a clean tree")
	}
}

// ---------------------------------------------------------------------------
// GATE 3 -- the runtime half
// ---------------------------------------------------------------------------

// TestGate3PinnedDialAddressIsTheOnlyRouteToASocket asserts the structural
// claim the runtime half rests on: exactly one exported function in the kernel
// yields something a dialer can be pointed at.
//
// RequireAuthorization's refusals are covered by TestRequireAuthorizationRefusals
// and TestPinnedDialAddressRefusesWithoutAnAuthorization. What NEITHER of them
// covers is whether a SECOND, ungated route to a dial address has appeared --
// and a choke point with two doors is not a choke point. The check is by
// signature: netip.AddrPort is the type the egress layer needs and a hostname
// is not in it, so any exported function returning one is a route.
func TestGate3PinnedDialAddressIsTheOnlyRouteToASocket(t *testing.T) {
	root := repoRootForGuards(t)
	kernelDir := filepath.Join(root, "internal", "dast", "authz")

	entries, err := os.ReadDir(kernelDir)
	if err != nil {
		t.Fatalf("reading the kernel directory: %v", err)
	}

	fset := token.NewFileSet()
	var routes []string
	inspected := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(kernelDir, name), nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		inspected++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() || fn.Type.Results == nil {
				continue
			}
			for _, res := range fn.Type.Results.List {
				sel, ok := res.Type.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || ident.Name != "netip" || sel.Sel.Name != "AddrPort" {
					continue
				}
				routes = append(routes, fmt.Sprintf("%s (%s:%d)",
					fn.Name.Name, name, fset.Position(fn.Pos()).Line))
			}
		}
	}

	if inspected == 0 {
		t.Fatal("no non-test .go files were parsed in the kernel directory. This check " +
			"found nothing because it looked at nothing.")
	}
	sort.Strings(routes)
	want := []string{"PinnedDialAddress"}
	got := make([]string, 0, len(routes))
	for _, r := range routes {
		got = append(got, strings.SplitN(r, " ", 2)[0])
	}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("the kernel exports %d function(s) returning a netip.AddrPort: %v.\n"+
			"Exactly one is expected -- PinnedDialAddress, which calls "+
			"RequireAuthorization before it returns. Every other route to a dial "+
			"address is an ungated door in the choke point. If the new one is "+
			"legitimate it must call RequireAuthorization first, and this test must "+
			"be widened in the same diff so the widening is reviewed.",
			len(routes), routes)
	}
	t.Logf("gate 3 runtime half: %d kernel files inspected, exactly one gated route to a "+
		"dial address (%s)", inspected, routes[0])
}
