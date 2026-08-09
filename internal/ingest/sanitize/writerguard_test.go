// The writer guard: "every writer runs external text through Sanitize" as a
// test rather than as a sentence in a doc comment.
//
// ===========================================================================
// WHY THIS FILE EXISTS
// ===========================================================================
//
// A.3's stop condition is a claim about EVERY write path into `advisory`,
// `affected` and `advisory_fts`. A.5 checked it and found the claim true and
// worthless: there is no writer. `internal/ingest/cache` exports statement
// TEXTS and migration plumbing; nothing in the repository binds a parameter to
// UpsertAdvisorySQL outside cache's own tests. So the obligation lived in two
// comments — cache/schema.go:50-53 and :483-486 — which is the shape
// plan/00-SPINE.md S7 names as the thing to avoid: "enforce in code, not
// documentation".
//
// This guard is what can be enforced from inside A.3's write scope. It walks
// the AST of every package under internal/ingest and asks one question of
// every function:
//
//	if this function binds an ADVISORY WRITE SHAPE, can the same call graph be
//	shown to reach internal/ingest/sanitize first?
//
// Today it flags nothing, because there is nothing to flag. That is exactly
// the state in which a guard is worth writing: the first writer is written
// against a suite that already refuses the unsanitised version of it, rather
// than against a comment the author may not read. It is kept from being inert
// by two synthetic writers it must classify correctly on every run — one that
// skips Sanitize and must be flagged, one that calls it and must not be.
//
// MEASURED END TO END, not only through the probes' own controls. With
// wgLeakProbeSource injected into the real scan of internal/ingest/cache,
// TestNoIngestWriterBindsAnUnsanitizedString reports:
//
//	writer guard: 145 functions scanned, 5 bind an advisory write shape
//	              (0 reach sanitize, 0 allowlisted)
//	cache.Writer.UpsertAdvisoryUnsanitized      … binds UpsertAdvisorySQL
//	cache.Writer.UpsertViaOwnStatement          … binds a SQL literal
//	cache.Writer.UpsertViaAnUnexportedHelper    … binds UpsertAdvisorySQL
//	cache.Writer.UpsertWithADiscardedSanitizeCall … binds UpsertAdvisorySQL
//	cache.Writer.bind                           … binds UpsertAdvisorySQL
//
// and the test fails. Without the injection it scans 140 functions and finds
// none.
//
// The shape is taken from internal/record/readpath_test.go's read-gate guard
// (gateParseSource / gateUngatedAllowlist / TestResultReachingEntryPointsAreGated),
// deliberately: that guard was written after five authors independently
// re-derived a rule and five got it wrong, and its structure — name-resolved
// call graph, allowlist entries that are claims about a BODY, synthetic
// probes as permanent negative controls — is the pattern this repository has
// already paid for. Read that file's KNOWN LIMITS section as well as this
// one; the limits are largely the same limits.
//
// ===========================================================================
// KNOWN LIMITS — READ BEFORE TRUSTING A GREEN RUN
// ===========================================================================
//
// This is a heuristic over an untyped AST. It catches the ACCIDENTAL bypass —
// the writer somebody actually writes, which binds a raw feed string to an
// upsert because the sanitizer was three packages away and easy not to think
// about. It is not a security boundary, and the following are OPEN:
//
//   - NAME RESOLUTION, NO TYPES. `x.Sanitize(s)` counts as reaching this
//     package even if x is something else entirely, and a write site is
//     recognised by the NAME of a statement constant or by the text of a SQL
//     literal. A writer that assembles its INSERT from concatenated fragments,
//     or reads it from a file, is invisible here.
//   - REACHING IS NOT OBEYING. A call to Sanitize whose result is used counts,
//     even if the value actually bound is a different, unsanitised string.
//     Pairing the sanitised value with the bound parameter is a dataflow
//     question this cannot answer, and pretending otherwise would manufacture
//     the confidence the package comment warns about. The real fix is a
//     signature: a writer that takes record.TrustedString cannot be handed a
//     raw string at all, and that is A.7/A.8's to build.
//   - PACKAGE-LOCAL CALL GRAPH ONLY. A helper in another package is not
//     followed; only the callee NAME is matched. A writer that puts its bind
//     in package P and its Sanitize call in package Q is flagged (P's graph
//     never names Sanitize), which errs toward a false alarm rather than a
//     miss.
//   - FUNC VALUES, INTERFACES, REFLECTION. Not followed, as in the read-gate
//     guard.
//   - UNPARSEABLE FILES ARE SKIPPED, with a log line. A file that does not
//     parse does not compile either, so nothing hides there for long — but a
//     green run over a tree with skips is a weaker statement, and the skips
//     are printed for that reason.
//   - DELETE STATEMENTS ARE NOT WRITE SITES. DeleteAdvisoryFTSSQL binds a
//     rowid and no external text. If a delete ever binds feed text, add it to
//     wgAdvisoryWriteShapes.

package sanitize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// wgScanRoot is the tree this guard is responsible for: internal/ingest, the
// parent of this package. Lane A's writers will live here.
const wgScanRoot = ".."

// wgAdvisoryWriteShapes are the exported statement constants from
// internal/ingest/cache that BIND EXTERNALLY-SOURCED TEXT. Naming one of them
// inside a function body is what makes that function a write site.
//
// UpsertFeedStateSQL is deliberately absent: its parameters are a feed id, an
// etag, timestamps and counters that Anvil itself computes. DeleteAdvisoryFTSSQL
// is absent for the same reason — it binds a rowid.
var wgAdvisoryWriteShapes = map[string]bool{
	"UpsertAdvisorySQL":    true,
	"UpsertAdvisoryFTSSQL": true,
}

// wgAdvisoryWriteSQL catches a writer that composes its own statement instead
// of using the shared constant — which is the more likely accident of the two,
// because a constant in another package is a thing you have to go and find.
var wgAdvisoryWriteSQL = regexp.MustCompile(`(?is)\b(insert|replace|update)\b.{0,160}?\b(advisory|advisory_fts|affected)\b`)

// wgSanitizeEntries are the callee names that mean "this call graph went
// through A.3". They are matched as CALLEE names on a call whose result is
// used, exactly as the read-gate guard matches its gate names: a mention is
// not a call, and a discarded result is not obedience.
var wgSanitizeEntries = map[string]bool{
	"Sanitize":           true,
	"SanitizeSlice":      true,
	"Ingest":             true,
	"IngestSlice":        true,
	"AssertSanitized":    true,
	"AssertAllSanitized": true,
}

// wgExemption is one allowlist entry: why this write site does not need to
// reach A.3, and the hash of the BODY that claim was made about. A rewritten
// body expires the exemption, so a reason cannot be inherited by code nobody
// re-read.
type wgExemption struct {
	reason string
	body   string
}

// wgAllowlist is EMPTY, and its emptiness is the current state of Lane A
// rather than an oversight: there are no writers yet, so there is nothing to
// exempt. The machinery is here so that the first entry has to arrive in the
// right shape — a reason and a body hash — instead of as a deleted assertion.
//
// Keys are "<package>.<Func>" or "<package>.<Recv>.<Method>".
func wgAllowlist() map[string]wgExemption {
	return map[string]wgExemption{}
}

// ---------------------------------------------------------------------------
// The analysis
// ---------------------------------------------------------------------------

type wgIndex struct {
	pkg      string
	fset     *token.FileSet
	decl     map[string]*ast.FuncDecl
	file     map[string]string
	byName   map[string][]string
	byMethod map[string][]string
	keys     []string
}

// wgParseDir indexes one directory's non-test Go files. extra injects
// synthetic source (filename -> body) so the negative controls run the
// identical analysis against a probe rather than against a copy of it.
func wgParseDir(t *testing.T, dir string, extra map[string]string) (*wgIndex, []string) {
	t.Helper()
	fset := token.NewFileSet()
	idx := &wgIndex{
		pkg:      filepath.Base(dir),
		fset:     fset,
		decl:     map[string]*ast.FuncDecl{},
		file:     map[string]string{},
		byName:   map[string][]string{},
		byMethod: map[string][]string{},
	}
	var skipped []string

	files := map[string]*ast.File{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			skipped = append(skipped, path)
			continue
		}
		files[path] = f
	}
	for name, src := range extra {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parsing synthetic source %s: %v", name, err)
		}
		files[name] = f
	}

	for path, f := range files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				recv := wgBaseTypeName(fn.Recv.List[0].Type)
				if recv == "" {
					continue
				}
				key = recv + "." + fn.Name.Name
				idx.byMethod[fn.Name.Name] = append(idx.byMethod[fn.Name.Name], key)
			} else {
				idx.byName[key] = append(idx.byName[key], key)
			}
			if _, dup := idx.decl[key]; dup {
				continue
			}
			idx.decl[key] = fn
			idx.file[key] = filepath.Base(path)
			idx.keys = append(idx.keys, key)
		}
	}
	sort.Strings(idx.keys)
	return idx, skipped
}

func wgBaseTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return wgBaseTypeName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.ArrayType:
		return wgBaseTypeName(t.Elt)
	case *ast.IndexExpr:
		return wgBaseTypeName(t.X)
	}
	return ""
}

// wgCalleeName is the name a call site uses for its callee. It is the only
// place a sanitize entry point may be recognised, so that a local variable
// named Sanitize is not obedience — the read-gate guard lost an attack to
// exactly that and the fix is not worth re-losing.
func wgCalleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.IndexExpr:
		return wgCalleeName(f.X)
	case *ast.IndexListExpr:
		return wgCalleeName(f.X)
	case *ast.ParenExpr:
		return wgCalleeName(f.X)
	}
	return ""
}

// wgDiscardedCalls marks every call whose result is thrown away: statement
// position, under go/defer, or assigned entirely to blanks. `_ = Sanitize(s)`
// sanitises nothing, because the sanitised value is what has to be bound.
func wgDiscardedCalls(body *ast.BlockStmt) map[*ast.CallExpr]bool {
	out := map[*ast.CallExpr]bool{}
	mark := func(e ast.Expr) {
		if c, ok := e.(*ast.CallExpr); ok {
			out[c] = true
		}
	}
	allBlank := func(lhs []ast.Expr) bool {
		for _, e := range lhs {
			id, ok := e.(*ast.Ident)
			if !ok || id.Name != "_" {
				return false
			}
		}
		return len(lhs) > 0
	}
	isBlank := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "_"
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.ExprStmt:
			mark(s.X)
		case *ast.GoStmt:
			out[s.Call] = true
		case *ast.DeferStmt:
			out[s.Call] = true
		case *ast.AssignStmt:
			if len(s.Rhs) == 1 {
				if allBlank(s.Lhs) {
					mark(s.Rhs[0])
				}
				return true
			}
			for i := range s.Rhs {
				if i < len(s.Lhs) && isBlank(s.Lhs[i]) {
					mark(s.Rhs[i])
				}
			}
		}
		return true
	})
	return out
}

type wgMarks struct {
	writesAdvisory  bool
	writeDetail     string
	reachesSanitize bool
}

func (idx *wgIndex) marks(key string) wgMarks {
	var m wgMarks
	fn := idx.decl[key]
	if fn == nil {
		return m
	}
	discarded := wgDiscardedCalls(fn.Body)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.Ident:
			if wgAdvisoryWriteShapes[e.Name] {
				m.writesAdvisory = true
				m.writeDetail = e.Name
			}
		case *ast.SelectorExpr:
			if wgAdvisoryWriteShapes[e.Sel.Name] {
				m.writesAdvisory = true
				m.writeDetail = e.Sel.Name
			}
		case *ast.BasicLit:
			if e.Kind == token.STRING && wgAdvisoryWriteSQL.MatchString(e.Value) {
				m.writesAdvisory = true
				m.writeDetail = "a SQL literal writing advisory/affected"
			}
		case *ast.CallExpr:
			if wgSanitizeEntries[wgCalleeName(e.Fun)] && !discarded[e] {
				m.reachesSanitize = true
			}
		}
		return true
	})
	return m
}

func (idx *wgIndex) callees(key string) []string {
	fn := idx.decl[key]
	if fn == nil {
		return nil
	}
	var out []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			out = append(out, idx.byName[f.Name]...)
		case *ast.SelectorExpr:
			out = append(out, idx.byMethod[f.Sel.Name]...)
		}
		return true
	})
	return out
}

// reach walks the package-local call graph from key and unions the marks.
func (idx *wgIndex) reach(key string) wgMarks {
	out := idx.marks(key)
	seen := map[string]bool{key: true}
	queue := idx.callees(key)
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		m := idx.marks(cur)
		out.reachesSanitize = out.reachesSanitize || m.reachesSanitize
		if m.writesAdvisory && !out.writesAdvisory {
			out.writesAdvisory, out.writeDetail = true, m.writeDetail
		}
		queue = append(queue, idx.callees(cur)...)
	}
	return out
}

type wgVerdict int

const (
	// wgNoWriteSite: this call graph never names an advisory write shape.
	wgNoWriteSite wgVerdict = iota
	// wgSanitized: it does, and the same call graph reaches A.3.
	wgSanitized
	// wgUnsanitized: it does, and nothing in the call graph reaches A.3.
	// This is the finding.
	wgUnsanitized
)

// classifyWrite is THE analysis. The guard and both negative controls call it,
// so a control cannot pass against a code path that does not ship.
func (idx *wgIndex) classifyWrite(key string) (wgVerdict, string) {
	if idx.decl[key] == nil {
		return wgNoWriteSite, ""
	}
	m := idx.reach(key)
	switch {
	case !m.writesAdvisory:
		return wgNoWriteSite, ""
	case m.reachesSanitize:
		return wgSanitized, m.writeDetail
	default:
		return wgUnsanitized, m.writeDetail
	}
}

// wgBodyHash is the identity of a function BODY: printed back to source,
// re-tokenised, and the token stream hashed. Comments and layout do not change
// it; statements, names and literals do. Same construction, and same reasons,
// as gateBodyHash in internal/record/readpath_test.go.
func (idx *wgIndex) wgBodyHash(key string) string {
	fn := idx.decl[key]
	if fn == nil || fn.Body == nil {
		return ""
	}
	var buf bytes.Buffer
	if err := (&printer.Config{Mode: printer.RawFormat, Tabwidth: 8}).Fprint(&buf, idx.fset, fn.Body); err != nil {
		return ""
	}
	src := buf.Bytes()
	var fs token.FileSet
	var sc scanner.Scanner
	sc.Init(fs.AddFile("", fs.Base(), len(src)), src, nil, 0)
	var stream strings.Builder
	for {
		_, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		stream.WriteString(tok.String())
		if lit != "" {
			stream.WriteByte('\x1f')
			stream.WriteString(lit)
		}
		stream.WriteByte('\x1e')
	}
	sum := sha256.Sum256([]byte(stream.String()))
	return hex.EncodeToString(sum[:])[:16]
}

// wgCheckExemption is the allowlist check, factored out so that
// TestTheWriterGuardsAllowlistIsAClaimAboutABody exercises the shipping code
// rather than a re-implementation of it.
func wgCheckExemption(idx *wgIndex, key string, ex wgExemption) error {
	if strings.TrimSpace(ex.reason) == "" {
		return fmt.Errorf("%s is allowlisted with an empty reason; an allowlist without reasons "+
			"is not an allowlist", key)
	}
	got := idx.wgBodyHash(key)
	switch {
	case got == "":
		return fmt.Errorf("%s is allowlisted but its body could not be hashed; the exemption "+
			"cannot be checked and must not be trusted", key)
	case strings.TrimSpace(ex.body) == "":
		return fmt.Errorf("%s is allowlisted with no body hash. An allowlist entry is a claim "+
			"about a BODY, not about a name. Record body: %q", key, got)
	case ex.body != got:
		return fmt.Errorf("%s is allowlisted, but its body has CHANGED since the exemption was "+
			"written.\n    recorded %s\n    current  %s\n    The reason on file was written about "+
			"the old implementation:\n      %s\n    Re-read the function as it is NOW. If it still "+
			"does not need Sanitize, update the hash to %s and say so in the reason.",
			key, ex.body, got, ex.reason, got)
	}
	return nil
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

// TestNoIngestWriterBindsAnUnsanitizedString is the guard. It reports every
// function under internal/ingest that binds an advisory write shape without
// its call graph reaching this package.
//
// IT FLAGS NOTHING TODAY. That is not a pass in the sense that matters — A.3's
// stop condition is CARRIED FORWARD UNMET to A.7/A.8, and no reader should
// record this test's green run as having verified the ingest property at
// system level. What a green run does say is: as of this commit, no writer
// exists that skips Sanitize, and the next one cannot be added silently.
func TestNoIngestWriterBindsAnUnsanitizedString(t *testing.T) {
	allow := wgAllowlist()
	used := map[string]bool{}
	scanned, writeSites, sanitized := 0, 0, 0
	var allSkipped []string

	for _, dir := range wgPackageDirs(t, wgScanRoot) {
		idx, skipped := wgParseDir(t, dir, nil)
		allSkipped = append(allSkipped, skipped...)
		for _, key := range idx.keys {
			scanned++
			verdict, detail := idx.classifyWrite(key)
			if verdict == wgNoWriteSite {
				continue
			}
			writeSites++
			full := idx.pkg + "." + key
			if verdict == wgSanitized {
				sanitized++
				continue
			}
			if ex, ok := allow[full]; ok {
				used[full] = true
				if err := wgCheckExemption(idx, key, ex); err != nil {
					t.Error(err)
				}
				continue
			}
			t.Errorf("%s (%s/%s) binds %s and nothing in its call graph reaches "+
				"internal/ingest/sanitize.\n"+
				"    Run every externally-sourced string through sanitize.Ingest (which also\n"+
				"    stamps anvil/trust) or sanitize.Sanitize, and call sanitize.AssertAllSanitized\n"+
				"    on the field map before binding. If this function structurally cannot bind\n"+
				"    external text, add it to wgAllowlist WITH A REASON and its body hash.\n"+
				"    plan/00-SPINE.md S7: sanitize at ingest, not at prompt time.",
				full, idx.pkg, idx.file[key], detail)
		}
	}

	for key := range allow {
		if !used[key] {
			t.Errorf("wgAllowlist names %q, which this guard does not flag (it no longer exists, "+
				"no longer writes, or now reaches Sanitize). Delete the entry: a stale exemption "+
				"is how the next real one gets waved through.", key)
		}
	}
	if scanned == 0 {
		t.Fatal("the scan indexed no functions at all under " + wgScanRoot +
			"; the guard is inert and would pass anything")
	}
	if len(allSkipped) > 0 {
		t.Logf("SKIPPED (did not parse): %s", strings.Join(allSkipped, ", "))
	}
	t.Logf("writer guard: %d functions scanned, %d bind an advisory write shape (%d reach "+
		"sanitize, %d allowlisted)", scanned, writeSites, sanitized, len(used))
	if writeSites == 0 {
		t.Logf("NO WRITER EXISTS YET. A.3's stop condition — every write path into advisory, " +
			"affected and advisory_fts — is satisfied VACUOUSLY and is carried forward to " +
			"A.7/A.8 unmet. Do not record it as verified.")
	}
}

// wgPackageDirs returns every directory under root that holds Go source,
// sorted. testdata is skipped by convention; so is anything hidden.
func wgPackageDirs(t *testing.T, root string) []string {
	t.Helper()
	seen := map[string]bool{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == "testdata" || (strings.HasPrefix(base, ".") && base != "." && base != "..") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			seen[filepath.Dir(path)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatalf("no Go packages found under %s; the guard has nothing to scan", root)
	}
	return out
}

// ---------------------------------------------------------------------------
// Negative controls — the writers this guard must catch, and the one it must
// not
// ---------------------------------------------------------------------------

// wgLeakProbeSource is the writer someone will actually write: a poller that
// unmarshals a feed, takes the description straight out of the JSON, and binds
// it to UpsertAdvisorySQL. It is the shape A.5 said the stop condition was
// supposed to be about, and it lives here as source text so the guard is
// exercised against it on every run.
//
// wgCleanProbeSource is the same writer done correctly. It is here because a
// guard that flags everything is as useless as one that flags nothing, and a
// control that only proves the first half would not notice.
const wgLeakProbeSource = `package cache

func (w *Writer) UpsertAdvisoryUnsanitized(source, id, description string) error {
	_, err := w.db.Exec(UpsertAdvisorySQL, source, id, description)
	return err
}

func (w *Writer) UpsertViaOwnStatement(source, description string) error {
	_, err := w.db.Exec("INSERT INTO advisory (source, description) VALUES (?, ?)", source, description)
	return err
}

func (w *Writer) UpsertWithADiscardedSanitizeCall(source, description string) error {
	_ = sanitize.Sanitize(description)
	_, err := w.db.Exec(UpsertAdvisorySQL, source, description)
	return err
}

func (w *Writer) UpsertViaAnUnexportedHelper(source, description string) error {
	return w.bind(source, description)
}

func (w *Writer) bind(source, description string) error {
	_, err := w.db.Exec(UpsertAdvisorySQL, source, description)
	return err
}
`

const wgCleanProbeSource = `package cache

func (w *Writer) UpsertAdvisorySanitized(source, id, description string) error {
	clean, _ := sanitize.Ingest(description)
	_, err := w.db.Exec(UpsertAdvisorySQL, source, id, clean.Text)
	return err
}

func (w *Writer) UpsertViaASanitizingHelper(source, description string) error {
	return w.bindClean(source, description)
}

func (w *Writer) bindClean(source, description string) error {
	clean, _ := sanitize.Sanitize(description)
	_, err := w.db.Exec(UpsertAdvisorySQL, source, clean)
	return err
}
`

// TestTheWriterGuardCatchesAWriterThatSkipsSanitize is the control that keeps
// the guard from being a test that cannot fail — which is precisely the defect
// A.5 found in TestCommentPassLimitFailsClosed, and the reason this file
// ships with probes rather than with an empty scan and a green tick.
//
// Four shapes, all of which must be flagged:
//
//	the shared constant bound directly
//	a hand-written INSERT, so the guard does not depend on the constant
//	a Sanitize call whose result is discarded — a call that sanitises nothing
//	the bind moved into an unexported helper, which is the shape that defeats
//	  a scan that only looks at the exported function's own body
func TestTheWriterGuardCatchesAWriterThatSkipsSanitize(t *testing.T) {
	idx, _ := wgParseDir(t, filepath.Join(wgScanRoot, "cache"),
		map[string]string{"zz_writer_leak_probe.go": wgLeakProbeSource})

	for _, key := range []string{
		"Writer.UpsertAdvisoryUnsanitized",
		"Writer.UpsertViaOwnStatement",
		"Writer.UpsertWithADiscardedSanitizeCall",
		"Writer.UpsertViaAnUnexportedHelper",
	} {
		t.Run(key, func(t *testing.T) {
			if idx.decl[key] == nil {
				t.Fatalf("%s is not in the index; the synthetic file was not read", key)
			}
			if _, ok := wgAllowlist()["cache."+key]; ok {
				t.Fatalf("%s is allowlisted, which would let this control pass without the "+
					"analysis doing anything", key)
			}
			switch v, detail := idx.classifyWrite(key); v {
			case wgUnsanitized:
				t.Logf("flagged, correctly: %s (%s)", key, detail)
			case wgSanitized:
				t.Errorf("%s classifies as sanitized: the analysis believes it reaches A.3. It "+
					"does not — it binds a raw string.", key)
			case wgNoWriteSite:
				t.Errorf("%s classifies as no-write-site: the analysis cannot see that it binds "+
					"an advisory write shape. That is the hole a real writer would walk through.", key)
			}
		})
	}
}

// TestTheWriterGuardAcceptsAWriterThatSanitizes is the other half of the
// control. A guard that flagged every writer would be deleted by the first
// author who had done the right thing and been failed for it.
func TestTheWriterGuardAcceptsAWriterThatSanitizes(t *testing.T) {
	idx, _ := wgParseDir(t, filepath.Join(wgScanRoot, "cache"),
		map[string]string{"zz_writer_clean_probe.go": wgCleanProbeSource})

	for _, key := range []string{
		"Writer.UpsertAdvisorySanitized",
		"Writer.UpsertViaASanitizingHelper",
	} {
		t.Run(key, func(t *testing.T) {
			if idx.decl[key] == nil {
				t.Fatalf("%s is not in the index; the synthetic file was not read", key)
			}
			if v, _ := idx.classifyWrite(key); v != wgSanitized {
				t.Errorf("%s classifies as %v, want sanitized; this writer does exactly what the "+
					"guard asks for and must not be failed for it", key, v)
			}
		})
	}
}

// TestTheWriterGuardsAllowlistIsAClaimAboutABody exercises the exemption
// machinery, which the empty allowlist would otherwise leave untested until
// the day someone needed it and found out it did not work.
//
// It runs the SHIPPING check, wgCheckExemption, over a probe body: the right
// hash is accepted, a stale hash is refused with the reason quoted back, and
// an entry with no reason or no hash is refused outright.
func TestTheWriterGuardsAllowlistIsAClaimAboutABody(t *testing.T) {
	idx, _ := wgParseDir(t, filepath.Join(wgScanRoot, "cache"),
		map[string]string{"zz_writer_leak_probe.go": wgLeakProbeSource})
	const key = "Writer.UpsertAdvisoryUnsanitized"

	hash := idx.wgBodyHash(key)
	if hash == "" {
		t.Fatal("the probe body did not hash; the exemption machinery cannot work")
	}
	if err := wgCheckExemption(idx, key, wgExemption{reason: "a probe", body: hash}); err != nil {
		t.Errorf("a matching hash was rejected: %v", err)
	}
	err := wgCheckExemption(idx, key, wgExemption{reason: "written about the OLD body", body: "0000000000000000"})
	if err == nil {
		t.Fatal("a stale body hash was accepted; an exemption would outlive the code it was " +
			"written about, which is how a reason gets inherited by a function nobody re-read")
	}
	if !strings.Contains(err.Error(), "written about the OLD body") || !strings.Contains(err.Error(), hash) {
		t.Errorf("the failure must quote the stale reason and the current hash, got: %v", err)
	}
	if wgCheckExemption(idx, key, wgExemption{reason: "", body: hash}) == nil {
		t.Error("an exemption with no reason was accepted")
	}
	if wgCheckExemption(idx, key, wgExemption{reason: "why", body: ""}) == nil {
		t.Error("an exemption with no body hash was accepted")
	}
	// The hash must be stable across runs and independent of comments and
	// layout, or the first person it annoys will delete it.
	idx2, _ := wgParseDir(t, filepath.Join(wgScanRoot, "cache"),
		map[string]string{"zz_writer_leak_probe.go": wgCommentedProbe(wgLeakProbeSource)})
	if got := idx2.wgBodyHash(key); got != hash {
		t.Errorf("adding a comment changed the body hash (%s -> %s); a hash that expires on a "+
			"doc edit gets deleted rather than updated", hash, got)
	}
}

// wgCommentedProbe re-emits the probe with a comment inside every body, to
// prove the hash is over tokens rather than over text.
func wgCommentedProbe(src string) string {
	return strings.ReplaceAll(src, "{\n\t_,", "{\n\t// a comment that must not change the hash\n\t_,")
}
