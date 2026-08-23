//go:build !race

// This file is EXCLUDED FROM THE -race LANE, and the exclusion is the whole
// reason it is its own file rather than a function in phase1_run_test.go.
//
// The test below is the concurrent-writer harness that
// CheckGate4ScopeFile's doc comment promises. It works by racing a writer
// against the caller's buffer, which means THE HARNESS IS ITSELF A DATA RACE —
// deliberately, because that is the only shape in which the defect it guards
// is observable at all. A concurrent write is the only thing that can make one
// read of the buffer differ from another, so there is no race-free program
// that can tell a build that reads the buffer once from a build that reads it
// twice.
//
// Measured, by deleting the build tag above on the SHIPPED, CORRECT tree and
// running `go test -race -count=1 -run TestScopeBytesAreReadOnce...`:
//
//	WARNING: DATA RACE
//	Write at 0x00c00020c000 by goroutine 10:
//	  runtime.slicecopy()
//	  ...authz.TestScopeBytesAreReadOnceUnderAConcurrentWriter.func1()
//	      .../phase1_scopebytes_race_test.go:120
//
//	Previous read at 0x00c00020c000 by goroutine 9:
//	  runtime.slicecopy()
//	  ...authz.CheckGate4ScopeFile()
//	      .../phase1_run.go:559
//	  ...authz.NewScope()
//	      .../types.go:859
//
// phase1_run.go:559 is `raw = append([]byte(nil), raw...)` — THE FIX ITSELF.
// The harness is red under -race whether or not the defect is present, so as a
// -race test it measures nothing and fails a correct build.
//
// So it runs in the ordinary `go test ./...` lane, where it is a real control
// with real numbers, and TestGate4ReadsTheCallersScopeBytesExactlyOnce — a
// source-level assertion, no goroutines — is what runs in every lane. The
// exclusion is recorded in internal/SKIPPED-CONTROLS.md as G4-1 rather than
// hidden behind a t.Skip.
//
// ===========================================================================
// BEFORE YOU REPORT ANYTHING ABOUT THE RACE DETECTOR ON THIS HOST: WHICH SHELL
// ===========================================================================
//
// `go test -race` WORKS FROM POWERSHELL AND FAILS FROM GIT BASH on this
// machine, uniformly across every package. The Git Bash failure is:
//
//	==25268==ERROR: ThreadSanitizer failed to allocate 0x000004aa0000
//	(78249984) bytes at 0x100eff42d0000 (error code: 87)
//	FAIL	github.com/Susquehanna-Syntax/Anvil/internal/dast/authz	1.031s
//
// Error code 87 is Windows ERROR_INVALID_PARAMETER out of a reservation at a
// fixed high address. It is an ADDRESS-SPACE problem in the Git Bash
// environment. IT IS NOT A DATA RACE, IT IS NOT A BROKEN TREE, AND IT IS NOT
// THIS FILE'S BUILD TAG — the tag excludes one test, and this failure hits
// every package including ones with no goroutines at all.
//
// Measured from PowerShell on 2026-08-22, `go test -race -count=1 ./...`:
// 25 packages ok, 0 data races, 0 ThreadSanitizer errors. (The two failures in
// that run were an unrelated gate-3 egress finding and a build failure, both
// in internal/dast/containment, and neither mentions a race.)
//
// This disagreement has now cost two review rounds: a worker reported that
// -race "cannot build on this machine", a critic called that false, and both
// were right about their own shell. So: RUN IT FROM POWERSHELL, and whatever
// you report about the race detector, SAY WHICH SHELL PRODUCED IT.

package authz

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// p1RaceDocs builds two scope documents of EQUAL LENGTH that differ in exactly
// one host, so that a writer alternating between them can tear a read without
// changing the document's size.
//
// A thousand entries is not decoration: the strict decode has to take long
// enough that a write can land inside it. At one entry the parse is fast enough
// that the interleaving is rare, and a control that rarely fires is a control
// that will be believed and is empty.
func p1RaceDocs(tb testing.TB) (benign, evil []byte) {
	tb.Helper()
	mk := func(head string) []byte {
		parts := make([]string, 0, 1000)
		parts = append(parts, fmt.Sprintf(`{"host":%q,"ports":[443]}`, head))
		for i := 1; i < 1000; i++ {
			parts = append(parts, fmt.Sprintf(`{"host":"h%04d.example.com","ports":[443]}`, i))
		}
		return []byte(`{"schema_version":1,"mode":"external","allow":[` +
			strings.Join(parts, ",") + `],"deny":[]}`)
	}
	benign = mk("benign00.example.com")
	evil = mk("evilzone.example.com")
	if len(benign) != len(evil) {
		tb.Fatalf("the two documents are %d and %d bytes; they must be the same length "+
			"or the fixture is not the one the attack used", len(benign), len(evil))
	}
	return benign, evil
}

// TestScopeBytesAreReadOnceUnderAConcurrentWriter is the behavioural
// regression for gate 4's one-read property, and it is the test
// CheckGate4ScopeFile's doc comment names.
//
// # What it asserts
//
// A Scope's ENTRIES and its HASH must come from ONE DOCUMENT. Gate 5 binds an
// attestation to the scope hash so that editing the scope file invalidates it
// (research/20 gate 5); a Scope carrying one document's entries under another
// document's hash defeats that binding exactly, and it does so silently.
//
// # What it measures
//
// A goroutine rewrites the caller's buffer between two same-length documents
// while this one calls NewScope in a loop. Every constructed Scope is checked:
// whichever document's entries it carries, its hash must be that document's
// hash.
//
//	shipped tree                                     0 of 200 mismatched
//	copy deleted                                    89 of 200 mismatched
//	copy replaced by `rawAlias := raw[:]`          102 of 200 mismatched
//
// The last of those three is the mutation that defeated the SOURCE-LEVEL pin
// while it was a denylist of spellings; this harness caught it either way,
// which is why it is worth having as well as the pin.
//
// # Why it cannot fail vacuously
//
// If the writer never interleaves, every Scope is the benign document and the
// mismatch count is zero for a reason that has nothing to do with the fix. So
// the test also requires that BOTH documents were actually observed coming out
// of NewScope. A run in which only one was seen fails rather than passes.
func TestScopeBytesAreReadOnceUnderAConcurrentWriter(t *testing.T) {
	benign, evil := p1RaceDocs(t)
	decl := p1Decl(t, ModeExternal)
	benignHash := ScopeHashOf(benign)
	evilHash := ScopeHashOf(evil)

	buf := append([]byte(nil), benign...)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			copy(buf, evil)
			copy(buf, benign)
		}
	}()

	const rounds = 200
	var built, sawBenign, sawEvil, mismatched, torn int
	for i := 0; i < rounds; i++ {
		s, err := NewScope(buf, decl)
		if err != nil {
			// A torn document that no longer parses is a legitimate outcome
			// and is not the defect: gate 4 refuses it, which is zero
			// permitted targets rather than a wrong Scope.
			torn++
			continue
		}
		built++
		isBenign := s.Permits("benign00.example.com", 443)
		isEvil := s.Permits("evilzone.example.com", 443)
		switch {
		case isBenign && !isEvil:
			sawBenign++
			if s.Hash() != benignHash {
				mismatched++
			}
		case isEvil && !isBenign:
			sawEvil++
			if s.Hash() != evilHash {
				mismatched++
			}
		default:
			// Entry zero came out as neither host, which means the write
			// landed inside that entry. The hash cannot be either document's,
			// and there is nothing to compare it to.
			torn++
		}
	}
	close(stop)
	wg.Wait()

	if mismatched != 0 {
		t.Fatalf("%d of %d constructed Scopes carried one document's ENTRIES under the "+
			"other document's HASH.\n\n"+
			"Gate 5 binds the attestation to the scope hash so that editing the scope "+
			"file invalidates it. That is only true while the hash is a hash of the "+
			"entries. A Scope built by reading the caller's buffer more than once can "+
			"have a write land between the reads, and this is what that looks like.\n"+
			"(benign=%d evil=%d torn=%d)",
			mismatched, built, sawBenign, sawEvil, torn)
	}
	if sawBenign == 0 || sawEvil == 0 {
		t.Fatalf("the writer never interleaved: benign=%d evil=%d torn=%d of %d rounds. "+
			"With only one document ever observed the mismatch count above is zero "+
			"for a reason that has nothing to do with gate 4, so this control "+
			"measured nothing and fails rather than passing vacuously.",
			sawBenign, sawEvil, torn, rounds)
	}
	t.Logf("entries and hash agreed on all %d constructed Scopes "+
		"(benign=%d evil=%d torn=%d)", built, sawBenign, sawEvil, torn)
}
