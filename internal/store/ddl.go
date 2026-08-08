// Package store owns Anvil's single SQLite store of record.
//
// plan/00-SPINE.md S1 collapsed the originally-specified "8-hour buffer file"
// into one SQLite database, a `handoff` table, and a regenerable tmpfs packet
// that is never a source of truth. This package holds the DDL for that
// database. plan/IMPLEMENTATION-PLAN.md §6 rulings G9 and G10 make schema.sql
// the ONLY definition of the `handoff` table anywhere in Anvil: area 70's O.3
// migration and area 60's rival `anvil_ledger` are both folded into it.
//
// This file is a thin, dependency-free wrapper. It embeds the DDL, exposes the
// connection pragmas the DDL deliberately does not contain, and offers just
// enough read-only introspection for R.5's migration ledger and for the test
// that proves the SQL vocabularies and internal/record's Go enums have not
// drifted apart. It opens no database and executes no statement.
package store

import (
	"crypto/sha256"
	_ "embed" // for the //go:embed directive on schemaSQL
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

//go:embed schema.sql
var schemaSQL string

// MaxDurableTextBytes is the byte cap enforced by schema.sql's
// finding_occurrence triggers on `message` and `evidence_ref`.
//
// research/07 Risk #13: if a raw snippet or a DAST request/response body is
// copied into a durable text column it outlives the payload purge forever, and
// those are exactly the fields most likely to carry a secret. The cap is far
// below internal/record's smallest inline body cap (8 KiB) so that no body can
// be smuggled into a durable column even at its minimum size, and ample for a
// rule title plus a pointer into the sealed payload.
//
// Changing this constant alone does nothing: the value is enforced by SQL.
// ddl_test.go asserts the trigger and this constant agree.
const MaxDurableTextBytes = 2048

// Schema returns the complete DDL for schema version 1, exactly as committed
// in schema.sql.
//
// It contains no PRAGMA statement, by design. `PRAGMA journal_mode = WAL`
// cannot run inside a transaction and R.5 applies this DDL inside
// BEGIN...COMMIT. Use ConnectionPragmas for the settings that must be applied
// per connection instead.
func Schema() string { return schemaSQL }

// SchemaSHA256 returns the lowercase hex SHA-256 of the embedded DDL, over its
// exact committed bytes with no normalisation. R.5's migration ledger records
// a checksum; this is the value for the initial migration, and it changes if
// so much as a comment in schema.sql changes, which is the intended
// sensitivity for a frozen interface.
func SchemaSHA256() string {
	sum := sha256.Sum256([]byte(schemaSQL))
	return hex.EncodeToString(sum[:])
}

// ConnectionPragmas returns the pragmas from plan/40-record-and-storage.md's
// Store Schema section, in the order they must be applied.
//
// Every one of these is per connection, not per database file, so they must be
// re-applied on every connection the pool opens — `foreign_keys` above all,
// which SQLite leaves OFF by default and which this schema depends on. R.5
// applies them before any other store operation, after its network-mount and
// FTS5 guards.
//
// The `synchronous = NORMAL` value resolves a research conflict on purpose:
// research/07 recommends NORMAL as the documented standard WAL pairing, while
// research/08 recommends FULL without any WAL-specific justification. NORMAL
// with WAL is crash-safe for the database file; the risk it accepts is losing
// the most recent commits on power loss, not corruption.
func ConnectionPragmas() []string {
	return []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 10000",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA wal_autocheckpoint = 1000",
	}
}

var tableRE = regexp.MustCompile(`(?m)^CREATE\s+(?:VIRTUAL\s+)?TABLE\s+([A-Za-z_][A-Za-z0-9_]*)`)

// Tables returns every table name schema.sql creates, ordinary and virtual
// alike, in file order. It is a parse of the committed DDL, not a hand-kept
// list, so a table added to schema.sql without a corresponding smoke-test
// insert fails ddl_test.go rather than going unexercised.
func Tables() []string {
	matches := tableRE.FindAllStringSubmatch(schemaSQL, -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	return names
}

// CheckConstraint returns the text of the named CHECK constraint's expression,
// without the enclosing parentheses.
//
// Every CHECK in schema.sql is named. research/07 Risk #15 records that
// batch-recreate tooling silently drops UNNAMED check constraints, which on a
// security tool's schema is an integrity regression with no error message;
// naming them is that risk's mitigation, and it also makes the constraints
// addressable from a test.
func CheckConstraint(name string) (string, error) {
	anchor := regexp.MustCompile(`CONSTRAINT\s+` + regexp.QuoteMeta(name) + `\s+CHECK\s*\(`)
	loc := anchor.FindStringIndex(schemaSQL)
	if loc == nil {
		return "", fmt.Errorf("store: no CHECK constraint named %q in schema.sql", name)
	}
	// loc[1] is the index just past the opening parenthesis. Scan forward to
	// its match, tracking nesting and single-quoted literals so that a
	// parenthesis inside a string literal cannot end the scan early.
	depth := 1
	inLiteral := false
	for i := loc[1]; i < len(schemaSQL); i++ {
		switch c := schemaSQL[i]; {
		case c == '\'':
			// Doubled '' inside a literal is an escaped quote; toggling twice
			// leaves the state correct, so no special case is needed.
			inLiteral = !inLiteral
		case inLiteral:
			// Parentheses inside a literal are data, not structure.
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return schemaSQL[loc[1]:i], nil
			}
		}
	}
	return "", fmt.Errorf("store: CHECK constraint %q has an unbalanced expression in schema.sql", name)
}

var literalRE = regexp.MustCompile(`'((?:[^']|'')*)'`)

// EnumCheckValues returns the SQL string literals of the named CHECK
// constraint, in the order they appear.
//
// This exists because of a real constraint on how the vocabulary is written
// down. plan/IMPLEMENTATION-PLAN.md §6 freezes the enums in
// internal/record/contract.go and forbids any second declaration; but a SQL
// CHECK constraint cannot reference a Go constant, and templating the DDL at
// run time would mean schema.sql was no longer a file that applies to an empty
// database on its own — which its own stop condition requires. So the literals
// are written once more, here, and ddl_test.go asserts set equality with
// internal/record's values for every one of them. A drift is a failed test,
// not an integration surprise in Phase 5.
func EnumCheckValues(name string) ([]string, error) {
	expr, err := CheckConstraint(name)
	if err != nil {
		return nil, err
	}
	matches := literalRE.FindAllStringSubmatch(expr, -1)
	values := make([]string, 0, len(matches))
	for _, m := range matches {
		values = append(values, strings.ReplaceAll(m[1], "''", "'"))
	}
	return values, nil
}
