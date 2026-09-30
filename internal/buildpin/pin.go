// Package buildpin holds Phase 0 dependency pins alive in the module graph
// until the packages that actually use them exist.
//
// The spine's Go control-plane decision mandates modernc.org/sqlite, and
// plan/design/spine-language.md's source table pins it at v1.56.0. plan/design/first-plan.md
// Phase 0 requires that dependency be added at bootstrap. But nothing imports
// it yet -- neither the store schema nor the migration runner's FTS5 startup guard existed --
// and `go mod tidy` removes a module that no package in the module imports.
// Without this file, CI's tidy check would silently delete the pin the
// bootstrap was supposed to establish.
//
// DELETE THIS PACKAGE when internal/store lands. It has no runtime
// purpose and must never be imported by anything other than itself.
package buildpin

import (
	// modernc.org/sqlite: the cgo-free SQLite driver the spine's Go
	// control-plane decision mandates. Do NOT substitute mattn/go-sqlite3 -- it
	// needs cgo and a C toolchain, which breaks the single static binary and
	// the cross-compilation matrix. Verified at bootstrap against this exact
	// version: SQLite 3.53.3, FTS5 virtual tables and MATCH queries both work.
	// Licence read as a file body per the spine's licence section:
	// BSD-3-Clause.
	_ "modernc.org/sqlite"
)
