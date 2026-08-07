// Command anvil-dast is the Anvil dynamic-analysis (DAST) binary.
//
// It ships as a SEPARATE distribution artifact from the core anvil binary,
// requires separate installation, and refuses to probe anything without an
// explicit attestation. See plan/00-SPINE.md S9-AMENDED for why this is a
// separate artifact rather than a configuration flag: a boolean inside a
// single shipped binary still supplies the probing capability to everyone who
// installs it.
//
// Nothing in this binary may be imported by cmd/anvil. TestSplit in
// ../anvil/split_test.go enforces that mechanically.
//
// Bootstrap placeholder. The real entrypoint is owned by plan step O.16; the
// authorization kernel it must route every request through is D.2-D.9.
package main

import (
	"fmt"
	"os"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "0.0.0-bootstrap"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println(version)
		return
	}
	fmt.Fprintf(os.Stderr, "anvil-dast %s: bootstrap placeholder, no subcommands yet (see plan step O.16)\n", version)
	os.Exit(2)
}
