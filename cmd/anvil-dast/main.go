// anvil-dast ships as a SEPARATE distribution artifact from the core anvil binary,
// requires separate installation, and refuses to probe anything without an
// explicit attestation. See the two-artifact split for why this is a
// separate artifact rather than a configuration flag: a boolean inside a
// single shipped binary still supplies the probing capability to everyone who
// installs it.
//
// Nothing in this binary may be imported by cmd/anvil. TestSplit in
// ../anvil/split_test.go enforces that mechanically.
//
// Bootstrap placeholder. The general entrypoint arrives with the live dynamic
// tier (plan node live); every request it makes routes through internal/dast/authz.

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
	// The first real subcommand: the supply-chain pinning job
	// for the nuclei-templates corpus (pin-templates.go). It is here rather
	// than under cmd/anvil because it links internal/dast/engines to reuse
	// the nuclei driver's template loader, and the two-artifact split forbids that in the core
	// binary. TestSplit in ../anvil/split_test.go is what keeps that true.
	if len(os.Args) > 1 && os.Args[1] == "pin-templates" {
		os.Exit(dispatchPinTemplates(os.Args[2:], os.Stdout, os.Stderr))
	}
	fmt.Fprintf(os.Stderr, "anvil-dast %s: the only wired subcommand is `pin-templates`; "+
		"the general entrypoint is not built yet\n", version)
	os.Exit(2)
}
