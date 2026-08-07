// Command anvil is the Anvil core binary.
//
// Anvil finds vulnerabilities in Linux servers and code repositories and
// proposes fixes. This binary is the core artifact: Lane A (deterministic
// SBOM/host package matching), Lane B (first-party source detection), the
// record, the store, and remediation.
//
// This binary has NO network-probing capability compiled in. The dynamic
// (DAST) tier ships as a separate artifact, cmd/anvil-dast, which must be
// separately installed and separately attested. That split is required by
// plan/00-SPINE.md S9-AMENDED and is enforced mechanically by TestSplit in
// split_test.go, which fails the build if any internal/dast package becomes
// reachable from this binary's import graph.
//
// Bootstrap placeholder. The real entrypoint — the anvil scan and
// anvil daemon --loop subcommands wired to internal/scanctl and
// internal/queue — is owned by plan step O.16.
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
	fmt.Fprintf(os.Stderr, "anvil %s: bootstrap placeholder, no subcommands yet (see plan step O.16)\n", version)
	os.Exit(2)
}
