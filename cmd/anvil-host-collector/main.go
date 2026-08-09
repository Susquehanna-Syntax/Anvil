// Command anvil-host-collector runs Anvil's read-only host package collector
// once, writes the resulting inventory to stdout as JSON, and exits.
//
// # Why this main package exists
//
// deploy/systemd/anvil-host-collector.service has always declared
// `ExecStart=/usr/lib/anvil/anvil-host-collector`. A.12's review found that no
// such main package existed anywhere in the repository, which made the unit
// non-installable: `systemctl start anvil-host-collector` could only ever fail
// with status=203/EXEC. A unit that cannot start is worse than no unit at all,
// because a reader takes its presence as evidence of a deployment. It also
// meant A.9's stop condition — "collector runs to completion and exits under a
// non-root UID on at least one fixture per family" — could not be demonstrated
// as an artifact question: there was nothing to run.
//
// The two honest resolutions were to ship the binary or to delete the unit's
// ExecStart and say the unit is not installable by design. Deleting it removes
// the SECOND enforcement layer that the whole read-only argument leans on —
// ProtectSystem=strict and DynamicUser=yes are the only place the rpmdb write
// side effect documented in internal/collector/host can actually be prevented
// — so the binary is shipped and the unit stays real.
//
// # What it is allowed to be
//
// Everything plan/00-SPINE.md S7 says about the collector is said again here,
// because moving the deployment boundary into cmd/ would otherwise move the
// mutation with it:
//
//   - IT TAKES NO ARGUMENTS. Not "no arguments today": passing any argument is
//     an error, `flag` is not imported, and internal/collector/host's own test
//     suite fails if this package imports it. S7's "not behind a flag" is a
//     statement about what may exist, and a command-line flag on the binary is
//     the same flag as a field on Options.
//   - IT SPAWNS NOTHING. It does not import os/exec or syscall. The single
//     process this product starts is runQuery's.
//   - IT WRITES NO FILE. The inventory goes to stdout, which under the unit is
//     the journal. Publication is a separate concern with its own process
//     (research/12 hard boundary #2), and a collector that drops a file on a
//     customer's server has mutated that server.
//   - IT IS NOT A DAEMON. It collects once and returns. The cadence belongs to
//     a .timer or to plan/00-SPINE.md S4's trigger policy, never to a loop in
//     here (Lane A exit criterion 14).
//
// internal/collector/host/collect_test.go's
// TestTheCollectorBinaryIsSubjectToTheSameGuards runs this package's source
// through the same spawn, filesystem-write, mutating-verb, shell, daemon and
// unresolvable-identity analysers as the collector package itself.
//
// # Deployment
//
// Build and install to the path the unit names:
//
//	go build -trimpath -o /usr/lib/anvil/anvil-host-collector ./cmd/anvil-host-collector
//	systemctl start anvil-host-collector.service
//
// RUN IT UNDER THE SHIPPED UNIT, OR REPRODUCE WHAT THE UNIT DOES. Running this
// binary as root outside the unit re-opens the rpmdb write side effect
// documented in internal/collector/host's package comment: on a
// Berkeley-DB-backed rpmdb, `rpm -qa` creates /var/lib/rpm/__db.001..003 when
// the caller can write that directory. The binary cannot prevent that — no rpm
// flag suppresses it, and branching on the effective uid is forbidden — so the
// non-root, read-only-filesystem confinement is the mitigation, and it lives
// in the unit.
//
// # Exit status
//
//	0  an inventory was collected and written to stdout
//	1  the collection failed; nothing usable was produced
//	2  the binary was given an argument, which it does not accept
//	3  no supported package manager was found. The inventory IS still written,
//	   carrying the per-family coverage report: Lane A exit criterion 20's rule
//	   is that a run never reports a silent "clean", and "we could not look" has
//	   to be distinguishable from "there is nothing here" by a caller reading
//	   the exit status alone.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Susquehanna-Syntax/Anvil/internal/collector/host"
)

// Exit statuses, documented in the package comment above.
const (
	exitCollected        = 0
	exitFailed           = 1
	exitUsage            = 2
	exitNoPackageManager = 3
)

// usage is the whole of this binary's command-line interface.
const usage = `anvil-host-collector: Anvil's read-only host package collector.

It takes NO arguments. It enumerates the packages this host has, writes the
inventory to stdout as JSON, and exits. There is no mode, no target and no
option, deliberately: plan/00-SPINE.md S7 makes the host agent read-only and
says so about what may EXIST, not about what is on by default.`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main's body with its edges as parameters, so the argument refusal and
// the exit statuses are testable without a process.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stderr, "%s\n\nrefusing the argument(s) %q\n", usage, args)
		return exitUsage
	}

	inv, err := host.Collect(context.Background(), host.Options{})
	if inv == nil {
		fmt.Fprintf(stderr, "anvil-host-collector: %v\n", err)
		return exitFailed
	}

	// The inventory is written FIRST and in every non-fatal case, including
	// the no-package-manager one. Its coverage report is what tells a reader
	// which families were looked at, and withholding it on the strength of an
	// error is how "we could not look" becomes indistinguishable from "clean".
	enc := json.NewEncoder(stdout)
	if encErr := enc.Encode(inv); encErr != nil {
		fmt.Fprintf(stderr, "anvil-host-collector: writing the inventory: %v\n", encErr)
		return exitFailed
	}

	switch {
	case err == nil:
		return exitCollected
	case errors.Is(err, host.ErrNoPackageManager):
		fmt.Fprintf(stderr, "anvil-host-collector: %v (the inventory above carries the coverage report)\n", err)
		return exitNoPackageManager
	default:
		fmt.Fprintf(stderr, "anvil-host-collector: %v\n", err)
		return exitFailed
	}
}
