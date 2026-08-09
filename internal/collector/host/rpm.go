package host

import "strings"

// rpm.go parses the output of the ONE RPM query this collector can run:
//
//	rpm -qa --qf '%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\n'
//
// (research/12-linux-host-scanning.md §2, "Native queries"; backing store
// /var/lib/rpm/rpmdb.sqlite on RHEL 9+, readable without root — research/12 §6.)
//
// THIS FILE EXECUTES NOTHING. The invocation lives in collect.go's argvRPMList
// constant and is reachable only through runQuery.
//
// RPMDB WRITE SIDE EFFECT — READ THIS BEFORE CALLING THE RPM FAMILY
// READ-ONLY. `rpm -qa` is the one query in this collector that is NOT
// filesystem-read-only on every host Anvil targets. On a Berkeley-DB-backed
// rpmdb — RHEL/CentOS 7 and 8, SLES 12 and 15, Amazon Linux 2, i.e. anything
// whose /var/lib/rpm holds `Packages` rather than `rpmdb.sqlite` — opening the
// database creates and updates /var/lib/rpm/__db.001..__db.003 when the caller
// can write that directory, which in practice means when it runs as root. rpm
// offers no flag that suppresses this, and this package will not branch on the
// effective uid to avoid it. collect.go's package comment carries the full
// statement, its limits, and the deployment-layer mitigation that is the only
// place the behaviour can actually be prevented.
//
// Unlike dpkg-query, `rpm` DOES have mutating modes — `-i`/`--install`,
// `-U`/`--upgrade`, `-F`/`--freshen`, `-e`/`--erase`. That is precisely why
// the argv is a compile-time constant and why collect_test.go's verb guard
// walks every string literal in this package looking for them.

// rpmFieldCount is the number of tab-separated fields rpmFormat produces.
const rpmFieldCount = 3

// rpmNone is what rpm prints for a tag the package does not carry.
const rpmNone = "(none)"

// parseRPM turns rpm -qa output into packages.
func parseRPM(out []byte) ([]Package, parseReport) {
	var pkgs []Package
	var rep parseReport

	for _, line := range splitLines(out) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rep.Lines++
		fields := strings.Split(line, "\t")
		if len(fields) != rpmFieldCount {
			rep.Skipped++
			rep.Degraded = true
			continue
		}
		name := strings.TrimSpace(fields[0])
		version := normaliseRPMVersion(strings.TrimSpace(fields[1]))
		arch := strings.TrimSpace(fields[2])
		if arch == rpmNone {
			// gpg-pubkey pseudo-packages carry no architecture. The row is
			// kept — dropping rows is how an inventory quietly stops
			// describing the host — and the empty arch says why.
			arch = ""
		}
		if name == "" || version == "" {
			rep.Skipped++
			rep.Degraded = true
			continue
		}
		pkgs = append(pkgs, Package{
			Ecosystem: EcosystemRPM,
			Name:      name,
			Version:   version,
			Arch:      arch,
		})
	}
	return pkgs, rep
}

// normaliseRPMVersion turns rpm's EPOCH:VERSION-RELEASE into the EVR string a
// comparator expects.
//
// The ONLY transformation applied is dropping the literal "(none):" prefix rpm
// prints for a package with no epoch. Nothing else is rewritten: RPM version
// comparison is rpmvercmp's, it is not lexical, and its subtleties (tilde,
// caret, alphanumeric segmentation) belong to A.17's comparator. A collector
// that "tidies" a version has already decided the comparison, and decided it
// wrong for the packages where it matters — which are exactly the backported
// ones this project's CVE-2023-32681/RHSA-2023:4520 regression fixture is
// about.
//
// A missing epoch is NOT rewritten to "0:" either. Absent and zero are treated
// as equal by rpmvercmp, so the substitution would be safe but pointless, and
// preserving what the host said keeps the inventory a record rather than an
// interpretation.
func normaliseRPMVersion(evr string) string {
	if trimmed, ok := strings.CutPrefix(evr, rpmNone+":"); ok {
		return trimmed
	}
	return evr
}
