package host

import "strings"

// dpkg.go parses the output of the ONE Debian query this collector can run:
//
//	dpkg-query -W -f '${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n'
//
// (research/12-linux-host-scanning.md §2, "Native queries"; backing store
// /var/lib/dpkg/status, world-readable, so no root — research/12 §6.)
//
// THIS FILE EXECUTES NOTHING. It does not import os/exec, it takes bytes and
// returns values, and collect_test.go fails if that ever stops being true.
// The invocation lives in collect.go's argvDpkgList constant and is reachable
// only through runQuery.
//
// A note on which binary: this is `dpkg-query`, not `dpkg`. dpkg-query is a
// pure query tool with no mutating mode at all — there is no `dpkg-query -i`
// to be one typo away from `dpkg -i`. That is a property of the tool, not of
// this code, and it is why the Debian family is the least dangerous of the
// three.

// dpkgFieldCount is the number of tab-separated fields dpkgFormat produces.
const dpkgFieldCount = 4

// parseDpkg turns dpkg-query output into packages.
//
// Rows whose `db:Status-Abbrev` says the package is not currently installed
// are EXCLUDED and counted. This is not cosmetic: `rc` means "removed, config
// files remain", and dpkg keeps the old version string on such a row. Feeding
// those to a version comparator manufactures findings about software that is
// not on the host — the exact false-positive class Lane A exists to avoid, and
// one that would be blamed on the advisory feed rather than on the collector.
func parseDpkg(out []byte) ([]Package, parseReport) {
	var pkgs []Package
	var rep parseReport

	for _, line := range splitLines(out) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rep.Lines++
		fields := strings.Split(line, "\t")
		if len(fields) != dpkgFieldCount {
			rep.Skipped++
			rep.Degraded = true
			continue
		}
		name, version, arch, status := fields[0], fields[1], fields[2], fields[3]

		installed, known := dpkgStatusInstalled(status)
		if !known {
			rep.Skipped++
			rep.Degraded = true
			continue
		}
		if !installed {
			rep.NotInstalled++
			continue
		}

		name = strings.TrimSpace(name)
		version = strings.TrimSpace(version)
		arch = strings.TrimSpace(arch)
		name = stripMultiarchQualifier(name, arch)
		if name == "" || version == "" {
			rep.Skipped++
			rep.Degraded = true
			continue
		}
		pkgs = append(pkgs, Package{
			Ecosystem: EcosystemDeb,
			Name:      name,
			Version:   version,
			Arch:      arch,
		})
	}
	return pkgs, rep
}

// dpkgStatusInstalled reads ${db:Status-Abbrev}, dpkg's three-character
// want/status/error abbreviation (for example "ii ", "rc ", "iU "). The
// SECOND character is the current status, and only 'i' means installed.
//
// It returns (installed, known); a value too short to carry a status is
// reported as unknown so the caller counts it as degraded rather than
// guessing.
func dpkgStatusInstalled(status string) (installed bool, known bool) {
	if len(status) < 2 {
		return false, false
	}
	switch status[1] {
	case 'i':
		// installed
		return true, true
	case 'n', 'c', 'H', 'U', 'F', 'W', 't':
		// not-installed, config-files, half-installed, unpacked,
		// half-configured, triggers-awaited, triggers-pending. None of these
		// is "this version's files are in place and usable".
		return false, true
	}
	return false, false
}

// stripMultiarchQualifier moves Debian's multi-arch `:arch` suffix off the
// package name, because ${binary:Package} renders `libc6:amd64` for a
// non-native-arch package while every advisory feed calls it `libc6`.
//
// Only the qualifier matching the row's own Architecture is removed. A package
// legitimately containing a colon keeps it, and a mismatched qualifier is left
// alone rather than guessed at.
func stripMultiarchQualifier(name, arch string) string {
	if arch == "" {
		return name
	}
	if trimmed, ok := strings.CutSuffix(name, ":"+arch); ok && trimmed != "" {
		return trimmed
	}
	return name
}
