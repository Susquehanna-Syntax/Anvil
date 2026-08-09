package host

import "strings"

// apk.go parses the output of the TWO Alpine queries this collector can run:
//
//	apk list --installed     (preferred: reports the architecture)
//	apk info -v              (fallback for apk builds predating `apk list`)
//
// (research/12-linux-host-scanning.md §2, "Native queries"; backing store
// /lib/apk/db/installed, readable without root — research/12 §6.)
//
// THIS FILE EXECUTES NOTHING. The invocations live in collect.go's argvAPKList
// and argvAPKInfo constants and are reachable only through runQuery.
//
// `apk` has mutating modes — `add`, `del`, `upgrade`, `fix`. Neither constant
// names one. Note also that `--installed` is a FILTER on the `list` verb and
// is not the verb `install`: collect_test.go's guard compares whole tokens
// (after stripping leading dashes) for exactly this reason, and it carries a
// case asserting that `--installed` passes while `install`, `--install`,
// `add` and `-y` do not.

// parseAPKList parses `apk list --installed`. Each line looks like:
//
//	musl-1.2.5-r0 x86_64 {musl} (MIT) [installed]
//
// Field 0 is name-version-revision and field 1 is the architecture. The
// remaining fields — origin package, licence, install state — are not carried:
// an inventory is not a place to accumulate unbounded host-controlled text,
// and the licence string in particular is NOT a licence determination (spine
// S8 requires reading LICENSE file bodies, never metadata).
func parseAPKList(out []byte) ([]Package, parseReport) {
	var pkgs []Package
	var rep parseReport

	for _, line := range splitLines(out) {
		line = strings.TrimSpace(line)
		if line == "" || isAPKNoise(line) {
			continue
		}
		rep.Lines++
		fields := strings.Fields(line)
		if len(fields) == 0 {
			rep.Skipped++
			rep.Degraded = true
			continue
		}
		name, version, ok := splitAPKNameVersion(fields[0])
		if !ok {
			rep.Skipped++
			rep.Degraded = true
			continue
		}
		arch := ""
		if len(fields) > 1 && isAPKArchField(fields[1]) {
			arch = fields[1]
		}
		pkgs = append(pkgs, Package{
			Ecosystem: EcosystemAPK,
			Name:      name,
			Version:   version,
			Arch:      arch,
		})
	}
	return pkgs, rep
}

// parseAPKInfo parses `apk info -v`, one `name-version-revision` per line.
// It reports no architecture, which is why argvAPKList is preferred and this
// is the fallback; Package.Arch is left empty rather than guessed.
func parseAPKInfo(out []byte) ([]Package, parseReport) {
	var pkgs []Package
	var rep parseReport

	for _, line := range splitLines(out) {
		line = strings.TrimSpace(line)
		if line == "" || isAPKNoise(line) {
			continue
		}
		rep.Lines++
		name, version, ok := splitAPKNameVersion(line)
		if !ok {
			rep.Skipped++
			rep.Degraded = true
			continue
		}
		pkgs = append(pkgs, Package{
			Ecosystem: EcosystemAPK,
			Name:      name,
			Version:   version,
		})
	}
	return pkgs, rep
}

// isAPKNoise recognises the diagnostic lines apk emits alongside its output.
// They are ignored rather than counted as skipped rows, because they are not
// rows.
func isAPKNoise(line string) bool {
	return strings.HasPrefix(line, "WARNING:") || strings.HasPrefix(line, "ERROR:")
}

// isAPKArchField reports whether a field looks like an architecture rather
// than one of `apk list`'s bracketed annotations ({origin}, (licence),
// [installed]).
func isAPKArchField(f string) bool {
	if f == "" {
		return false
	}
	switch f[0] {
	case '{', '(', '[':
		return false
	}
	return true
}

// splitAPKNameVersion splits apk's `name-version-revision` into name and
// `version-revision`.
//
// apk's own format is `$name-$pkgver-r$pkgrel`, and a package NAME may contain
// hyphens (`ca-certificates-bundle`) while `$pkgver` may not. So the split is
// anchored on the revision: the final hyphen-separated token must match
// `r<digits>`, and the token before it is the version. That is a rule about
// the format rather than a heuristic about the data, and it is why a name with
// four hyphens parses correctly.
//
// The fallback — no `r<digits>` tail — splits at the last hyphen whose
// successor begins with a digit. It exists so an unexpected line degrades to a
// plausible parse instead of vanishing, and when even that fails the caller
// counts the line as skipped rather than dropping it silently.
func splitAPKNameVersion(s string) (name, version string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	if cut := strings.LastIndexByte(s, '-'); cut > 0 {
		rev := s[cut+1:]
		if isAPKRevision(rev) {
			head := s[:cut]
			if vcut := strings.LastIndexByte(head, '-'); vcut > 0 {
				return head[:vcut], head[vcut+1:] + "-" + rev, true
			}
		}
	}
	// Fallback: last hyphen introducing a digit.
	for i := len(s) - 1; i > 0; i-- {
		if s[i] != '-' || i+1 >= len(s) {
			continue
		}
		if s[i+1] >= '0' && s[i+1] <= '9' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

// isAPKRevision reports whether tok is apk's `r<digits>` package-release
// suffix.
func isAPKRevision(tok string) bool {
	if len(tok) < 2 || tok[0] != 'r' {
		return false
	}
	for i := 1; i < len(tok); i++ {
		if tok[i] < '0' || tok[i] > '9' {
			return false
		}
	}
	return true
}
