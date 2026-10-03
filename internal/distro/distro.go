package distro

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// The comparator's scheme names. They are spelled here rather than imported
// from internal/match because this package is a leaf every side can import;
// TestSchemesAreTheComparators pins them to match's constants.
const (
	SchemeDeb = "deb"
	SchemeRPM = "rpm"
	SchemeAPK = "apk"
)

// release is one supported operating-system family: its os-release ID, the
// purl namespace its packages use, the comparator scheme, and how its
// VERSION_ID is cut down to the granularity its advisories are published at.
type release struct {
	osID      string
	namespace string
	scheme    string
	// cut keeps the leading `parts` dot-separated components of VERSION_ID:
	// 1 for Debian and the RHEL family (12, 9), 2 for Ubuntu and Alpine
	// (22.04, 3.19).
	parts int
}

var releases = []release{
	{osID: "debian", namespace: "debian", scheme: SchemeDeb, parts: 1},
	{osID: "ubuntu", namespace: "ubuntu", scheme: SchemeDeb, parts: 2},
	{osID: "alpine", namespace: "alpine", scheme: SchemeAPK, parts: 2},
	{osID: "rhel", namespace: "redhat", scheme: SchemeRPM, parts: 1},
	{osID: "rocky", namespace: "rocky", scheme: SchemeRPM, parts: 1},
	{osID: "almalinux", namespace: "almalinux", scheme: SchemeRPM, parts: 1},
}

func byOSID(id string) (release, bool) {
	for _, r := range releases {
		if r.osID == id {
			return r, true
		}
	}
	return release{}, false
}

var versionComponent = regexp.MustCompile(`^[0-9]+$`)

// cut returns the first n dot-separated numeric components of v, or false
// when v has fewer, or any of them is not a plain number.
func cut(v string, n int) (string, bool) {
	parts := strings.Split(v, ".")
	if len(parts) < n {
		return "", false
	}
	for _, p := range parts[:n] {
		if !versionComponent.MatchString(p) {
			return "", false
		}
	}
	return strings.Join(parts[:n], "."), true
}

// Host is an installed system's release, from its os-release ID and
// VERSION_ID.
type Host struct {
	Key       string // debian-12
	Scheme    string // deb
	Namespace string // debian
}

// FromOSRelease maps os-release's ID and VERSION_ID to a release. A system
// with no VERSION_ID (Debian testing, a rolling release) has no release an
// advisory names, and is refused.
func FromOSRelease(id, versionID string) (Host, bool) {
	r, ok := byOSID(strings.ToLower(strings.TrimSpace(id)))
	if !ok {
		return Host{}, false
	}
	v, ok := cut(strings.TrimSpace(versionID), r.parts)
	if !ok {
		return Host{}, false
	}
	return Host{Key: r.osID + "-" + v, Scheme: r.scheme, Namespace: r.namespace}, true
}

// osvDistro matches the OSV ecosystem spellings for the supported families:
// "Debian:12", "Ubuntu:22.04" and "Ubuntu:22.04:LTS", "Alpine:v3.19",
// "Rocky Linux:9", "AlmaLinux:9", "Red Hat:enterprise_linux:9...".
var osvDistro = []struct {
	re    *regexp.Regexp
	osID  string
	parts int
}{
	{regexp.MustCompile(`^Debian:([0-9]+)$`), "debian", 1},
	{regexp.MustCompile(`^Ubuntu:([0-9]+\.[0-9]+)(?::LTS)?$`), "ubuntu", 2},
	{regexp.MustCompile(`^Alpine:v([0-9]+\.[0-9]+)$`), "alpine", 2},
	{regexp.MustCompile(`^Rocky Linux:([0-9]+)$`), "rocky", 1},
	{regexp.MustCompile(`^AlmaLinux:([0-9]+)$`), "almalinux", 1},
	{regexp.MustCompile(`^Red Hat:enterprise_linux:([0-9]+)(?::.*)?$`), "rhel", 1},
}

// FromOSVEcosystem maps an OSV `affected.package.ecosystem` naming an
// operating-system release onto the comparator's scheme and a release key.
// Language ecosystems (npm, PyPI, Go) and distro spellings outside the
// allowlist return ok=false, and the caller leaves them as published.
func FromOSVEcosystem(ecosystem string) (Host, bool) {
	for _, d := range osvDistro {
		m := d.re.FindStringSubmatch(ecosystem)
		if m == nil {
			continue
		}
		return FromOSRelease(d.osID, m[1])
	}
	return Host{}, false
}

// FromAlpineBranch maps an Alpine secdb branch ("v3.19") to a release.
func FromAlpineBranch(branch string) (Host, bool) {
	v, ok := strings.CutPrefix(strings.TrimSpace(branch), "v")
	if !ok {
		return Host{}, false
	}
	return FromOSRelease("alpine", v)
}

var elTag = regexp.MustCompile(`\.el([0-9]+)(?:[._]|$)`)

// FromRHELRelease reads the RHEL major release from an RPM release string's
// dist tag ("3.el9", "3.el9_2", "1.el8.noarch"). A release with no elN tag is
// refused: Red Hat CSAF ranges without one cannot be placed on a release.
func FromRHELRelease(rpmRelease string) (Host, bool) {
	m := elTag.FindStringSubmatch(rpmRelease)
	if m == nil {
		return Host{}, false
	}
	return FromOSRelease("rhel", m[1])
}

// QualifierKey is the purl qualifier carrying the release key.
const QualifierKey = "distro"

// escape percent-encodes a purl name or version: everything outside the
// unreserved set, so an epoch's ':' and a Debian '+' cannot be read as purl
// syntax.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '.', c == '-', c == '_', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// PackagePurl builds an installed package's purl for this release:
// pkg:<scheme>/<namespace>/<name>@<version>?arch=<arch>&distro=<key>.
// Qualifiers are in purl's required lexical order; arch is omitted when empty.
func (h Host) PackagePurl(name, version, arch string) string {
	u := "pkg:" + h.Scheme + "/" + h.Namespace + "/" + escape(name)
	if version != "" {
		u += "@" + escape(version)
	}
	q := url.Values{}
	if arch != "" {
		q.Set("arch", arch)
	}
	q.Set(QualifierKey, h.Key)
	return u + "?" + q.Encode()
}

// RangePurl is the purl an advisory range carries: no version, no arch, the
// release key as the distro qualifier.
func (h Host) RangePurl(name string) string {
	return h.PackagePurl(name, "", "")
}

// KeyOfPurl returns a purl's distro qualifier, or "" when it has none.
func KeyOfPurl(purl string) string {
	_, query, ok := strings.Cut(purl, "?")
	if !ok {
		return ""
	}
	if i := strings.IndexByte(query, '#'); i >= 0 {
		query = query[:i]
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return ""
	}
	return q.Get(QualifierKey)
}
