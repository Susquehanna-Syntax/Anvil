package distro

import (
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/match"
)

func TestSchemesAreTheComparators(t *testing.T) {
	if SchemeDeb != match.EcosystemDeb || SchemeRPM != match.EcosystemRPM || SchemeAPK != match.EcosystemAPK {
		t.Fatalf("distro's schemes %q %q %q drifted from the comparator's", SchemeDeb, SchemeRPM, SchemeAPK)
	}
}

func TestBothSidesReachTheSameKey(t *testing.T) {
	cases := []struct {
		osID, versionID, osv string
		key, scheme          string
	}{
		{"debian", "12", "Debian:12", "debian-12", "deb"},
		{"ubuntu", "22.04", "Ubuntu:22.04:LTS", "ubuntu-22.04", "deb"},
		{"alpine", "3.19.1", "Alpine:v3.19", "alpine-3.19", "apk"},
		{"rhel", "9.4", "Red Hat:enterprise_linux:9::appstream", "rhel-9", "rpm"},
		{"rocky", "9.3", "Rocky Linux:9", "rocky-9", "rpm"},
		{"almalinux", "8.10", "AlmaLinux:8", "almalinux-8", "rpm"},
	}
	for _, c := range cases {
		h, ok := FromOSRelease(c.osID, c.versionID)
		if !ok || h.Key != c.key || h.Scheme != c.scheme {
			t.Errorf("FromOSRelease(%q, %q) = %+v, %v; want key %q scheme %q", c.osID, c.versionID, h, ok, c.key, c.scheme)
		}
		a, ok := FromOSVEcosystem(c.osv)
		if !ok || a != h {
			t.Errorf("FromOSVEcosystem(%q) = %+v, %v; want %+v (the host side's answer)", c.osv, a, ok, h)
		}
	}
	if h, ok := FromAlpineBranch("v3.19"); !ok || h.Key != "alpine-3.19" {
		t.Errorf("FromAlpineBranch = %+v, %v", h, ok)
	}
	for rel, want := range map[string]string{"3.el9": "rhel-9", "3.el9_2": "rhel-9", "1.el8.noarch": "rhel-8"} {
		if h, ok := FromRHELRelease(rel); !ok || h.Key != want {
			t.Errorf("FromRHELRelease(%q) = %+v, %v; want %q", rel, h, ok, want)
		}
	}
}

// Everything off the allowlist is refused, never guessed.
func TestUnknownReleasesAreRefused(t *testing.T) {
	for _, c := range [][2]string{
		{"debian", ""}, {"debian", "trixie"}, {"fedora", "40"}, {"arch", ""},
		{"ubuntu", "22"}, {"alpine", "edge"}, {"", "12"},
	} {
		if h, ok := FromOSRelease(c[0], c[1]); ok {
			t.Errorf("FromOSRelease(%q, %q) = %+v, want refused", c[0], c[1], h)
		}
	}
	for _, e := range []string{"npm", "PyPI", "Go", "Debian", "Debian:sid", "Ubuntu:Pro:22.04:LTS", "Alpine:edge", "Red Hat", "openSUSE:Tumbleweed"} {
		if h, ok := FromOSVEcosystem(e); ok {
			t.Errorf("FromOSVEcosystem(%q) = %+v, want refused", e, h)
		}
	}
	if _, ok := FromRHELRelease("2.25.1-3"); ok {
		t.Error("a release with no elN tag was placed on a RHEL release")
	}
	if _, ok := FromAlpineBranch("edge"); ok {
		t.Error("alpine edge was placed on a release")
	}
}

func TestPurlsRoundTripThroughTheComparatorsParser(t *testing.T) {
	h, _ := FromOSRelease("debian", "12")
	p := h.PackagePurl("libc6", "1:2.36-9+deb12u4", "amd64")
	if p != "pkg:deb/debian/libc6@1%3A2.36-9%2Bdeb12u4?arch=amd64&distro=debian-12" {
		t.Fatalf("PackagePurl = %q", p)
	}
	parsed, err := match.ParsePurl(p)
	if err != nil {
		t.Fatalf("the comparator cannot parse %q: %v", p, err)
	}
	if parsed.Type != "deb" || parsed.Namespace != "debian" || parsed.Name != "libc6" || parsed.Version != "1:2.36-9+deb12u4" {
		t.Errorf("parsed %+v", parsed)
	}
	if KeyOfPurl(p) != "debian-12" {
		t.Errorf("KeyOfPurl(%q) = %q", p, KeyOfPurl(p))
	}
	if r := h.RangePurl("openssl"); r != "pkg:deb/debian/openssl?distro=debian-12" || KeyOfPurl(r) != "debian-12" {
		t.Errorf("RangePurl = %q", r)
	}
	if KeyOfPurl("pkg:npm/lodash@4.17.15") != "" {
		t.Error("a purl with no qualifiers has a key")
	}
}
