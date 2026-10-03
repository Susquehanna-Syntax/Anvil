package decode

import (
	"os"
	"testing"
)

// TestDistroRangesCarryTheirRelease: a distro range is written in the
// comparator's scheme with its release in the purl's distro qualifier, and a
// language ecosystem is left as published. This is SEAM 1 of the Lane A
// conformance harness, closed in the package that owned it.
func TestDistroRangesCarryTheirRelease(t *testing.T) {
	osv := func(eco string) []byte {
		return []byte(`{"id":"DEBIAN-CVE-2026-9001","modified":"2026-09-01T00:00:00Z","aliases":["CVE-2026-9001"],
			"affected":[{"package":{"ecosystem":"` + eco + `","name":"zzpkg"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2-1"}]}]}]}`)
	}
	for eco, want := range map[string][2]string{
		"Debian:12":        {"deb", "pkg:deb/debian/zzpkg?distro=debian-12"},
		"Ubuntu:22.04:LTS": {"deb", "pkg:deb/ubuntu/zzpkg?distro=ubuntu-22.04"},
		"Alpine:v3.19":     {"apk", "pkg:apk/alpine/zzpkg?distro=alpine-3.19"},
		"npm":              {"npm", ""},
		"Debian:sid":       {"Debian:sid", ""},
	} {
		rec, ok, err := New("osv-test").OSV(osv(eco))
		if err != nil || !ok || len(rec.Affected) != 1 {
			t.Fatalf("%s: decoded %+v, %v, %v", eco, rec.Affected, ok, err)
		}
		a := rec.Affected[0]
		if a.Ecosystem != want[0] || a.PURL != want[1] {
			t.Errorf("%s: ecosystem %q purl %q, want %q %q", eco, a.Ecosystem, a.PURL, want[0], want[1])
		}
		if eco == "Debian:12" && !a.DistroBackport {
			t.Error("a distro range lost its backport marking")
		}
	}
}

func TestAlpineAndRedHatRangesCarryTheirRelease(t *testing.T) {
	raw, err := os.ReadFile("../../../test/conformance/lanea/fixtures/alpine/v3.19-main.json")
	if err != nil {
		t.Fatal(err)
	}
	var got []Record
	if _, err := New("alpine-test").AlpineSecdb(raw, func(r Record) error { got = append(got, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("the Alpine fixture decoded to nothing")
	}
	for _, r := range got {
		for _, a := range r.Affected {
			if a.PURL != "pkg:apk/alpine/"+a.Package+"?distro=alpine-3.19" {
				t.Errorf("alpine range for %s has purl %q", a.Package, a.PURL)
			}
		}
	}

	for version, want := range map[string]string{
		"2.25.1-3.el9": "pkg:rpm/redhat/python3-requests?distro=rhel-9",
		"2.25.1-3":     "",
	} {
		if got := rhelRangePurl("python3-requests", version); got != want {
			t.Errorf("rhelRangePurl(%q) = %q, want %q", version, got, want)
		}
	}
}
