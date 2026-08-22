package decode

import "testing"

// TestSplitNEVRADropsTheArchAndNothingElse is the direct test of the fix A.21's
// end-to-end harness forced.
//
// WHY IT MATTERS. `affected.fixed` is an EXCLUSIVE upper bound. A Red Hat VEX
// "fixed" product id that leaves its architecture on the version —
// "2.25.1-3.el9.noarch" — sorts ABOVE the installed "2.25.1-3.el9" under RPM
// version comparison, so a host running EXACTLY the fixed package is reported
// vulnerable by the advisory whose purpose is to say it is not. That is the
// CVE-2023-32681 / RHSA-2023:4520 false-positive class (research/12 §3)
// reintroduced by the decoder, on the one path Lane A relies on to defeat it.
//
// THE CORPUS IS HAND-WRITTEN. Every product id below is typed from the shape
// Red Hat's CSAF product tree documents, not captured from this package's own
// output — a test whose corpus comes from the implementation is not a test.
//
// THE ARCH LIST IS AN ALLOWLIST and the last two cases are why: a suffix that
// is not a known architecture STAYS, because "drop whatever follows the last
// dot" eats `.el9`, and a release qualifier removed from a version is a
// comparison against a different package.
func TestSplitNEVRADropsTheArchAndNothingElse(t *testing.T) {
	cases := []struct {
		product     string
		wantName    string
		wantVersion string
		why         string
	}{
		{
			product:  "Red Hat Enterprise Linux 9:python3-requests-0:2.25.1-3.el9.noarch",
			wantName: "python3-requests", wantVersion: "2.25.1-3.el9",
			why: "the backport case: a host at 2.25.1-3.el9 must not be flagged by this range",
		},
		{
			product:  "Red Hat Enterprise Linux 9:openssl-1:3.0.7-24.el9.x86_64",
			wantName: "openssl", wantVersion: "3.0.7-24.el9",
			why: "an epoch AND an arch, both removed",
		},
		{
			product:  "Red Hat Enterprise Linux 8:kernel-0:4.18.0-513.5.1.el8_9.aarch64",
			wantName: "kernel", wantVersion: "4.18.0-513.5.1.el8_9",
			why: "a release with its own dots keeps every one of them",
		},
		{
			product:  "AppStream-9.3.0.GA:nodejs-1:18.18.2-2.module+el9.3.0+20334+3dd35b3f.ppc64le",
			wantName: "nodejs", wantVersion: "18.18.2-2.module+el9.3.0+20334+3dd35b3f",
			why: "a modular release: only the trailing arch goes",
		},
		{
			product:  "Red Hat Enterprise Linux 9:python3-requests-0:2.25.1-3.el9",
			wantName: "python3-requests", wantVersion: "2.25.1-3.el9",
			why: "NO arch at all — the release must survive untouched, which is what an " +
				"allowlist buys over trimming the last dotted segment",
		},
		{
			product:  "Red Hat Enterprise Linux 9:widget-0:1.2.3-4.el9.sparc128",
			wantName: "widget", wantVersion: "1.2.3-4.el9.sparc128",
			why: "an UNKNOWN arch stays in place. Leaving it can make the comparator " +
				"over-report or refuse; guessing it away can silently under-report, and " +
				"under-reporting is the failure a security tool must not choose",
		},
		{
			product:  "Red Hat Enterprise Linux 9",
			wantName: "", wantVersion: "",
			why: "a product tree branch with no NEVRA yields nothing rather than a " +
				"package name nobody has",
		},
	}

	for _, tc := range cases {
		name, version := SplitNEVRA(tc.product)
		if name != tc.wantName || version != tc.wantVersion {
			t.Errorf("SplitNEVRA(%q) = (%q, %q), want (%q, %q)\n    %s",
				tc.product, name, version, tc.wantName, tc.wantVersion, tc.why)
		}
	}
}

// TestTheArchAllowlistIsNotEmpty keeps the guard from going inert: an empty
// map would make stripArchSuffix a no-op and every case above would still
// "pass" for the no-arch rows.
func TestTheArchAllowlistIsNotEmpty(t *testing.T) {
	if len(rpmArchSuffixes) == 0 {
		t.Fatal("the arch allowlist is empty, so stripArchSuffix strips nothing and the NEVRA " +
			"tests above pass over a function that does not run")
	}
	if !rpmArchSuffixes["noarch"] || !rpmArchSuffixes["x86_64"] {
		t.Error("the two architectures Red Hat's own advisories use most are not on the allowlist")
	}
	if rpmArchSuffixes["el9"] {
		t.Error("a release qualifier is on the ARCHITECTURE allowlist; it would be stripped off " +
			"every version and every comparison would be against a different package")
	}
}
