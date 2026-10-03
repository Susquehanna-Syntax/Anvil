// Package distro is the one vocabulary for "which operating-system release does
// this advisory range, or this installed package, belong to".
//
// A Debian 11 advisory range says nothing about a Debian 12 package, yet the
// comparator asks for ranges by (ecosystem, package) alone. Before plan node
// cli, the advisory side wrote the publisher's spelling ("Debian:11",
// "Alpine:v3.19") into the cache, the host side carried no release at all, and
// nothing mapped one onto the other: the Lane A conformance harness called
// that SEAM 1 and SEAM 2. This package is the mapping. Ingestion uses it to
// write the comparator's scheme plus a `distro` purl qualifier; the scan uses
// it to build an installed package's purl from os-release; and the
// cache-backed advisory source uses it to consult only the ranges for the
// host's own release.
//
// The key is "<id>-<release>" at the granularity advisories are published at:
// debian-12, ubuntu-22.04, alpine-3.19, rhel-9, rocky-9, almalinux-9. Every
// supported spelling is on an allowlist; anything else returns ok=false and
// the caller refuses rather than guessing a release.
package distro
