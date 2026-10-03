// This file turns a host inventory into the comparator's input, which is where
// SEAM 2 closes: host.Package carries no purl, record emission refuses a finding
// without one, and the namespace a purl needs comes from os-release, which the
// inventory carries and a MatchResult does not.

package scan

import (
	"errors"
	"fmt"

	"github.com/Susquehanna-Syntax/Anvil/internal/collector/host"
	"github.com/Susquehanna-Syntax/Anvil/internal/distro"
	"github.com/Susquehanna-Syntax/Anvil/internal/match"
)

// ErrUnknownRelease means the inventory's os-release names no release the
// distro vocabulary knows, so no advisory range can be placed on it. The scan
// reports that rather than consulting another release's ranges.
var ErrUnknownRelease = errors.New("scan: the host's operating-system release is not one Anvil can match")

// HostRecords maps an inventory's packages onto the comparator's input, each
// with the purl its release implies. It returns the release, which scopes the
// cache-backed advisory source to the same key.
//
// A package whose ecosystem is not the release's scheme (a stray rpm database
// on a Debian host) is still submitted, without a purl: the comparator decides
// it on its own scheme and emission refuses it by name, rather than this
// function inventing an identity for it.
func HostRecords(inv *host.Inventory) ([]match.PackageRecord, distro.Host, error) {
	if inv == nil {
		return nil, distro.Host{}, errors.New("scan: no host inventory")
	}
	rel, ok := distro.FromOSRelease(inv.OSRelease.ID, inv.OSRelease.VersionID)
	if !ok {
		return nil, distro.Host{}, fmt.Errorf("%w: ID=%q VERSION_ID=%q", ErrUnknownRelease,
			inv.OSRelease.ID, inv.OSRelease.VersionID)
	}
	out := make([]match.PackageRecord, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		r := match.PackageRecord{
			Collector: match.CollectorHost,
			Ecosystem: p.Ecosystem,
			Name:      p.Name,
			Version:   p.Version,
			Arch:      p.Arch,
		}
		if p.Ecosystem == rel.Scheme {
			r.Purl = rel.PackagePurl(p.Name, p.Version, p.Arch)
		}
		out = append(out, r)
	}
	return out, rel, nil
}
