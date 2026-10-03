// This file is the read side of the ingestion cache as the comparator and
// record emission need it: CacheSource implements match.AdvisorySource, and
// AdvisoryRows reads the `advisory` row a match was decided on. Both were test
// stand-ins in the Lane A conformance harness (cacheSource, advisoryLookup)
// until this package existed.

package scan

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/distro"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
	"github.com/Susquehanna-Syntax/Anvil/internal/match"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/record/lanea"
)

// CacheSource is internal/match's AdvisorySource read off the ingestion cache,
// scoped to ONE operating-system release.
//
// THE RELEASE SCOPE IS THE POINT. The comparator asks for ranges by scheme and
// package, and a Debian 11 range is wrong about a Debian 12 package. Ingestion
// writes each distro range with its release in the purl's distro qualifier
// (internal/distro), and this source returns only the ranges whose qualifier
// is Release. A range with no qualifier — an upstream range, or a distro range
// ingestion could not place on a release — is consulted for no host: a host
// package's verdict comes from its own distribution's advisories, which is
// also what keeps the backport class of false positive out.
//
// Withdrawn and rejected advisories keep their rows and stop deciding findings
// (Lane A exit criterion 22, seen from the read side).
type CacheSource struct {
	DB      *sql.DB
	Release string // a distro key, e.g. "debian-12"
}

// AffectedRanges implements match.AdvisorySource.
func (s *CacheSource) AffectedRanges(ctx context.Context, ecosystem, pkg string) ([]match.AffectedRange, error) {
	if s.Release == "" {
		return nil, errors.New("scan: a CacheSource with no release would consult every release's ranges")
	}
	const q = `
SELECT a.source, a.source_id, ifnull(a.cve_id,''), af.ecosystem, af.package, ifnull(af.purl,''),
       ifnull(af.introduced,''), ifnull(af.fixed,''), af.distro_backport
FROM affected af
JOIN advisory a ON a.source = af.source AND a.source_id = af.source_id
WHERE af.ecosystem = ? AND af.package = ? AND a.state = ?
ORDER BY a.source, a.source_id, af.id`
	rows, err := s.DB.QueryContext(ctx, q, ecosystem, pkg, cache.AdvisoryPublished)
	if err != nil {
		return nil, fmt.Errorf("scan: reading affected ranges for %s/%s: %w", ecosystem, pkg, err)
	}
	defer func() { _ = rows.Close() }()

	var out []match.AffectedRange
	for rows.Next() {
		var r match.AffectedRange
		var backport int
		if err := rows.Scan(&r.Source, &r.SourceID, &r.CVEID, &r.Ecosystem, &r.Package,
			&r.Purl, &r.Introduced, &r.Fixed, &backport); err != nil {
			return nil, err
		}
		if distro.KeyOfPurl(r.Purl) != s.Release {
			continue
		}
		r.DistroBackport = backport == 1
		// A range with neither bound is what a failed parse looks like in a
		// column, and the comparator refuses it; skip it here so one bad row
		// does not refuse the whole package.
		if r.Introduced == "" && r.Fixed == "" {
			continue
		}
		// An advisory that names only a fixed version is unbounded below. "0"
		// is the OSV convention for that lower bound.
		if r.Introduced == "" {
			r.Introduced = "0"
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AdvisoryRows reads `advisory` rows into the shape record emission takes. The
// feed table supplies each feed's freshness SLO, which the cache does not
// store.
type AdvisoryRows struct {
	DB    *sql.DB
	Feeds config.FeedSet
}

// Lookup returns the row (source, sourceID) names, and false when there is
// none. It is the signature record emission's EmitAll takes, and it cannot
// tell a missing row from a failing read; a caller that must, calls Read.
func (r *AdvisoryRows) Lookup(source, sourceID string) (lanea.AdvisoryRow, bool) {
	row, err := r.Read(context.Background(), source, sourceID)
	return row, err == nil
}

// ErrNoAdvisoryRow means the cache holds no row for the advisory.
var ErrNoAdvisoryRow = errors.New("scan: no advisory row in the cache")

// Read is Lookup with the error kept.
func (r *AdvisoryRows) Read(ctx context.Context, source, sourceID string) (lanea.AdvisoryRow, error) {
	const q = `
SELECT ifnull(cve_id,''), ifnull(license_spdx,''), ifnull(license_manual_note,''), anvil_trust,
       as_of, staleness_seconds, parse_degraded, ifnull(data_version,''),
       ifnull(cvss_vector,''), cvss_score, epss_score, ifnull(epss_as_of,''), kev
FROM advisory WHERE source = ? AND source_id = ?`
	var (
		cveID, spdx, note, trust, asOf, dataVersion, vector, epssAsOf string
		staleness, degraded, kev                                      int
		cvss, epss                                                    sql.NullFloat64
	)
	err := r.DB.QueryRowContext(ctx, q, source, sourceID).Scan(&cveID, &spdx, &note, &trust, &asOf,
		&staleness, &degraded, &dataVersion, &vector, &cvss, &epss, &epssAsOf, &kev)
	if errors.Is(err, sql.ErrNoRows) {
		return lanea.AdvisoryRow{}, fmt.Errorf("%w: %s/%s", ErrNoAdvisoryRow, source, sourceID)
	}
	if err != nil {
		return lanea.AdvisoryRow{}, fmt.Errorf("scan: reading advisory %s/%s: %w", source, sourceID, err)
	}
	when, err := time.Parse(time.RFC3339, asOf)
	if err != nil {
		return lanea.AdvisoryRow{}, fmt.Errorf("scan: advisory %s/%s has an unreadable as_of %q: %w", source, sourceID, asOf, err)
	}
	row := lanea.AdvisoryRow{
		Source: source, SourceID: sourceID, CVEID: cveID,
		FeedID:            source,
		SnapshotDigest:    cache.SchemaSHA256(),
		LicenseSPDX:       spdx,
		LicenseManualNote: note,
		Trust:             record.Trust(trust),
		AsOf:              when,
		StalenessSeconds:  staleness,
		ParseDegraded:     degraded == 1,
		DataVersion:       dataVersion,
		CVSSVector:        vector,
		KEVMember:         kev == 1,
	}
	for _, f := range r.Feeds.Feeds {
		if f.ID == source {
			row.FreshnessSLOSeconds = f.FreshnessSLOSeconds
		}
	}
	if cvss.Valid {
		v := cvss.Float64
		row.CVSSScore = &v
	}
	if epss.Valid {
		v := epss.Float64
		row.EPSSScore = &v
	}
	if epssAsOf != "" {
		if t, err := time.Parse(time.RFC3339, epssAsOf); err == nil {
			row.EPSSAsOf = &t
		}
	}
	return row, nil
}
