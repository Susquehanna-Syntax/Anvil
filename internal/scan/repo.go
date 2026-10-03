// This file turns a Trivy scan of a repository into matches record emission
// can emit, under the owner's accelerator decision of 2026-10-03.
//
// THE DECISION. Trivy decides a repository finding against its own
// vulnerability database, which aggregates the same CC-BY-SA-4.0 and ODbL
// sources tier 2 quarantines (Ubuntu, Alpine) and whose publishers state no
// redistribution terms. Publishing a Trivy-decided finding unmarked would
// launder share-alike data past the quarantine. So:
//
//   - repository SCA is OFF by default. It runs only when the operator's
//     configuration enables the Trivy database (TrivyDB.Enabled); no scan flag
//     can turn it on, because no flag may widen what a scan touches;
//   - every finding it produces carries tier-2 attribution: its licence is
//     LicenseTrivyDBTier2 and its source names the database and the upstream
//     Trivy reports (trivy-db/<DataSourceID>);
//   - with it off, `anvil scan --repo` refuses with ErrRepoSCANotEnabled, which
//     the command reports as its own exit status. It never reports clean.
//
// SEAM 3 dissolves here rather than in the comparator: Trivy has already
// decided the verdict in its own ecosystems (npm, gomod, pip, ...), so these
// matches go to emission directly and the comparator, which implements only
// the OS schemes, is not asked to re-decide them.

package scan

import (
	"errors"
	"strconv"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/collector/repo"
	"github.com/Susquehanna-Syntax/Anvil/internal/match"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
	"github.com/Susquehanna-Syntax/Anvil/internal/record/lanea"
)

// TrivyDB is the operator's accelerator setting.
type TrivyDB struct {
	// Enabled admits findings decided by Trivy's own database, with tier-2
	// attribution. False by default.
	Enabled bool
}

// ErrRepoSCANotEnabled means repository SCA was asked for and the Trivy
// database is not enabled in the operator's configuration.
var ErrRepoSCANotEnabled = errors.New("scan: repository SCA needs the Trivy database, which this installation has not enabled")

// TrivyDBSource is the `source` every Trivy-decided finding carries, with the
// upstream Trivy names after a slash.
const TrivyDBSource = "trivy-db"

// LicenseTrivyDBTier2 is the licence a Trivy-decided finding is attributed
// under: the database is an aggregate holding share-alike data, its publisher
// states no terms, so every finding derived from it is treated as tier 2.
const LicenseTrivyDBTier2 = "LicenseRef-Anvil-TrivyDB-Tier2"

// RepoMatches maps Trivy's findings onto matches and the advisory rows record
// emission reads them against. Every row carries the database's own build time
// as its as_of: a verdict is only as fresh as the database that produced it.
func RepoMatches(res repo.ScanResult, db repo.DatabaseInfo) ([]match.MatchResult, map[[2]string]lanea.AdvisoryRow) {
	rows := map[[2]string]lanea.AdvisoryRow{}
	var out []match.MatchResult
	for _, f := range res.Findings {
		source := TrivyDBSource
		if f.DataSourceID != "" {
			source += "/" + f.DataSourceID
		}
		cve := ""
		if strings.HasPrefix(f.AdvisoryID, "CVE-") {
			cve = f.AdvisoryID
		}
		out = append(out, match.MatchResult{
			Source:           source,
			SourceID:         f.AdvisoryID,
			CVEID:            cve,
			Collector:        match.CollectorRepoSCA,
			Ecosystem:        f.Ecosystem,
			Package:          f.PackageName,
			Purl:             f.Purl,
			ManifestRelPath:  f.ManifestRelPath,
			InstalledVersion: f.InstalledVersion,
			MatchedRange:     trivyRange(f.FixedVersion),
			FixedVersion:     f.FixedVersion,
			Detector:         record.DetectorKindSCA,
			EvidenceClass:    record.EvidenceClassSCA,
			// The verdict is Trivy's, read from bytes Anvil did not write.
			Trust: record.TrustUntrusted,
		})
		key := [2]string{source, f.AdvisoryID}
		if _, ok := rows[key]; ok {
			continue
		}
		row := lanea.AdvisoryRow{
			Source: source, SourceID: f.AdvisoryID, CVEID: cve,
			FeedID:         TrivyDBSource,
			SnapshotDigest: TrivyDBSource + "/v" + strconv.Itoa(db.DBVersion) + "@" + db.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			LicenseSPDX:    LicenseTrivyDBTier2,
			Trust:          record.TrustUntrusted,
			AsOf:           db.UpdatedAt,
		}
		if t := f.Title.Text; t != "" && len(t) <= record.MaxAdvisoryExcerptBytes {
			row.ExcerptText = t
		}
		rows[key] = row
	}
	return out, rows
}

// trivyRange states the range a Trivy verdict rests on. Trivy reports the
// fixed version and not the lower bound it matched against, so the range says
// exactly that much.
func trivyRange(fixed string) string {
	if fixed == "" {
		return "every version the Trivy database lists (no fixed version)"
	}
	return "below " + fixed + " per the Trivy database"
}
