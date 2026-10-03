package decode

import (
	"encoding/json"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
)

// ---------------------------------------------------------------------------
// OSV, and therefore GHSA: github/advisory-database is OSV format
// ---------------------------------------------------------------------------

type osvDoc struct {
	SchemaVersion string          `json:"schema_version"`
	ID            string          `json:"id"`
	Withdrawn     string          `json:"withdrawn"`
	Published     string          `json:"published"`
	Modified      string          `json:"modified"`
	Summary       string          `json:"summary"`
	Details       string          `json:"details"`
	Aliases       []string        `json:"aliases"`
	Related       []string        `json:"related"`
	Severity      []osvSeverity   `json:"severity"`
	References    []osvReference  `json:"references"`
	Affected      []osvAffected   `json:"affected"`
	DatabaseSpec  json.RawMessage `json:"database_specific"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced string `json:"introduced"`
			Fixed      string `json:"fixed"`
			LastAffect string `json:"last_affected"`
		} `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

// OSV decodes one OSV-schema advisory document.
//
// The bool is false for a document that parsed as JSON but carries no `id`,
// which is not an error: it is how "this JSON object is not an OSV advisory"
// is reported to a dispatch that has to decide between skipping and refusing.
func (dc *Decoder) OSV(raw []byte) (Record, bool, error) {
	var d osvDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return Record{}, false, err
	}
	if d.ID == "" {
		return Record{}, false, nil
	}

	rec := Record{
		Source:   dc.feedID,
		SourceID: dc.s(d.ID),
		State:    cache.AdvisoryPublished,
		Raw:      raw,
	}
	if d.Withdrawn != "" {
		rec.State = cache.AdvisoryWithdrawn
		rec.TombstonedAt = dc.s(d.Withdrawn)
	}
	rec.Published = dc.s(d.Published)
	rec.Modified = dc.s(d.Modified)
	rec.Description = dc.s(strings.TrimSpace(d.Summary + "\n\n" + d.Details))
	for _, s := range d.Severity {
		if strings.HasPrefix(strings.ToUpper(s.Type), "CVSS") {
			rec.CVSSVector = dc.s(s.Score)
			break
		}
	}
	for _, r := range d.References {
		if r.URL != "" {
			rec.References = append(rec.References, dc.s(r.URL))
		}
	}

	// A CVE alias is a nullable, indexed alias and never the primary key
	// (research/06 Risk #2): GHSA advisories frequently carry none.
	for _, a := range append(append([]string{}, d.Aliases...), d.Related...) {
		if IsCVEID(a) {
			rec.Aliases = AppendUnique(rec.Aliases, dc.s(a))
		}
	}
	if IsCVEID(d.ID) {
		rec.CVEID = rec.SourceID
		rec.Aliases = AppendUnique(rec.Aliases, rec.SourceID)
	} else if len(rec.Aliases) > 0 {
		rec.CVEID = rec.Aliases[0]
	}

	for _, a := range d.Affected {
		eco := dc.s(a.Package.Ecosystem)
		pkg := dc.s(a.Package.Name)
		if eco == "" || pkg == "" {
			continue
		}
		purl := dc.s(a.Package.PURL)
		// A distro's OSV export carries a backported fix: the version number
		// does not move upstream, so an upstream range would call a patched
		// package vulnerable. research/12 §3, the CVE-2023-32681 /
		// RHSA-2023:4520 class of false positive.
		backport := IsDistroEcosystem(eco)
		emitted := false
		for _, rg := range a.Ranges {
			var introduced string
			for _, ev := range rg.Events {
				switch {
				case ev.Introduced != "":
					introduced = dc.s(ev.Introduced)
				case ev.Fixed != "":
					rec.Affected = append(rec.Affected, AffectedRange{
						Ecosystem: eco, Package: pkg, PURL: purl,
						Introduced: introduced, Fixed: dc.s(ev.Fixed), DistroBackport: backport,
					})
					emitted = true
				case ev.LastAffect != "":
					rec.Affected = append(rec.Affected, AffectedRange{
						Ecosystem: eco, Package: pkg, PURL: purl,
						Introduced: introduced, DistroBackport: backport,
					})
					emitted = true
				}
			}
		}
		if !emitted {
			rec.Affected = append(rec.Affected, AffectedRange{
				Ecosystem: eco, Package: pkg, PURL: purl, DistroBackport: backport,
			})
		}
	}
	return rec, true, nil
}

// ---------------------------------------------------------------------------
// CVE 5.x — the cvelistV5 baseline and the shape the deltaLog names
// ---------------------------------------------------------------------------

type cve5Doc struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CVEMetadata struct {
		CVEID     string `json:"cveId"`
		State     string `json:"state"`
		Published string `json:"datePublished"`
		Updated   string `json:"dateUpdated"`
		Rejected  string `json:"dateRejected"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA cve5Container   `json:"cna"`
		ADP []cve5Container `json:"adp"`
	} `json:"containers"`
}

type cve5Container struct {
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Metrics []struct {
		CVSSv31 *cve5CVSS `json:"cvssV3_1"`
		CVSSv30 *cve5CVSS `json:"cvssV3_0"`
		CVSSv40 *cve5CVSS `json:"cvssV4_0"`
	} `json:"metrics"`
	Affected []struct {
		Vendor   string   `json:"vendor"`
		Product  string   `json:"product"`
		PackageN string   `json:"packageName"`
		Repo     string   `json:"repo"`
		CPEs     []string `json:"cpes"`
		Versions []struct {
			Version     string `json:"version"`
			LessThan    string `json:"lessThan"`
			LessOrEqual string `json:"lessThanOrEqual"`
			Status      string `json:"status"`
		} `json:"versions"`
	} `json:"affected"`
}

type cve5CVSS struct {
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// CVE5 decodes one CVE Record Format 5.x document.
//
// An unknown dataVersion sets ParseDegraded and the record is still returned.
// Lane A exit criterion 23 and spine S6: a record from a newer schema is
// persisted and flagged, never dropped.
func (dc *Decoder) CVE5(raw []byte) (Record, bool, error) {
	var d cve5Doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return Record{}, false, err
	}
	if d.CVEMetadata.CVEID == "" {
		return Record{}, false, nil
	}

	rec := Record{
		Source:        dc.feedID,
		SourceID:      dc.s(d.CVEMetadata.CVEID),
		CVEID:         dc.s(d.CVEMetadata.CVEID),
		Published:     dc.s(d.CVEMetadata.Published),
		Modified:      dc.s(d.CVEMetadata.Updated),
		State:         cache.AdvisoryPublished,
		DataVersion:   dc.s(d.DataVersion),
		ParseDegraded: !KnownCVEDataVersion(d.DataVersion),
		Raw:           raw,
	}
	rec.Aliases = append(rec.Aliases, rec.CVEID)
	if strings.EqualFold(d.CVEMetadata.State, "REJECTED") {
		rec.State = cache.AdvisoryRejected
		rec.TombstonedAt = dc.s(FirstNonEmpty(d.CVEMetadata.Rejected, d.CVEMetadata.Updated))
	}

	containers := append([]cve5Container{d.Containers.CNA}, d.Containers.ADP...)
	for _, c := range containers {
		for _, desc := range c.Descriptions {
			if rec.Description == "" && (desc.Lang == "" || strings.HasPrefix(strings.ToLower(desc.Lang), "en")) {
				rec.Description = dc.s(desc.Value)
			}
		}
		for _, ref := range c.References {
			if ref.URL != "" {
				rec.References = AppendUnique(rec.References, dc.s(ref.URL))
			}
		}
		for _, m := range c.Metrics {
			for _, v := range []*cve5CVSS{m.CVSSv40, m.CVSSv31, m.CVSSv30} {
				if v == nil || v.VectorString == "" || rec.CVSSVector != "" {
					continue
				}
				rec.CVSSVector = dc.s(v.VectorString)
				rec.Severity = dc.s(v.BaseSeverity)
				score := v.BaseScore
				rec.CVSSScore = score
			}
		}
		for _, a := range c.Affected {
			pkg := dc.s(FirstNonEmpty(a.PackageN, a.Product))
			if pkg == "" {
				continue
			}
			eco := dc.s(FirstNonEmpty(a.Vendor, "cpe"))
			for _, v := range a.Versions {
				if strings.EqualFold(v.Status, "unaffected") {
					continue
				}
				rec.Affected = append(rec.Affected, AffectedRange{
					Ecosystem:  eco,
					Package:    pkg,
					Introduced: dc.s(v.Version),
					Fixed:      dc.s(FirstNonEmpty(v.LessThan, v.LessOrEqual)),
				})
			}
		}
	}
	return rec, true, nil
}

// ---------------------------------------------------------------------------
// CISA KEV
// ---------------------------------------------------------------------------

// kevDoc keeps its entries as RAW MESSAGES rather than as decoded structs.
//
// That is not a style choice: `advisory.raw_json` stores the publisher's bytes
// verbatim, and re-marshalling a decoded struct would store Anvil's rendering
// of the entry instead — different key order, dropped unknown fields, and a
// different digest from the one the streaming importer writes for the same
// catalogue entry.
type kevDoc struct {
	CatalogVersion  string            `json:"catalogVersion"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
}

// KEVEntry decodes ONE element of the KEV catalogue's `vulnerabilities` array.
//
// It is the shared unit deliberately: the bulk importer streams the catalogue
// element by element (it is walking a 570 MB archive and will not hold a file
// in memory) while the delta path is handed a body the poller already read
// under its own cap. Those are different traversals of the same array, and
// before this package they were also two different mappings of the same entry.
//
// The bool is false for an element that is not a KEV entry — malformed, or
// carrying no cveID. The caller decides what that means; both callers today
// skip the element, which is the one place a skip is right because the KEV
// catalogue is a single document holding every entry and one bad element must
// not cost the rest.
func (dc *Decoder) KEVEntry(entryRaw []byte) (Record, bool, error) {
	var e kevEntry
	if err := json.Unmarshal(entryRaw, &e); err != nil {
		return Record{}, false, err
	}
	if e.CVEID == "" {
		return Record{}, false, nil
	}
	rec := Record{
		Source:      dc.feedID,
		SourceID:    dc.s(e.CVEID),
		CVEID:       dc.s(e.CVEID),
		Published:   dc.s(e.DateAdded),
		State:       cache.AdvisoryPublished,
		KEV:         true,
		Description: dc.s(strings.TrimSpace(e.VulnerabilityName + "\n\n" + e.ShortDescription + "\n\n" + e.RequiredAction)),
		Raw:         append([]byte(nil), entryRaw...),
	}
	rec.Aliases = append(rec.Aliases, rec.CVEID)
	if pkg := dc.s(e.Product); pkg != "" {
		rec.Affected = append(rec.Affected, AffectedRange{
			Ecosystem: dc.s(FirstNonEmpty(e.VendorProject, "vendor")),
			Package:   pkg,
		})
	}
	if e.Notes != "" {
		rec.References = append(rec.References, dc.s(e.Notes))
	}
	return rec, true, nil
}

// KEVDocument decodes a whole KEV catalogue held in memory.
//
// A malformed catalogue is an error — the caller asked for a document it had
// already read and bounded — while a malformed ENTRY inside a well-formed
// catalogue is skipped by KEVEntry's contract.
func (dc *Decoder) KEVDocument(raw []byte) ([]Record, error) {
	var d kevDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(d.Vulnerabilities))
	for _, entryRaw := range d.Vulnerabilities {
		rec, ok, err := dc.KEVEntry(entryRaw)
		if err != nil || !ok {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}
