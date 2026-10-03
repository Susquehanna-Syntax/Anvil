package decode

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/cache"
)

// ---------------------------------------------------------------------------
// Alpine secdb: per-branch JSON, package -> secfixes -> CVE list
// ---------------------------------------------------------------------------

type alpineDoc struct {
	APKURL        string `json:"apkurl"`
	Archs         []any  `json:"archs"`
	Reponame      string `json:"reponame"`
	URLPrefix     string `json:"urlprefix"`
	DistroVersion string `json:"distroversion"`
	Packages      []struct {
		Pkg struct {
			Name     string              `json:"name"`
			Secfixes map[string][]string `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

// AlpineSecdb decodes one Alpine secdb branch file, already read and bounded by
// the caller, and emits one advisory per (branch, CVE).
//
// The branch is part of the id because the same CVE is fixed at different
// versions on different Alpine branches, and collapsing them would lose the
// version that actually matters to a host.
//
// A document that does not parse emits nothing and is NOT an error: a secdb
// file is one member of a bulk pull, and the caller counts the skip.
func (dc *Decoder) AlpineSecdb(raw []byte, emit func(Record) error) (int, error) {
	var d alpineDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return 0, nil
	}

	branch := dc.s(FirstNonEmpty(d.DistroVersion, "alpine"))
	byCVE := map[string]*Record{}
	var order []string
	for _, p := range d.Packages {
		pkg := dc.s(p.Pkg.Name)
		if pkg == "" {
			continue
		}
		for version, cves := range p.Pkg.Secfixes {
			fixed := dc.s(version)
			for _, cve := range cves {
				id := dc.s(strings.TrimSpace(cve))
				if id == "" {
					continue
				}
				key := branch + "/" + id
				rec, ok := byCVE[key]
				if !ok {
					rec = &Record{
						Source:   dc.feedID,
						SourceID: key,
						State:    cache.AdvisoryPublished,
						Raw:      raw,
					}
					if IsCVEID(id) {
						rec.CVEID = id
						rec.Aliases = append(rec.Aliases, id)
					}
					byCVE[key] = rec
					order = append(order, key)
				}
				rec.Affected = append(rec.Affected, AffectedRange{
					Ecosystem: "apk",
					Package:   pkg,
					Fixed:     fixed,
					// Alpine ships backported fixes with an -rN suffix, which
					// is precisely the case an upstream range gets wrong.
					DistroBackport: true,
				})
			}
		}
	}
	// Deterministic order: the map iteration above is not, and an importer
	// whose row order varies between runs is a resume cursor that means
	// different things on different days.
	sort.Strings(order)
	for _, key := range order {
		if err := emit(*byCVE[key]); err != nil {
			return 0, err
		}
	}
	return len(order), nil
}

// ---------------------------------------------------------------------------
// Red Hat CSAF/VEX
// ---------------------------------------------------------------------------
//
// OVAL v2 is deprecated and must not be ingested: since 2024-07-10 Red Hat
// publishes CSAF for every RHSA and VEX for every CVE touching the portfolio
// (research/06 S19). This decoder reads the shape both share.

type csafDoc struct {
	Document struct {
		Category string `json:"category"`
		Title    string `json:"title"`
		Tracking struct {
			ID                 string `json:"id"`
			InitialReleaseDate string `json:"initial_release_date"`
			CurrentReleaseDate string `json:"current_release_date"`
			Status             string `json:"status"`
		} `json:"tracking"`
		Notes []struct {
			Category string `json:"category"`
			Text     string `json:"text"`
		} `json:"notes"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"document"`
	Vulnerabilities []struct {
		CVE   string `json:"cve"`
		Title string `json:"title"`
		Notes []struct {
			Category string `json:"category"`
			Text     string `json:"text"`
		} `json:"notes"`
		ProductStatus struct {
			Fixed         []string `json:"fixed"`
			KnownAffected []string `json:"known_affected"`
		} `json:"product_status"`
		Scores []struct {
			CVSSv3 struct {
				VectorString string  `json:"vectorString"`
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvss_v3"`
		} `json:"scores"`
	} `json:"vulnerabilities"`
}

// CSAF decodes one Red Hat CSAF or VEX document.
func (dc *Decoder) CSAF(raw []byte) (Record, bool, error) {
	var d csafDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		return Record{}, false, err
	}
	if d.Document.Tracking.ID == "" {
		return Record{}, false, nil
	}

	rec := Record{
		Source:    dc.feedID,
		SourceID:  dc.s(d.Document.Tracking.ID),
		Published: dc.s(d.Document.Tracking.InitialReleaseDate),
		Modified:  dc.s(d.Document.Tracking.CurrentReleaseDate),
		State:     cache.AdvisoryPublished,
		Raw:       raw,
	}
	rec.Description = dc.s(d.Document.Title)
	for _, n := range d.Document.Notes {
		if n.Category == "description" || n.Category == "summary" {
			rec.Description = dc.s(strings.TrimSpace(rec.Description + "\n\n" + n.Text))
		}
	}
	for _, r := range d.Document.References {
		if r.URL != "" {
			rec.References = AppendUnique(rec.References, dc.s(r.URL))
		}
	}
	if strings.EqualFold(d.Document.Tracking.Status, "withdrawn") {
		rec.State = cache.AdvisoryWithdrawn
		rec.TombstonedAt = rec.Modified
	}

	for _, v := range d.Vulnerabilities {
		if IsCVEID(v.CVE) {
			id := dc.s(v.CVE)
			rec.Aliases = AppendUnique(rec.Aliases, id)
			if rec.CVEID == "" {
				rec.CVEID = id
			}
		}
		for _, s := range v.Scores {
			if s.CVSSv3.VectorString != "" && rec.CVSSVector == "" {
				rec.CVSSVector = dc.s(s.CVSSv3.VectorString)
				rec.Severity = dc.s(s.CVSSv3.BaseSeverity)
				score := s.CVSSv3.BaseScore
				rec.CVSSScore = score
			}
		}
		// A VEX "fixed" product id is an RPM NEVRA. The fix is BACKPORTED —
		// Red Hat patches without bumping the upstream version — which is the
		// column that defeats the CVE-2023-32681 / RHSA-2023:4520 false
		// positive class (research/12 §3).
		for _, p := range v.ProductStatus.Fixed {
			name, version := SplitNEVRA(p)
			if name == "" {
				continue
			}
			rec.Affected = append(rec.Affected, AffectedRange{
				Ecosystem: "rpm", Package: dc.s(name),
				Fixed: dc.s(version), DistroBackport: true,
			})
		}
		for _, p := range v.ProductStatus.KnownAffected {
			name, version := SplitNEVRA(p)
			if name == "" {
				continue
			}
			rec.Affected = append(rec.Affected, AffectedRange{
				Ecosystem: "rpm", Package: dc.s(name),
				Introduced: dc.s(version), DistroBackport: true,
			})
		}
	}
	return rec, true, nil
}

// SplitNEVRA pulls a package name and version out of a CSAF product id such as
// "Red Hat Enterprise Linux 9:openssl-1:3.0.7-24.el9.x86_64". It is deliberately
// conservative: a shape it does not recognise yields an empty name and is
// dropped, because a wrong package name in `affected` is a false positive
// against a package nobody has.
func SplitNEVRA(product string) (string, string) {
	p := strings.TrimSpace(product)

	// A product id is "<product tree branch>:<nevra>", and only the FIRST
	// colon separates the two — the second colon, if there is one, is the
	// RPM epoch inside the NEVRA. Splitting on the last colon (the obvious
	// first attempt) strips the package name and leaves the version, which
	// then reaches `affected.package` as a version string.
	if i := strings.Index(p, ":"); i >= 0 {
		if candidate := strings.TrimSpace(p[i+1:]); looksLikeNEVRA(candidate) {
			p = candidate
		}
	}

	// name-[epoch:]version-release.arch. The name ends at the first hyphen
	// followed by a digit, which is where RPM's version field begins.
	idx := -1
	for k := 0; k+1 < len(p); k++ {
		if p[k] == '-' && p[k+1] >= '0' && p[k+1] <= '9' {
			idx = k
			break
		}
	}
	if idx <= 0 {
		return "", ""
	}
	name, rest := p[:idx], p[idx+1:]
	if j := strings.Index(rest, ":"); j >= 0 {
		rest = rest[j+1:]
	}
	return name, stripArchSuffix(rest)
}

// rpmArchSuffixes is the ALLOWLIST of architecture suffixes a NEVRA may end
// with. It is an allowlist because the alternative — "drop whatever follows
// the last dot" — eats `.el9`, and a release qualifier removed from a version
// is a comparison against a different package.
//
// A suffix not on this list is LEFT IN PLACE. That is the conservative
// direction: an unknown arch stays part of the version string, which can only
// make the comparator refuse or over-report, never silently under-report.
var rpmArchSuffixes = map[string]bool{
	"noarch": true, "src": true, "nosrc": true,
	"x86_64": true, "i386": true, "i486": true, "i586": true, "i686": true, "athlon": true,
	"aarch64": true, "armv5tel": true, "armv6hl": true, "armv7hl": true, "armv7hnl": true,
	"ppc": true, "ppc64": true, "ppc64le": true, "ppc64p7": true,
	"s390": true, "s390x": true, "riscv64": true, "loongarch64": true,
	"sparc": true, "sparc64": true, "sparcv9": true, "ia64": true, "alpha": true,
	"mips": true, "mipsel": true, "mips64": true, "mips64el": true,
}

// stripArchSuffix removes the trailing ".<arch>" of an RPM NEVRA.
//
// WHY THIS EXISTS. Without it, a Red Hat VEX "fixed" product id such as
//
//	Red Hat Enterprise Linux 9:python3-requests-0:2.25.1-3.el9.noarch
//
// lands in `affected.fixed` as "2.25.1-3.el9.noarch". `fixed` is an EXCLUSIVE
// upper bound, and under RPM version comparison "2.25.1-3.el9" sorts BELOW
// "2.25.1-3.el9.noarch", so a host running EXACTLY the fixed package is
// reported vulnerable — by the vendor advisory whose whole purpose is to say
// it is not. That is the CVE-2023-32681 / RHSA-2023:4520 false-positive class
// (research/12 §3) reintroduced by the decoder, on the one path Lane A relies
// on to defeat it.
//
// Found by A.21's end-to-end harness, and invisible from inside this package:
// A.8's own CSAF test asserts that a backported rpm range EXISTS and never
// asserts what its `fixed` value is, so nothing compared the string to a real
// installed version until a comparator was put on the other end of it.
func stripArchSuffix(version string) string {
	dot := strings.LastIndex(version, ".")
	if dot <= 0 {
		return version
	}
	if rpmArchSuffixes[version[dot+1:]] {
		return version[:dot]
	}
	return version
}

func looksLikeNEVRA(s string) bool {
	for k := 0; k+1 < len(s); k++ {
		if s[k] == '-' && s[k+1] >= '0' && s[k+1] <= '9' {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// EPSS: a CSV with comment lines, streamed row by row
// ---------------------------------------------------------------------------

// EPSS decodes the EPSS daily CSV, emitting one record per scored CVE.
//
// A malformed line ENDS the file rather than the import: an EPSS score is never
// load-bearing for a verdict (it is Tier 3, opt-in, risk-accepted) and what has
// been read is still usable.
func (dc *Decoder) EPSS(br *bufio.Reader, emit func(Record) error) (int, error) {
	asOf := ""
	// Skip and remember the leading '#' comment lines; the model date lives
	// there and it is what as_of should say about an EPSS score.
	for {
		peek, err := br.Peek(1)
		if err != nil || len(peek) == 0 || peek[0] != '#' {
			break
		}
		line, err := br.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("decode: reading EPSS header: %w", err)
		}
		if i := strings.Index(line, "score_date:"); i >= 0 {
			asOf = strings.TrimSpace(strings.TrimSuffix(line[i+len("score_date:"):], "\n"))
		}
		if err != nil {
			return 0, nil
		}
	}

	r := csv.NewReader(br)
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	header, err := r.Read()
	if err != nil {
		return 0, nil
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	cveCol, ok := col["cve"]
	if !ok {
		return 0, nil
	}
	epssCol, hasEPSS := col["epss"]

	n := 0
	for {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, nil
		}
		if cveCol >= len(row) || !IsCVEID(row[cveCol]) {
			continue
		}
		rec := Record{
			Source:   dc.feedID,
			SourceID: dc.s(row[cveCol]),
			CVEID:    dc.s(row[cveCol]),
			State:    cache.AdvisoryPublished,
			EPSSAsOf: dc.s(asOf),
			Raw:      []byte(strings.Join(row, ",")),
		}
		rec.Aliases = append(rec.Aliases, rec.CVEID)
		if hasEPSS && epssCol < len(row) {
			if f, err := strconv.ParseFloat(strings.TrimSpace(row[epssCol]), 64); err == nil {
				rec.EPSSScore = f
			}
		}
		n++
		if err := emit(rec); err != nil {
			return n, err
		}
	}
}
