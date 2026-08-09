package license

import (
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/ingest/config"
)

// ---------------------------------------------------------------------------
// The pin
// ---------------------------------------------------------------------------
//
// This file is the answer to A.6's central finding: that no verbatim publisher
// licence text was checked in anywhere, so every body the gate read was Anvil
// prose committed alongside the claim it was supposed to validate. A document
// written by the same commit as the claim is not evidence of the claim. It is
// worse than reading API metadata, because it looks rigorous.
//
// The shape is M0.7's, already established in this repository for the opengrep
// engine (eval/tools/opengrep/MANIFEST.toml, anvil_opengrep/acquire.py):
//
//	a pinned manifest records, per artefact, where the bytes come from and
//	what they must hash to;
//	the artefact itself is NOT committed;
//	a documented acquisition step an operator runs deliberately fetches it and
//	verifies the hash;
//	everything that consumes the artefact refuses to run without it, loudly,
//	naming the command that fixes it.
//
// Applied here that means: mirror/LICENSE-MANIFEST.toml pins, per feed, the
// canonical URL of the publisher's own licence text, the sha256 that text must
// have, and the SPDX id it is claimed to be. The text lands at
// <tier>/<dir>/LICENSE.full.txt and is gitignored. A feed with no pin, no
// acquired text, or a text whose digest does not match its pin is REFUSED.

const (
	// ManifestFileName is the pinned manifest, relative to the mirror FS root.
	ManifestFileName = MirrorDirName + "/LICENSE-MANIFEST.toml"

	// VerbatimFileName is the acquired publisher licence text inside a feed's
	// mirror directory. It is the ONLY document this gate treats as evidence.
	//
	// It is never committed — see mirror/.gitignore. The pin lives in git; the
	// bytes do not, exactly as the opengrep engine's do not.
	VerbatimFileName = "LICENSE.full.txt"

	// ManifestSchemaVersion is the only schema_version this parser accepts. A
	// manifest from the future is refused rather than read optimistically.
	ManifestSchemaVersion = 1

	// AcquireCommand is the operator step that fills the mirror. It is quoted
	// verbatim into every refusal caused by a missing or stale body, because a
	// fail-closed gate that does not say how to satisfy it is just an outage.
	AcquireCommand = "sh mirror/acquire-license-bodies.sh   (Windows: pwsh -File mirror/acquire-license-bodies.ps1)"
)

// PinnedBody is one manifest entry: everything the gate needs in order to
// decide whether the bytes on disk are the publisher's licence text.
type PinnedBody struct {
	// FeedID is the config.FeedConfig.ID this pin belongs to.
	FeedID string

	// Tier and Dir locate the body. They are pinned rather than taken from
	// the feed row so that a row which has been re-tiered or re-homed since
	// the evidence was acquired is a REFUSAL rather than a silent re-read of
	// some other feed's licence.
	Tier config.LicenseTier
	Dir  string

	// SPDXID is the identifier this text is CLAIMED to be. It is a claim, and
	// the gate treats it as one: the body is classified independently and a
	// disagreement between the two refuses the feed.
	SPDXID string

	// TextURL is where the verbatim licence text is fetched from — the
	// publisher's own licence file, or the canonical legalcode of the licence
	// the publisher names.
	TextURL string

	// SHA256 is the lowercase hex digest the fetched text must have.
	//
	// EMPTY MEANS UNPINNED, AND UNPINNED MEANS REFUSED. It is empty for every
	// entry in this repository right now: pinning a digest requires
	// downloading the text, and no download has been performed or authorised.
	// Recording a digest from memory would be a fabrication, and recording one
	// "to be replaced later" would admit feeds on a number nobody checked.
	SHA256 string

	// ClaimURL and ClaimSource record where the CLAIM that this feed is under
	// this licence comes from — often a different document from TextURL. For
	// Ubuntu the text is the CC-BY-SA-4.0 legalcode while the claim is OSV's
	// source table, and that gap is the whole reason the Ubuntu conclusion is
	// weaker than Alpine's.
	ClaimURL    string
	ClaimSource string

	// Note is free prose for the operator. It is never classified.
	Note string

	// line is where the entry began, for diagnostics.
	line int
}

// Path is the file the acquired verbatim text must be written to. It is
// DERIVED, never a second pinned field, so the manifest and the gate cannot
// disagree about where a body lives.
func (p PinnedBody) Path() string {
	return path.Join(TierDir(p.Tier), p.Dir, VerbatimFileName)
}

// Pinned reports whether SHA256 is a usable digest. Anything else — empty, the
// wrong length, non-hex — is unpinned and refused.
func (p PinnedBody) Pinned() bool {
	if len(p.SHA256) != 64 || p.SHA256 != strings.ToLower(p.SHA256) {
		return false
	}
	_, err := hex.DecodeString(p.SHA256)
	return err == nil
}

// Manifest is the parsed pin file.
type Manifest struct {
	SchemaVersion int
	GeneratedUTC  string
	GeneratedBy   string

	bodies map[string]PinnedBody
	order  []string
}

// Body returns the pin for a feed id.
func (m Manifest) Body(feedID string) (PinnedBody, bool) {
	b, ok := m.bodies[feedID]
	return b, ok
}

// FeedIDs returns every pinned feed id in document order.
func (m Manifest) FeedIDs() []string {
	out := make([]string, len(m.order))
	copy(out, m.order)
	return out
}

// Bodies returns every pin in document order.
func (m Manifest) Bodies() []PinnedBody {
	out := make([]PinnedBody, 0, len(m.order))
	for _, id := range m.order {
		out = append(out, m.bodies[id])
	}
	return out
}

// Unpinned returns the pins that carry no usable digest, in document order.
// Every one of them is a feed the gate refuses.
func (m Manifest) Unpinned() []PinnedBody {
	var out []PinnedBody
	for _, b := range m.Bodies() {
		if !b.Pinned() {
			out = append(out, b)
		}
	}
	return out
}

// LoadManifest reads and validates mirror/LICENSE-MANIFEST.toml from fsys.
//
// Every failure is a refusal. There is no partial load: a manifest that cannot
// be parsed exactly is a manifest whose pins cannot be trusted, and a licence
// gate running on pins it half-understood is the failure this file exists to
// prevent.
func LoadManifest(fsys fs.FS) (Manifest, error) {
	raw, err := fs.ReadFile(fsys, ManifestFileName)
	if err != nil {
		return Manifest{}, refuse(ErrNoLicenseManifest,
			"cannot read %s: %v; the pinned licence manifest is what makes a body evidence rather than an assertion",
			ManifestFileName, err)
	}
	return parseManifest(string(raw))
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------
//
// A deliberately tiny, strict subset of TOML: comments, top-level `key = value`
// scalars, and repeated `[[body]]` tables of the same. Values are double-quoted
// strings (with \" and \\ escapes and nothing else) or bare non-negative
// integers.
//
// It is hand-written for the same reason internal/ingest/config's YAML subset
// is: this repository takes no new dependencies, and a full TOML implementation
// would accept a great deal this file must not contain. Everything it does not
// understand is an error — unknown keys, duplicate keys, missing required keys,
// a second entry for one feed, trailing junk after a value. A permissive parser
// in front of a fail-closed gate moves the failure somewhere quieter, it does
// not remove it.

var manifestTopKeys = map[string]bool{
	"schema_version": true,
	"generated_utc":  true,
	"generated_by":   true,
}

var manifestBodyKeys = map[string]bool{
	"feed_id":      true,
	"tier":         true,
	"dir":          true,
	"spdx_id":      true,
	"text_url":     true,
	"sha256":       true,
	"claim_url":    true,
	"claim_source": true,
	"note":         true,
}

// manifestBodyRequired are the keys every [[body]] must state. sha256 is
// required as a KEY and may be the empty string: "unpinned" must be written
// down deliberately, never expressed by omission.
var manifestBodyRequired = []string{
	"feed_id", "tier", "dir", "spdx_id", "text_url", "sha256", "claim_source",
}

type manifestValue struct {
	str   string
	num   int
	isNum bool
	line  int
}

func parseManifest(text string) (Manifest, error) {
	m := Manifest{bodies: map[string]PinnedBody{}}

	top := map[string]manifestValue{}
	var entries []map[string]manifestValue
	var current map[string]manifestValue

	for i, rawLine := range strings.Split(text, "\n") {
		line := i + 1
		s := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if s == "[[body]]" {
			current = map[string]manifestValue{}
			entries = append(entries, current)
			continue
		}
		if strings.HasPrefix(s, "[") {
			return Manifest{}, refuse(ErrInvalidLicenseManifest,
				"%s line %d: %q is not a table header this manifest understands; the only one is [[body]]",
				ManifestFileName, line, s)
		}

		key, val, err := parseManifestPair(s, line)
		if err != nil {
			return Manifest{}, err
		}
		target, allowed, where := top, manifestTopKeys, "top level"
		if current != nil {
			target, allowed, where = current, manifestBodyKeys, "[[body]]"
		}
		if !allowed[key] {
			return Manifest{}, refuse(ErrInvalidLicenseManifest,
				"%s line %d: %q is not a key the %s of this manifest accepts",
				ManifestFileName, line, key, where)
		}
		if prev, dup := target[key]; dup {
			return Manifest{}, refuse(ErrInvalidLicenseManifest,
				"%s line %d: %q was already set on line %d; a duplicated pin is a pin nobody can read",
				ManifestFileName, line, key, prev.line)
		}
		target[key] = val
	}

	// --- top level ---
	sv, ok := top["schema_version"]
	if !ok || !sv.isNum {
		return Manifest{}, refuse(ErrInvalidLicenseManifest,
			"%s: schema_version is missing or is not an integer", ManifestFileName)
	}
	if sv.num != ManifestSchemaVersion {
		return Manifest{}, refuse(ErrInvalidLicenseManifest,
			"%s: schema_version %d; this build understands %d only",
			ManifestFileName, sv.num, ManifestSchemaVersion)
	}
	m.SchemaVersion = sv.num
	m.GeneratedUTC = top["generated_utc"].str
	m.GeneratedBy = top["generated_by"].str

	// --- entries ---
	for _, e := range entries {
		b, err := bindPinnedBody(e)
		if err != nil {
			return Manifest{}, err
		}
		if prev, dup := m.bodies[b.FeedID]; dup {
			return Manifest{}, refuse(ErrInvalidLicenseManifest,
				"%s line %d: feed %q is pinned twice (also line %d); which pin wins is not a question a licence gate may answer",
				ManifestFileName, b.line, b.FeedID, prev.line)
		}
		m.bodies[b.FeedID] = b
		m.order = append(m.order, b.FeedID)
	}
	return m, nil
}

func bindPinnedBody(e map[string]manifestValue) (PinnedBody, error) {
	line := 0
	for _, v := range e {
		if line == 0 || v.line < line {
			line = v.line
		}
	}
	for _, k := range manifestBodyRequired {
		if _, ok := e[k]; !ok {
			return PinnedBody{}, refuse(ErrInvalidLicenseManifest,
				"%s: the [[body]] near line %d states no %q; every pin must state %s",
				ManifestFileName, line, k, strings.Join(manifestBodyRequired, ", "))
		}
	}

	b := PinnedBody{
		FeedID:      e["feed_id"].str,
		Dir:         e["dir"].str,
		SPDXID:      e["spdx_id"].str,
		TextURL:     e["text_url"].str,
		SHA256:      strings.TrimSpace(e["sha256"].str),
		ClaimURL:    e["claim_url"].str,
		ClaimSource: e["claim_source"].str,
		Note:        e["note"].str,
		line:        line,
	}

	tier := e["tier"]
	if !tier.isNum {
		return PinnedBody{}, refuse(ErrInvalidLicenseManifest,
			"%s line %d: tier must be an integer", ManifestFileName, tier.line)
	}
	b.Tier = config.LicenseTier(tier.num)
	if !b.Tier.Valid() {
		return PinnedBody{}, refuse(ErrInvalidLicenseManifest,
			"%s line %d: tier %d is outside {0,1,2,3}", ManifestFileName, tier.line, tier.num)
	}
	if !config.ValidFeedID(b.FeedID) {
		return PinnedBody{}, refuse(ErrInvalidLicenseManifest,
			"%s line %d: feed_id %q is not a legal feed id", ManifestFileName, line, b.FeedID)
	}
	if !config.ValidPathSegment(b.Dir) {
		return PinnedBody{}, refuse(ErrInvalidLicenseManifest,
			"%s line %d: dir %q must be one safe path segment", ManifestFileName, line, b.Dir)
	}
	if strings.TrimSpace(b.SPDXID) == "" {
		return PinnedBody{}, refuse(ErrInvalidLicenseManifest,
			"%s line %d: spdx_id is empty; say %s or %s rather than nothing",
			ManifestFileName, line, config.LicenseNone, config.LicenseNoAssertion)
	}
	if !strings.HasPrefix(b.TextURL, "https://") {
		return PinnedBody{}, refuse(ErrInvalidLicenseManifest,
			"%s line %d: text_url %q must be an https URL; a licence text fetched over http is not evidence of anything",
			ManifestFileName, line, b.TextURL)
	}
	if strings.TrimSpace(b.ClaimSource) == "" {
		return PinnedBody{}, refuse(ErrInvalidLicenseManifest,
			"%s line %d: claim_source is empty; a pin with no cited provenance is an assertion",
			ManifestFileName, line)
	}
	if b.SHA256 != "" && !b.Pinned() {
		return PinnedBody{}, refuse(ErrInvalidLicenseManifest,
			"%s line %d: sha256 %q is neither empty (unpinned) nor 64 lower-case hex characters",
			ManifestFileName, line, b.SHA256)
	}
	return b, nil
}

func parseManifestPair(s string, line int) (string, manifestValue, error) {
	eq := strings.Index(s, "=")
	if eq < 0 {
		return "", manifestValue{}, refuse(ErrInvalidLicenseManifest,
			"%s line %d: %q is neither a comment, a table header, nor a key = value pair",
			ManifestFileName, line, s)
	}
	key := strings.TrimSpace(s[:eq])
	rest := strings.TrimSpace(s[eq+1:])
	if key == "" {
		return "", manifestValue{}, refuse(ErrInvalidLicenseManifest,
			"%s line %d: empty key", ManifestFileName, line)
	}

	if strings.HasPrefix(rest, `"`) {
		v, err := unquoteManifestString(rest, line)
		if err != nil {
			return "", manifestValue{}, err
		}
		return key, manifestValue{str: v, line: line}, nil
	}

	// Bare integer. Anything else — booleans, dates, arrays, inline tables,
	// bare words — is refused rather than coerced.
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 {
		return "", manifestValue{}, refuse(ErrInvalidLicenseManifest,
			"%s line %d: value for %q must be a double-quoted string or a non-negative integer, got %q",
			ManifestFileName, line, key, rest)
	}
	return key, manifestValue{num: n, isNum: true, line: line}, nil
}

// unquoteManifestString reads one double-quoted value and refuses trailing
// content after it, so a second value smuggled onto the line cannot be lost.
func unquoteManifestString(s string, line int) (string, error) {
	var out strings.Builder
	i := 1 // past the opening quote
	for i < len(s) {
		c := s[i]
		switch c {
		case '\\':
			if i+1 >= len(s) {
				break
			}
			switch s[i+1] {
			case '"':
				out.WriteByte('"')
			case '\\':
				out.WriteByte('\\')
			default:
				return "", refuse(ErrInvalidLicenseManifest,
					`%s line %d: unsupported escape \%c; this manifest understands \" and \\ only`,
					ManifestFileName, line, s[i+1])
			}
			i += 2
			continue
		case '"':
			trailing := strings.TrimSpace(s[i+1:])
			if trailing != "" && !strings.HasPrefix(trailing, "#") {
				return "", refuse(ErrInvalidLicenseManifest,
					"%s line %d: trailing content %q after the value", ManifestFileName, line, trailing)
			}
			return out.String(), nil
		default:
			out.WriteByte(c)
			i++
			continue
		}
		break
	}
	return "", refuse(ErrInvalidLicenseManifest,
		"%s line %d: unterminated string", ManifestFileName, line)
}

// ---------------------------------------------------------------------------
// Operator-facing verification
// ---------------------------------------------------------------------------

// BodyStatus is one line of a MirrorStatus report.
type BodyStatus struct {
	Pin PinnedBody

	// State is one of the constants below.
	State BodyState

	// ActualSHA256 is the digest of the bytes on disk, when there were any.
	ActualSHA256 string

	// Obligation and SPDXID are what the acquired text actually classifies
	// as. They are reported so that an operator pinning a digest sees the
	// conclusion the gate will draw BEFORE committing the pin.
	Obligation Obligation
	SPDXID     string
}

// BodyState is why a pinned body is or is not usable.
type BodyState int

// The states a pinned body can be in.
const (
	// BodyUnpinned: the manifest records no digest. The feed is refused.
	BodyUnpinned BodyState = iota
	// BodyMissing: pinned, but the text has not been acquired.
	BodyMissing
	// BodyMismatch: acquired, but the bytes do not match the pin.
	BodyMismatch
	// BodyVerified: acquired and matching. The only admissible state.
	BodyVerified
)

// String renders a body state for the status report.
func (s BodyState) String() string {
	switch s {
	case BodyMissing:
		return "MISSING"
	case BodyMismatch:
		return "MISMATCH"
	case BodyVerified:
		return "verified"
	default:
		return "UNPINNED"
	}
}

// MirrorStatus reports, for every pin in the manifest, whether the publisher's
// licence text is present and matches.
//
// It exists so that "why is every feed refused?" has a one-call answer, and so
// that the skipping tests can name the exact artefact that is missing. It
// fetches nothing.
func MirrorStatus(fsys fs.FS) ([]BodyStatus, error) {
	m, err := LoadManifest(fsys)
	if err != nil {
		return nil, err
	}
	out := make([]BodyStatus, 0, len(m.order))
	for _, b := range m.Bodies() {
		st := BodyStatus{Pin: b}
		raw, readErr := fs.ReadFile(fsys, b.Path())
		switch {
		case readErr != nil:
			st.State = BodyMissing
			if !b.Pinned() {
				st.State = BodyUnpinned
			}
		default:
			st.ActualSHA256 = digestOf(string(raw))
			st.SPDXID, st.Obligation = Classify(string(raw))
			switch {
			case !b.Pinned():
				st.State = BodyUnpinned
			case st.ActualSHA256 != b.SHA256:
				st.State = BodyMismatch
			default:
				st.State = BodyVerified
			}
		}
		out = append(out, st)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Pin.FeedID < out[j].Pin.FeedID })
	return out, nil
}

// String renders one status line for a test skip reason or an operator report.
func (s BodyStatus) String() string {
	switch s.State {
	case BodyVerified:
		return fmt.Sprintf("%s: verified %s (%s, %v)", s.Pin.FeedID, s.Pin.Path(), s.SPDXID, s.Obligation)
	case BodyMismatch:
		return fmt.Sprintf("%s: MISMATCH at %s — pinned %s, on disk %s",
			s.Pin.FeedID, s.Pin.Path(), s.Pin.SHA256, s.ActualSHA256)
	case BodyMissing:
		return fmt.Sprintf("%s: MISSING %s — fetch %s and re-run: %s",
			s.Pin.FeedID, s.Pin.Path(), s.Pin.TextURL, AcquireCommand)
	default:
		return fmt.Sprintf("%s: UNPINNED — %s carries no sha256 for %s, so the gate refuses the feed; "+
			"acquire the text (%s), review it, and record its digest",
			s.Pin.FeedID, ManifestFileName, s.Pin.TextURL, AcquireCommand)
	}
}
