// purl.go is the package-identity half of A.17: turning the identity strings a
// collector reports into something a comparator may act on, and REFUSING every
// string it cannot account for.
//
// ---------------------------------------------------------------------------
// WHY IDENTITY IS A SEPARATE PROBLEM FROM VERSION COMPARISON
// ---------------------------------------------------------------------------
//
// research/01 ("Package/dependency vulnerability data vs source-code weakness
// data") settles that purl is the correct identity scheme, and it is the right
// call for a reason worth stating: `openssl` is not one package. It is
// `pkg:deb/debian/openssl`, `pkg:rpm/redhat/openssl`, `pkg:apk/alpine/openssl`
// and half a dozen language ports, and their VERSION STRINGS ARE NOT
// COMPARABLE WITH EACH OTHER. Matching `openssl 3.0.2` against an advisory
// that meant a different `openssl` is the silently-wrong match that this whole
// lane exists to avoid.
//
// So identity resolution runs FIRST and its output includes the version
// SCHEME. A record whose scheme cannot be resolved never reaches a comparator
// at all — it is refused, counted, and reported, because a package Anvil
// cannot identify is a FALSE-NEGATIVE RISK (research/12 §3's documented
// false-negative classes: unpackaged binaries, stripped metadata,
// third-party-repo installs) and the operator has to be able to see it.
//
// ---------------------------------------------------------------------------
// THE TYPE ALLOWLIST IS THREE ENTRIES LONG AND THAT IS DELIBERATE
// ---------------------------------------------------------------------------
//
// SchemeForPurlType and SchemeForEcosystem are ALLOWLISTS. Everything not
// named is refused with a typed reason. This is the shape this project paid
// for three times over: a denylist loses, because the string nobody listed is
// the one that walks through.
//
// The practical consequence is stated plainly in the package doc: this
// comparator covers `deb`, `rpm` and `apk`, and refuses `npm`, `pypi`,
// `golang`, `maven`, `nuget`, `cargo`, `gem`, `composer` and everything else.
// A refusal is a visible gap. A fallback to semver, or to a lexical compare,
// would be an invisible wrong answer.
package match

import (
	"strconv"
	"strings"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Version schemes — the closed set this comparator implements
// ---------------------------------------------------------------------------

// Scheme names a VERSION-ORDERING ALGORITHM, not an ecosystem. Two ecosystems
// may share a scheme (Debian and Ubuntu both order versions by dpkg's
// algorithm) and one ecosystem never has two.
//
// It is a closed set. SchemeValues() is its census and every function that
// accepts a Scheme rejects a value outside it, so a zero-valued Scheme cannot
// be mistaken for a default.
type Scheme string

const (
	// SchemeDebian is dpkg's `deb-version(7)` ordering: an optional numeric
	// epoch, an upstream version, an optional Debian revision, and the
	// alternating digit/non-digit segment comparison in which `~` sorts
	// BEFORE everything including the end of the string. Implemented in
	// dpkg_compare.go.
	SchemeDebian Scheme = "deb"

	// SchemeRPM is rpm's `rpmvercmp` over an epoch:version-release triple,
	// with `~` sorting before and `^` sorting after. The RELEASE field is
	// part of the comparison, which is what makes `2.25.1-3.el9` orderable
	// against `2.25.1-1.el9` at all — and that is the field a distro
	// backport moves. Implemented in rpm_compare.go.
	SchemeRPM Scheme = "rpm"

	// SchemeAPK is Alpine's apk ordering: dotted numeric parts, an optional
	// trailing letter, `_`-separated suffixes with their own documented rank
	// order, and an `-rN` package revision. Implemented in apk_compare.go.
	SchemeAPK Scheme = "apk"
)

// schemeOrder is the canonical ordering of Scheme values. It exists so that
// SchemeValues() and every sorted report over schemes agree, without ranging
// over a map.
var schemeOrder = []Scheme{SchemeDebian, SchemeRPM, SchemeAPK}

// SchemeValues returns every implemented scheme, in canonical order. It
// returns a fresh slice so a caller cannot mutate the census.
func SchemeValues() []Scheme {
	out := make([]Scheme, len(schemeOrder))
	copy(out, schemeOrder)
	return out
}

// Valid reports whether s is one of the implemented schemes.
func (s Scheme) Valid() bool {
	for _, k := range schemeOrder {
		if s == k {
			return true
		}
	}
	return false
}

// String renders the scheme, or "<invalid scheme>" for anything outside the
// closed set — including the zero value, which must never print as an empty
// string in an error message.
func (s Scheme) String() string {
	if s.Valid() {
		return string(s)
	}
	if s == "" {
		return "<unset scheme>"
	}
	return "<invalid scheme " + strconv.Quote(string(s)) + ">"
}

// ---------------------------------------------------------------------------
// Ecosystem and purl-type allowlists
// ---------------------------------------------------------------------------

// EcosystemDeb, EcosystemRPM and EcosystemAPK are the Lane-A-local ecosystem
// vocabulary. They are declared here rather than imported because
// internal/collector/host (which declares the same three) links os/exec and
// internal/ingest/cache links a SQL driver, and neither belongs in the
// comparator's dependency graph.
//
// That duplication is the kind that drifts, so it is ENFORCED rather than
// documented: comparator_test.go imports both packages (a test may) and fails
// if any of these three constants stops equalling its counterpart.
const (
	EcosystemDeb = "deb"
	EcosystemRPM = "rpm"
	EcosystemAPK = "apk"
)

// CollectorHost and CollectorRepoSCA mirror internal/ingest/cache's `finding`
// collector vocabulary, for the same reason and under the same test.
const (
	CollectorHost    = "host"
	CollectorRepoSCA = "repo-sca"
)

// ecosystemAllowlist maps an `affected.ecosystem` / inventory ecosystem string
// to the scheme that orders its versions.
//
// It is EXACT-MATCH and case-sensitive on purpose. "Debian:11", "Alpine:v3.19"
// and "Red Hat" are real ecosystem spellings in OSV, and normalising them here
// would put a second, undocumented identity mapping inside the comparator. The
// ingestion layer owns normalisation into this vocabulary; anything that
// reaches here unnormalised is refused with the string it carried, which is
// exactly the report an operator needs in order to fix the ingestion mapping.
var ecosystemAllowlist = map[string]Scheme{
	EcosystemDeb: SchemeDebian,
	EcosystemRPM: SchemeRPM,
	EcosystemAPK: SchemeAPK,
}

// purlTypeAllowlist maps a purl `type` to a scheme. The three entries are the
// purl-spec types for the three OS package managers this comparator
// implements: `pkg:deb/debian/openssl@3.0.11-1~deb12u2`,
// `pkg:rpm/redhat/python-requests@2.25.1-3.el9`,
// `pkg:apk/alpine/openssl@3.1.4-r5`.
var purlTypeAllowlist = map[string]Scheme{
	"deb": SchemeDebian,
	"rpm": SchemeRPM,
	"apk": SchemeAPK,
}

// SchemeForEcosystem resolves an ecosystem string to its version scheme.
//
// The error is a *Refusal carrying RefusalUnsupportedEcosystem, so a caller
// that swallows it still produces a countable gap rather than a silent one.
func SchemeForEcosystem(ecosystem string) (Scheme, error) {
	s, ok := ecosystemAllowlist[ecosystem]
	if !ok {
		return "", &Refusal{
			Reason:    RefusalUnsupportedEcosystem,
			Ecosystem: ecosystem,
			Detail: "no version comparator is implemented for this ecosystem; implemented schemes are " +
				joinSchemes(schemeOrder),
		}
	}
	return s, nil
}

// SchemeForPurlType resolves a purl type to its version scheme. The type is
// lowercased first because the purl specification defines the type segment as
// case-insensitive with a lowercase canonical form.
func SchemeForPurlType(purlType string) (Scheme, error) {
	canonical := strings.ToLower(purlType)
	s, ok := purlTypeAllowlist[canonical]
	if !ok {
		return "", &Refusal{
			Reason: RefusalUnsupportedPurlType,
			// PurlType carries the CANONICAL form because
			// CoverageReport.EcosystemsRefused deduplicates on it: "npm" and
			// "NPM" are one thing to implement, not two. Detail keeps the
			// spelling that actually arrived, because that is what an
			// operator greps their collector output for.
			PurlType: canonical,
			Detail: "no version comparator is implemented for purl type " + strconv.Quote(purlType) +
				"; implemented schemes are " + joinSchemes(schemeOrder),
		}
	}
	return s, nil
}

func joinSchemes(ss []Scheme) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = string(s)
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// purl parsing
// ---------------------------------------------------------------------------

// Purl is a parsed package URL: `pkg:type/namespace/name@version?qualifiers#subpath`.
//
// Every component is percent-DECODED, because two collectors may encode the
// same identity differently ("%40angular/core" and, in a lenient producer,
// "@angular/core" is illegal but "%2Bbuild" versus "+build" is not) and an
// identity comparison over raw text would treat them as different packages.
type Purl struct {
	// Type is the lowercased purl type: "deb", "rpm", "apk", "npm", ...
	// Parsing does NOT require the type to be one this comparator supports;
	// that is SchemeForPurlType's decision, kept separate so a refusal names
	// the type rather than reporting a parse failure.
	Type string
	// Namespace is the decoded namespace, "/"-joined, empty when absent.
	// For OS packages it is the distro: "debian", "ubuntu", "redhat",
	// "alpine".
	Namespace string
	// Name is the decoded package name. Never empty in a valid purl.
	Name string
	// Version is the decoded version, empty when the purl carries none.
	Version string
	// Qualifiers are the decoded `?k=v&k=v` pairs, SORTED BY KEY. Sorting is
	// not cosmetic: it is what lets two purls that differ only in qualifier
	// order compare equal, and it is one of the places a map range would
	// have made this package's output depend on Go's per-process map seed.
	Qualifiers []Qualifier
	// Subpath is the decoded `#subpath`, empty when absent.
	Subpath string
}

// Qualifier is one decoded purl qualifier.
type Qualifier struct {
	Key   string
	Value string
}

// Qualifier returns the value for key and whether it was present.
func (p Purl) Qualifier(key string) (string, bool) {
	for _, q := range p.Qualifiers {
		if q.Key == key {
			return q.Value, true
		}
	}
	return "", false
}

// Base returns the version-free base purl, delegating to record.PurlBase.
//
// It DELEGATES rather than reimplements because record.PurlBase is the
// enforcement point for anvil-fp/v1's rule that the version string is never
// hashed. A second base-purl derivation in this package would be a second
// answer to a question the record contract already froze.
func (p Purl) Base() (string, error) {
	return record.PurlBase(p.String())
}

// String renders the purl in canonical form: lowercased scheme and type,
// qualifiers sorted by key, components percent-encoded again.
func (p Purl) String() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	if p.Namespace != "" {
		for _, seg := range strings.Split(p.Namespace, "/") {
			b.WriteByte('/')
			b.WriteString(purlEncode(seg))
		}
	}
	b.WriteByte('/')
	b.WriteString(purlEncode(p.Name))
	if p.Version != "" {
		b.WriteByte('@')
		b.WriteString(purlEncode(p.Version))
	}
	for i, q := range p.Qualifiers {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		b.WriteString(q.Key)
		b.WriteByte('=')
		b.WriteString(purlEncode(q.Value))
	}
	if p.Subpath != "" {
		// The subpath is percent-encoded SEGMENT BY SEGMENT, for the same
		// reason the namespace is: purlEncode escapes '/', so encoding the
		// joined string would turn a path into a single opaque segment.
		// Encoding it at all is not cosmetic — identity.Purl is this
		// re-rendered form and it lands in MatchResult.Purl, so a subpath
		// carrying a reserved byte must round-trip through ParsePurl.
		b.WriteByte('#')
		for i, seg := range strings.Split(p.Subpath, "/") {
			if i > 0 {
				b.WriteByte('/')
			}
			b.WriteString(purlEncode(seg))
		}
	}
	return b.String()
}

// ParsePurl parses a package URL. It follows the purl specification's own
// parsing order: subpath, then qualifiers, then the "pkg:" scheme, then
// version, then type, then namespace/name.
//
// It is STRICT. A missing type, a missing name, an unparseable percent escape,
// a duplicate qualifier key or a qualifier key outside the specification's
// character set is a *Refusal carrying RefusalMalformedPurl, never a
// best-effort result. A purl is an IDENTITY; a half-understood identity is how
// a finding gets attached to the wrong package.
func ParsePurl(raw string) (Purl, error) {
	bad := func(detail string) (Purl, error) {
		return Purl{}, &Refusal{
			Reason: RefusalMalformedPurl,
			Detail: detail + " (purl " + strconv.Quote(raw) + ")",
		}
	}

	s := strings.TrimSpace(raw)
	if s == "" {
		return bad("purl is empty")
	}
	if strings.ContainsAny(s, " \t\r\n") {
		return bad("purl contains whitespace")
	}

	var p Purl

	// 1. Subpath.
	if i := strings.IndexByte(s, '#'); i >= 0 {
		sub, err := purlDecode(s[i+1:])
		if err != nil {
			return bad("subpath: " + err.Error())
		}
		p.Subpath = strings.Trim(sub, "/")
		s = s[:i]
	}

	// 2. Qualifiers.
	if i := strings.IndexByte(s, '?'); i >= 0 {
		qs, err := parseQualifiers(s[i+1:])
		if err != nil {
			return bad(err.Error())
		}
		p.Qualifiers = qs
		s = s[:i]
	}

	// 3. Scheme.
	if len(s) < 4 || !strings.EqualFold(s[:4], "pkg:") {
		return bad(`purl must begin with "pkg:"`)
	}
	s = strings.TrimLeft(s[4:], "/")
	if s == "" {
		return bad("purl carries no type or name")
	}

	// 4. Version. The purl specification requires a literal '@' inside a
	// namespace or name to be percent-encoded, so the FIRST raw '@' can only
	// be the version delimiter.
	if i := strings.IndexByte(s, '@'); i >= 0 {
		v, err := purlDecode(s[i+1:])
		if err != nil {
			return bad("version: " + err.Error())
		}
		p.Version = v
		s = s[:i]
	}

	// 5. Type.
	i := strings.IndexByte(s, '/')
	if i < 0 {
		return bad("purl carries a type but no name")
	}
	p.Type = strings.ToLower(s[:i])
	if err := validPurlType(p.Type); err != nil {
		return bad(err.Error())
	}
	s = s[i+1:]

	// 6. Namespace and name. Empty segments are dropped, per the
	// specification's "remove empty segments" rule.
	var segs []string
	for _, seg := range strings.Split(s, "/") {
		if seg == "" {
			continue
		}
		dec, err := purlDecode(seg)
		if err != nil {
			return bad("path segment: " + err.Error())
		}
		if dec == "" {
			return bad("path segment decodes to an empty string")
		}
		segs = append(segs, dec)
	}
	if len(segs) == 0 {
		return bad("purl carries no name")
	}
	p.Name = segs[len(segs)-1]
	if len(segs) > 1 {
		p.Namespace = strings.Join(segs[:len(segs)-1], "/")
	}

	return p, nil
}

// validPurlType enforces the specification's type grammar. It is an ALLOWLIST
// of characters: an ASCII letter first, then letters, digits, '.', '+' and
// '-'. Anything else — a '%', a slash that survived the split, a non-ASCII
// byte — is refused.
func validPurlType(t string) error {
	if t == "" {
		return errString("purl type is empty")
	}
	if !isASCIILower(t[0]) {
		return errString("purl type must start with an ASCII letter, got " + strconv.Quote(t))
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case isASCIILower(c), isDigit(c), c == '.', c == '+', c == '-':
		default:
			return errString("purl type contains an illegal character " + strconv.Quote(string(c)) +
				": " + strconv.Quote(t))
		}
	}
	return nil
}

// parseQualifiers parses `k=v&k=v`, lowercasing keys, decoding values, and
// dropping pairs with an empty value (the specification says an empty value is
// the same as the qualifier being absent). A duplicate key is a refusal, not a
// last-one-wins: two conflicting `distro=` values mean the producer disagrees
// with itself and this comparator must not pick a winner.
func parseQualifiers(s string) ([]Qualifier, error) {
	if s == "" {
		return nil, nil
	}
	var out []Qualifier
	seen := make(map[string]bool)
	for _, pair := range strings.Split(s, "&") {
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			return nil, errString("qualifier " + strconv.Quote(pair) + " has no '='")
		}
		key := strings.ToLower(pair[:eq])
		if err := validQualifierKey(key); err != nil {
			return nil, err
		}
		val, err := purlDecode(pair[eq+1:])
		if err != nil {
			return nil, errString("qualifier " + strconv.Quote(key) + ": " + err.Error())
		}
		if val == "" {
			continue
		}
		if seen[key] {
			return nil, errString("qualifier key " + strconv.Quote(key) + " appears more than once")
		}
		seen[key] = true
		out = append(out, Qualifier{Key: key, Value: val})
	}
	// Sort by key. insertionSortQualifiers rather than sort.Slice keeps this
	// file's import list at the four packages the dependency guard allows.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Key < out[j-1].Key; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

// validQualifierKey enforces the specification's key grammar as an allowlist:
// lowercase ASCII letters, digits, '.', '-' and '_', starting with a letter.
func validQualifierKey(k string) error {
	if k == "" {
		return errString("qualifier key is empty")
	}
	if !isASCIILower(k[0]) {
		return errString("qualifier key must start with an ASCII letter: " + strconv.Quote(k))
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case isASCIILower(c), isDigit(c), c == '.', c == '-', c == '_':
		default:
			return errString("qualifier key contains an illegal character " +
				strconv.Quote(string(c)) + ": " + strconv.Quote(k))
		}
	}
	return nil
}

// purlDecode percent-decodes one purl component. It is written here rather
// than taken from net/url because net/url's decoders each apply an
// encoding-specific rule ('+' means space in a query, but '+' is a LITERAL
// PLUS in a version string, and "1.0+deb11u1" decoded as "1.0 deb11u1" is a
// version no comparator will ever match).
func purlDecode(s string) (string, error) {
	if !strings.ContainsRune(s, '%') {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", errString("truncated percent escape")
		}
		hi, ok1 := hexNibble(s[i+1])
		lo, ok2 := hexNibble(s[i+2])
		if !ok1 || !ok2 {
			return "", errString("invalid percent escape " + strconv.Quote(s[i:i+3]))
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

// purlEncode is purlDecode's inverse over the specification's unreserved set
// plus the characters that appear unencoded in real package versions.
func purlEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isASCIILower(c) || isASCIIUpper(c) || isDigit(c):
			b.WriteByte(c)
		case c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == ':' || c == '^':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// ---------------------------------------------------------------------------
// Byte classifiers
// ---------------------------------------------------------------------------
//
// These are ASCII-only by construction. A package version is not free text:
// dpkg, rpm and apk all define their grammars over ASCII, and a Unicode-aware
// classifier would silently accept a Cyrillic 'а' where an ASCII 'a' was meant
// and then order it somewhere no upstream tool would.

func isDigit(c byte) bool      { return c >= '0' && c <= '9' }
func isASCIILower(c byte) bool { return c >= 'a' && c <= 'z' }
func isASCIIUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isAlpha(c byte) bool      { return isASCIILower(c) || isASCIIUpper(c) }
func isAlnum(c byte) bool      { return isAlpha(c) || isDigit(c) }

// errString is a minimal error value. It exists so this package's error
// construction needs neither `errors` nor `fmt` in the hot path, keeping the
// direct-import allowlist that comparator_test.go enforces as short as it is.
type errString string

func (e errString) Error() string { return string(e) }
