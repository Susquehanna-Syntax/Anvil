// Package target parses `.anvil/target.yaml`, the DECLARED description of a
// repository's runtime target, and decides -- once, in one place -- whether the
// DAST half has a target to work with at all.
//
// The one sentence that governs every decision in this file, from
// plan/design/dynamic-tier.md's "Target Manifest Schema" section:
//
//	Declared only -- Anvil never infers how to run a repo.
//
// So there is no Dockerfile sniffing here, no framework detection, no "find the
// compose file" search, and no port guessing. If the operator did not write it
// down, it does not exist. TestNoInferenceFromRepoContents pins that: a repo
// carrying a docker-compose.yml, a Dockerfile and a package.json but no
// manifest yields SkipReasonNoManifest and a nil Manifest.
//
// # The distinction this package exists to keep
//
// "No manifest" and "manifest present but broken" are DIFFERENT OUTCOMES and
// must never collapse into one value:
//
//   - SkipReasonNoManifest is a legitimate opt-out. The repo declared no
//     runtime target; the scan proceeds SAST-only. It is not an error, and
//     Load returns a nil error for it.
//   - SkipReasonInvalidManifest is a REFUSAL. The repo tried to opt in and the
//     opt-in is broken. Load returns the reason AND a non-nil error describing
//     what is wrong, so a caller that only checks `err != nil` still refuses
//     and a caller that only reads the SkipReason still sees a distinct value.
//
// If those two collapsed, an operator could not tell "we never wrote one" from
// "we wrote a broken one", and the second would silently read as the first --
// which is the reading the spine's record section forbids ("a target that failed to
// boot must be distinguishable from scanned clean").
//
// # Strictness
//
// Unknown fields REJECT, they do not warn. Malformed input REJECTS. Nothing
// degrades to a permissive default. Every accepted construct is on an
// allowlist -- key names, URL schemes, reset strategies, auth methods, scalar
// shapes -- because a denylist of "bad YAML" loses to the first construct
// nobody thought of.
//
// # Why there is a YAML decoder in here
//
// Anvil's module graph carries exactly one dependency (modernc.org/sqlite) and
// a YAML library is not on the table; internal/policy took the same route for
// the same reason. The decoder below implements a deliberately small subset --
// block mappings, block and flow sequences of scalars, quoted and plain
// scalars -- and REFUSES everything else (anchors, aliases, tags, block
// scalars, multi-document streams, flow mappings, nested collections inside
// sequences, tabs). Refusing an unsupported construct is safe; guessing at one
// is not.
package target

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Declared constants
// ---------------------------------------------------------------------------

const (
	// SchemaVersion is the only `schema_version` this loader accepts. A
	// future version gets an explicit branch here; it never gets silently
	// accepted because the field was absent or unrecognised.
	SchemaVersion = 1

	// ManifestDirName, ManifestFileName and DefaultRelPath are the ONE
	// declared location. Anvil does not search for a manifest: there is
	// exactly one path, and Load refuses a file that is not at it. A search
	// path is inference wearing a different hat.
	ManifestDirName  = ".anvil"
	ManifestFileName = "target.yaml"
	DefaultRelPath   = ManifestDirName + "/" + ManifestFileName

	// ResetStrategyDestroyRecreate is the only `reset.strategy` v1 supports.
	// plan/design/dynamic-tier.md: snapshot/restore is reserved for a future Firecracker
	// tier and is unsafe for anything holding a real credential. The field is
	// REQUIRED rather than defaulted precisely so that adding a second value
	// later cannot change an existing manifest's behaviour by omission.
	ResetStrategyDestroyRecreate = "destroy_recreate"

	// AuthMethodBrowser is the only `auth.method` v1 supports -- the ZAP
	// Authentication Helper's scripted browser flow. Never autodetection.
	AuthMethodBrowser = "browser"
)

// Bounds. Each is a refusal threshold, never a default that widens anything.
const (
	maxManifestBytes = 64 << 10
	maxScalarBytes   = 2048
	maxSeedArgs      = 64
	maxEndpoints     = 64
	maxEgressEntries = 64

	minTimeoutSeconds  = 1
	maxTimeoutSeconds  = 3600
	minIntervalSeconds = 1
	maxIntervalSeconds = 300

	// The three defaulted values. All three are TIMEOUTS -- i.e. caps on how
	// long Anvil will wait -- so a default narrows behaviour rather than
	// widening it. No field that grants, authorizes or widens anything has a
	// default; those are all required.
	defaultHealthTimeoutSeconds  = 120
	defaultHealthIntervalSeconds = 5
	defaultSeedTimeoutSeconds    = 60
)

// ErrInvalidManifest wraps every schema-invalid refusal, so a caller can
// errors.Is against one sentinel instead of string-matching diagnostics.
var ErrInvalidManifest = errors.New("target manifest is schema-invalid")

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidManifest, fmt.Sprintf(format, args...))
}

// ---------------------------------------------------------------------------
// SkipReason
// ---------------------------------------------------------------------------

// SkipReason is why (or whether) the DAST half is skipped for this repo.
//
// FAIL CLOSED: the zero value is SkipReasonUnset, which is NOT valid and which
// Skips() reports as skipping. A Go zero value never means "DAST is
// authorized to proceed" -- reaching that state takes an explicit
// SkipReasonNotSkipped from a successful Load.
type SkipReason string

const (
	// SkipReasonUnset is the zero value. It is not a legal outcome; it means
	// nobody has decided yet. Skips() is true for it and RecordOutcome()
	// refuses it.
	SkipReasonUnset SkipReason = ""

	// SkipReasonNoManifest: no `.anvil/target.yaml` exists. A legitimate
	// opt-out, not an error.
	SkipReasonNoManifest SkipReason = "no_manifest"

	// SkipReasonInvalidManifest: a manifest exists and is broken. A refusal.
	// Load pairs this with a non-nil error.
	SkipReasonInvalidManifest SkipReason = "invalid_manifest"

	// SkipReasonNotSkipped: a valid manifest was loaded. The DAST half has a
	// declared target. This is the only value that does not skip, and it is
	// deliberately not the zero value.
	SkipReasonNotSkipped SkipReason = "not_skipped"
)

// SkipReasonValues returns every legal SkipReason, excluding the zero value.
func SkipReasonValues() []SkipReason {
	return []SkipReason{SkipReasonNoManifest, SkipReasonInvalidManifest, SkipReasonNotSkipped}
}

// Valid reports whether r is one of the three legal outcomes. SkipReasonUnset
// is not one of them.
func (r SkipReason) Valid() bool {
	for _, v := range SkipReasonValues() {
		if r == v {
			return true
		}
	}
	return false
}

// Skips reports whether the DAST half must be skipped. Everything that is not
// an explicit SkipReasonNotSkipped skips, including the zero value and any
// value this package does not recognise.
func (r SkipReason) Skips() bool { return r != SkipReasonNotSkipped }

// RecordOutcome maps a skip onto the record area's frozen record enums.
//
// The two record fields are DIFFERENT MEASUREMENTS and are both returned:
// record.DastStatus is the DAST half's outcome, record.TargetProvenance is the
// boot/reachability outcome. The first plan's target-provenance split separated
// them and forbids merging them back.
//
// WHY SkipReasonInvalidManifest DOES NOT MAP TO skipped_no_manifest -- this is
// a deliberate departure from plan/design/dynamic-tier.md's "same downstream effect as a
// missing file", and it is flagged for the orchestrator:
//
// The frozen ten-value dast_status enum has no "manifest present but broken"
// literal, and neither the audit record nor record.Target carries a free-form
// reason string. So mapping the invalid case onto skipped_no_manifest would
// erase, in the record, exactly the distinction this package exists to keep --
// the record would state that no manifest was declared, which is false. The
// pair (target_boot_failed, build_failed) is the closest honest fit: a broken
// manifest means provisioning never got off the ground and no boot was ever
// attempted, which is what record.TargetProvenanceBuildFailed documents, and
// record.TargetProvenance's own doc comment states the derivation
// build_failed -> target_boot_failed. Both fields then differ from the
// no-manifest case, and neither reads as "scanned clean".
//
// SkipReasonNotSkipped returns an error: when DAST actually runs, its outcome
// is the run's to report, not the loader's.
func (r SkipReason) RecordOutcome() (record.DastStatus, record.TargetProvenance, error) {
	switch r {
	case SkipReasonNoManifest:
		return record.DastStatusSkippedNoManifest, record.TargetProvenanceNoTargetDeclared, nil
	case SkipReasonInvalidManifest:
		return record.DastStatusTargetBootFailed, record.TargetProvenanceBuildFailed, nil
	case SkipReasonNotSkipped:
		return "", "", fmt.Errorf("target: %q is not a skip; the DAST run reports its own outcome", string(r))
	default:
		return "", "", fmt.Errorf("target: %q is not a legal SkipReason", string(r))
	}
}

// ---------------------------------------------------------------------------
// AuthorizedService -- exactly one, structurally
// ---------------------------------------------------------------------------

// AuthorizedService is the single Compose service Anvil may probe.
//
// plan/design/dynamic-tier.md: every other service in the Compose file is provisioned (for
// realistic dependencies) and is NOT a probe target. That is enforced by TYPE,
// not by convention: this is a struct wrapping ONE unexported string, so
//
//   - no package outside this one can construct a populated value, and
//   - there is no slice, map or variadic anywhere in the API that a later
//     change could append a second service to. Widening the authorization
//     would require changing this type, which is a visible, reviewable edit.
//
// FAIL CLOSED: the zero value has an empty name and Authorizes() returns false
// for every input including the empty string.
type AuthorizedService struct {
	name string
}

// Name returns the authorized Compose service name, or "" for the zero value.
func (s AuthorizedService) Name() string { return s.name }

// IsZero reports whether no service is authorized.
func (s AuthorizedService) IsZero() bool { return s.name == "" }

// Authorizes reports whether name is THE authorized service. The zero value
// authorizes nothing, and "" is never authorized.
func (s AuthorizedService) Authorizes(name string) bool {
	return s.name != "" && name != "" && name == s.name
}

// ---------------------------------------------------------------------------
// The manifest
// ---------------------------------------------------------------------------

// Manifest is a parsed, validated `.anvil/target.yaml`.
//
// String path fields hold the declared text verbatim (e.g. the leading "./"),
// which is what makes Marshal a byte-for-byte round trip. Use the resolver
// methods to turn them into filesystem paths.
type Manifest struct {
	SchemaVersion int
	ComposeFile   string
	Health        Health
	Reset         Reset

	// Optional sections. Nil means the section was absent. An empty-but-
	// present section is a refusal, not an empty struct -- writing `seed:`
	// with nothing under it is an authoring mistake, not a declaration.
	Seed      *Seed
	Auth      *Auth
	Inventory *Inventory
	Scope     *Scope

	// service is unexported so that AuthorizedService is the only way out.
	service AuthorizedService
}

// Health is the required health definition. plan/design/dynamic-tier.md: no health
// definition means no DAST -- provisioning aborts.
type Health struct {
	URL             string
	TimeoutSeconds  int
	IntervalSeconds int
}

// Seed runs once after health passes and before any probe fires.
type Seed struct {
	// Command is exec form -- argv, never a shell string. A bare string is
	// refused at parse time because it would imply shell interpretation of
	// operator-supplied text.
	Command        []string
	TimeoutSeconds int
}

// Reset declares how the target is returned to a known state.
type Reset struct {
	Strategy string
}

// Auth is consumed by the ZAP Authentication Helper (Tier 3 only).
type Auth struct {
	Method   string
	StepsRef string
}

// Inventory optionally overrides the Tier 0 runtime spec probe list. Config,
// never hard-coded, and never autodetected.
type Inventory struct {
	RuntimeSpecEndpoints []string
}

// Scope narrows what the scope layer permits WITHIN what the authorization
// kernel already allows.
//
// This field grants nothing. plan/design/dynamic-tier.md is explicit that anything listed
// here still passes through the kernel's non-configurable reserved-range
// denylist (gate 10), which lives in the authorization kernel, not here. This
// package validates the SYNTAX of these entries and nothing else; it makes no
// claim about what they are permitted to reach.
type Scope struct {
	AdditionalEgressAllow []string
}

// AuthorizedService returns the single service Anvil may probe.
func (m *Manifest) AuthorizedService() AuthorizedService { return m.service }

// Provisioning reports which provisioning path a manifest implies. A manifest
// always means Anvil builds and runs the target itself, in its own sandbox --
// record.TargetProvisioningEphemeralManifest. The other literal
// (live_url_authorized) is reachable only through the external-mode
// authorization path, which does not read this file.
//
// Note that this is anvil/target.provisioning, NOT anvil/target.provenance.
// The two were one field until the first plan's target-provenance split
// separated them; see record.TargetProvisioning's doc comment.
func (m *Manifest) Provisioning() record.TargetProvisioning {
	return record.TargetProvisioningEphemeralManifest
}

// ComposeFilePath resolves ComposeFile against repoRoot.
func (m *Manifest) ComposeFilePath(repoRoot string) string {
	return filepath.Join(repoRoot, filepath.FromSlash(path.Clean(m.ComposeFile)))
}

// AuthStepsPath resolves Auth.StepsRef against repoRoot. Returns "" when no
// auth section was declared.
func (m *Manifest) AuthStepsPath(repoRoot string) string {
	if m.Auth == nil {
		return ""
	}
	return filepath.Join(repoRoot, filepath.FromSlash(path.Clean(m.Auth.StepsRef)))
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

// LoadInRepo loads the manifest at repoRoot/.anvil/target.yaml. This is the
// entry point Anvil itself uses; there is no search and no fallback path.
func LoadInRepo(repoRoot string) (*Manifest, SkipReason, error) {
	if strings.TrimSpace(repoRoot) == "" {
		return nil, SkipReasonInvalidManifest, invalidf("repo root is empty")
	}
	return Load(filepath.Join(repoRoot, ManifestDirName, ManifestFileName))
}

// Load reads and validates the manifest at path.
//
// Outcomes, and only these:
//
//	(m,   SkipReasonNotSkipped,      nil)  -- valid manifest
//	(nil, SkipReasonNoManifest,      nil)  -- no file. NOT an error.
//	(nil, SkipReasonInvalidManifest, err)  -- a refusal, err says why.
//
// The non-nil error on the invalid path is a deliberate strengthening of
// plan/design/dynamic-tier.md's `(nil, SkipReasonInvalidManifest, nil)`: a caller that
// only tests `err != nil` must not be able to read a broken opt-in as a clean
// skip. The SkipReason is exactly as the plan specifies, so a caller that
// switches on it is unaffected.
//
// path must be a `.anvil/target.yaml`; the repo root is its grandparent. Any
// other layout is refused rather than accommodated, because accommodating it
// would mean guessing where the repo root is, and the repo root is what
// compose_file and auth.steps_ref are resolved against.
func Load(path string) (*Manifest, SkipReason, error) {
	if strings.TrimSpace(path) == "" {
		return nil, SkipReasonInvalidManifest, invalidf("manifest path is empty")
	}

	// Existence is decided FIRST and on its own, so that a wrong-layout path
	// that happens not to exist is still just "no manifest".
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, SkipReasonNoManifest, nil
		}
		return nil, SkipReasonInvalidManifest, invalidf("cannot stat %s: %v", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, SkipReasonInvalidManifest,
			invalidf("%s is not a regular file (mode %s)", path, info.Mode())
	}
	if info.Size() > maxManifestBytes {
		return nil, SkipReasonInvalidManifest,
			invalidf("%s is %d bytes; the limit is %d", path, info.Size(), maxManifestBytes)
	}

	if err := checkLayout(path); err != nil {
		return nil, SkipReasonInvalidManifest, err
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, SkipReasonInvalidManifest, invalidf("cannot read %s: %v", path, err)
	}

	m, err := Parse(raw)
	if err != nil {
		return nil, SkipReasonInvalidManifest, err
	}

	repoRoot := filepath.Dir(filepath.Dir(path))
	if err := m.validateFilesystem(repoRoot); err != nil {
		return nil, SkipReasonInvalidManifest, err
	}
	return m, SkipReasonNotSkipped, nil
}

// checkLayout enforces the single declared location.
func checkLayout(p string) error {
	if filepath.Base(p) != ManifestFileName {
		return invalidf("manifest must be named %q, got %q", ManifestFileName, filepath.Base(p))
	}
	dir := filepath.Dir(p)
	if filepath.Base(dir) != ManifestDirName {
		return invalidf("manifest must live in a %q directory, got %q", ManifestDirName, filepath.Base(dir))
	}
	return nil
}

// Parse decodes and shape-validates manifest bytes without touching the
// filesystem. Load calls it; tests use it to exercise the schema without
// materialising a repo.
func Parse(raw []byte) (*Manifest, error) {
	if err := checkBytes(raw); err != nil {
		return nil, err
	}
	doc, err := decodeYAML(string(raw))
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, invalidf("manifest is empty")
	}
	return fromDocument(doc)
}

// checkBytes refuses anything that is not printable UTF-8 text. Control
// characters other than LF and CR are refused outright rather than escaped,
// which also removes tabs -- and with them every "was that indentation?"
// question the decoder would otherwise have to answer.
func checkBytes(raw []byte) error {
	if !utf8.Valid(raw) {
		return invalidf("manifest is not valid UTF-8")
	}
	for i, b := range raw {
		if b == '\n' || b == '\r' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			return invalidf("byte %d is control character 0x%02x; manifests are printable UTF-8 text "+
				"(tabs are not permitted for indentation)", i, b)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Document -> Manifest
// ---------------------------------------------------------------------------

// The accepted key sets. These are allowlists: a key that is not here is a
// refusal. plan/design/dynamic-tier.md's own reason for strictness is that a typo like
// `helth:` would otherwise parse cleanly, disable the health gate, and
// silently mean "no DAST" forever.
var (
	keysRoot = []string{
		"schema_version", "compose_file", "service",
		"health", "seed", "reset", "auth", "inventory", "scope",
	}
	keysHealth    = []string{"url", "timeout_seconds", "interval_seconds"}
	keysSeed      = []string{"command", "timeout_seconds"}
	keysReset     = []string{"strategy"}
	keysAuth      = []string{"method", "steps_ref"}
	keysInventory = []string{"runtime_spec_endpoints"}
	keysScope     = []string{"additional_egress_allow"}
)

func fromDocument(doc any) (*Manifest, error) {
	top, err := asMapping(doc, "")
	if err != nil {
		return nil, err
	}
	if err := checkKeys(top, keysRoot, ""); err != nil {
		return nil, err
	}

	m := &Manifest{}

	version, err := intAt(top, "schema_version", "")
	if err != nil {
		return nil, err
	}
	if version != SchemaVersion {
		return nil, invalidf("schema_version: %d is not supported; this loader accepts %d only",
			version, SchemaVersion)
	}
	m.SchemaVersion = version

	composeFile, err := stringAt(top, "compose_file", "")
	if err != nil {
		return nil, err
	}
	if err := checkRepoRelPath(composeFile, "compose_file"); err != nil {
		return nil, err
	}
	if err := checkYAMLExt(composeFile, "compose_file"); err != nil {
		return nil, err
	}
	m.ComposeFile = composeFile

	serviceName, err := stringAt(top, "service", "")
	if err != nil {
		return nil, err
	}
	if err := checkServiceName(serviceName); err != nil {
		return nil, err
	}
	m.service = AuthorizedService{name: serviceName}

	healthDoc, err := requiredSection(top, "health", keysHealth)
	if err != nil {
		return nil, err
	}
	if m.Health, err = healthFrom(healthDoc, m.service); err != nil {
		return nil, err
	}

	resetDoc, err := requiredSection(top, "reset", keysReset)
	if err != nil {
		return nil, err
	}
	if m.Reset, err = resetFrom(resetDoc); err != nil {
		return nil, err
	}

	if seedDoc, present, err := optionalSection(top, "seed", keysSeed); err != nil {
		return nil, err
	} else if present {
		seed, err := seedFrom(seedDoc)
		if err != nil {
			return nil, err
		}
		m.Seed = &seed
	}

	if authDoc, present, err := optionalSection(top, "auth", keysAuth); err != nil {
		return nil, err
	} else if present {
		auth, err := authFrom(authDoc)
		if err != nil {
			return nil, err
		}
		m.Auth = &auth
	}

	if invDoc, present, err := optionalSection(top, "inventory", keysInventory); err != nil {
		return nil, err
	} else if present {
		inv, err := inventoryFrom(invDoc)
		if err != nil {
			return nil, err
		}
		m.Inventory = &inv
	}

	if scopeDoc, present, err := optionalSection(top, "scope", keysScope); err != nil {
		return nil, err
	} else if present {
		sc, err := scopeFrom(scopeDoc)
		if err != nil {
			return nil, err
		}
		m.Scope = &sc
	}

	return m, nil
}

func healthFrom(doc map[string]any, svc AuthorizedService) (Health, error) {
	var h Health

	rawURL, err := stringAt(doc, "url", "health")
	if err != nil {
		return h, err
	}
	if err := checkHealthURL(rawURL, svc); err != nil {
		return h, err
	}
	h.URL = rawURL

	if h.TimeoutSeconds, err = optionalBoundedInt(doc, "timeout_seconds", "health",
		defaultHealthTimeoutSeconds, minTimeoutSeconds, maxTimeoutSeconds); err != nil {
		return h, err
	}
	if h.IntervalSeconds, err = optionalBoundedInt(doc, "interval_seconds", "health",
		defaultHealthIntervalSeconds, minIntervalSeconds, maxIntervalSeconds); err != nil {
		return h, err
	}
	if h.IntervalSeconds > h.TimeoutSeconds {
		return h, invalidf("health.interval_seconds (%d) exceeds health.timeout_seconds (%d); "+
			"the health check would never poll", h.IntervalSeconds, h.TimeoutSeconds)
	}
	return h, nil
}

func resetFrom(doc map[string]any) (Reset, error) {
	strategy, err := stringAt(doc, "strategy", "reset")
	if err != nil {
		return Reset{}, err
	}
	if strategy != ResetStrategyDestroyRecreate {
		return Reset{}, invalidf("reset.strategy: %q is not supported; v1 accepts %q only",
			strategy, ResetStrategyDestroyRecreate)
	}
	return Reset{Strategy: strategy}, nil
}

func seedFrom(doc map[string]any) (Seed, error) {
	var s Seed

	raw, ok := doc["command"]
	if !ok {
		return s, invalidf("seed.command is required when a seed section is present")
	}
	if _, isString := raw.(string); isString {
		return s, invalidf(`seed.command must be a list of arguments (exec form, e.g. ` +
			`["make", "seed"]); a bare string would imply shell interpretation`)
	}
	args, err := stringsOf(raw, "seed.command")
	if err != nil {
		return s, err
	}
	if len(args) == 0 {
		return s, invalidf("seed.command is empty; omit the seed section instead")
	}
	if len(args) > maxSeedArgs {
		return s, invalidf("seed.command has %d arguments; the limit is %d", len(args), maxSeedArgs)
	}
	s.Command = args

	if s.TimeoutSeconds, err = optionalBoundedInt(doc, "timeout_seconds", "seed",
		defaultSeedTimeoutSeconds, minTimeoutSeconds, maxTimeoutSeconds); err != nil {
		return s, err
	}
	return s, nil
}

func authFrom(doc map[string]any) (Auth, error) {
	var a Auth

	method, err := stringAt(doc, "method", "auth")
	if err != nil {
		return a, err
	}
	if method != AuthMethodBrowser {
		return a, invalidf("auth.method: %q is not supported; v1 accepts %q only",
			method, AuthMethodBrowser)
	}
	a.Method = method

	stepsRef, err := stringAt(doc, "steps_ref", "auth")
	if err != nil {
		return a, err
	}
	if err := checkRepoRelPath(stepsRef, "auth.steps_ref"); err != nil {
		return a, err
	}
	if err := checkYAMLExt(stepsRef, "auth.steps_ref"); err != nil {
		return a, err
	}
	a.StepsRef = stepsRef
	return a, nil
}

func inventoryFrom(doc map[string]any) (Inventory, error) {
	var inv Inventory

	raw, ok := doc["runtime_spec_endpoints"]
	if !ok {
		return inv, invalidf("inventory.runtime_spec_endpoints is required when an inventory " +
			"section is present; omit the section to keep the built-in Tier 0 list")
	}
	endpoints, err := stringsOf(raw, "inventory.runtime_spec_endpoints")
	if err != nil {
		return inv, err
	}
	if len(endpoints) == 0 {
		return inv, invalidf("inventory.runtime_spec_endpoints is empty; omit the section to keep " +
			"the built-in Tier 0 list")
	}
	if len(endpoints) > maxEndpoints {
		return inv, invalidf("inventory.runtime_spec_endpoints has %d entries; the limit is %d",
			len(endpoints), maxEndpoints)
	}
	seen := make(map[string]bool, len(endpoints))
	for i, ep := range endpoints {
		if err := checkEndpointPath(ep, fmt.Sprintf("inventory.runtime_spec_endpoints[%d]", i)); err != nil {
			return inv, err
		}
		if seen[ep] {
			return inv, invalidf("inventory.runtime_spec_endpoints: %q appears twice", ep)
		}
		seen[ep] = true
	}
	inv.RuntimeSpecEndpoints = endpoints
	return inv, nil
}

func scopeFrom(doc map[string]any) (Scope, error) {
	var sc Scope

	raw, ok := doc["additional_egress_allow"]
	if !ok {
		return sc, invalidf("scope.additional_egress_allow is required when a scope section is " +
			"present; write [] to state explicitly that nothing extra is permitted")
	}
	// An explicitly empty list IS meaningful here -- it is the documented
	// default, written down. Unlike the inventory list, it is accepted.
	entries, err := stringsOf(raw, "scope.additional_egress_allow")
	if err != nil {
		return sc, err
	}
	if len(entries) > maxEgressEntries {
		return sc, invalidf("scope.additional_egress_allow has %d entries; the limit is %d",
			len(entries), maxEgressEntries)
	}
	seen := make(map[string]bool, len(entries))
	for i, e := range entries {
		if err := checkEgressEntry(e, fmt.Sprintf("scope.additional_egress_allow[%d]", i)); err != nil {
			return sc, err
		}
		if seen[e] {
			return sc, invalidf("scope.additional_egress_allow: %q appears twice", e)
		}
		seen[e] = true
	}
	sc.AdditionalEgressAllow = entries
	return sc, nil
}

// ---------------------------------------------------------------------------
// Field validators -- allowlists throughout
// ---------------------------------------------------------------------------

// checkServiceName accepts the Compose service-name character set as an
// ALLOWLIST. A denylist of "characters that break Compose" would have to
// anticipate every shell, DNS label and YAML quirk downstream; this cannot.
//
// The character set alone is not enough. "169.254.169.254" is spelled entirely
// out of [A-Za-z0-9_.-], so it passes the loop below -- and a service name is
// the host the health gate is allowed to address. .anvil/target.yaml is a file
// IN THE SCANNED REPOSITORY, which makes this field attacker-authored input:
// the repo would be telling Anvil which host to fetch. So the name must also
// be a NAME. A Compose service name is a DNS label inside a Docker network; it
// is not an address and never legitimately looks like one.
func checkServiceName(s string) error {
	if s == "" {
		return invalidf("service is empty")
	}
	if len(s) > 63 {
		return invalidf("service %q is %d characters; the limit is 63 (a DNS label)", s, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i > 0 {
			ok = ok || c == '_' || c == '.' || c == '-'
		}
		if !ok {
			return invalidf("service %q: character %q at offset %d is not permitted; the first "+
				"character must be alphanumeric and the rest [A-Za-z0-9_.-]", s, string(c), i)
		}
	}
	if form := ipLiteralForm(s); form != "" {
		return invalidf("service %q is %s; a Compose service name is a DNS label inside the "+
			"Docker network, never an address. Anvil resolves the authorized service through "+
			"Compose's own DNS, so naming an address here would point the health gate at a host "+
			"outside the target stack", s, form)
	}
	return nil
}

// checkHealthURL constrains the health endpoint to the ONE authorized service.
//
// The scheme set is an allowlist of http/https. The host set is an allowlist
// of {the authorized service name, loopback}. That is what makes "exactly one
// service is authorized" structural rather than conventional: a manifest
// cannot name `web` as its target and then point the health gate at `db` or at
// some third-party host.
//
// Residual: Compose aliases and container_name overrides are NOT accepted --
// the health URL has to use the service name, which Compose always publishes
// as a network alias. That is a refusal, not a silent permit, and the error
// message says so.
func checkHealthURL(raw string, svc AuthorizedService) error {
	if raw == "" {
		return invalidf("health.url is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return invalidf("health.url %q does not parse: %v", raw, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return invalidf("health.url %q has scheme %q; only http and https are permitted", raw, u.Scheme)
	}
	if u.User != nil {
		return invalidf("health.url %q carries credentials in the URL; put them in auth.steps_ref", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return invalidf("health.url %q has a fragment; a fragment is never sent to the server", raw)
	}
	host := u.Hostname()
	if host == "" {
		return invalidf("health.url %q has no host", raw)
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return invalidf("health.url %q has port %q, which is not 1-65535", raw, port)
		}
	}
	if !isLoopbackHost(host) {
		// Checked BEFORE the service comparison, not after. If this ran second
		// it would be dead code the moment a service name were an address, and
		// "the address check is unreachable because the other check catches
		// it" is how a control disappears during a later refactor. Order here
		// means an address host is refused even if some future caller hands in
		// an AuthorizedService this package did not build.
		if form := ipLiteralForm(host); form != "" {
			return invalidf("health.url %q addresses host %q, which is %s; the health gate must "+
				"address the authorized service %q by its Compose service name. An address "+
				"literal names a host outside the Compose network, and no authorization gate "+
				"sits on the health-check path", raw, host, form, svc.Name())
		}
		if !svc.Authorizes(host) {
			return invalidf("health.url %q addresses host %q, which is neither the authorized "+
				"service %q nor loopback; exactly one service is authorized and the health gate "+
				"must address it by its Compose service name", raw, host, svc.Name())
		}
	}
	return nil
}

// isLoopbackHost is an allowlist of three exact spellings, not a range test.
// "127.0.0.2", "127.1", "2130706433", "0177.0.0.1" and "[0:0:0:0:0:0:0:1]" are
// all loopback to a resolver and none of them is on this list; each is refused
// by the address-literal check instead. TestLoopbackAllowlistIsExact pins that.
func isLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// ipLiteralForm names the encoding under which host would be read as an IP
// address literal, or returns "" when nothing reads it as one.
//
// It is deliberately WIDER than netip.ParseAddr, because netip is strict and
// the resolvers downstream are not. Measured against Go 1.26's netip:
// ParseAddr accepts "169.254.169.254" but refuses "2852039166" ("unable to
// parse IP"), "0251.0376.0251.0376" ("IPv4 field has octet with leading zero")
// and "169.254.169.254." ("IPv4 field must have at least one digit"). Those
// three are the same destination: 0xA9FEA9FE == 2852039166, and 0251 == 169,
// 0376 == 254 in octal. A guard that asked only netip would refuse the dotted
// quad and admit its synonyms, which is a guard that refuses the example in
// the finding and nothing else.
//
// So the second test is a SHAPE rather than a canonical parse: dot-separated
// parts that are all integers, decimal, octal or hexadecimal. Anything with
// that shape is refused whether or not it is a well-formed address --
// over-refusing a string like "1.2.3" costs a manifest author a rename, while
// under-refusing costs a credential.
//
// This is not a denylist of reserved ranges. A range list would lose to the
// next encoding, and to a hostname that merely RESOLVES into the range. The
// whole CATEGORY of address literals is refused; what remains is names.
func ipLiteralForm(host string) string {
	if host == "" {
		return ""
	}
	// A DNS label never contains ':'. In a host position a colon can only be
	// an IPv6 literal.
	//
	// Measured: reached from checkHealthURL this branch never fires first,
	// because net/url validates a bracketed host through netip itself --
	// url.Parse("http://[1:2]/x") fails with `ParseAddr("1:2"): address string
	// too short`, and every bracketed host that DOES survive is one netip
	// accepts on the next line. The branch stays because ipLiteralForm takes a
	// host from any caller, not only from url.Hostname(), and "1:2" is a
	// string netip and the inet_aton shape both read as a NAME.
	// TestIPLiteralFormBranchesAreEachLoadBearing pins it directly.
	if strings.Contains(host, ":") {
		return "an IPv6 address literal"
	}
	// One trailing dot is the FQDN root form; it does not change where the
	// string points.
	bare := strings.TrimSuffix(host, ".")
	if _, err := netip.ParseAddr(bare); err == nil {
		return "an IP address literal"
	}
	if allNumericParts(bare) {
		return "an IP address literal in a non-canonical encoding"
	}
	return ""
}

// allNumericParts reports whether every '.'-separated part of s is an integer:
// decimal, octal ("0...") or hexadecimal ("0x..."). That is the shape
// inet_aton(3) reads as an IPv4 address.
//
// There is deliberately no cap on the number of parts. inet_aton itself takes
// at most four, so "1.2.3.4.5" is not an address to it -- but a length cap
// here would be a branch whose only possible effect is to ADMIT an all-numeric
// string, and a branch that can only widen is the wrong branch to carry. A
// manifest that wanted to call its service "1.2.3.4.5" pays a rename.
func allNumericParts(s string) bool {
	for _, p := range strings.Split(s, ".") {
		if !numericHostPart(p) {
			return false
		}
	}
	return true
}

// numericHostPart reports whether p is a single integer part: "0x" followed by
// hex digits, or a run of decimal digits (which covers the octal form, since
// octal differs only by its leading zero). "2fa" is neither, which is why a
// service may still be called that.
func numericHostPart(p string) bool {
	if p == "" {
		return false
	}
	if len(p) > 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X') {
		for i := 2; i < len(p); i++ {
			c := p[i]
			if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
	}
	return true
}

// checkRepoRelPath refuses anything that is not a repo-root-relative,
// non-escaping, slash-separated path.
func checkRepoRelPath(raw, field string) error {
	if raw == "" {
		return invalidf("%s is empty", field)
	}
	if len(raw) > maxScalarBytes {
		return invalidf("%s is %d bytes; the limit is %d", field, len(raw), maxScalarBytes)
	}
	if strings.ContainsRune(raw, '\\') {
		return invalidf("%s %q contains a backslash; repo paths are slash-separated", field, raw)
	}
	if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "~") {
		return invalidf("%s %q is absolute; it must be relative to the repo root", field, raw)
	}
	if len(raw) >= 2 && raw[1] == ':' {
		return invalidf("%s %q looks like a drive-qualified path; it must be relative to the repo root",
			field, raw)
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || cleaned == "/" {
		return invalidf("%s %q does not name a file", field, raw)
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return invalidf("%s %q escapes the repo root", field, raw)
	}
	return nil
}

func checkYAMLExt(raw, field string) error {
	ext := strings.ToLower(path.Ext(path.Clean(raw)))
	if ext != ".yaml" && ext != ".yml" {
		return invalidf("%s %q must be a YAML file (.yaml or .yml), got extension %q", field, raw, ext)
	}
	return nil
}

// checkEndpointPath keeps a runtime-spec probe on the target. An entry that
// carried a scheme or was protocol-relative would move the probe to a host
// nobody authorized, which is the same hole as an unconstrained health URL.
//
// The three shape rules below are each a denylist of one construct, so they
// leave gaps by construction: `/\/other-host/x` is not "//", carries no "://"
// and has no ".." segment, yet it is the same host-substitution attempt in a
// character the rules never named. The allowlist closes the category --
// nothing outside the RFC 3986 path character set reaches whichever URL parser
// the probe layer ends up using.
func checkEndpointPath(ep, field string) error {
	if ep == "" {
		return invalidf("%s is empty", field)
	}
	if len(ep) > maxScalarBytes {
		return invalidf("%s is %d bytes; the limit is %d", field, len(ep), maxScalarBytes)
	}
	if !strings.HasPrefix(ep, "/") {
		return invalidf("%s %q must be an absolute path on the target, starting with %q", field, ep, "/")
	}
	if strings.HasPrefix(ep, "//") {
		return invalidf("%s %q is protocol-relative; that would address a different host", field, ep)
	}
	if strings.Contains(ep, "://") {
		return invalidf("%s %q is a URL; runtime spec endpoints are paths on the authorized service",
			field, ep)
	}
	for i := 0; i < len(ep); i++ {
		if !pathCharAllowed(ep[i]) {
			return invalidf("%s %q: character %q at offset %d is not permitted; a runtime spec "+
				"endpoint is a path on the authorized service, restricted to the RFC 3986 path "+
				"character set (unreserved, sub-delims, %q, %q, %q and %q)",
				field, ep, string(ep[i]), i, ":", "@", "%", "/")
		}
	}
	for _, seg := range strings.Split(ep, "/") {
		if seg == ".." {
			return invalidf("%s %q contains a %q segment", field, ep, "..")
		}
	}
	return nil
}

// pathCharAllowed is RFC 3986's <pchar> plus '/': ALPHA / DIGIT / "-" / "." /
// "_" / "~" (unreserved), "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / ","
// / ";" / "=" (sub-delims), ":", "@", "%" and "/".
//
// Excluded, and therefore refused: '\', '?', '#', space, every control byte,
// and every byte above 0x7F. A query or a fragment is not part of an endpoint
// PATH, and this schema has no field that needs one.
func pathCharAllowed(c byte) bool {
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
		return true
	}
	switch c {
	case '-', '.', '_', '~',
		'!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=',
		':', '@', '%', '/':
		return true
	}
	return false
}

// checkEgressEntry validates the SYNTAX of an egress entry: an IP address, a
// CIDR prefix, or a hostname. Nothing here grants egress -- gate 10's
// reserved-range floor is in the authorization kernel and is not configurable
// from this file.
func checkEgressEntry(e, field string) error {
	if e == "" {
		return invalidf("%s is empty", field)
	}
	if len(e) > 253 {
		return invalidf("%s is %d bytes; the limit is 253", field, len(e))
	}
	if strings.Contains(e, "/") {
		if _, err := netip.ParsePrefix(e); err != nil {
			return invalidf("%s %q is not a valid CIDR prefix: %v", field, e, err)
		}
		return nil
	}
	if _, err := netip.ParseAddr(e); err == nil {
		return nil
	}
	if isHostname(e) {
		return nil
	}
	return invalidf("%s %q is not an IP address, a CIDR prefix, or a hostname", field, e)
}

// isHostname is an allowlist: dot-separated labels of [A-Za-z0-9-], each 1-63
// characters, none starting or ending with '-'. No wildcards: a wildcard in an
// egress allowlist is a hole with a friendly name.
func isHostname(s string) bool {
	if s == "" || len(s) > 253 || strings.HasSuffix(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Filesystem validation
// ---------------------------------------------------------------------------

// validateFilesystem checks the declared files actually exist inside the repo.
// plan/design/dynamic-tier.md: "If compose_file is present but does not exist ... the
// manifest is schema-invalid."
func (m *Manifest) validateFilesystem(repoRoot string) error {
	if err := requireFileWithin(repoRoot, m.ComposeFile, "compose_file"); err != nil {
		return err
	}
	if m.Auth != nil {
		if err := requireFileWithin(repoRoot, m.Auth.StepsRef, "auth.steps_ref"); err != nil {
			return err
		}
	}
	return nil
}

// requireFileWithin resolves rel against repoRoot and refuses unless the
// result is a regular file that is still inside repoRoot after symlinks are
// resolved.
func requireFileWithin(repoRoot, rel, field string) error {
	rootAbs, err := filepath.Abs(repoRoot)
	if err != nil {
		return invalidf("%s: cannot resolve repo root %q: %v", field, repoRoot, err)
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return invalidf("%s: cannot resolve repo root %q: %v", field, repoRoot, err)
	}

	joined := filepath.Join(rootReal, filepath.FromSlash(path.Clean(rel)))
	target, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return invalidf("%s %q does not exist at %s", field, rel, joined)
	}
	if !within(rootReal, target) {
		return invalidf("%s %q resolves to %s, which is outside the repo root %s",
			field, rel, target, rootReal)
	}
	info, err := os.Stat(target)
	if err != nil {
		return invalidf("%s %q cannot be read: %v", field, rel, err)
	}
	if !info.Mode().IsRegular() {
		return invalidf("%s %q is not a regular file (mode %s)", field, rel, info.Mode())
	}
	return nil
}

// within reports whether p is root or is inside root. Both are expected to be
// already-cleaned, symlink-resolved absolute paths.
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	if filepath.IsAbs(rel) {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Typed accessors over the decoded document
// ---------------------------------------------------------------------------

func fieldPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func describe(v any) string {
	switch v.(type) {
	case nil:
		return "nothing"
	case string:
		return "a string"
	case int:
		return "an integer"
	case []any:
		return "a list"
	case map[string]any:
		return "a mapping"
	default:
		return fmt.Sprintf("%T", v)
	}
}

func asMapping(v any, where string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		name := "the document root"
		if where != "" {
			name = where
		}
		return nil, invalidf("%s must be a mapping, got %s", name, describe(v))
	}
	return m, nil
}

// checkKeys is the unknown-field refusal. Unknown keys are reported sorted so
// a document with two typos always produces the same message.
func checkKeys(m map[string]any, allowed []string, prefix string) error {
	permitted := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		permitted[k] = true
	}
	var unknown []string
	for k := range m {
		if !permitted[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	where := "the document root"
	if prefix != "" {
		where = prefix
	}
	return invalidf("unknown field(s) %s in %s; permitted: %s",
		strings.Join(quoteAll(unknown), ", "), where, strings.Join(quoteAll(allowed), ", "))
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strconv.Quote(s)
	}
	return out
}

func requiredSection(top map[string]any, key string, allowed []string) (map[string]any, error) {
	raw, ok := top[key]
	if !ok {
		return nil, invalidf("%s is required", key)
	}
	doc, err := asMapping(raw, key)
	if err != nil {
		return nil, err
	}
	if err := checkKeys(doc, allowed, key); err != nil {
		return nil, err
	}
	return doc, nil
}

func optionalSection(top map[string]any, key string, allowed []string) (map[string]any, bool, error) {
	raw, ok := top[key]
	if !ok {
		return nil, false, nil
	}
	if raw == nil {
		return nil, false, invalidf("%s is present but empty; omit it entirely, or fill it in", key)
	}
	doc, err := asMapping(raw, key)
	if err != nil {
		return nil, false, err
	}
	if err := checkKeys(doc, allowed, key); err != nil {
		return nil, false, err
	}
	return doc, true, nil
}

func stringAt(m map[string]any, key, prefix string) (string, error) {
	fp := fieldPath(prefix, key)
	raw, ok := m[key]
	if !ok {
		return "", invalidf("%s is required", fp)
	}
	s, ok := raw.(string)
	if !ok {
		return "", invalidf("%s must be a string, got %s", fp, describe(raw))
	}
	if strings.TrimSpace(s) == "" {
		return "", invalidf("%s is empty", fp)
	}
	return s, nil
}

func intAt(m map[string]any, key, prefix string) (int, error) {
	fp := fieldPath(prefix, key)
	raw, ok := m[key]
	if !ok {
		return 0, invalidf("%s is required", fp)
	}
	n, ok := raw.(int)
	if !ok {
		return 0, invalidf("%s must be an integer, got %s", fp, describe(raw))
	}
	return n, nil
}

func optionalBoundedInt(m map[string]any, key, prefix string, def, lo, hi int) (int, error) {
	fp := fieldPath(prefix, key)
	raw, ok := m[key]
	if !ok {
		return def, nil
	}
	n, ok := raw.(int)
	if !ok {
		return 0, invalidf("%s must be an integer, got %s", fp, describe(raw))
	}
	if n < lo || n > hi {
		return 0, invalidf("%s is %d; it must be between %d and %d", fp, n, lo, hi)
	}
	return n, nil
}

func stringsOf(raw any, fp string) ([]string, error) {
	list, ok := raw.([]any)
	if !ok {
		return nil, invalidf("%s must be a list, got %s", fp, describe(raw))
	}
	out := make([]string, 0, len(list))
	for i, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, invalidf("%s[%d] must be a string, got %s", fp, i, describe(item))
		}
		if strings.TrimSpace(s) == "" {
			return nil, invalidf("%s[%d] is empty", fp, i)
		}
		if len(s) > maxScalarBytes {
			return nil, invalidf("%s[%d] is %d bytes; the limit is %d", fp, i, len(s), maxScalarBytes)
		}
		out = append(out, s)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Marshal -- the canonical form
// ---------------------------------------------------------------------------

// Marshal renders the manifest in ONE canonical form: fixed key order (the
// schema's own order), two-space indent, LF endings, flow sequences with
// always-quoted items, and plain scalars only where a plain scalar is
// unambiguous. Comments are not preserved -- this decoder does not model them,
// and pretending otherwise would be a claim the round-trip test cannot back.
//
// Marshal validates shape first, so a hand-built Manifest with a zero value in
// a required field is a refusal rather than an unloadable file.
func (m *Manifest) Marshal() ([]byte, error) {
	if err := m.validateShape(); err != nil {
		return nil, err
	}

	var b strings.Builder
	emitInt(&b, 0, "schema_version", m.SchemaVersion)
	emitScalar(&b, 0, "compose_file", m.ComposeFile)
	emitScalar(&b, 0, "service", m.service.Name())

	emitSection(&b, 0, "health")
	emitScalar(&b, 1, "url", m.Health.URL)
	emitInt(&b, 1, "timeout_seconds", m.Health.TimeoutSeconds)
	emitInt(&b, 1, "interval_seconds", m.Health.IntervalSeconds)

	if m.Seed != nil {
		emitSection(&b, 0, "seed")
		emitFlow(&b, 1, "command", m.Seed.Command)
		emitInt(&b, 1, "timeout_seconds", m.Seed.TimeoutSeconds)
	}

	emitSection(&b, 0, "reset")
	emitScalar(&b, 1, "strategy", m.Reset.Strategy)

	if m.Auth != nil {
		emitSection(&b, 0, "auth")
		emitScalar(&b, 1, "method", m.Auth.Method)
		emitScalar(&b, 1, "steps_ref", m.Auth.StepsRef)
	}

	if m.Inventory != nil {
		emitSection(&b, 0, "inventory")
		emitFlow(&b, 1, "runtime_spec_endpoints", m.Inventory.RuntimeSpecEndpoints)
	}

	if m.Scope != nil {
		emitSection(&b, 0, "scope")
		emitFlow(&b, 1, "additional_egress_allow", m.Scope.AdditionalEgressAllow)
	}

	return []byte(b.String()), nil
}

// validateShape re-runs every non-filesystem rule against an in-memory
// Manifest. It exists so Marshal cannot emit a document that Parse would
// reject, and so the zero Manifest is refused rather than serialised.
func (m *Manifest) validateShape() error {
	if m == nil {
		return invalidf("manifest is nil")
	}
	if m.SchemaVersion != SchemaVersion {
		return invalidf("schema_version: %d is not supported; this loader accepts %d only",
			m.SchemaVersion, SchemaVersion)
	}
	if err := checkRepoRelPath(m.ComposeFile, "compose_file"); err != nil {
		return err
	}
	if err := checkYAMLExt(m.ComposeFile, "compose_file"); err != nil {
		return err
	}
	if err := checkServiceName(m.service.Name()); err != nil {
		return err
	}
	if err := checkHealthURL(m.Health.URL, m.service); err != nil {
		return err
	}
	if m.Health.TimeoutSeconds < minTimeoutSeconds || m.Health.TimeoutSeconds > maxTimeoutSeconds {
		return invalidf("health.timeout_seconds is %d; it must be between %d and %d",
			m.Health.TimeoutSeconds, minTimeoutSeconds, maxTimeoutSeconds)
	}
	if m.Health.IntervalSeconds < minIntervalSeconds || m.Health.IntervalSeconds > maxIntervalSeconds {
		return invalidf("health.interval_seconds is %d; it must be between %d and %d",
			m.Health.IntervalSeconds, minIntervalSeconds, maxIntervalSeconds)
	}
	if m.Health.IntervalSeconds > m.Health.TimeoutSeconds {
		return invalidf("health.interval_seconds (%d) exceeds health.timeout_seconds (%d)",
			m.Health.IntervalSeconds, m.Health.TimeoutSeconds)
	}
	if m.Reset.Strategy != ResetStrategyDestroyRecreate {
		return invalidf("reset.strategy: %q is not supported; v1 accepts %q only",
			m.Reset.Strategy, ResetStrategyDestroyRecreate)
	}
	if m.Seed != nil {
		if len(m.Seed.Command) == 0 {
			return invalidf("seed.command is empty; omit the seed section instead")
		}
		if len(m.Seed.Command) > maxSeedArgs {
			return invalidf("seed.command has %d arguments; the limit is %d",
				len(m.Seed.Command), maxSeedArgs)
		}
		for i, arg := range m.Seed.Command {
			if strings.TrimSpace(arg) == "" {
				return invalidf("seed.command[%d] is empty", i)
			}
		}
		if m.Seed.TimeoutSeconds < minTimeoutSeconds || m.Seed.TimeoutSeconds > maxTimeoutSeconds {
			return invalidf("seed.timeout_seconds is %d; it must be between %d and %d",
				m.Seed.TimeoutSeconds, minTimeoutSeconds, maxTimeoutSeconds)
		}
	}
	if m.Auth != nil {
		if m.Auth.Method != AuthMethodBrowser {
			return invalidf("auth.method: %q is not supported; v1 accepts %q only",
				m.Auth.Method, AuthMethodBrowser)
		}
		if err := checkRepoRelPath(m.Auth.StepsRef, "auth.steps_ref"); err != nil {
			return err
		}
		if err := checkYAMLExt(m.Auth.StepsRef, "auth.steps_ref"); err != nil {
			return err
		}
	}
	if m.Inventory != nil {
		if len(m.Inventory.RuntimeSpecEndpoints) == 0 {
			return invalidf("inventory.runtime_spec_endpoints is empty; omit the section instead")
		}
		for i, ep := range m.Inventory.RuntimeSpecEndpoints {
			if err := checkEndpointPath(ep, fmt.Sprintf("inventory.runtime_spec_endpoints[%d]", i)); err != nil {
				return err
			}
		}
	}
	if m.Scope != nil {
		for i, e := range m.Scope.AdditionalEgressAllow {
			if err := checkEgressEntry(e, fmt.Sprintf("scope.additional_egress_allow[%d]", i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func indentOf(level int) string { return strings.Repeat("  ", level) }

func emitSection(b *strings.Builder, level int, key string) {
	b.WriteString(indentOf(level))
	b.WriteString(key)
	b.WriteString(":\n")
}

func emitInt(b *strings.Builder, level int, key string, n int) {
	b.WriteString(indentOf(level))
	b.WriteString(key)
	b.WriteString(": ")
	b.WriteString(strconv.Itoa(n))
	b.WriteString("\n")
}

func emitScalar(b *strings.Builder, level int, key, val string) {
	b.WriteString(indentOf(level))
	b.WriteString(key)
	b.WriteString(": ")
	if plainSafe(val) {
		b.WriteString(val)
	} else {
		b.WriteString(quoteYAML(val))
	}
	b.WriteString("\n")
}

// emitFlow always quotes items. A bare item beginning with '-', '[' or a digit
// would be ambiguous, and deciding per item would make the output depend on
// its contents in a way a reader has to reason about.
func emitFlow(b *strings.Builder, level int, key string, items []string) {
	b.WriteString(indentOf(level))
	b.WriteString(key)
	b.WriteString(": [")
	for i, it := range items {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(quoteYAML(it))
	}
	b.WriteString("]\n")
}

// plainSafe reports whether s can be written without quotes and read back
// identically by this package's decoder. It is an allowlist of characters plus
// an allowlist of first characters, and it excludes every word the decoder
// treats as reserved.
func plainSafe(s string) bool {
	if s == "" || len(s) > maxScalarBytes {
		return false
	}
	if isReservedWord(s) {
		return false
	}
	first := s[0]
	if (first >= '0' && first <= '9') || first == '-' || first == '+' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '/', c == ':', c == '@', c == '+', c == '-':
		default:
			return false
		}
	}
	return true
}

// quoteYAML emits a double-quoted scalar. Only '\' and '"' are escaped,
// because checkBytes has already refused every control character, so there is
// nothing else that needs an escape -- and the decoder's escape allowlist
// accepts only those two.
func quoteYAML(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

// ---------------------------------------------------------------------------
// The YAML subset decoder
// ---------------------------------------------------------------------------
//
// Supported, and nothing else:
//
//	block mappings                key: value / key: <children>
//	block sequences of scalars    - item
//	flow sequences of scalars     [a, b] / []
//	scalars                       plain, 'single-quoted', "double-quoted"
//	comments                      # to end of line, outside quotes
//
// Refused, explicitly: tabs, anchors (&), aliases (*), tags (!), block scalars
// (| and >), directives (%), document markers (--- / ...), flow mappings ({}),
// nested collections inside a sequence, duplicate keys, keys with both an
// inline value and children, and the YAML 1.1 bare words true/false/yes/no/
// on/off/null/~ (quote them if you meant the string).

type yamlLine struct {
	num    int
	indent int
	text   string
}

func decodeYAML(src string) (any, error) {
	lines, err := scanLines(src)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}
	return parseBlock(lines)
}

func scanLines(src string) ([]yamlLine, error) {
	var out []yamlLine
	for i, raw := range strings.Split(src, "\n") {
		num := i + 1
		text := strings.TrimSuffix(raw, "\r")
		text = stripComment(text)
		text = strings.TrimRight(text, " ")
		if strings.TrimSpace(text) == "" {
			continue
		}
		trimmed := strings.TrimLeft(text, " ")
		if trimmed == "---" || trimmed == "..." {
			return nil, invalidf("line %d: document markers are not supported; a manifest is one document",
				num)
		}
		if strings.HasPrefix(trimmed, "%") {
			return nil, invalidf("line %d: YAML directives are not supported", num)
		}
		out = append(out, yamlLine{num: num, indent: len(text) - len(trimmed), text: trimmed})
	}
	return out, nil
}

// stripComment removes a trailing comment. '#' starts a comment only outside
// quotes and only at the start of the line or after a space, so a value
// containing '#' mid-token survives to be judged on its merits.
func stripComment(text string) string {
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			if i == 0 || text[i-1] == ' ' {
				return text[:i]
			}
		}
	}
	return text
}

func parseBlock(lines []yamlLine) (any, error) {
	if len(lines) == 0 {
		return nil, nil
	}
	base := lines[0].indent
	for _, ln := range lines {
		if ln.indent < base {
			return nil, invalidf("line %d: indent %d is shallower than the block's %d",
				ln.num, ln.indent, base)
		}
	}
	if isSeqItem(lines[0].text) {
		return parseSequence(lines, base)
	}
	return parseMapping(lines, base)
}

func isSeqItem(text string) bool { return text == "-" || strings.HasPrefix(text, "- ") }

func parseSequence(lines []yamlLine, base int) ([]any, error) {
	out := []any{}
	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		if ln.indent != base {
			return nil, invalidf("line %d: expected a sequence item at indent %d, found indent %d",
				ln.num, base, ln.indent)
		}
		if !isSeqItem(ln.text) {
			return nil, invalidf("line %d: %q does not start a sequence item", ln.num, ln.text)
		}
		if i+1 < len(lines) && lines[i+1].indent > base {
			return nil, invalidf("line %d: a sequence item may not have child lines; this schema has "+
				"no nested collections inside a sequence", ln.num)
		}
		rest := strings.TrimSpace(ln.text[1:])
		if rest == "" {
			return nil, invalidf("line %d: empty sequence item", ln.num)
		}
		val, err := parseValue(rest, ln.num)
		if err != nil {
			return nil, err
		}
		if _, isList := val.([]any); isList {
			return nil, invalidf("line %d: nested sequences are not supported", ln.num)
		}
		out = append(out, val)
	}
	return out, nil
}

func parseMapping(lines []yamlLine, base int) (map[string]any, error) {
	out := map[string]any{}
	for i := 0; i < len(lines); {
		ln := lines[i]
		if ln.indent != base {
			return nil, invalidf("line %d: indent %d does not line up with the mapping's %d",
				ln.num, ln.indent, base)
		}
		key, rest, ok := splitKey(ln.text)
		if !ok {
			return nil, invalidf("line %d: %q is not a mapping entry (expected %q)", ln.num, ln.text, "key: value")
		}
		if _, dup := out[key]; dup {
			return nil, invalidf("line %d: duplicate key %q", ln.num, key)
		}

		end := i + 1
		for end < len(lines) && lines[end].indent > base {
			end++
		}

		var (
			val any
			err error
		)
		if rest != "" {
			if end > i+1 {
				return nil, invalidf("line %d: key %q has both an inline value and child lines",
					ln.num, key)
			}
			val, err = parseValue(rest, ln.num)
		} else {
			val, err = parseBlock(lines[i+1 : end])
		}
		if err != nil {
			return nil, err
		}
		out[key] = val
		i = end
	}
	return out, nil
}

// splitKey splits "key: value" at the first colon that is outside quotes and
// is followed by a space or the end of the line. That rule is what keeps
// "http://web:8080/healthz" from being misread as a key.
func splitKey(text string) (key, rest string, ok bool) {
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '[' || c == ']' || c == '{' || c == '}':
			return "", "", false
		case c == ':':
			if i+1 < len(text) && text[i+1] != ' ' {
				return "", "", false
			}
			key = strings.TrimSpace(text[:i])
			if unq, wasQuoted, err := unquoteScalar(key); err == nil && wasQuoted {
				key = unq
			}
			if key == "" {
				return "", "", false
			}
			return key, strings.TrimSpace(text[i+1:]), true
		}
	}
	return "", "", false
}

func parseValue(text string, line int) (any, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, invalidf("line %d: empty value; omit the key or give it a value", line)
	}
	if strings.HasPrefix(text, "{") {
		return nil, invalidf("line %d: flow mappings are not supported by this schema", line)
	}
	if strings.HasPrefix(text, "[") {
		return parseFlowSeq(text, line)
	}
	return parseScalar(text, line)
}

func parseFlowSeq(text string, line int) ([]any, error) {
	if !strings.HasSuffix(text, "]") {
		return nil, invalidf("line %d: unterminated flow sequence %q", line, text)
	}
	inner := strings.TrimSpace(text[1 : len(text)-1])
	if inner == "" {
		return []any{}, nil
	}

	var (
		items []string
		cur   strings.Builder
		quote byte
	)
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case quote != 0:
			cur.WriteByte(c)
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
			cur.WriteByte(c)
		case c == '[' || c == ']' || c == '{' || c == '}':
			return nil, invalidf("line %d: nested collections inside a flow sequence are not supported", line)
		case c == ',':
			items = append(items, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if quote != 0 {
		return nil, invalidf("line %d: unterminated quoted scalar in flow sequence", line)
	}
	items = append(items, strings.TrimSpace(cur.String()))

	out := make([]any, 0, len(items))
	for _, it := range items {
		if it == "" {
			return nil, invalidf("line %d: empty item in flow sequence", line)
		}
		val, err := parseScalar(it, line)
		if err != nil {
			return nil, err
		}
		out = append(out, val)
	}
	return out, nil
}

// reservedWords are the YAML 1.1 bare words this decoder refuses. None of them
// is a legal value anywhere in this schema, and silently turning `no` into a
// boolean (the "Norway problem") is the exact class of quiet misread that
// strict parsing exists to prevent.
var reservedWords = []string{
	"true", "false", "yes", "no", "on", "off", "y", "n", "null", "nil", "none", "~",
}

func isReservedWord(s string) bool {
	lower := strings.ToLower(s)
	for _, w := range reservedWords {
		if lower == w {
			return true
		}
	}
	return false
}

func parseScalar(text string, line int) (any, error) {
	if len(text) > maxScalarBytes {
		return nil, invalidf("line %d: scalar is %d bytes; the limit is %d", line, len(text), maxScalarBytes)
	}
	if s, wasQuoted, err := unquoteScalar(text); err != nil {
		return nil, invalidf("line %d: %v", line, err)
	} else if wasQuoted {
		return s, nil
	}

	switch text[0] {
	case '&':
		return nil, invalidf("line %d: anchors are not supported", line)
	case '*':
		return nil, invalidf("line %d: aliases are not supported", line)
	case '!':
		return nil, invalidf("line %d: tags are not supported", line)
	case '|', '>':
		return nil, invalidf("line %d: block scalars are not supported", line)
	case '@', '`':
		return nil, invalidf("line %d: %q is a YAML reserved indicator", line, string(text[0]))
	case '"', '\'':
		return nil, invalidf("line %d: unterminated quoted scalar %q", line, text)
	}
	if strings.Contains(text, ": ") {
		return nil, invalidf("line %d: plain scalar %q contains %q, which is ambiguous; quote it",
			line, text, ": ")
	}
	if isReservedWord(text) {
		return nil, invalidf("line %d: %q is a YAML reserved word and this schema has no boolean or "+
			"null field; quote it if you meant the string", line, text)
	}

	if c := text[0]; (c >= '0' && c <= '9') || c == '-' || c == '+' {
		n, err := parseStrictInt(text)
		if err != nil {
			return nil, invalidf("line %d: %q looks numeric but is not a plain decimal integer (%v); "+
				"quote it if you meant a string", line, text, err)
		}
		return n, nil
	}
	return text, nil
}

// parseStrictInt accepts only an optional '-' followed by "0" or a digit string
// with no leading zero. It refuses "010" (YAML 1.1 octal), "0x10", "1_000",
// "1e3", "+1" and "1.5" -- every form whose meaning depends on which YAML
// version the reader has in mind.
func parseStrictInt(s string) (int, error) {
	body := s
	neg := false
	if strings.HasPrefix(body, "-") {
		neg = true
		body = body[1:]
	}
	if body == "" {
		return 0, errors.New("no digits")
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return 0, fmt.Errorf("character %q is not a digit", string(body[i]))
		}
	}
	if len(body) > 1 && body[0] == '0' {
		return 0, errors.New("leading zero")
	}
	n, err := strconv.Atoi(body)
	if err != nil {
		return 0, err
	}
	if neg {
		n = -n
	}
	return n, nil
}

// unquoteScalar handles the two quoted forms. The double-quoted escape set is
// an ALLOWLIST of \\ and \" -- \n, \t, \xNN and \uNNNN are refused, because
// this schema has no field that needs them and accepting them would let a
// manifest smuggle a control character past checkBytes.
func unquoteScalar(text string) (string, bool, error) {
	if len(text) < 2 {
		return "", false, nil
	}
	switch text[0] {
	case '"':
		if text[len(text)-1] != '"' {
			return "", false, fmt.Errorf("unterminated double-quoted scalar %q", text)
		}
		body := text[1 : len(text)-1]
		var b strings.Builder
		for i := 0; i < len(body); i++ {
			if body[i] != '\\' {
				b.WriteByte(body[i])
				continue
			}
			if i+1 >= len(body) {
				return "", false, fmt.Errorf("trailing backslash in %q", text)
			}
			switch body[i+1] {
			case '\\':
				b.WriteByte('\\')
			case '"':
				b.WriteByte('"')
			default:
				return "", false, fmt.Errorf("escape %q is not supported; only %q and %q are",
					`\`+string(body[i+1]), `\\`, `\"`)
			}
			i++
		}
		return b.String(), true, nil
	case '\'':
		if text[len(text)-1] != '\'' {
			return "", false, fmt.Errorf("unterminated single-quoted scalar %q", text)
		}
		body := text[1 : len(text)-1]
		var b strings.Builder
		for i := 0; i < len(body); i++ {
			if body[i] == '\'' {
				if i+1 < len(body) && body[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				return "", false, fmt.Errorf("unescaped quote inside single-quoted scalar %q", text)
			}
			b.WriteByte(body[i])
		}
		return b.String(), true, nil
	}
	return "", false, nil
}
