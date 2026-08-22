// Package authz is Anvil's authorization kernel: the only thing in the system
// that may turn a proposed network request into a permitted one.
//
// The decision flow — Decide, Adjudicate, Authorization, RequireAuthorization —
// is documented at the top of kernel.go. This file holds the VOCABULARY: the
// types every one of the 21 gates in plan/50-dast.md's Authorization Gate
// Sequence is written against.
//
// # The single rule this file exists to enforce
//
// THE ZERO VALUE OF EVERY TYPE IN THIS FILE MEANS REFUSE.
//
// Not "unknown", not "use the default", not "ask someone else". Refuse. A Go
// struct literal that a contributor writes without filling in a field, a value
// decoded from JSON that was missing a key, a value that survived a partially
// failed parse — all of them must arrive at the kernel meaning "no".
//
// That is why almost every type here carries unexported fields and a
// constructor that returns an error. A composite literal written in another
// package cannot set an unexported field; that is a compile error, not a lint,
// and it is the only mechanism in Go that a future contributor cannot
// accidentally route around. The idiom is borrowed wholesale from
// internal/record/sealing.go's seal provenance, which closed the same class of
// hole for the record's read gate.
//
// # What is NOT here
//
// No net.Dial, no http.Client, no socket construction of any kind — D.2's
// forbidden actions, and gate 3's whole point. This file imports stdlib only,
// and gate 2 (phase0_build.go) is the machine check that keeps it that way.
package authz

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// SENTINELS — every refusal in this package wraps ErrRefused
// ---------------------------------------------------------------------------

// The sentinel set is deliberately small. A caller that wants to know "was I
// refused" tests errors.Is(err, ErrRefused) and gets a true answer for every
// refusal path in the kernel, including ones added after this comment was
// written. A caller that wants to know WHY reads the GateFailure's Reason,
// which is a validated, gate-numbered token rather than free text.
var (
	// ErrRefused is the umbrella. Every other sentinel here wraps it, and
	// every GateFailure unwraps to it.
	ErrRefused = errors.New("authz: refused")

	// ErrUnconstructed is the zero-value refusal: a Target, Scope,
	// Attestation, Clock, Ruling, Decision or Authorization that no
	// constructor in this package ever minted. It is the single most
	// important error in the file, because it is what a forgotten field
	// turns into.
	ErrUnconstructed = fmt.Errorf("%w: value was not constructed by internal/dast/authz "+
		"(a zero value, a composite literal from another package, or a value decoded from "+
		"untrusted bytes) and therefore authorizes nothing", ErrRefused)

	// ErrGateNotRegistered fires when the admission chain names a gate that
	// has no implementation compiled in. A missing gate is a REFUSAL, never
	// a skipped step — see kernel.go's chain runner.
	ErrGateNotRegistered = fmt.Errorf("%w: gate has no implementation compiled in", ErrRefused)

	// ErrAuditWriteFailed is gate 21 as an error value: "a gate decision is
	// not 'allowed' if its paired audit write fails".
	ErrAuditWriteFailed = fmt.Errorf("%w: the gate decision's paired audit write failed, so "+
		"the decision is not allowed (gate 21)", ErrRefused)

	// ErrCapRaise is the floor rule: configuration may lower a coded cap and
	// may never raise one.
	ErrCapRaise = fmt.Errorf("%w: configuration may only LOWER a coded cap, never raise it", ErrRefused)

	// ErrNotMeasured is the Phase 0 refusal: a build-time gate was handed
	// facts that were never actually measured. internal/SKIPPED-CONTROLS.md
	// records two separate incidents in this repository where a guard that
	// could not run reported success; a gate that cannot measure must fail,
	// not pass.
	ErrNotMeasured = fmt.Errorf("%w: the build fact was never measured, and a gate that "+
		"cannot measure must refuse rather than pass vacuously", ErrRefused)
)

// ---------------------------------------------------------------------------
// GateID — the 21 gates, by number
// ---------------------------------------------------------------------------

// GateID names one gate in plan/50-dast.md's Authorization Gate Sequence.
//
// The zero value, GateUnspecified, is not a gate. Every construct in this
// package that carries a GateID refuses when it is unset, so "I forgot to say
// which gate ruled" can never read as "some gate ruled".
type GateID uint8

// The 21 gates. The numbering is plan/50-dast.md's Authorization Gate Sequence,
// which that file declares authoritative over research/20's prose.
const (
	// GateUnspecified is the zero value and is not a gate.
	GateUnspecified GateID = 0

	// --- Phase 0: build and packaging (this file's phase0_build.go) ---

	// Gate1DastShipsDisabled: DAST ships disabled. Per
	// plan/00-SPINE.md S9-AMENDED and plan/IMPLEMENTATION-PLAN.md 2.2 this
	// is the TWO-ARTIFACT SPLIT, not a config key: `anvil` has no network
	// probing capability compiled in, `anvil-dast` is separately installed
	// and separately attested.
	Gate1DastShipsDisabled GateID = 1
	// Gate2KernelCompiledSeparately: the kernel is compiled separately with
	// zero imports from the inference layer (plan/00-SPINE.md S7).
	Gate2KernelCompiledSeparately GateID = 2
	// Gate3EgressChokePoint: no socket is constructed outside the kernel.
	Gate3EgressChokePoint GateID = 3

	// --- Phase 1: run initiation (D.4, phase1_run.go) ---

	// Gate4ScopeFile: scope file exists, parses strictly, is schema-valid,
	// and yields zero permitted targets on anything malformed.
	Gate4ScopeFile GateID = 4
	// Gate5Attestation: affirmative attestation present, valid, unexpired,
	// bound to the scope hash.
	Gate5Attestation GateID = 5
	// Gate6ModeDeclaration: mode is explicit and irreversible for the run.
	// There is no `auto`.
	Gate6ModeDeclaration GateID = 6
	// Gate7TriggerProvenance: CI-initiated runs verify a write-authority
	// principal; fork PRs and untrusted pull_request_target are refused.
	Gate7TriggerProvenance GateID = 7

	// --- Phase 2: per-target admission (D.5, phase2_admission.go) ---

	// Gate8Canonicalize: canonicalize before matching.
	Gate8Canonicalize GateID = 8
	// Gate9ResolveAndPin: resolve DNS in the kernel, match the resolved IP
	// against scope, pin it, and connect only to the pinned address.
	Gate9ResolveAndPin GateID = 9
	// Gate10ReservedRanges: the non-configurable reserved-range denylist in
	// external mode.
	Gate10ReservedRanges GateID = 10
	// Gate11RobotsDeny: robots/ToS deny signals as ADDITIONAL denies only.
	Gate11RobotsDeny GateID = 11
	// Gate12SecurityTxtReportingChannel: security.txt is fetched for
	// reporting-channel resolution ONLY.
	//
	// GATE 12 IS DELIBERATELY ABSENT FROM EVERY CHAIN IN kernel.go. It has a
	// number because the audit log records it, not because it participates
	// in an admission decision. See ReportingChannelOnly below and the
	// "gate 12" section of kernel.go.
	Gate12SecurityTxtReportingChannel GateID = 12

	// --- Phase 3: per-request enforcement (D.6, phase3_enforcement.go) ---

	// Gate13RevalidateEveryRequest: re-validate scope on every request
	// including every redirect hop; cross-host redirects are never followed.
	Gate13RevalidateEveryRequest GateID = 13
	// Gate14HardCaps: the token-bucket caps, each a coded floor that config
	// may only lower.
	Gate14HardCaps GateID = 14
	// Gate15DestructiveTechniques: the compiled-in, static
	// destructive-technique denylist.
	Gate15DestructiveTechniques GateID = 15
	// Gate16CircuitBreaker: the target-health circuit breaker.
	Gate16CircuitBreaker GateID = 16
	// Gate17RetryAfter: 429/Retry-After honoured as absolute.
	Gate17RetryAfter GateID = 17

	// --- Phase 4: output and disclosure (D.7, phase4_disclosure.go) ---

	// Gate18Embargo: no auto-publication of third-party findings.
	Gate18Embargo GateID = 18
	// Gate19DisclosureStateInDB: disclosure state lives in the record store,
	// not the handoff buffer.
	Gate19DisclosureStateInDB GateID = 19
	// Gate20NoUnsolicitedFixes: no unsolicited fixes pushed to third
	// parties.
	Gate20NoUnsolicitedFixes GateID = 20
	// Gate21ImmutableAudit: immutable audit of every gate decision. A gate
	// decision is not "allowed" if its paired audit write fails.
	Gate21ImmutableAudit GateID = 21

	// gateMax is the highest legal gate number. It is unexported so that no
	// other package can compute a "next" gate and invent a 22nd.
	gateMax GateID = 21
)

// Valid reports whether g names one of the 21 gates. GateUnspecified is not
// valid, and neither is any number above 21.
func (g GateID) Valid() bool { return g >= Gate1DastShipsDisabled && g <= gateMax }

// String renders the gate as "gate07" — the same token Reason embeds — or
// "gate?(n)" for an illegal value, which is deliberately ugly so it shows up
// in a failure message rather than reading as a real gate.
func (g GateID) String() string {
	if !g.Valid() {
		return "gate?(" + strconv.Itoa(int(g)) + ")"
	}
	return fmt.Sprintf("gate%02d", uint8(g))
}

// Phase reports which of the five phases (0–4) the gate belongs to. It returns
// -1 for an invalid gate, which no phase equals.
func (g GateID) Phase() int {
	switch {
	case !g.Valid():
		return -1
	case g <= Gate3EgressChokePoint:
		return 0
	case g <= Gate7TriggerProvenance:
		return 1
	case g <= Gate12SecurityTxtReportingChannel:
		return 2
	case g <= Gate17RetryAfter:
		return 3
	default:
		return 4
	}
}

// ---------------------------------------------------------------------------
// Outcome — plan/50-dast.md's (Allow|Deny)
// ---------------------------------------------------------------------------

// Outcome is the two-valued result plan/50-dast.md D.2 writes as `Allow|Deny`.
//
// It is a string type so that the empty string — the zero value — is a THIRD
// state that is neither, and every accessor in this package treats that third
// state as a refusal. A bool cannot express "nobody decided", and "nobody
// decided" is exactly the condition that must not read as permission.
type Outcome string

// The three Outcome states. Only two of them are decisions.
const (
	// OutcomeUnset is the zero value. It is not a decision and never allows.
	OutcomeUnset Outcome = ""
	// OutcomeDeny is a refusal by a gate that looked.
	OutcomeDeny Outcome = "deny"
	// OutcomeAllow is a permit by a gate that looked. It is meaningful only
	// on a value this package minted.
	OutcomeAllow Outcome = "allow"
)

// Allows reports whether o is OutcomeAllow. OutcomeUnset does not allow.
func (o Outcome) Allows() bool { return o == OutcomeAllow }

// Valid reports whether o is one of the two real decisions.
func (o Outcome) Valid() bool { return o == OutcomeAllow || o == OutcomeDeny }

// ---------------------------------------------------------------------------
// Reason — a gate-numbered token, never free text
// ---------------------------------------------------------------------------

// Reason is why a gate ruled the way it did.
//
// It is a CONSTRAINED token of the form "gateNN.slug", not free text, for one
// reason: plan/00-SPINE.md S7 makes the DAST response body "the highest-risk
// field — up to 32 KB of attacker-controlled bytes fed to a repo-credentialed
// agent". A free-text reason string is a place for those bytes to land in the
// audit log and, from there, in a prompt. A validated token cannot carry a
// payload.
//
// Operator-facing colour goes in GateFailure.Detail, which is Anvil-authored
// and is never assembled from a response body.
//
// Later gate packets (D.4–D.7) declare their own Reason constants in their own
// files. They do not need to edit this one; they need only obey the format,
// which Validate enforces and which the kernel checks on every ruling.
type Reason string

// ReasonUnspecified is the zero value and is never legal on a ruling.
const ReasonUnspecified Reason = ""

// The Phase 0 reasons. Phase 1–4 reasons are declared by the packets that own
// those gates.
const (
	// ReasonDastNotEnabled is gate 1 at ADJUDICATION time: EnableDAST's
	// explicit, non-defaulted write is a precondition of minting permission,
	// not a decoration. See Adjudicate.
	ReasonDastNotEnabled          Reason = "gate01.dast_not_enabled"
	ReasonEnablementWrongScope    Reason = "gate01.enablement_covers_a_different_scope"
	ReasonCoreArtifactReachesDAST Reason = "gate01.core_artifact_reaches_dast"
	ReasonZeroValueWouldAuthorize Reason = "gate01.zero_value_would_authorize"
	ReasonWrongArtifact           Reason = "gate01.wrong_artifact"
	ReasonImportGraphNotWalked    Reason = "gate01.import_graph_not_walked"

	ReasonKernelImportsInference   Reason = "gate02.kernel_imports_inference_layer"
	ReasonKernelImportNotAllowed   Reason = "gate02.kernel_import_not_on_allowlist"
	ReasonKernelGraphNotWalked     Reason = "gate02.import_graph_not_walked"
	ReasonKernelGraphWrongRoot     Reason = "gate02.import_graph_wrong_root"
	ReasonEgressScanNotRun         Reason = "gate03.egress_scan_not_run"
	ReasonEgressOutsideKernel      Reason = "gate03.socket_constructed_outside_kernel"
	ReasonEgressInsideDastNotAuthz Reason = "gate03.socket_constructed_inside_dast_outside_kernel"

	// Kernel-structural reasons for a malformed or absent gate stack, in
	// their CHAIN-LEVEL form: they are numbered against gate 21, which is
	// the gate that makes a decision durable and is therefore the one that
	// has failed when the kernel cannot say which gate failed at all — an
	// empty chain, an empty trace, a chain position that is not one of the
	// 21.
	//
	// When the kernel CAN name the gate, it must, and the reason token must
	// name that same gate. GateRecord.Validate refuses a row whose reason
	// names a different gate from the row's own Gate field, and Adjudicate
	// validates every row before it writes any — so a gate21.* token minted
	// against gate 11 does not merely mis-file itself, it aborts the whole
	// write loop and ZERO ROWS LAND for a denial that really happened.
	// structuralRefusal in kernel.go mints the per-gate form from
	// slugGateNotRegistered and slugGateIdentityMismatch below;
	// TestStructuralRefusalNamesTheGateItRefusesAt pins both.
	ReasonGateNotRegistered    Reason = "gate21.gate_not_registered"
	ReasonGateIdentityMismatch Reason = "gate21.ruling_names_a_different_gate"
	ReasonAuditWriteFailed     Reason = "gate21.audit_write_failed"
	ReasonAuditKeyIncomplete   Reason = "gate21.audit_key_incomplete"
	ReasonAuditSinkMissing     Reason = "gate21.audit_sink_missing"

	// Kernel-precondition reasons, each attributed to the gate whose input
	// was malformed rather than to some generic "bad input", so that an
	// operator reading the audit log sees which gate was starved.
	ReasonScopeUnconstructed       Reason = "gate04.scope_not_constructed"
	ReasonAttestationUnconstructed Reason = "gate05.attestation_not_constructed"
	ReasonClockUnconstructed       Reason = "gate05.clock_not_constructed"
	ReasonScopeAttestationMismatch Reason = "gate05.attestation_not_bound_to_this_scope"
	ReasonTargetUnconstructed      Reason = "gate08.target_not_constructed"
)

// The slugs the kernel's per-gate structural refusals are built from.
//
// A structural refusal about gate 11 is reported as
// "gate11.gate_not_registered", not as ReasonGateNotRegistered — see the
// comment on that constant. The slugs are declared here, next to the gate-21
// forms they mirror, so that the two spellings cannot drift apart:
// TestStructuralRefusalNamesTheGateItRefusesAt asserts that
// Reason("gate21."+slugGateNotRegistered) IS ReasonGateNotRegistered.
const (
	slugGateNotRegistered    = "gate_not_registered"
	slugGateIdentityMismatch = "ruling_names_a_different_gate"
)

// Validate reports whether r is a legal "gateNN.slug" token.
//
// The slug charset is an ALLOWLIST — lowercase letters, digits, underscore and
// dot — rather than a denylist of dangerous characters. A denylist of
// characters that must not appear in a token destined for a log and possibly a
// prompt would have to anticipate every encoding trick; an allowlist has to
// anticipate nothing.
func (r Reason) Validate() error {
	s := string(r)
	if s == "" {
		return fmt.Errorf("%w: reason is unset", ErrRefused)
	}
	if len(s) > 96 {
		return fmt.Errorf("%w: reason %q is %d bytes; the cap is 96, because a reason is a "+
			"token and not a message", ErrRefused, s, len(s))
	}
	if !strings.HasPrefix(s, "gate") {
		return fmt.Errorf("%w: reason %q does not start with %q; every reason must name the "+
			"gate that produced it", ErrRefused, s, "gate")
	}
	rest := s[len("gate"):]
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	if digits == 0 || digits > 2 {
		return fmt.Errorf("%w: reason %q has no one- or two-digit gate number after %q",
			ErrRefused, s, "gate")
	}
	n, err := strconv.Atoi(rest[:digits])
	if err != nil || GateID(n) < Gate1DastShipsDisabled || GateID(n) > gateMax {
		return fmt.Errorf("%w: reason %q names gate %s, and the sequence has gates 1..%d",
			ErrRefused, s, rest[:digits], gateMax)
	}
	if digits >= len(rest) || rest[digits] != '.' {
		return fmt.Errorf("%w: reason %q has no %q separating the gate number from the slug",
			ErrRefused, s, ".")
	}
	slug := rest[digits+1:]
	if slug == "" {
		return fmt.Errorf("%w: reason %q has an empty slug", ErrRefused, s)
	}
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '.'
		if !ok {
			return fmt.Errorf("%w: reason %q has byte %q at offset %d, which is not in the "+
				"allowed set [a-z0-9_.]", ErrRefused, s, string(c), i)
		}
	}
	if strings.HasPrefix(slug, ".") || strings.HasSuffix(slug, ".") || strings.Contains(slug, "..") {
		return fmt.Errorf("%w: reason %q has a leading, trailing or doubled dot in its slug",
			ErrRefused, s)
	}
	return nil
}

// Gate returns the gate the reason names. It returns GateUnspecified and an
// error for any reason Validate rejects.
func (r Reason) Gate() (GateID, error) {
	if err := r.Validate(); err != nil {
		return GateUnspecified, err
	}
	rest := string(r)[len("gate"):]
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	n, _ := strconv.Atoi(rest[:digits])
	return GateID(n), nil
}

// ---------------------------------------------------------------------------
// Mode — gate 6. There is no "auto", and there is no default.
// ---------------------------------------------------------------------------

// Mode is the run's operating mode.
//
// plan/50-dast.md gate 6: "Mode declaration explicit and irreversible for the
// run (lab | external)... Refuse if absent; no `auto` value exists...
// Configurable? No — there is no configurable 'auto' path, ever."
//
// THE ABSENCE OF `auto` IS A TYPE-LEVEL FACT, NOT A CONVENTION. There is no
// ModeAuto constant here, ParseMode rejects the literal string "auto" with a
// message saying why, and the zero value is ModeUnset, which is not lab and is
// not external and permits nothing. A future contributor who wants "just pick
// the right one" has to add a constant to this file, which is where a reviewer
// will see it.
type Mode string

// The three Mode states. Only two of them are modes.
const (
	// ModeUnset is the zero value. It is not a mode. Nothing runs under it.
	ModeUnset Mode = ""
	// ModeLab is RFC 1918 / loopback only, with relaxed caps. It is the only
	// mode that may reach a reserved range, and then only for addresses
	// explicitly enumerated in scope (gate 10).
	ModeLab Mode = "lab"
	// ModeExternal is public targets, hard caps, and the full gate stack.
	// It cannot be entered without gate 5's attestation.
	ModeExternal Mode = "external"
)

// Valid reports whether m is one of the two real modes.
func (m Mode) Valid() bool { return m == ModeLab || m == ModeExternal }

// ParseMode turns an operator-supplied string into a Mode, refusing everything
// that is not exactly "lab" or "external".
//
// This is an allowlist of two literals. It does not lowercase, trim, or
// otherwise repair its input: a mode declaration that needed repairing was not
// explicit, and gate 6 requires explicit.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeLab:
		return ModeLab, nil
	case ModeExternal:
		return ModeExternal, nil
	case ModeUnset:
		return ModeUnset, fmt.Errorf("%w: no mode was declared, and gate 6 requires an "+
			"explicit declaration of either %q or %q", ErrRefused, ModeLab, ModeExternal)
	}
	if s == "auto" {
		return ModeUnset, fmt.Errorf("%w: %q is not a mode. Gate 6 in plan/50-dast.md is "+
			"explicit that no `auto` value exists and that this is not configurable, "+
			"because inferring lab-vs-external from the target is the inference the "+
			"kernel exists to refuse to make", ErrRefused, s)
	}
	return ModeUnset, fmt.Errorf("%w: %q is not a mode; the only two are %q and %q",
		ErrRefused, s, ModeLab, ModeExternal)
}

// ModeDeclaration is a declared mode.
//
// The mode lives in an unexported field and no method in this package writes
// it after construction, so a value that came from DeclareMode carries the mode
// DeclareMode was given.
//
// The zero ModeDeclaration declares nothing and Mode() refuses it.
//
// Gate 6's "irreversible FOR THE RUN" is not a property of this type and is not
// claimed by it. Nothing here is scoped to a run: DeclareMode may be called
// twice with two different modes, and both values are valid. What binds a mode
// to a run is the Scope it is sealed into (a Scope carries exactly one
// ModeDeclaration and has no setter) and EnableDAST, which refuses when the
// run's declaration and the scope's disagree.
type ModeDeclaration struct {
	mode Mode
}

// DeclareMode makes the run's one irreversible mode declaration (gate 6).
func DeclareMode(m Mode) (ModeDeclaration, error) {
	if !m.Valid() {
		if m == ModeUnset {
			return ModeDeclaration{}, fmt.Errorf("%w: gate 6 requires an explicit mode "+
				"declaration and none was made", ErrRefused)
		}
		return ModeDeclaration{}, fmt.Errorf("%w: %q is not a mode; the only two are %q and %q",
			ErrRefused, string(m), ModeLab, ModeExternal)
	}
	return ModeDeclaration{mode: m}, nil
}

// Mode returns the declared mode, or an error if nothing was declared.
func (d ModeDeclaration) Mode() (Mode, error) {
	if !d.mode.Valid() {
		return ModeUnset, fmt.Errorf("%w: this ModeDeclaration was never made by DeclareMode",
			ErrUnconstructed)
	}
	return d.mode, nil
}

// Declared reports whether a real mode was declared. It is false for the zero
// value, which is the whole point.
func (d ModeDeclaration) Declared() bool { return d.mode.Valid() }

// ---------------------------------------------------------------------------
// Artifact and DastEnablement — gate 1, as the two-artifact split
// ---------------------------------------------------------------------------

// Artifact names which of Anvil's two distribution artifacts is running.
//
// plan/00-SPINE.md S9-AMENDED and plan/IMPLEMENTATION-PLAN.md 2.2: `anvil`
// (core, no network-probing capability compiled in) and `anvil-dast` (the
// dynamic tier, separately installed, separately attested). The ruling is
// explicit that a config flag inside one binary does not address the supply
// concern the split exists for, so this is not a config key — it is a
// statement about which binary is executing, and the import-graph gate
// (Gate2KernelCompiledSeparately, plus cmd/anvil/split_test.go and the
// artifact-split job in .github/workflows/ci.yml) is what makes the statement
// true rather than merely claimed.
//
// The zero value is ArtifactUnset, which is not either artifact.
type Artifact string

// The artifacts. ArtifactUnset is not one.
const (
	// ArtifactUnset is the zero value and names no artifact.
	ArtifactUnset Artifact = ""
	// ArtifactCore is `anvil`: Lane A, Lane B, record, store, remediation.
	// No network probing compiled in. It can never enable DAST.
	ArtifactCore Artifact = "anvil"
	// ArtifactDAST is `anvil-dast`: the dynamic tier.
	ArtifactDAST Artifact = "anvil-dast"
)

// Valid reports whether a names one of the two artifacts.
func (a Artifact) Valid() bool { return a == ArtifactCore || a == ArtifactDAST }

// DastEnablement is D.2's "`dast.enabled` defaulting to `false` at the type
// level (a struct field with no zero-value path to `true`)".
//
// There is no exported field, no setter, and no way to produce an enabled
// value except EnableDAST in phase0_build.go, which checks the artifact, the
// mode declaration and the attestation before it will mint one. `var e
// DastEnablement` is disabled. `DastEnablement{}` is disabled. A
// DastEnablement decoded from a config file is disabled, because encoding/json
// cannot write an unexported field either.
type DastEnablement struct {
	enabled   bool
	artifact  Artifact
	mode      Mode
	attestID  AttestationID
	scopeHash ScopeHash
}

// Enabled reports whether DAST is enabled. False for the zero value.
func (e DastEnablement) Enabled() bool {
	return e.enabled && e.artifact == ArtifactDAST && e.mode.Valid() &&
		e.attestID.Validate() == nil && e.scopeHash.Validate() == nil
}

// Artifact returns the artifact the enablement was minted against.
func (e DastEnablement) Artifact() Artifact { return e.artifact }

// Mode returns the mode the enablement was minted against, or ModeUnset.
func (e DastEnablement) Mode() Mode { return e.mode }

// ---------------------------------------------------------------------------
// Scheme — an allowlist of two
// ---------------------------------------------------------------------------

// Scheme is the URL scheme of a target. It is an allowlist of exactly two
// values rather than a denylist of dangerous ones, because the set of schemes
// a URL parser will accept (file:, gopher:, dict:, jar:, data:) is open-ended
// and the set Anvil probes is not.
type Scheme string

// The schemes. SchemeUnset is not one.
const (
	// SchemeUnset is the zero value and names no scheme.
	SchemeUnset Scheme = ""
	// SchemeHTTP is plaintext HTTP.
	SchemeHTTP Scheme = "http"
	// SchemeHTTPS is HTTP over TLS.
	SchemeHTTPS Scheme = "https"
)

// Valid reports whether s is one of the two permitted schemes.
func (s Scheme) Valid() bool { return s == SchemeHTTP || s == SchemeHTTPS }

// ---------------------------------------------------------------------------
// ScopeHash and AttestationID — the two audit keys gate 21 requires
// ---------------------------------------------------------------------------

// ScopeHash is the SHA-256 of the scope file's exact bytes, lowercase hex.
//
// Gate 5 binds the attestation to it: "the attestation covers the scope hash,
// so editing scope silently invalidates it". Gate 21 keys every audit row on
// it. Both properties fail open if an empty or malformed hash is accepted, so
// Validate is strict about length and charset and there is no "best effort"
// path.
type ScopeHash string

// Validate reports whether h is 64 lowercase hex characters.
func (h ScopeHash) Validate() error {
	if h == "" {
		return fmt.Errorf("%w: scope hash is empty, so no attestation can be bound to this "+
			"scope and no audit row can be keyed to it (gates 5 and 21)", ErrRefused)
	}
	const want = 64 // sha256, hex
	if len(h) != want {
		return fmt.Errorf("%w: scope hash %q is %d characters; a lowercase-hex SHA-256 is %d",
			ErrRefused, string(h), len(h), want)
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("%w: scope hash %q has byte %q at offset %d, which is not "+
				"lowercase hex", ErrRefused, string(h), string(c), i)
		}
	}
	return nil
}

// AttestationID is the stable identifier of one attestation record. Gate 21
// keys the audit log on it together with the scope hash.
type AttestationID string

// maxAttestationIDLen bounds the identifier so an attestation file cannot
// smuggle a payload into an audit key.
const maxAttestationIDLen = 128

// Validate reports whether id is a non-empty, bounded, allowlisted token.
//
// The charset is an allowlist for the same reason Reason's is: this value
// reaches the audit log, and the audit log is read by humans and by tooling.
func (id AttestationID) Validate() error {
	if id == "" {
		return fmt.Errorf("%w: attestation ID is empty, so gate 21 cannot key the audit row "+
			"to an attestation", ErrRefused)
	}
	if len(id) > maxAttestationIDLen {
		return fmt.Errorf("%w: attestation ID is %d bytes; the cap is %d",
			ErrRefused, len(id), maxAttestationIDLen)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			return fmt.Errorf("%w: attestation ID has byte %q at offset %d, which is not in "+
				"the allowed set [A-Za-z0-9._-]", ErrRefused, string(c), i)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// ScopeEntry and Scope — deny by default, always
// ---------------------------------------------------------------------------

// ScopeEntry is one host pattern in a scope file.
//
// Its fields are exported because D.4 parses scope files into these, and a
// parser needs to write them. That is safe: an entry is inert on its own.
// Nothing can be probed because an entry exists — an entry only ever reaches
// the kernel inside a Scope, and Scope's fields are unexported, so the only
// way to get entries into a Scope is NewScope, which validates every one.
type ScopeEntry struct {
	// Host is a canonical hostname, or a single-label wildcard of the form
	// "*.example.com". It is never a bare "*" and never "*.tld".
	Host string
	// Ports is the set of ports the entry covers. An EMPTY SLICE COVERS
	// NOTHING. It does not mean "all ports": gate 4 requires that a scope
	// file which failed to say something yields zero permitted targets, and
	// "the author left this blank" is exactly that case.
	Ports []uint16
}

// Validate reports whether e is a well-formed entry.
//
// The wildcard rule is research/20 gate 4's: "No wildcards that expand beyond
// a single label (*.example.com permitted; * and *.com rejected at parse
// time)." That is implementable without a public-suffix list: the wildcard
// must be the entire first label, and what remains must still have at least
// two labels. "*.com" leaves one label and is refused; "*" leaves none.
//
// This is the TYPE-LEVEL FLOOR. D.4 layers the scope file's schema validation
// (unknown fields, deny-beats-allow precedence, strict parsing) on top of it.
func (e ScopeEntry) Validate() error {
	h := e.Host
	if h == "" {
		return fmt.Errorf("%w: scope entry has an empty host", ErrRefused)
	}
	if len(h) > 253 {
		return fmt.Errorf("%w: scope entry host is %d bytes; the DNS name limit is 253",
			ErrRefused, len(h))
	}
	if h != strings.ToLower(h) {
		return fmt.Errorf("%w: scope entry host %q is not lowercase; gate 8 matches on the "+
			"canonical form only, and an entry that is not canonical can never match",
			ErrRefused, h)
	}
	if strings.HasSuffix(h, ".") {
		return fmt.Errorf("%w: scope entry host %q has a trailing dot; gate 8 strips it "+
			"before matching, so an entry carrying one can never match", ErrRefused, h)
	}
	if strings.ContainsAny(h, " \t\r\n/\\?#@:%") {
		return fmt.Errorf("%w: scope entry host %q contains a character that cannot appear "+
			"in a canonical hostname", ErrRefused, h)
	}
	body := h
	if strings.HasPrefix(h, "*") {
		if !strings.HasPrefix(h, "*.") {
			return fmt.Errorf("%w: scope entry host %q uses a wildcard that is not a whole "+
				"label; the only permitted form is \"*.example.com\"", ErrRefused, h)
		}
		body = h[len("*."):]
		if strings.Count(body, ".") < 1 {
			return fmt.Errorf("%w: scope entry host %q expands beyond a single label. "+
				"research/20 gate 4 permits \"*.example.com\" and rejects \"*\" and "+
				"\"*.com\", because a wildcard over a public suffix is an allow-all "+
				"wearing a disguise", ErrRefused, h)
		}
	}
	if strings.Contains(body, "*") {
		return fmt.Errorf("%w: scope entry host %q has a wildcard somewhere other than the "+
			"leading label", ErrRefused, h)
	}
	if strings.Contains(body, "..") || strings.HasPrefix(body, ".") {
		return fmt.Errorf("%w: scope entry host %q has an empty DNS label", ErrRefused, h)
	}
	for _, p := range e.Ports {
		if p == 0 {
			return fmt.Errorf("%w: scope entry host %q lists port 0, which is not a port",
				ErrRefused, h)
		}
	}
	return nil
}

// Covers reports whether the entry covers a canonical host and port.
//
// It is a pure string/number comparison and does no canonicalization of its
// own: gate 8 canonicalizes, and doing it again here would mean two
// implementations that can disagree. A non-canonical host simply does not
// match, which is the fail-closed direction.
func (e ScopeEntry) Covers(canonicalHost string, port uint16) bool {
	if e.Validate() != nil || canonicalHost == "" {
		return false
	}
	portOK := false
	for _, p := range e.Ports {
		if p == port {
			portOK = true
			break
		}
	}
	if !portOK {
		return false
	}
	if strings.HasPrefix(e.Host, "*.") {
		suffix := e.Host[len("*."):]
		// A single-label wildcard. "*.example.com" covers "a.example.com"
		// and does NOT cover "example.com" or "a.b.example.com".
		rest, ok := strings.CutSuffix(canonicalHost, "."+suffix)
		return ok && rest != "" && !strings.Contains(rest, ".")
	}
	return e.Host == canonicalHost
}

// Scope is the set of things an operator said Anvil may probe, together with
// the hash that binds an attestation to it.
//
// The zero Scope permits nothing, and so does a Scope with an empty allow set.
// That is deliberate and matches research/20 gate 4: "an empty, missing,
// malformed, or unknown-field scope file yields zero permitted targets, never
// 'allow all'". NewScope therefore ACCEPTS an empty allow list — it is a legal
// scope file — and every target checked against it is refused.
//
// Every slice a Scope owns, down to each entry's Ports array, is deep-copied on
// the way in (cloneScopeEntries) and on the way out (AllowEntries,
// DenyEntries). TestScopeSealsEveryFieldOfEveryEntry mutates every field of an
// allow entry and of a deny entry, before and after construction, and asserts
// that what the scope permits does not move.
type Scope struct {
	hash   ScopeHash
	mode   ModeDeclaration
	allow  []ScopeEntry
	deny   []ScopeEntry
	sealed bool
}

// cloneScopeEntries deep-copies a slice of entries, including the Ports backing
// array of every entry.
//
// `append([]ScopeEntry(nil), in...)` is NOT enough and the difference is a
// privilege escalation. A ScopeEntry owns a []uint16; copying the struct copies
// the slice HEADER, so the copy and the original point at the same array.
// D.3's critic used exactly that to turn an explicitly DENIED host into a
// permitted one after construction:
//
//	deny := []ScopeEntry{{Host: "admin.example.com", Ports: []uint16{443}}}
//	s, _ := NewScope(...)      // the deny entry is sealed into the scope
//	deny[0].Ports[0] = 0       // ...and the sealed copy's port changes too
//
// Port 0 covers nothing, so the deny entry stopped matching and the host became
// permitted. The same write against an allow entry widened it to port 22.
// TestScopeSealsEveryFieldOfEveryEntry performs both writes and asserts the
// scope does not move.
func cloneScopeEntries(in []ScopeEntry) []ScopeEntry {
	if in == nil {
		return nil
	}
	out := make([]ScopeEntry, len(in))
	for i, e := range in {
		out[i] = ScopeEntry{Host: e.Host}
		if e.Ports != nil {
			out[i].Ports = append([]uint16(nil), e.Ports...)
		}
	}
	return out
}

// NewScope constructs a Scope from the scope file's EXACT BYTES.
//
// # The hash is derived, never asserted
//
// An earlier signature took the ScopeHash as a parameter and never saw the
// bytes. D.3's critic named what that costs: gate 5 binds an attestation to the
// scope hash "so that editing scope silently invalidates it", and a hash the
// caller asserts about a scope is not a hash of that scope. Two Scopes with
// different entries and different modes could carry one hash, and CoversScope —
// which compares only hashes — would say one attestation covered both.
//
// So there is no hash parameter. NewScope takes the file's bytes, hands them to
// gate 4's strict parser, and derives the hash from those same bytes with
// ScopeHashOf. The entries in the Scope and the hash on the Scope therefore
// come from one document, and editing a byte of it changes the hash.
//
// Gate 4's full refusal set applies — strict parsing, schema version, the
// mode-must-match check, entry bounds — because this IS gate 4's loader;
// CheckGate4ScopeFile is the same path with a typed GateResult instead of an
// error.
func NewScope(raw []byte, decl ModeDeclaration) (Scope, error) {
	s, res := CheckGate4ScopeFile(raw, decl)
	if !res.Passed() {
		return Scope{}, fmt.Errorf("scope: %w", res.Err())
	}
	return s, nil
}

// sealScope is the single mint point for a Scope, called by gate 4's loader
// once it has parsed the bytes it is about to hash.
//
// It is UNEXPORTED because its allow and deny arguments are an assertion about
// raw — the one thing NewScope exists to remove — and the only caller that may
// make that assertion is the parser that produced them from those bytes.
func sealScope(raw []byte, decl ModeDeclaration, allow, deny []ScopeEntry) (Scope, error) {
	if len(raw) == 0 {
		return Scope{}, fmt.Errorf("scope: %w: no scope-file bytes to hash, and a scope with "+
			"no hash cannot have an attestation bound to it (gates 5 and 21)", ErrRefused)
	}
	hash := ScopeHashOf(raw)
	if err := hash.Validate(); err != nil {
		return Scope{}, fmt.Errorf("scope: %w", err)
	}
	if !decl.Declared() {
		return Scope{}, fmt.Errorf("scope: %w: no mode was declared for this scope, and "+
			"gate 6 has no default", ErrRefused)
	}
	for i, e := range allow {
		if err := e.Validate(); err != nil {
			return Scope{}, fmt.Errorf("scope: allow entry %d: %w", i, err)
		}
	}
	for i, e := range deny {
		if err := e.Validate(); err != nil {
			return Scope{}, fmt.Errorf("scope: deny entry %d: %w", i, err)
		}
	}
	return Scope{
		hash:   hash,
		mode:   decl,
		allow:  cloneScopeEntries(allow),
		deny:   cloneScopeEntries(deny),
		sealed: true,
	}, nil
}

// Constructed reports whether this Scope came from NewScope. False for the
// zero value and for any composite literal built elsewhere.
func (s Scope) Constructed() bool { return s.sealed && s.hash.Validate() == nil && s.mode.Declared() }

// Hash returns the scope hash.
func (s Scope) Hash() ScopeHash { return s.hash }

// Mode returns the declared mode, or an error if the scope was never
// constructed.
func (s Scope) Mode() (Mode, error) {
	if !s.Constructed() {
		return ModeUnset, fmt.Errorf("scope: %w", ErrUnconstructed)
	}
	return s.mode.Mode()
}

// Permits reports whether the scope layer allows a canonical host and port.
//
// DENY BEATS ALLOW, unconditionally, and an unconstructed scope permits
// nothing. This is only the scope LAYER's answer: gates 9 and 10 (resolved-IP
// matching and the reserved-range denylist) still apply on top of it, and
// nothing in a scope file can punch through them.
func (s Scope) Permits(canonicalHost string, port uint16) bool {
	if !s.Constructed() {
		return false
	}
	for _, e := range s.deny {
		if e.Covers(canonicalHost, port) {
			return false
		}
	}
	for _, e := range s.allow {
		if e.Covers(canonicalHost, port) {
			return true
		}
	}
	return false
}

// AllowEntries returns a DEEP copy of the allow list, for gates that need to
// enumerate it (gate 10's lab-mode "explicitly enumerated in scope" rule).
//
// Deep, not shallow: a shallow copy hands the caller the live Ports arrays, and
// a caller that writes to one rewrites the sealed scope. That is the same
// aliasing D.3's critic exploited on the way IN, and it is the same escalation
// on the way out.
func (s Scope) AllowEntries() []ScopeEntry {
	if !s.Constructed() {
		return nil
	}
	return cloneScopeEntries(s.allow)
}

// DenyEntries returns a DEEP copy of the deny list. See AllowEntries.
func (s Scope) DenyEntries() []ScopeEntry {
	if !s.Constructed() {
		return nil
	}
	return cloneScopeEntries(s.deny)
}

// ---------------------------------------------------------------------------
// Attestation — gate 5
// ---------------------------------------------------------------------------

// AttestationAuthority is the authority under which someone attests, from
// research/20 gate 5: "owner / operator / written engagement / published VDP
// URL". It is an allowlist; the zero value names no authority.
type AttestationAuthority string

// The four authorities. AuthorityUnset is not one.
const (
	// AuthorityUnset is the zero value and names no authority.
	AuthorityUnset AttestationAuthority = ""
	// AuthorityOwner: the attesting identity owns the target.
	AuthorityOwner AttestationAuthority = "owner"
	// AuthorityOperator: the attesting identity operates the target.
	AuthorityOperator AttestationAuthority = "operator"
	// AuthorityWrittenEngagement: a written engagement covers the target.
	AuthorityWrittenEngagement AttestationAuthority = "written_engagement"
	// AuthorityPublishedVDP: a published vulnerability disclosure policy
	// covers the target.
	//
	// NOTE FOR GATE 12: a published VDP is not security.txt. RFC 9116 and
	// plan/00-SPINE.md S7 are explicit that security.txt "resolves a
	// reporting channel and never grants permission". An operator citing a
	// VDP here is making an affirmative claim under their own identity; the
	// kernel never derives this value from a fetched file.
	AuthorityPublishedVDP AttestationAuthority = "published_vdp"
)

// Valid reports whether a is one of the four authorities.
func (a AttestationAuthority) Valid() bool {
	switch a {
	case AuthorityOwner, AuthorityOperator, AuthorityWrittenEngagement, AuthorityPublishedVDP:
		return true
	}
	return false
}

// MaxAttestationLifetime is the coded ceiling on an attestation's validity
// window: 30 days, from research/20 gate 5 ("an expiry no more than N days out
// (recommend 30)").
//
// plan/50-dast.md gate 5 says the ceiling "may be lowered from the 30-day
// recommended default; presence/validity checking is not optional". Lowering is
// what AttestationCeiling exists for, and NewAttestation compares every
// lifetime against THIS CONST as well as against the supplied ceiling, so a
// ceiling nobody could have raised is checked against a floor nobody can move.
const MaxAttestationLifetime = 30 * 24 * time.Hour

// AttestationCeiling is a lifetime ceiling that configuration may lower and
// may not raise. It is a Cap, so the floor rule is enforced by the same code
// path gate 14's five caps use.
type AttestationCeiling = Cap[time.Duration]

// DefaultAttestationCeiling returns the coded 30-day ceiling. Call Lower on it
// to tighten; there is no method that loosens it, and there is no exported
// constructor that mints a different one.
func DefaultAttestationCeiling() AttestationCeiling {
	return newCap(MaxAttestationLifetime)
}

// Attestation is the affirmative, per-scope authorization record gate 5
// requires before Anvil probes anything it does not itself own.
//
// Every field is unexported. D.4's attestation loader parses a file and calls
// NewAttestation; nothing else can produce one, and a zero Attestation is
// refused by every accessor.
type Attestation struct {
	id        AttestationID
	identity  string
	authority AttestationAuthority
	scopeHash ScopeHash
	issuedAt  time.Time
	expiresAt time.Time
	sealed    bool
}

// maxIdentityLen bounds the attesting identity string. It originates outside
// Anvil (plan/00-SPINE.md S6's `anvil/trust: untrusted`) and reaches the audit
// log, so it is bounded here rather than wherever it is eventually rendered.
const maxIdentityLen = 256

// NewAttestation constructs an Attestation, refusing everything gate 5 says
// must be refused.
//
// ceiling is the lifetime ceiling. Pass DefaultAttestationCeiling() for the
// coded 30 days, or a lowered one. A zero-value Cap refuses every lifetime,
// which is the fail-closed direction for a caller that forgot the argument.
func NewAttestation(
	id AttestationID,
	identity string,
	authority AttestationAuthority,
	scopeHash ScopeHash,
	issuedAt, expiresAt time.Time,
	ceiling AttestationCeiling,
) (Attestation, error) {
	if err := id.Validate(); err != nil {
		return Attestation{}, fmt.Errorf("attestation: %w", err)
	}
	if identity == "" {
		return Attestation{}, fmt.Errorf("attestation: %w: no attesting identity. Gate 5 "+
			"requires one, because an audit that cannot name who authorised the probe is "+
			"not an audit", ErrRefused)
	}
	if len(identity) > maxIdentityLen {
		return Attestation{}, fmt.Errorf("attestation: %w: attesting identity is %d bytes; "+
			"the cap is %d", ErrRefused, len(identity), maxIdentityLen)
	}
	if !authority.Valid() {
		return Attestation{}, fmt.Errorf("attestation: %w: %q is not one of the four "+
			"authorities (%q, %q, %q, %q)", ErrRefused, string(authority),
			AuthorityOwner, AuthorityOperator, AuthorityWrittenEngagement, AuthorityPublishedVDP)
	}
	if err := scopeHash.Validate(); err != nil {
		return Attestation{}, fmt.Errorf("attestation: %w", err)
	}
	if issuedAt.IsZero() || expiresAt.IsZero() {
		return Attestation{}, fmt.Errorf("attestation: %w: issuedAt or expiresAt is the zero "+
			"time, which would make the validity window unbounded in the direction that "+
			"matters", ErrRefused)
	}
	if !expiresAt.After(issuedAt) {
		return Attestation{}, fmt.Errorf("attestation: %w: expiresAt (%s) is not after "+
			"issuedAt (%s)", ErrRefused, expiresAt.UTC(), issuedAt.UTC())
	}
	life := expiresAt.Sub(issuedAt)
	// The CODED floor, checked before and independently of the supplied
	// ceiling. The ceiling argument can only ever be a lowered
	// DefaultAttestationCeiling now that newCap is unexported, but this
	// comparison is against a const in this file and takes no argument at all,
	// so it holds for a Cap minted inside this package too.
	// TestTheCriticsForgedTenYearCeilingIsRefusedAtConstruction mints exactly
	// such a Cap through the unexported constructor and shows this branch
	// refusing it.
	if life > MaxAttestationLifetime {
		return Attestation{}, fmt.Errorf("attestation: %w: the validity window is %s and the "+
			"CODED ceiling is %s. Gate 5's ceiling may be LOWERED from the 30-day default "+
			"and may never be raised, so no supplied ceiling, no configuration and no Cap "+
			"minted anywhere admits a longer one", ErrRefused, life, MaxAttestationLifetime)
	}
	if !ceiling.Allows(life) {
		eff, err := ceiling.Effective()
		if err != nil {
			return Attestation{}, fmt.Errorf("attestation: %w: no lifetime ceiling was "+
				"supplied, so no lifetime is permitted; pass "+
				"DefaultAttestationCeiling()", ErrRefused)
		}
		return Attestation{}, fmt.Errorf("attestation: %w: validity window is %s and the "+
			"ceiling is %s", ErrRefused, life, eff)
	}
	return Attestation{
		id:        id,
		identity:  identity,
		authority: authority,
		scopeHash: scopeHash,
		issuedAt:  issuedAt,
		expiresAt: expiresAt,
		sealed:    true,
	}, nil
}

// Constructed reports whether this Attestation came from NewAttestation.
func (a Attestation) Constructed() bool { return a.sealed && a.id.Validate() == nil }

// ID returns the attestation identifier gate 21 keys the audit log on.
func (a Attestation) ID() AttestationID { return a.id }

// Identity returns the attesting identity. It originates outside Anvil and is
// `anvil/trust: untrusted` wherever it lands on the record.
func (a Attestation) Identity() string { return a.identity }

// Authority returns the authority under which the identity attested.
func (a Attestation) Authority() AttestationAuthority { return a.authority }

// ScopeHash returns the scope hash the attestation is bound to.
func (a Attestation) ScopeHash() ScopeHash { return a.scopeHash }

// Live reports whether the attestation is constructed and unexpired at the
// given instant. An unconstructed attestation and an invalid clock are both
// not-live.
func (a Attestation) Live(c Clock) bool {
	if !a.Constructed() || !c.Valid() {
		return false
	}
	now := c.Instant()
	return !now.Before(a.issuedAt) && now.Before(a.expiresAt)
}

// CoversScope reports whether the attestation is bound to this exact scope.
//
// Gate 5: "the attestation covers the scope hash, so editing scope silently
// invalidates it". Comparing hashes is how "silently" becomes "loudly".
func (a Attestation) CoversScope(s Scope) bool {
	if !a.Constructed() || !s.Constructed() {
		return false
	}
	return a.scopeHash == s.Hash()
}

// ---------------------------------------------------------------------------
// Target — gate 8/9's output, and one of Decide's four inputs
// ---------------------------------------------------------------------------

// Target is the one host, port and pinned address the kernel is being asked
// about.
//
// It carries BOTH the literal form the operator or the engine supplied and the
// canonical form gate 8 produced, because gate 8's fail-closed behaviour is
// "Reject if canonical form diverges from literal form unexpectedly; log
// both". A type that kept only the canonical form would make that impossible
// after the fact.
//
// It also carries the PINNED address from gate 9. Pinning is why this is a
// value and not a hostname: "never re-resolve between check and connect"
// cannot be enforced by a discipline, only by making the resolved address part
// of the thing that was authorized.
//
// # The literal field is bounded and charset-restricted
//
// NewTarget once checked only that the literal was non-empty, and D.3's critic
// pushed a 40 KB security.txt body through it. Every gateFunc can read it back
// with Target.Literal(), which made the field a channel around gate 12's
// structural exclusion: the admission input closure has no interface and no
// `any`, but a string with no bound is an `any` with extra steps. It is now
// bounded at maxLiteralHostBytes and restricted to the bytes a host literal can
// contain, and TestGate8BoundsTheTargetLiteral replays the critic's exact 40 KB
// payload against it.
type Target struct {
	scheme    Scheme
	literal   string
	canonical string
	port      uint16
	pinned    netip.Addr
	sealed    bool
}

// maxLiteralHostBytes bounds Target.literal — the host AS SUPPLIED, before
// canonicalization. Gate 8's own bound (phase2_admission.go's maxRawHostBytes)
// is defined as this one, so there is a single number rather than two that can
// drift.
//
// 512 is twice the 253-byte DNS name limit, which leaves room for the
// percent-encoded and uppercase spellings gate 8 exists to fold together while
// refusing anything that is a document rather than a name.
const maxLiteralHostBytes = 512

// literalHostExtraBytes is the non-alphanumeric part of the literal-host
// ALLOWLIST: the punctuation a host literal can legitimately carry before
// canonicalization.
//
//	.  -  _   DNS label punctuation
//	%          a percent-encoded spelling gate 8 decodes exactly once
//	[  ]  :    an IPv6 address literal, which arrives bracketed
//
// It is an allowlist, not a denylist of dangerous bytes, for the reason
// Reason.Validate gives: this value reaches the audit log and is readable by
// every gate, and a denylist would have to anticipate every encoding trick.
// Notably absent: whitespace, `/`, `\`, `?`, `#`, `@`, `*`, every control byte
// and every byte above 0x7E.
const literalHostExtraBytes = ".-_%[]:"

// indexNonLiteralHostByte returns the offset of the first byte of s that is not
// on the literal-host allowlist, or -1 if every byte is.
func indexNonLiteralHostByte(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9':
			continue
		}
		if strings.IndexByte(literalHostExtraBytes, c) < 0 {
			return i
		}
	}
	return -1
}

// NewTarget constructs a Target from gate 8's canonicalization and gate 9's
// pinned address.
//
// The canonical-form checks here are a FLOOR, not gate 8. Full IDNA/punycode
// normalization, percent-decoding, port normalization and IPv4-mapped-IPv6
// unwrapping are D.5's Canonicalize. What this refuses is a value that is
// obviously not canonical — uppercase, trailing dot, embedded delimiters,
// surrounding whitespace — so that a gate 8 that silently returned its input
// unchanged cannot produce a Target the kernel treats as canonicalized.
func NewTarget(scheme Scheme, literal, canonical string, port uint16, pinned netip.Addr) (Target, error) {
	if !scheme.Valid() {
		return Target{}, fmt.Errorf("target: %w: %q is not a permitted scheme; the only two "+
			"are %q and %q", ErrRefused, string(scheme), SchemeHTTP, SchemeHTTPS)
	}
	if literal == "" {
		return Target{}, fmt.Errorf("target: %w: the literal host is empty, so gate 8 has "+
			"nothing to log alongside the canonical form", ErrRefused)
	}
	if len(literal) > maxLiteralHostBytes {
		return Target{}, fmt.Errorf("target: %w: the literal host is %d bytes and the coded "+
			"bound is %d. A host literal that large is a payload rather than a name, and "+
			"Target.Literal() is readable by every gate", ErrRefused, len(literal),
			maxLiteralHostBytes)
	}
	if i := indexNonLiteralHostByte(literal); i >= 0 {
		return Target{}, fmt.Errorf("target: %w: the literal host has byte %q at offset %d, "+
			"which is not in the allowed set [A-Za-z0-9] plus %q. The literal is kept for "+
			"gate 8's \"log both forms\" and is read by every gate, so it carries a host "+
			"literal and nothing else", ErrRefused, string(literal[i]), i, literalHostExtraBytes)
	}
	if canonical == "" {
		return Target{}, fmt.Errorf("target: %w: the canonical host is empty", ErrRefused)
	}
	if len(canonical) > 253 {
		return Target{}, fmt.Errorf("target: %w: canonical host is %d bytes; the DNS name "+
			"limit is 253", ErrRefused, len(canonical))
	}
	if canonical != strings.ToLower(canonical) {
		return Target{}, fmt.Errorf("target: %w: canonical host %q is not case-folded, so "+
			"gate 8 did not canonicalize it", ErrRefused, canonical)
	}
	if strings.TrimSpace(canonical) != canonical {
		return Target{}, fmt.Errorf("target: %w: canonical host %q has surrounding "+
			"whitespace", ErrRefused, canonical)
	}
	if strings.HasSuffix(canonical, ".") {
		return Target{}, fmt.Errorf("target: %w: canonical host %q has a trailing dot, which "+
			"gate 8 strips", ErrRefused, canonical)
	}
	if strings.ContainsAny(canonical, " \t\r\n/\\?#@:%*") {
		return Target{}, fmt.Errorf("target: %w: canonical host %q contains a character that "+
			"cannot appear in a canonical hostname; a percent sign in particular means "+
			"gate 8's percent-decoding did not run", ErrRefused, canonical)
	}
	if strings.Contains(canonical, "..") || strings.HasPrefix(canonical, ".") {
		return Target{}, fmt.Errorf("target: %w: canonical host %q has an empty DNS label",
			ErrRefused, canonical)
	}
	if port == 0 {
		return Target{}, fmt.Errorf("target: %w: port 0 is not a port. Gate 8 normalizes the "+
			"scheme default (%d for http, %d for https) into an explicit port so that scope "+
			"matching never has to guess", ErrRefused, 80, 443)
	}
	if !pinned.IsValid() {
		return Target{}, fmt.Errorf("target: %w: no pinned address. Gate 9 requires the "+
			"kernel to resolve, match the resolved IP against scope, pin it, and connect "+
			"only to the pinned address; a Target without one cannot be connected to "+
			"without re-resolving, which is the DNS-rebinding TOCTOU gate 9 closes",
			ErrRefused)
	}
	if pinned.Is4In6() {
		return Target{}, fmt.Errorf("target: %w: pinned address %s is an IPv4-mapped IPv6 "+
			"address; gate 8 unwraps these before matching, because ::ffff:169.254.169.254 "+
			"and 169.254.169.254 must not compare differently against gate 10's reserved "+
			"ranges", ErrRefused, pinned)
	}
	return Target{
		scheme:    scheme,
		literal:   literal,
		canonical: canonical,
		port:      port,
		pinned:    pinned.Unmap(),
		sealed:    true,
	}, nil
}

// Constructed reports whether this Target came from NewTarget.
func (t Target) Constructed() bool { return t.sealed && t.canonical != "" && t.pinned.IsValid() }

// Scheme returns the target's scheme.
func (t Target) Scheme() Scheme { return t.scheme }

// Literal returns the host as it was supplied, before canonicalization. Gate 8
// logs it next to the canonical form.
func (t Target) Literal() string { return t.literal }

// Canonical returns the canonical host. Scope matching uses this and only
// this.
func (t Target) Canonical() string { return t.canonical }

// Port returns the explicit, normalized port.
func (t Target) Port() uint16 { return t.port }

// Pinned returns the address gate 9 pinned. The connection is made to this
// address and never to a fresh resolution.
func (t Target) Pinned() netip.Addr { return t.pinned }

// Diverged reports whether the canonical form differs from the literal form.
// Gate 8 logs both when it does; it is not by itself a refusal, because
// "example.COM" canonicalizing to "example.com" is a divergence and is fine.
func (t Target) Diverged() bool { return t.literal != t.canonical }

// String renders the target for an audit row: "https://host:443 -> 93.184.x.x".
func (t Target) String() string {
	if !t.Constructed() {
		return "<unconstructed target>"
	}
	return fmt.Sprintf("%s://%s:%d -> %s", t.scheme, t.canonical, t.port, t.pinned)
}

// ---------------------------------------------------------------------------
// Clock — an instant, not an interface
// ---------------------------------------------------------------------------

// Clock is the instant a decision is being adjudicated at.
//
// # Why this is a value and not an interface
//
// Two reasons, and the second one is the important one.
//
// First, plan/00-SPINE.md S7 makes the kernel "a pure function of (target,
// scope, attestation, clock)". A function that calls Now() on an interface is
// not pure; a function handed an instant is.
//
// Second, and this is gate 12: an interface parameter is a HOLE in the
// admission decision's input type. Anything satisfying `interface{ Now()
// time.Time }` can be passed, including a type that also carries a security.txt
// result, and a type assertion inside a gate could read it back out. Gate 12
// requires that the admission function "must not be ABLE to see it". A struct
// wrapping a time.Time can carry nothing else, and that is enforced by the
// compiler rather than by a reviewer noticing.
//
// The zero Clock is invalid, and so is any instant before minPlausibleInstant —
// which catches the classic uninitialized-clock bug where a Unix epoch zero
// sails past an IsZero check and makes every attestation look expired or every
// embargo look elapsed.
type Clock struct {
	at time.Time
}

// minPlausibleInstant is the floor a real Anvil run's clock must be above.
// Anything below it is an uninitialized clock, not a time.
var minPlausibleInstant = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)

// NewClock constructs a Clock from an instant.
func NewClock(at time.Time) (Clock, error) {
	if at.IsZero() {
		return Clock{}, fmt.Errorf("clock: %w: the zero time is not an instant", ErrRefused)
	}
	if at.Before(minPlausibleInstant) {
		return Clock{}, fmt.Errorf("clock: %w: %s is before %s, which means the clock was "+
			"never set rather than that the run is happening in 1970", ErrRefused,
			at.UTC(), minPlausibleInstant)
	}
	return Clock{at: at}, nil
}

// Valid reports whether the Clock was constructed by NewClock.
func (c Clock) Valid() bool { return !c.at.IsZero() && !c.at.Before(minPlausibleInstant) }

// Instant returns the instant. It returns the zero time for an unconstructed
// Clock, and every caller in this package checks Valid first.
func (c Clock) Instant() time.Time { return c.at }

// ---------------------------------------------------------------------------
// RunClock — THE run's clock, and it is not something a caller mints
// ---------------------------------------------------------------------------

// RunClock is the one instant a run is adjudicated at.
//
// # Why this type exists at all when Clock already does
//
// Because a function that TAKES a Clock can be lied to and a function that
// READS THE RUN'S clock cannot, and the difference was worth an entire class
// of defeat.
//
// Every Phase 4 embargo decision is a comparison between two instants. While
// each of those instants was an independent Clock parameter, a caller who
// supplied all of them CONSISTENTLY told a lie no comparison between two of
// them could catch: record first contact on 3 January against a 3 January
// clock — a back-date of zero, so MaxVendorContactBackdate never engages —
// open the embargo against the same January clock, and then publish against
// the real August present. Forty-five days of embargo elapsed and nobody was
// ever contacted. Bounding one caller-supplied instant against a second
// caller-supplied instant catches the lie told with ONE clock and misses the
// lie told with TWO, and a third such comparison fails the same way.
//
// So the run's clock is established ONCE, at run initiation, and every gate
// that needs "now" reads it instead of accepting one. A contact instant is
// still a parameter — it is a recorded fact about the past, not a "now" — but
// it is now recorded AGAINST the run's clock, and MaxVendorContactBackdate
// bounds how far behind that clock it may sit.
//
// # Why it is sealed, and what the seal is worth
//
// sealRunClock is unexported and there is no exported function anywhere in
// this package that returns a RunClock. The only route to one from outside is
// RunInitiation.RunClock, and a RunInitiation exists only after gates 6, 4, 5
// and 7 and EnableDAST have all passed. TestRunClockHasNoExportedConstructor
// parses the package and fails if that stops being true.
//
// The ZERO VALUE IS NOT A CLOCK: Valid() is false and every Phase 4 gate
// refuses it rather than reading it as 1970, which is a date that is after no
// deadline and before every one.
//
// # What this does NOT close, stated rather than implied
//
// A run's clock is still the instant the operator's harness handed to
// InitiateRun; this package has no ambient time source, by S7's purity rule.
// What it buys is that ONE RUN HAS ONE CLOCK. Telling the January/August lie
// now costs two separate run initiations, which means two scope loads, two
// gate-7 trigger checks, and two attestations that are live at instants seven
// months apart — the 30-day ceiling in gate 5 means one attestation cannot
// cover both — and the audit rows for the two are keyed to different
// attestation IDs. That is a materially larger and more visible act than
// passing a different time.Time to the next call, and it is as far as a kernel
// with no trusted clock can go.
type RunClock struct {
	at     time.Time
	sealed bool
}

// sealRunClock mints the run's clock from the instant run initiation was
// handed. It is unexported ON PURPOSE — see the type comment.
//
// An invalid Clock yields the zero RunClock rather than a RunClock carrying a
// zero instant, so there is no shape of this type that is sealed and wrong.
func sealRunClock(c Clock) RunClock {
	if !c.Valid() {
		return RunClock{}
	}
	return RunClock{at: c.at, sealed: true}
}

// Valid reports whether this is a run clock sealed at run initiation. It is
// false for the zero value.
func (r RunClock) Valid() bool {
	return r.sealed && !r.at.IsZero() && !r.at.Before(minPlausibleInstant)
}

// Instant returns the run's instant, or the zero time for an unsealed one.
func (r RunClock) Instant() time.Time {
	if !r.Valid() {
		return time.Time{}
	}
	return r.at
}

// Now returns the run's instant as a Clock, for the per-target gates that take
// one. It returns the zero Clock — which every gate refuses — for an unsealed
// run clock, so an unsealed one cannot be laundered into a valid Clock.
func (r RunClock) Now() Clock {
	if !r.Valid() {
		return Clock{}
	}
	return Clock{at: r.at}
}

// ---------------------------------------------------------------------------
// Cap — a coded floor that configuration may only LOWER
// ---------------------------------------------------------------------------

// Cap is a coded limit that configuration may lower and may never raise.
//
// It exists here, in the kernel contract, rather than being re-implemented by
// each gate that needs one, because "no config key may raise a cap above its
// coded floor" appears in D.2's, D.4's and D.6's forbidden actions and a rule
// implemented three times is a rule implemented two ways. Gate 14's five caps
// (10 rps/host, 4 concurrent/host, 20,000 req/target/run, 30 min/target, 1 MiB
// body, 3 retries) and gate 5's 30-day attestation ceiling are all this type.
//
// THE ZERO VALUE PERMITS NOTHING. `var c Cap[int]` has set=false, and Allows
// returns false for every value including zero. A gate that forgot to
// initialize its cap blocks every request rather than allowing every request,
// which is the whole design rule stated once in a type.
//
// # There is no exported constructor, and that is the fix for a real forgery
//
// D.3's critic compiled and ran this:
//
//	tenYears := authz.NewCap(10 * 365 * 24 * time.Hour)
//	a, err := authz.NewAttestation("forged-long-life", "attacker", authz.AuthorityOwner,
//	    goodHash, now, now.Add(10*365*24*time.Hour), tenYears)
//
// err was nil and the attestation was live nine years later. An exported,
// unvalidated NewCap means any caller can mint a "coded floor" of any size, so
// a cap that is only ever compared against a caller-supplied Cap has no floor
// at all — it has whatever floor the caller wanted. Gate 5 says the ceiling
// "may be LOWERED from the 30-day recommended default"; lowering must be the
// only direction that is expressible.
//
// So the constructor is UNEXPORTED. Every Cap that exists anywhere in Anvil is
// minted inside internal/dast/authz from a compiled-in const — gate 14's six
// caps (CodedCaps), gate 16's thresholds (CodedHealthThresholds) and gate 5's
// ceiling (DefaultAttestationCeiling) — and the only operation a caller has on
// one is Lower. The critic's line no longer compiles, and
// TestNoExportedSurfaceMintsACap is the guard that keeps it that way: it walks
// this package's whole EXPORTED surface — functions, methods on exported types,
// type declarations including ALIASES, and exported vars and consts — and
// requires every declaration naming a Cap to be on an allowlist with a written
// justification.
type Cap[T cmp.Ordered] struct {
	coded     T
	effective T
	set       bool
}

// newCap declares a coded floor. The effective value starts equal to it.
//
// It is unexported: see the type's doc comment. Callers outside this package
// reach a Cap only through a named, argument-free constructor over a const —
// DefaultAttestationCeiling, CodedCaps, CodedHealthThresholds — and may only
// Lower what they are given.
func newCap[T cmp.Ordered](coded T) Cap[T] {
	return Cap[T]{coded: coded, effective: coded, set: true}
}

// Lower tightens the cap.
//
// The comparison is against the CURRENT EFFECTIVE value, and that single
// comparison enforces both rules at once:
//
//   - it refuses anything above the coded floor, because effective is never
//     above coded (NewCap sets them equal and this is the only method that
//     changes either, downward);
//   - it refuses a sequence of config layers walking the cap back up — lower
//     to 4, then "lower" to 9 — which a comparison against coded alone would
//     let through.
//
// An earlier draft compared against coded first and against effective second.
// The coded comparison was strictly subsumed by the effective one, so the
// branch could never be the only thing refusing anything, and a mutation test
// that deleted it stayed green. It is gone rather than commented, and its one
// contribution — naming the coded floor in the message — is folded in below.
func (c Cap[T]) Lower(v T) (Cap[T], error) {
	if !c.set {
		return Cap[T]{}, fmt.Errorf("cap: %w: this Cap was never declared with NewCap, so "+
			"there is no coded floor to lower from", ErrUnconstructed)
	}
	if v > c.effective {
		return Cap[T]{}, fmt.Errorf("cap: %w: %v exceeds the current effective cap %v "+
			"(coded floor %v). Configuration may only LOWER a cap; no sequence of "+
			"settings may walk one back up", ErrCapRaise, v, c.effective, c.coded)
	}
	c.effective = v
	return c, nil
}

// Allows reports whether v is within the effective cap. It is false for an
// undeclared Cap, for every v.
func (c Cap[T]) Allows(v T) bool { return c.set && v <= c.effective }

// Effective returns the effective cap, or an error if the Cap was never
// declared.
func (c Cap[T]) Effective() (T, error) {
	var zero T
	if !c.set {
		return zero, fmt.Errorf("cap: %w", ErrUnconstructed)
	}
	return c.effective, nil
}

// Coded returns the compiled-in floor, which no configuration can change.
func (c Cap[T]) Coded() (T, error) {
	var zero T
	if !c.set {
		return zero, fmt.Errorf("cap: %w", ErrUnconstructed)
	}
	return c.coded, nil
}

// ---------------------------------------------------------------------------
// GATE 12 — the type-level exclusion
// ---------------------------------------------------------------------------

// ReportingChannelOnly is the marker every security.txt-derived type must
// embed, and it is gate 12's enforcement surface.
//
// plan/50-dast.md gate 12: security.txt is fetched for reporting-channel
// resolution only, its "Result recorded in the audit log; structurally
// excluded from the admission decision's input type... enforced at the type
// level, not by convention". plan/00-SPINE.md S7 says the same thing and adds
// why: "Enforce at the type level so the inevitable contributor proposal fails
// to compile."
//
// # How the exclusion actually works
//
// Three mechanisms, in descending strength.
//
//  1. Decide's four parameters are Target, Scope, Attestation and Clock, all
//     declared in THIS file. Adding an extension point to any of them requires
//     editing types.go, which is D.2's write scope and is explicitly not D.5's.
//
//  2. gateFunc (kernel.go) has the same four parameters. Every gate
//     implementation in phases 1–3 is a gateFunc, so no gate can receive a
//     security.txt result even inside this package.
//
//  3. Any type embedding ReportingChannelOnly satisfies excludedFromAdmission
//     via an UNEXPORTED method, so only types declared in this package can
//     satisfy it, and the reflection walk in kernel_test.go's
//     TestAdmissionInputClosureIsClosed refuses any such type appearing
//     anywhere in the closure.
//
// D.5 declares `type SecurityTxtResult struct { ReportingChannelOnly; ... }`.
// The embed is what makes mechanism 3 bite; mechanisms 1 and 2 hold whether or
// not D.5 remembers it.
//
// What this does NOT close, stated plainly: a contributor with write access to
// types.go can add a field. Nothing in Go prevents that. What the design buys
// is that the change lands in the kernel's own vocabulary file, in a diff a
// reviewer is looking at, rather than in a Phase 2 file where an extra
// parameter looks like plumbing.
type ReportingChannelOnly struct{}

// reportingChannelOnly is the unexported marker method. It is unexported so
// that no type outside internal/dast/authz can satisfy excludedFromAdmission
// by declaring its own method of the same name.
func (ReportingChannelOnly) reportingChannelOnly() {}

// excludedFromAdmission is satisfied by exactly the types that embed
// ReportingChannelOnly. Nothing in the admission input closure may implement
// it; kernel_test.go asserts that by reflection over the closure.
type excludedFromAdmission interface{ reportingChannelOnly() }

// compile-time assertion that the marker satisfies its own interface.
var _ excludedFromAdmission = ReportingChannelOnly{}

// ---------------------------------------------------------------------------
// GateFailure and GateResult — the typed failure Phase 0 returns
// ---------------------------------------------------------------------------

// GateFailure is a gate's typed refusal. D.2's expected output schema requires
// "a typed failure, not a bool".
type GateFailure struct {
	// Gate is the gate that refused.
	Gate GateID
	// Reason is the validated gateNN.slug token.
	Reason Reason
	// Detail is Anvil-authored operator-facing text. It is NEVER assembled
	// from a response body, a scope file, or any other bytes that originated
	// outside Anvil; those are `anvil/trust: untrusted` per
	// plan/00-SPINE.md S6 and belong in a hashed-and-referenced field, not
	// in a message that will be read by an agent.
	Detail string
	// Evidence is the specific offending items, one per line when rendered.
	// It carries Anvil-measured facts such as import paths and file
	// positions.
	Evidence []string
	// Err is the wrapped sentinel, always unwrapping to ErrRefused.
	Err error
}

// Error implements error.
func (f *GateFailure) Error() string {
	if f == nil {
		return "<nil gate failure>"
	}
	var b strings.Builder
	b.WriteString(f.Gate.String())
	b.WriteString(" refused (")
	b.WriteString(string(f.Reason))
	b.WriteString("): ")
	b.WriteString(f.Detail)
	for _, e := range f.Evidence {
		b.WriteString("\n  ")
		b.WriteString(e)
	}
	return b.String()
}

// Unwrap gives errors.Is(err, ErrRefused) a true answer for every gate
// failure.
func (f *GateFailure) Unwrap() error {
	if f == nil {
		return nil
	}
	if f.Err != nil {
		return f.Err
	}
	return ErrRefused
}

// GateResult is what a Phase 0 gate returns.
//
// # Why this is not `*GateFailure` with nil meaning pass
//
// Because the nil zero value of a pointer would mean PASS, and this package's
// one rule is that the zero value means refuse. `var r GateResult` has an
// unset gate and passed=false, so Passed() is false. A caller that forgets to
// assign the result of a gate call, or that builds a GateResult in another
// package, gets a refusal.
//
// The typed failure D.2's schema asks for is inside, reachable through
// Failure() and through errors.As.
type GateResult struct {
	gate    GateID
	passed  bool
	failure *GateFailure
}

// Passed reports whether the gate passed. It is false for the zero value, for
// a result naming no gate, and for any result carrying a failure.
func (r GateResult) Passed() bool { return r.passed && r.failure == nil && r.gate.Valid() }

// Gate returns the gate this result is about.
func (r GateResult) Gate() GateID { return r.gate }

// Failure returns the typed failure, or nil if the gate passed.
func (r GateResult) Failure() *GateFailure { return r.failure }

// Err returns the failure as an error, or nil if the gate passed. A
// zero-value GateResult returns a non-nil error, because it did not pass.
func (r GateResult) Err() error {
	if r.Passed() {
		return nil
	}
	if r.failure != nil {
		return r.failure
	}
	return fmt.Errorf("%w: %s produced a GateResult that no gate function minted",
		ErrUnconstructed, r.gate)
}

// gatePassed mints a passing result. Unexported: only a gate implementation in
// this package can declare that a gate passed.
func gatePassed(g GateID) GateResult {
	if !g.Valid() {
		return GateResult{}
	}
	return GateResult{gate: g, passed: true}
}

// gateFailed mints a failing result, refusing to mint one whose reason does
// not name the same gate — a mismatch means the caller copied a reason from
// another gate and the message would misattribute the refusal.
func gateFailed(g GateID, r Reason, detail string, evidence ...string) GateResult {
	f := &GateFailure{Gate: g, Reason: r, Detail: detail, Evidence: evidence, Err: ErrRefused}
	named, err := r.Gate()
	switch {
	case err != nil:
		f.Reason = ReasonUnspecified
		f.Detail = fmt.Sprintf("%s (the reason token %q supplied by this gate is itself "+
			"invalid: %v)", detail, string(r), err)
	case named != g:
		f.Detail = fmt.Sprintf("%s (reported under %s but the reason token names %s; the "+
			"refusal stands and the mismatch is a bug in the gate)", detail, g, named)
	}
	return GateResult{gate: g, passed: false, failure: f}
}
