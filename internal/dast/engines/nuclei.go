// This file is the Nuclei driver.
//
// # What this driver is for, stated as the failure it prevents
//
// Nuclei is a tool that probes whatever it is pointed at. It has no opinion
// about scope, no attestation to check, and no reason to refuse. Everything
// that makes a Nuclei run lawful lives OUTSIDE Nuclei, in
// internal/dast/authz, and the only thing standing between the kernel's
// judgement and Nuclei's willingness is this file.
//
// So the design rule here is narrow and it is the whole packet:
//
//	A TARGET REACHES THE ENGINE ONLY BY WAY OF AN authz.Authorization.
//
// There is no exported field, no config key, no environment variable and no
// string parameter anywhere in this package that puts a host into an engine
// run. TargetSpec — the only type the engine seam accepts as a destination —
// has unexported fields and exactly one constructor, NewTargetSpec, which
// begins by calling authz.RequireAuthorization and authz.PinnedDialAddress.
// A composite literal cannot forge one; that is a compile error in any other
// package, not a lint. Argument construction is a security boundary here,
// because a target that reaches the engine without having passed gates 8, 9
// and 10 is a scope bypass with extra steps.
//
// # This driver holds no socket, and cannot
//
// The spine's safety section says no model ever holds a network handle. The
// build-time guard's gate 3 extends that to the whole dynamic tier: any socket
// constructed inside internal/dast outside internal/dast/authz fails the build,
// with no allowlist and no code path that can add one
// (CheckGate3EgressChokePoint, tier 1).
//
// That is not an obstacle this file works around. It is the reason the file is
// shaped the way it is. Fire() produces a RequestProposal, runs it through the
// kernel's per-request interceptor, and — only if the kernel admits it — hands
// an AdmittedRequest to an Issuer supplied from outside internal/dast. The
// driver never learns an address it could dial and never holds a connection it
// could reuse. `go test` for the kernel walks this file and would report a
// tier-1 violation if that ever stopped being true.
//
// # Nuclei is not installed on the host this was written on, and says so
//
// MEASURED 2026-08-22 on the development host (`Get-Command nuclei` finds
// nothing; `go list -m all` contains no projectdiscovery module). There is
// therefore NO production Engine in this package, and SystemEngine returns a
// typed refusal rather than a no-op that would let a scan come back clean.
//
// This is the same hazard internal/collector/repo exists to close for the SCA
// side, and this file follows its shape deliberately:
//
//	engine absent                -> *EngineUnavailableError (ExitCodeArtefactAbsent)
//	template directory empty     -> ErrNoTemplates, never an empty pass
//	template unparseable         -> RejectedTemplate, never a skipped file
//	every request refused        -> Coverage says so
//	scan produced no findings    -> ScanResult.AssertNotSilentlyEmpty decides
//	                                whether that means "clean" or "nothing ran"
//
// "The tool ran and found nothing" and "the tool was not there" produce
// byte-identical finding lists. For a security scanner that is the worst
// available failure, so they are separated here by type, by exit code, and by
// a coverage predicate the caller must consult before reporting clean.
//
// docs/controls.md entry U4 records exactly what remains
// unexecuted and what would settle it. There is no t.Skip in this package.
//
// # What this driver assumes about template provenance: NOTHING
//
// Templates are supply-chain input. Template pinning owns pinning them — a commit SHA for
// `nuclei-templates`, diffed before promotion (plan/design/dynamic-tier.md, Pinned
// Versions And Licences). This file owns NOT TRUSTING THEM, and it does not
// depend on template pinning having run:
//
//   - Every template is analysed structurally before it is admitted, and the
//     analysis is an ALLOWLIST of top-level keys. A template carrying a key
//     nobody enumerated is rejected, not skipped and not partially loaded.
//   - The `code:` protocol is rejected AT LOAD TIME with its own named
//     reason, per the spine's exclusion list. So are `javascript:`, `flow:`, `headless:` and
//     `self-contained:`, for reasons stated at protocolAllowlist.
//   - Every admitted template carries a SHA-256 of its exact bytes. That is
//     the value template pinning pins against; this file computes and reports it so a
//     pin can be checked, and enforces its own allowlist regardless of
//     whether one was.
//   - No signature is verified here. Upstream templates carry a trailing
//     `# digest:` line signed by projectdiscovery; validating it needs
//     projectdiscovery's public key and their verifier, neither of which is
//     in this module. WHERE THAT ASSUMPTION IS ENFORCED: nowhere in this
//     package, and that is stated rather than implied — see U4.
//
// The consequence is worth writing down plainly: a hostile template in the
// directory cannot reach a host the kernel did not admit, because it does not
// get to name a host at all. It can, at most, cause a request the kernel then
// gates like every other request.

package engines

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/authz"
)

// ---------------------------------------------------------------------------
// Scrubbing, and why this package does not use internal/ingest/sanitize
// ---------------------------------------------------------------------------

// MaxEvidenceBytes bounds one piece of engine-authored prose the driver
// retains. Evidence is a snippet that demonstrates a finding, not a body.
const MaxEvidenceBytes = 4096

// EvidenceStats is what scrubbing removed from one external string.
//
// # This is a narrow local subset of internal/ingest/sanitize, on purpose,
// # and NOT because reimplementing it was preferable
//
// MEASURED, not assumed: importing internal/ingest/sanitize from this package
// fails the build-time guard's tier-wide gate 2 check. `go test -run
// TestGate2NoDastPackageReachesTheInferenceLayer ./internal/dast/authz/`
// reported, verbatim:
//
//	internal/dast/engines reaches 2 package(s) outside the standard library,
//	the DAST tree and the kernel's import allowlist:
//	  github.com/Susquehanna-Syntax/Anvil/internal/ingest/invisible
//	  github.com/Susquehanna-Syntax/Anvil/internal/ingest/sanitize
//
// That gate is right and this file is what moved. Every package under
// internal/dast may link only the standard library, the DAST tree, and
// kernelImportAllowlist — one entry, internal/record — because a DAST package
// that links what the KERNEL may not link puts it in the same process as the
// network handles. Widening it is an edit to phase0_build.go, which is the build-time guard's
// write scope and not this packet's.
//
// So the scrub below is DELIBERATELY SMALLER than sanitize's: it removes the
// character classes that make a string render differently from how it
// compares, it bounds the length, and it counts what it did. It does not do
// sanitize's hidden-markup analysis and it does not claim to. Where the two
// disagree, sanitize is the authority and this is a local bound on what this
// driver retains.
type EvidenceStats struct {
	// Controls is C0 (excluding tab and newline), DEL and C1 removed.
	Controls int
	// ZeroWidth is zero-width and word-joiner characters removed.
	ZeroWidth int
	// Bidi is bidirectional-override and isolate characters removed. These
	// are the ones that make a string render in an order it does not
	// compare in.
	Bidi int
	// Tag is Unicode tag characters (U+E0000..U+E007F) removed. They are
	// invisible everywhere and are the standard smuggling channel.
	Tag int
	// InvalidUTF8 is malformed byte sequences dropped.
	InvalidUTF8 int
	// TruncatedFrom is the original byte length when the string exceeded
	// MaxEvidenceBytes, 0 otherwise.
	TruncatedFrom int
}

// Removed reports how many runes were dropped.
func (s EvidenceStats) Removed() int {
	return s.Controls + s.ZeroWidth + s.Bidi + s.Tag + s.InvalidUTF8
}

// Modified reports whether scrubbing changed the string at all.
func (s EvidenceStats) Modified() bool { return s.Removed() > 0 || s.TruncatedFrom > 0 }

// Merge folds o into s.
func (s *EvidenceStats) Merge(o EvidenceStats) {
	s.Controls += o.Controls
	s.ZeroWidth += o.ZeroWidth
	s.Bidi += o.Bidi
	s.Tag += o.Tag
	s.InvalidUTF8 += o.InvalidUTF8
	if o.TruncatedFrom > s.TruncatedFrom {
		s.TruncatedFrom = o.TruncatedFrom
	}
}

func (s EvidenceStats) String() string {
	return fmt.Sprintf("controls=%d zero_width=%d bidi=%d tag=%d invalid_utf8=%d truncated_from=%d",
		s.Controls, s.ZeroWidth, s.Bidi, s.Tag, s.InvalidUTF8, s.TruncatedFrom)
}

// scrub removes the character classes that make a string render differently
// from how it compares, and bounds its length.
//
// It DROPS rather than substitutes. A replacement character would be a byte
// this driver invented appearing in prose attributed to the engine, and the
// count in EvidenceStats is how a reader learns something was removed.
func scrub(raw string) (string, EvidenceStats) {
	var st EvidenceStats
	if len(raw) > MaxEvidenceBytes {
		st.TruncatedFrom = len(raw)
		cut := MaxEvidenceBytes
		for cut > 0 && !utf8.RuneStart(raw[cut]) {
			cut--
		}
		raw = raw[:cut]
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRuneInString(raw[i:])
		if r == utf8.RuneError && size == 1 {
			st.InvalidUTF8++
			i++
			continue
		}
		i += size
		switch {
		case r == '\t' || r == '\n':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F):
			st.Controls++
		case r == 0x061C || r == 0x200E || r == 0x200F ||
			(r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069):
			st.Bidi++
		case r == 0x00AD || r == 0x180E || (r >= 0x200B && r <= 0x200D) ||
			r == 0x2060 || r == 0xFEFF:
			st.ZeroWidth++
		case r >= 0xE0000 && r <= 0xE007F:
			st.Tag++
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), st
}

// scrubEngineResult bounds and strips every ENGINE-AUTHORED string on one
// result, and reports what it removed.
//
// The identity pair is deliberately NOT scrubbed: Driver.Run only reaches this
// function after TemplateSet.Lookup matched the pair against the admitted set
// by identity, so at that point TemplateID and TemplateDigest are values this
// driver loaded and hashed itself. Everything else on an EngineResult is prose
// the engine wrote — Evidence most obviously, but Severity is documented
// "unvalidated", and Method and Path are the engine's account of a request
// this driver did not see.
func scrubEngineResult(r EngineResult) (EngineResult, EvidenceStats) {
	var total, one EvidenceStats
	r.Evidence, one = scrub(r.Evidence)
	total.Merge(one)
	r.Severity, one = scrub(r.Severity)
	total.Merge(one)
	r.Method, one = scrub(r.Method)
	total.Merge(one)
	r.Path, one = scrub(r.Path)
	total.Merge(one)
	return r, total
}

// ---------------------------------------------------------------------------
// redactIdentifier — the one channel from an external identifier to a message
// ---------------------------------------------------------------------------

// maxRedactedIdentifierBytes is how much of an untrusted identifier a refusal
// message may quote. It matches the kernel's bound, and so does the charset in
// redactIdentifier.
const maxRedactedIdentifierBytes = 64

// redactIdentifier renders an identifier that came from outside Anvil safely
// enough to appear in an operator-facing refusal.
//
// Every caller below is a refusal path, and the value it is handed has just
// FAILED an allowlist or a lookup — a template id the engine invented, a
// digest that matches nothing admitted, an origin nobody enumerated. Those
// strings reach an operator's terminal, the gate-21 audit and, downstream, a
// prompt-bound agent (the spine's record and safety sections). Length is its own payload and
// so is a bidi override, so neither reaches the message.
//
// # Why this is a copy of the kernel's redactUntrusted and not a call to it
//
// authz.redactUntrusted (phase1_run.go) is UNEXPORTED and there is no exported
// wrapper. MEASURED, PowerShell, on the development host:
//
//	go doc -all .../internal/dast/authz | Select-String "^func .*[Rr]edact"
//	COUNT: 0
//
// A package outside authz therefore cannot call it, and the choice is between
// mirroring it and having no bound at all. Mirroring is how two copies come to
// disagree, so the disagreement is made a TEST FAILURE rather than a hazard:
// TestTheEnginesRedactionAgreesWithTheKernelByteForByte drives the same strings
// through authz.NewRequestIntent — which redacts an unrecognised origin with
// the kernel's own function — and compares the two renderings. If either
// charset or bound moves on either side, that test fails.
//
// One consequence of the charset is worth stating because it reads as a bug the
// first time it is seen: [A-Z] is NOT on the allowlist, so a legitimate
// uppercase identifier such as `CVE-2021-44228` renders `???-2021-44228`. That
// is the kernel's choice; widening it here is precisely the divergence the test
// above exists to catch.
func redactIdentifier(s string) string {
	truncated := false
	if len(s) > maxRedactedIdentifierBytes {
		s = s[:maxRedactedIdentifierBytes]
		truncated = true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' || c == '*' || c == '/'
		if ok {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('?')
	}
	if truncated {
		b.WriteString("...")
	}
	return b.String()
}

// redactedIdentity renders an id/digest pair the way identityKey joins one,
// with each HALF redacted separately.
//
// Redacting the joined string would truncate at 64 bytes and throw the digest
// away — a sha-256 hex digest is 64 bytes on its own — leaving a message that
// names the half the operator already knows and drops the half that
// distinguishes one file from another. It would also render identityKey's own
// '@' as '?', since '@' is not on the kernel's allowlist.
func redactedIdentity(id, digest string) string {
	return redactIdentifier(id) + "@" + redactIdentifier(digest)
}

// ---------------------------------------------------------------------------
// Sentinels and the absence contract
// ---------------------------------------------------------------------------

// ExitCodeArtefactAbsent is the process exit code a command wrapping this
// driver MUST use when the probe engine is not present, distinct from both
// success and "the scan failed".
//
// The value matches internal/collector/repo.ExitCodeArtefactAbsent and
// eval/tools/opengrep/smoke.py on purpose: one code across Anvil for "the
// engine or the ruleset is not present", so an operator's wrapper does not
// need a per-tool table. It is duplicated rather than imported because
// importing the SCA collector into the DAST tree to reach one integer would
// widen this package's dependency surface for nothing; nuclei_test.go asserts
// the two agree, so a future divergence is a test failure rather than a
// silent drift.
const ExitCodeArtefactAbsent = 2

// EngineName is the probe engine this driver wraps.
const EngineName = "nuclei"

// InstallHint is printed inside every engine-absent error. It names the
// artefact and how to obtain it.
//
// It carries NO VERSION LITERAL and NO DIGEST. plan/design/dynamic-tier.md's Pinned
// Versions And Licences table pins the Nuclei engine as "Go SDK, pin at build
// time" and `nuclei-templates` "by commit SHA, diffed before promotion
// (template pinning)"; neither names a number, so neither does this constant. Inventing
// one here would put a version into an error message that no build ever
// produced.
const InstallHint = "the Nuclei Go SDK (MIT) is not in this module's dependency graph and no " +
	"Engine implementation is registered. Wire an Engine whose PinnedAddr contract is " +
	"honoured (see the Engine interface), or run the DAST tier on a host where the " +
	"pinned engine is available"

var (
	// ErrEngineUnavailable: no probe engine is present. Always carries
	// *EngineUnavailableError. A scan that ends here produced NO result,
	// empty or otherwise.
	ErrEngineUnavailable = errors.New("engines: the nuclei engine is not available")

	// ErrRefused: the kernel refused something this driver proposed, or this
	// driver refused it before the kernel saw it. Never a partial run.
	ErrRefused = errors.New("engines: refused")

	// ErrUnconstructed: a value that only a constructor in this package can
	// mint arrived as a zero value or a composite literal.
	ErrUnconstructed = errors.New("engines: value was not built by its constructor")

	// ErrNoTemplates: the template directory yielded zero admitted
	// templates. An engine with no templates finds nothing, and that is not
	// a clean target.
	ErrNoTemplates = errors.New("engines: no template was admitted")

	// ErrNothingProbed is the sentinel behind ScanResult.AssertNotSilentlyEmpty.
	ErrNothingProbed = errors.New("engines: nothing was probed; this is not a clean target")

	// ErrNoEgress: the driver admitted a request and had nowhere to send it.
	// This is a refusal, not a silent success.
	ErrNoEgress = errors.New("engines: no Issuer is wired, so an admitted request cannot be issued")
)

// EngineUnavailableError is the typed absence. It reports
// ExitCodeArtefactAbsent so a wrapping command does not have to re-derive the
// exit code from an error string.
type EngineUnavailableError struct {
	// Name is the engine that is missing, always EngineName.
	Name string
	// Detail is what was looked for and not found.
	Detail string
}

func (e *EngineUnavailableError) Error() string {
	return fmt.Sprintf(
		"engines: the %s engine is not available (%s). This is NOT a clean target: no probe "+
			"ran, so no result — empty or otherwise — was produced. To fix: %s. "+
			"A wrapping command must exit %d for this condition.",
		e.Name, e.Detail, InstallHint, ExitCodeArtefactAbsent)
}

func (e *EngineUnavailableError) Unwrap() error { return ErrEngineUnavailable }

// ExitCode reports the process exit code a wrapping command must use.
func (e *EngineUnavailableError) ExitCode() int { return ExitCodeArtefactAbsent }

// ---------------------------------------------------------------------------
// The engine seam
// ---------------------------------------------------------------------------

// Engine is the probe engine, as much of it as this driver uses.
//
// # Why an interface and not the SDK
//
// The Nuclei Go SDK is not in this module's graph and cannot be added from
// inside this packet's write scope. More importantly, the SDK constructs
// sockets, and a package under internal/dast that imports something which can
// construct a socket fails gate 3 tier 1 — no allowlist, no exception. So the
// engine lives on the far side of an interface, an adapter for it is built by
// whoever assembles the DAST binary, and this package is driven in tests by
// recorded shapes.
//
// # The obligation an implementation takes on
//
// TargetSpec carries BOTH a URL and a PinnedAddr. An implementation MUST dial
// PinnedAddr and MUST NOT resolve the URL's host. Gate 9's rule is "never
// re-resolve between check and connect"; the kernel makes that structural on
// its own egress path by handing out a netip.AddrPort with no hostname in it
// (authz.PinnedDialAddress), but an external engine is a process this package
// does not control, and an engine that re-resolves reopens DNS rebinding.
//
// That obligation is STATED HERE AND ENFORCED NOWHERE IN THIS FILE. It is a
// contract on the implementer, recorded in docs/controls.md U4 as
// the specific thing an integration lane must prove.
type Engine interface {
	// ExecuteCallbackWithCtx runs the plan and calls cb once per result.
	// Named for the SDK entry point the nuclei driver's design nominates; the
	// types are Anvil's.
	ExecuteCallbackWithCtx(ctx context.Context, plan RunPlan, cb func(EngineResult) error) error

	// WithPDCPUpload mirrors the SDK option the nuclei driver's design forbids
	// outright: "Never call WithPDCPUpload(scanID, teamID)".
	//
	// IT IS ON THIS INTERFACE PRECISELY SO THAT ITS ABSENCE FROM THE CALL
	// GRAPH IS PROVABLE. A forbidden call that no type declares cannot be
	// counted; a spy implementing this method can assert a count of zero,
	// and TestPDCPUploadAppearsInNoCallExpressionInThisPackage reads this
	// file's syntax tree and fails if the identifier ever appears in a call
	// expression. Two independent guards, one runtime and one structural,
	// because the runtime one only proves what a test happened to exercise.
	WithPDCPUpload(scanID, teamID string) error

	// Close releases the engine.
	Close() error
}

// SystemEngine returns the engine this host can run.
//
// It ALWAYS returns an error on every host, today. There is no production
// adapter in this module, and returning a no-op Engine that reported zero
// findings would be exactly the silent-clean failure this package's doc
// comment opens with. It never returns (nil, nil).
func SystemEngine() (Engine, error) {
	return nil, &EngineUnavailableError{
		Name: EngineName,
		Detail: "no Engine adapter is compiled into this module: `go list -m all` contains " +
			"no projectdiscovery module and this package registers no default",
	}
}

// RunPlan is one engine invocation, sealed. The zero value is not one.
//
// Every field is unexported and every one of them is set by NewRunPlan, which
// cannot be reached without an authz.Authorization. In particular `targets`
// is unexported: there is no way to append a host to a run plan.
type RunPlan struct {
	targets   []TargetSpec
	templates []Template
	// interactsh records whether out-of-band interaction is enabled. It is
	// ALWAYS false. There is no parameter, field or option in this package
	// that sets it true, and InteractshEnabled exists so a test can assert
	// that over every constructor rather than over one.
	interactsh bool
	// pdcpUpload records whether cloud upload is enabled. Same shape, same
	// reason, and the nuclei driver's design forbids the SDK call outright.
	pdcpUpload bool
	sealed     bool
}

// NewRunPlan seals a run plan.
//
// It refuses an empty target list and an empty template list. Both refusals
// are the anti-vacuity rule: an engine run with no targets and an engine run
// with no templates both complete successfully having probed nothing, and
// both produce the same empty finding list a clean target produces.
func NewRunPlan(targets []TargetSpec, templates []Template) (RunPlan, error) {
	if len(targets) == 0 {
		return RunPlan{}, fmt.Errorf("engines: %w: a run plan with no target probes "+
			"nothing and reports clean", ErrRefused)
	}
	for i, t := range targets {
		if !t.Constructed() {
			return RunPlan{}, fmt.Errorf("engines: %w: target %d was not built by "+
				"NewTargetSpec, so no authorization was ever checked for it", ErrUnconstructed, i)
		}
	}
	if len(templates) == 0 {
		return RunPlan{}, fmt.Errorf("engines: %w: a run plan with no template probes "+
			"nothing and reports clean", ErrNoTemplates)
	}
	for i, tpl := range templates {
		if !tpl.Constructed() {
			return RunPlan{}, fmt.Errorf("engines: %w: template %d was not built by "+
				"LoadTemplates, so its protocol allowlist was never applied",
				ErrUnconstructed, i)
		}
	}
	return RunPlan{
		targets:    cloneTargetSpecs(targets),
		templates:  cloneTemplates(templates),
		interactsh: false,
		pdcpUpload: false,
		sealed:     true,
	}, nil
}

// Constructed reports whether p came from NewRunPlan.
func (p RunPlan) Constructed() bool { return p.sealed && len(p.targets) > 0 && len(p.templates) > 0 }

// Targets returns the plan's targets as a FRESH SLICE, so a caller cannot
// write a target into a sealed plan through the slice it was handed.
func (p RunPlan) Targets() []TargetSpec { return cloneTargetSpecs(p.targets) }

// Templates returns the plan's templates as a fresh slice.
func (p RunPlan) Templates() []Template { return cloneTemplates(p.templates) }

// InteractshEnabled reports whether out-of-band interaction is on. It is
// always false: the nuclei driver's design requires interactsh/OAST off by default
// and this package provides no way to turn it on.
func (p RunPlan) InteractshEnabled() bool { return p.interactsh }

// PDCPUploadEnabled reports whether cloud upload is on. Always false.
func (p RunPlan) PDCPUploadEnabled() bool { return p.pdcpUpload }

// EngineResult is one raw result the engine reports. Everything in it
// originated outside Anvil and is treated as hostile input.
type EngineResult struct {
	// TemplateID is the template the engine attributes the result to.
	TemplateID string
	// TemplateDigest is the SHA-256 the driver recorded at load time. An
	// engine that cannot report it produces a result the driver cannot
	// attribute, and an unattributable result is dropped loudly.
	TemplateDigest string
	// Matched is the engine's verdict.
	Matched bool
	// Severity is the template's declared severity as the engine reported
	// it. Nothing validates it against a known set.
	Severity string
	// Method and Path are the request the engine says produced the result.
	// This driver did not see that request; these are the engine's account
	// of it.
	Method string
	Path   string
	// Status is the HTTP status observed.
	Status int
	// Evidence is engine-authored prose.
	Evidence string
}

// WHERE AN EngineResult IS SCRUBBED, stated on the type because the field
// comments used to claim it and the claim was not true: Driver.Run is the only
// route from an Engine to a caller, and it passes every result through
// scrubEngineResult before the callback sees it — Evidence, Severity, Method
// and Path — merging what was removed into Coverage.Evidence. A value built by
// hand, or one an Engine implementation holds on its way in, has not been
// through it.

// ---------------------------------------------------------------------------
// TargetSpec — the only route from an Authorization to an engine argument
// ---------------------------------------------------------------------------

// TargetSpec is a destination the kernel admitted.
//
// The zero value names nothing. Every field is unexported and the only
// constructor is NewTargetSpec, which will not build one without an
// authz.Authorization that names EXACTLY this target, pinned address
// included. That is what makes "a target cannot reach the engine without
// passing gates 8-10" a property of the type system rather than a convention.
type TargetSpec struct {
	url    string
	pinned string
	target authz.Target
	sealed bool
}

// NewTargetSpec turns an admitted authz.Target into an engine argument.
//
// authz.PinnedDialAddress calls authz.RequireAuthorization first, so a token
// that is not real, or is real but covers a different scheme, host, port or
// PINNED ADDRESS, produces an error here and no TargetSpec at all.
func NewTargetSpec(auth authz.Authorization, target authz.Target) (TargetSpec, error) {
	addr, err := authz.PinnedDialAddress(auth, target)
	if err != nil {
		return TargetSpec{}, fmt.Errorf("engines: %w: no target reaches the engine without "+
			"an authorization the kernel minted for it: %w", ErrRefused, err)
	}
	return TargetSpec{
		url:    fmt.Sprintf("%s://%s:%d", target.Scheme(), target.Canonical(), target.Port()),
		pinned: addr.String(),
		target: target,
		sealed: true,
	}, nil
}

// Constructed reports whether s came from NewTargetSpec.
func (s TargetSpec) Constructed() bool { return s.sealed && s.pinned != "" && s.target.Constructed() }

// URL is the origin the engine should send in the request line and the Host
// header. It is the CANONICAL host from gate 8, never the literal the
// operator typed.
func (s TargetSpec) URL() string { return s.url }

// PinnedAddr is the address:port the engine MUST connect to, and the only one
// it may. See the Engine interface for the obligation this creates.
func (s TargetSpec) PinnedAddr() string { return s.pinned }

// Target returns the kernel's admitted target.
func (s TargetSpec) Target() authz.Target { return s.target }

func cloneTargetSpecs(in []TargetSpec) []TargetSpec {
	if in == nil {
		return nil
	}
	out := make([]TargetSpec, len(in))
	copy(out, in)
	return out
}

// ---------------------------------------------------------------------------
// Templates: the protocol allowlist
// ---------------------------------------------------------------------------

// Protocol is a top-level Nuclei template key.
type Protocol string

// The top-level keys this loader recognises. The zero value names none.
const (
	// ProtocolUnspecified is the zero value and is not a protocol.
	ProtocolUnspecified Protocol = ""

	// --- structural keys, carrying no execution ---

	// ProtocolID is the template identifier.
	ProtocolID Protocol = "id"
	// ProtocolInfo is the metadata block.
	ProtocolInfo Protocol = "info"
	// ProtocolVariables is the template's variable block.
	ProtocolVariables Protocol = "variables"

	// --- the one executable protocol this driver admits ---

	// ProtocolHTTP is the HTTP request block.
	ProtocolHTTP Protocol = "http"

	// --- named refusals: enumerated so the message is right ---

	// ProtocolCode is the `code:` protocol. The spine's hard exclusion.
	ProtocolCode Protocol = "code"
	// ProtocolJavaScript runs JS inside the engine.
	ProtocolJavaScript Protocol = "javascript"
	// ProtocolFlow is the JS orchestration block.
	ProtocolFlow Protocol = "flow"
	// ProtocolHeadless drives a browser.
	ProtocolHeadless Protocol = "headless"
	// ProtocolSelfContained lets a template name its own absolute target.
	ProtocolSelfContained Protocol = "self-contained"
)

// protocolAllowlist is every top-level template key this loader admits.
//
// # An allowlist, matched by identity
//
// The nuclei driver's design requires that `code:` templates be REJECTED AT LOAD
// TIME rather than skipped at match time. The obvious implementation is a
// check for the string "code". That is a denylist of one, and a denylist
// loses: `javascript:` executes, `flow:` executes, `headless:` drives a
// browser that fetches whatever a page references, `self-contained:` lets the
// template name its own absolute target, `network:`/`tcp:` open a socket the
// kernel's HTTP-shaped RequestIntent cannot describe, and `file:` reads the
// local disk. None of those contains the substring "code".
//
// So the question is inverted, the same way the kernel's build-time guard
// inverted gate 3's scanner: a template is admitted only if EVERY top-level key
// it declares is on this list. A protocol nobody has heard of — one that ships
// in a future template schema — is refused by default, and no one has to have
// remembered it.
//
// # Why the executable list is exactly one entry
//
// The kernel gates an HTTP request: authz.RequestIntent is a method, a path,
// an origin and a hop count, and gates 11, 13 and 15 all read those fields.
// There is no kernel vocabulary for "a raw TCP payload to port 6379". A
// protocol the kernel cannot describe is a protocol the kernel cannot gate,
// and admitting one would put requests outside the interceptor while leaving
// the audit log looking complete. Widening this list therefore requires
// widening RequestIntent first, which is a kernel edit, which is the review
// this shape exists to force.
func protocolAllowlist() []Protocol {
	return []Protocol{ProtocolID, ProtocolInfo, ProtocolVariables, ProtocolHTTP}
}

// Admitted reports whether p is on the allowlist.
func (p Protocol) Admitted() bool {
	for _, a := range protocolAllowlist() {
		if a == p {
			return true
		}
	}
	return false
}

// Executable reports whether p causes requests to be issued. It is
// documentation with a return value: `id`, `info` and `variables` describe
// the template, `http` is what actually probes.
func (p Protocol) Executable() bool { return p == ProtocolHTTP }

// RejectionReason names why a template did not load. Every value is a
// constant; nothing here is assembled from the template's own bytes.
type RejectionReason string

// The rejection reasons.
const (
	// RejectUnspecified is the zero value and is not a reason. A
	// RejectedTemplate carrying it is itself a defect, and
	// RejectedTemplate.Valid refuses it.
	RejectUnspecified RejectionReason = ""

	// RejectCodeProtocol is the spine's hard exclusion, by name.
	RejectCodeProtocol RejectionReason = "code_protocol_hard_exclusion"
	// RejectExecutesCode covers `javascript:` and `flow:`.
	RejectExecutesCode RejectionReason = "template_executes_code"
	// RejectDrivesBrowser covers `headless:`.
	RejectDrivesBrowser RejectionReason = "template_drives_a_browser"
	// RejectSelfContained covers `self-contained:`: the template names its
	// own absolute target, which is the scope-bypass shape this driver
	// exists to make impossible.
	RejectSelfContained RejectionReason = "template_names_its_own_target"
	// RejectProtocolNotAllowlisted is every other unrecognised top-level
	// key, including protocols that do not exist yet.
	RejectProtocolNotAllowlisted RejectionReason = "protocol_not_on_allowlist"
	// RejectNoExecutableProtocol: the template declares no `http:` block, so
	// admitting it would put a template in the set that can never fire.
	RejectNoExecutableProtocol RejectionReason = "no_executable_protocol"
	// RejectUnanalysable: the loader could not establish the template's
	// top-level structure with certainty. Fail closed — see analyse.
	RejectUnanalysable RejectionReason = "structure_not_analysable"
	// RejectDuplicateKey: a duplicated top-level key. Which one wins is a
	// property of the YAML implementation, and a template whose meaning
	// depends on that is not one this loader will admit.
	RejectDuplicateKey RejectionReason = "duplicate_top_level_key"
	// RejectMissingID / RejectBadID / RejectMissingInfo are the identity
	// checks. A template with no usable id cannot be attributed in a
	// finding or pinned by template pinning.
	RejectMissingID   RejectionReason = "missing_id"
	RejectBadID       RejectionReason = "malformed_id"
	RejectMissingInfo RejectionReason = "missing_info"
	// RejectTooLarge / RejectNotUTF8 / RejectUnreadable are the input
	// bounds. An unreadable file is reported, never passed over.
	RejectTooLarge   RejectionReason = "file_exceeds_size_cap"
	RejectNotUTF8    RejectionReason = "file_is_not_utf8"
	RejectUnreadable RejectionReason = "file_unreadable"
	// RejectSymlink: an entry in the template tree that is neither an
	// ordinary file nor an ordinary directory — a symlink, a Windows
	// junction, a device node. Following one lets a template directory reach
	// outside itself, which is the same escape internal/mirror/accelerator
	// was defeated by.
	RejectSymlink RejectionReason = "path_is_a_link"
	// RejectDuplicateID: two files claiming the same template id. Findings
	// are attributed by id, so a duplicate makes attribution ambiguous.
	RejectDuplicateID RejectionReason = "duplicate_template_id"
)

// rejectionReasons is every reason this loader can emit, as a fresh slice.
func rejectionReasons() []RejectionReason {
	return []RejectionReason{
		RejectCodeProtocol, RejectExecutesCode, RejectDrivesBrowser, RejectSelfContained,
		RejectProtocolNotAllowlisted, RejectNoExecutableProtocol, RejectUnanalysable,
		RejectDuplicateKey, RejectMissingID, RejectBadID, RejectMissingInfo,
		RejectTooLarge, RejectNotUTF8, RejectUnreadable, RejectSymlink, RejectDuplicateID,
	}
}

// Recognised reports whether r is one of the enumerated reasons.
func (r RejectionReason) Recognised() bool {
	for _, k := range rejectionReasons() {
		if k == r {
			return true
		}
	}
	return false
}

// reasonForProtocol maps a refused top-level key to its named reason.
//
// The specific entries are redundant against RejectProtocolNotAllowlisted —
// the allowlist already refuses every one of them — and they are kept for the
// same reason the kernel core kept gate 2's inference denylist alongside its allowlist:
// so the failure the spine's exclusion list names produces a message that says so, instead of
// "this key is not on the allowlist". Both refuse.
func reasonForProtocol(p Protocol) RejectionReason {
	switch p {
	case ProtocolCode:
		return RejectCodeProtocol
	case ProtocolJavaScript, ProtocolFlow:
		return RejectExecutesCode
	case ProtocolHeadless:
		return RejectDrivesBrowser
	case ProtocolSelfContained:
		return RejectSelfContained
	default:
		return RejectProtocolNotAllowlisted
	}
}

// RejectedTemplate is one template that did not load, and why.
//
// It is RETURNED, not logged and dropped. The nuclei driver's design validation
// requires a `code:` template to be "rejected at LoadTemplates time and never
// reach Fire"; a rejection nobody can see is indistinguishable from a file
// that was never there.
type RejectedTemplate struct {
	// Path is the file, relative to the template root.
	Path string
	// ID is the template's declared id when one was readable, empty
	// otherwise. Sanitized.
	ID string
	// Protocol is the offending key when the rejection was a protocol
	// rejection, ProtocolUnspecified otherwise. Sanitized.
	Protocol Protocol
	// Reason is the constant. Never assembled from the file's bytes.
	Reason RejectionReason
	// Detail is Anvil-authored prose.
	Detail string
}

// Valid reports whether the rejection is a usable record.
func (r RejectedTemplate) Valid() bool { return r.Path != "" && r.Reason.Recognised() }

func (r RejectedTemplate) String() string {
	s := fmt.Sprintf("%s: %s", r.Path, r.Reason)
	if r.Protocol != ProtocolUnspecified {
		s += fmt.Sprintf(" (%s:)", r.Protocol)
	}
	if r.Detail != "" {
		s += ": " + r.Detail
	}
	return s
}

// Template is one admitted template. The zero value is not one.
type Template struct {
	id        string
	path      string
	digest    string
	protocols []Protocol
	sealed    bool
}

// Constructed reports whether t came from LoadTemplates.
func (t Template) Constructed() bool {
	return t.sealed && t.id != "" && t.digest != "" && len(t.protocols) > 0
}

// ID is the template's declared identifier, sanitized.
func (t Template) ID() string { return t.id }

// Path is the file it came from, relative to the template root.
func (t Template) Path() string { return t.path }

// Digest is the lowercase hex SHA-256 of the template's exact bytes as they
// were read from disk — before any normalisation this loader applies.
//
// This is the value template pinning pins against. It is computed here, and reported
// here, so that a pin can be checked against what was actually loaded rather
// than against what a manifest claims was loaded.
func (t Template) Digest() string { return t.digest }

// Protocols returns the template's top-level keys as a FRESH SLICE.
func (t Template) Protocols() []Protocol {
	if t.protocols == nil {
		return nil
	}
	out := make([]Protocol, len(t.protocols))
	copy(out, t.protocols)
	return out
}

// Declares reports whether the template declares p.
func (t Template) Declares(p Protocol) bool {
	for _, k := range t.protocols {
		if k == p {
			return true
		}
	}
	return false
}

func cloneTemplates(in []Template) []Template {
	if in == nil {
		return nil
	}
	out := make([]Template, len(in))
	for i, t := range in {
		out[i] = t
		out[i].protocols = t.Protocols()
	}
	return out
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

// MaxTemplateBytes bounds one template file. Upstream templates are a few
// kilobytes; a megabyte is three orders of magnitude of headroom and still
// bounds a directory someone pointed at a corpus.
const MaxTemplateBytes = 1 << 20

// MaxTemplates bounds one load. A template set larger than this is a
// misconfigured root, not a scan.
const MaxTemplates = 50_000

// maxTemplateIDLen bounds the identifier a finding is attributed by.
const maxTemplateIDLen = 128

// templateExtensions is what the walk reads. Everything else in the tree is
// ignored without comment; a README is not a rejected template.
func templateExtensions() []string { return []string{".yaml", ".yml"} }

// LoadTemplates reads a template directory and separates what may run from
// what may not.
//
// It returns admitted templates, rejected ones, and an error. The three are
// distinct on purpose:
//
//	error != nil          the load itself failed — bad root, unwalkable
//	                      tree, or zero admitted templates. NOT a scan.
//	len(rejected) > 0     files were refused, by name and reason. The load
//	                      still succeeded.
//	len(templates) == 0   never returned with a nil error; that is
//	                      ErrNoTemplates.
//
// The last one is the anti-vacuity floor. An empty template set makes an
// engine run come back clean over any target, and "the directory was empty"
// must not be reportable as "the target has no findings".
func LoadTemplates(dir string) ([]Template, []RejectedTemplate, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil, fmt.Errorf("engines: %w: no template directory was named", ErrRefused)
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("engines: resolving template root %q: %w", dir, err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, fmt.Errorf("engines: %w: template root %q is not readable: %w",
			ErrNoTemplates, dir, err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("engines: %w: template root %q is not a directory",
			ErrRefused, dir)
	}

	var (
		admitted []Template
		rejected []RejectedTemplate
		seenID   = map[string]string{}
		examined int
	)

	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking %q: %w", p, err)
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return fmt.Errorf("relativising %q: %w", p, rerr)
		}
		rel = filepath.ToSlash(rel)

		// Anything that is not an ordinary directory or an ordinary file is
		// refused, and REPORTED. A link makes the template root able to
		// reach outside itself, which means it is not a root.
		//
		// This is an ALLOWLIST of two shapes rather than a check for
		// os.ModeSymlink, and the reason is measured rather than
		// theoretical. On this Windows host a DIRECTORY JUNCTION (`mklink
		// /J`, which needs no privilege at all, unlike `mklink /D`) is
		// reported by filepath.WalkDir as:
		//
		//	type=?--------- isdir=false symlink=false
		//
		// — os.ModeIrregular, with the symlink bit CLEAR and IsDir false. A
		// `d.Type()&os.ModeSymlink != 0` check sees nothing there. That is
		// the same primitive that walked through internal/mirror/accelerator's
		// quarantine guard (docs/controls.md H1), and it is why
		// the question here is "is this one of the two shapes a template tree
		// is made of" rather than "is this one of the link kinds I have heard
		// of".
		isOrdinaryDir := d.IsDir() && d.Type()&^fs.ModeDir == 0
		if !isOrdinaryDir && !d.Type().IsRegular() {
			rejected = append(rejected, RejectedTemplate{
				Path:   rel,
				Reason: RejectSymlink,
				Detail: fmt.Sprintf("the entry is neither an ordinary directory nor an "+
					"ordinary file (mode %s); the loader does not follow a link, a "+
					"junction, a device or any other reparse point, because each of them "+
					"makes the template root able to reach outside itself", d.Type()),
			})
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !hasTemplateExtension(rel) {
			return nil
		}
		examined++
		if examined > MaxTemplates {
			return fmt.Errorf("%w: more than %d template files under %q; that is a "+
				"misconfigured root, not a template set", ErrRefused, MaxTemplates, dir)
		}

		tpl, rej := loadOne(p, rel)
		if rej != nil {
			rejected = append(rejected, *rej)
			return nil
		}
		if prev, dup := seenID[tpl.id]; dup {
			rejected = append(rejected, RejectedTemplate{
				Path:     rel,
				ID:       tpl.id,
				Reason:   RejectDuplicateID,
				Protocol: ProtocolUnspecified,
				Detail: "another file already claims this template id (" + prev + "). " +
					"Findings are attributed by id, and two files under one id make " +
					"attribution a coin toss",
			})
			return nil
		}
		seenID[tpl.id] = rel
		admitted = append(admitted, tpl)
		return nil
	})
	if walkErr != nil {
		return nil, rejected, fmt.Errorf("engines: reading template root %q: %w", dir, walkErr)
	}

	// Deterministic order. A template set whose order depends on the
	// filesystem makes two runs over one directory produce two different
	// argument orders, and a difference nobody can explain is a difference
	// nobody can review.
	sort.Slice(admitted, func(i, j int) bool { return admitted[i].id < admitted[j].id })
	sort.Slice(rejected, func(i, j int) bool {
		if rejected[i].Path != rejected[j].Path {
			return rejected[i].Path < rejected[j].Path
		}
		return rejected[i].Reason < rejected[j].Reason
	})

	if len(admitted) == 0 {
		return nil, rejected, fmt.Errorf("engines: %w: %d file(s) examined under %q, "+
			"%d rejected, 0 admitted. An engine with no template probes nothing and "+
			"reports clean, which is byte-identical to a target with no findings",
			ErrNoTemplates, examined, dir, len(rejected))
	}
	return admitted, rejected, nil
}

func hasTemplateExtension(rel string) bool {
	ext := strings.ToLower(filepath.Ext(rel))
	for _, e := range templateExtensions() {
		if ext == e {
			return true
		}
	}
	return false
}

// loadOne reads and analyses one file. Exactly one of its returns is nil.
func loadOne(abs, rel string) (Template, *RejectedTemplate) {
	reject := func(r RejectionReason, p Protocol, detail string) (Template, *RejectedTemplate) {
		return Template{}, &RejectedTemplate{Path: rel, Protocol: p, Reason: r, Detail: detail}
	}

	st, err := os.Stat(abs)
	if err != nil {
		return reject(RejectUnreadable, ProtocolUnspecified,
			"the file could not be stat'd; an unreadable template is reported, not skipped")
	}
	if st.Size() > MaxTemplateBytes {
		return reject(RejectTooLarge, ProtocolUnspecified,
			fmt.Sprintf("%d bytes exceeds the %d-byte cap", st.Size(), MaxTemplateBytes))
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return reject(RejectUnreadable, ProtocolUnspecified,
			"the file could not be read; an unreadable template is reported, not skipped")
	}
	if len(raw) > MaxTemplateBytes {
		return reject(RejectTooLarge, ProtocolUnspecified,
			fmt.Sprintf("%d bytes exceeds the %d-byte cap (the file grew between stat and read)",
				len(raw), MaxTemplateBytes))
	}
	if !utf8.Valid(raw) {
		return reject(RejectNotUTF8, ProtocolUnspecified,
			"the file is not valid UTF-8, so its top-level structure cannot be established")
	}

	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])

	keys, aerr := analyse(string(raw))
	if aerr != nil {
		return reject(RejectUnanalysable, ProtocolUnspecified, aerr.Error())
	}

	seen := map[Protocol]bool{}
	var protocols []Protocol
	for _, k := range keys {
		if seen[k] {
			return reject(RejectDuplicateKey, k,
				"the top-level key appears more than once; which one wins is a property of "+
					"the YAML implementation, not of the template")
		}
		seen[k] = true
		protocols = append(protocols, k)
		if !k.Admitted() {
			return reject(reasonForProtocol(k), k, protocolRejectionDetail(k))
		}
	}
	if !seen[ProtocolHTTP] {
		return reject(RejectNoExecutableProtocol, ProtocolUnspecified,
			"the template declares no `http:` block, so it can never fire. Admitting it "+
				"would inflate the template count — the number this driver's coverage "+
				"predicate reads to decide whether anything ran at all")
	}
	if !seen[ProtocolInfo] {
		return reject(RejectMissingInfo, ProtocolUnspecified,
			"the template declares no `info:` block")
	}

	id, ok := topLevelScalar(string(raw), ProtocolID)
	if !ok {
		return reject(RejectMissingID, ProtocolUnspecified,
			"the template declares `id:` but not as a single-line scalar this loader can read")
	}
	clean, _ := scrub(id)
	if clean != id {
		return reject(RejectBadID, ProtocolUnspecified,
			"the template id carries invisible or bidirectional characters. A finding is "+
				"attributed by id, and an id that does not render as it compares is how "+
				"one template's findings get filed under another's name")
	}
	if !validTemplateID(clean) {
		return reject(RejectBadID, ProtocolUnspecified,
			fmt.Sprintf("the template id is empty, longer than %d bytes, or contains a byte "+
				"outside [A-Za-z0-9._-]", maxTemplateIDLen))
	}

	sort.Slice(protocols, func(i, j int) bool { return protocols[i] < protocols[j] })
	return Template{
		id:        clean,
		path:      rel,
		digest:    digest,
		protocols: protocols,
		sealed:    true,
	}, nil
}

func protocolRejectionDetail(p Protocol) string {
	switch p {
	case ProtocolCode:
		return "The spine's exclusion list excludes the `code:` protocol outright — 251 such " +
			"templates exist upstream. It is a hard exclusion, not a tunable, and it is " +
			"applied HERE, at load, so the template never reaches Fire"
	case ProtocolJavaScript, ProtocolFlow:
		return "the template executes engine-side script. A scripted template decides at " +
			"runtime what to request, which puts the decision behind the kernel's back"
	case ProtocolHeadless:
		return "the template drives a browser, which fetches every subresource a rendered " +
			"page references. Those fetches are requests no RequestIntent describes"
	case ProtocolSelfContained:
		return "a self-contained template names its own absolute target. That is precisely " +
			"the shape this driver exists to make impossible: the only route from a host " +
			"to the engine is an authz.Authorization"
	default:
		return "the top-level key is not on this loader's allowlist. The list is an " +
			"allowlist and not a denylist so that a protocol nobody has heard of — one " +
			"shipping in a future template schema — is refused by default"
	}
}

func validTemplateID(s string) bool {
	if s == "" || len(s) > maxTemplateIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// The structural analysis
// ---------------------------------------------------------------------------

// analyse returns the template's top-level keys, or an error naming why the
// structure could not be established.
//
// # This is NOT a YAML parser, and the difference is the point
//
// This module has no YAML dependency and this packet's write scope cannot add
// one. More importantly, a parser's job is to extract meaning from whatever it
// is given, and this function's job is the opposite: to REFUSE anything whose
// meaning is not obvious. So it accepts one narrow, boring shape — the shape
// every Nuclei template in the upstream corpus is written in — and rejects
// everything else as unanalysable.
//
// Refusing is safe in the direction that matters. A template this function
// cannot read does not run. The dangerous direction would be a `code:` block
// this function fails to SEE, and the rules below are chosen to close that:
//
//   - Every non-blank, non-comment line at column 0 must parse as `key:`.
//     Anything else — a stray continuation, a flow mapping, a document that
//     starts with `[` — refuses the whole file.
//   - A file with ZERO column-0 keys refuses. This is the rule that closes
//     the real hole: YAML permits a root mapping indented as a whole, and a
//     scanner that only reads column 0 would report "no protocols" for such a
//     file, which without this rule would be an empty-and-therefore-clean
//     result. It is refused instead.
//   - Tabs refuse. YAML forbids a tab in indentation, and a tab makes column
//     arithmetic unreliable.
//   - A second document (`---` or `...` after the first line of content)
//     refuses. Two documents in one file is two templates in one path.
//
// Block scalars need no special handling and that is a property of YAML, not
// an assumption: the content of a block scalar under a column-0 key must be
// indented more than its parent, and its parent is at column 0. The same
// applies to a multi-line flow scalar in block context. So no `code:` can hide
// inside one at column 0, and none of the corpus's `matchers: |` blocks can
// forge a key.
//
// The residual limit, stated rather than papered over: a line at column 0
// inside a block scalar that happens to read `http:` would be counted as an
// admitted key. That direction only ever ADDS an admitted structural key; it
// cannot remove a refused one, because a refused key at column 0 is refused
// wherever it came from, and a refused key that is NOT at column 0 is not an
// executable top-level key at all.
func analyse(text string) ([]Protocol, error) {
	if strings.ContainsRune(text, '\t') {
		return nil, errors.New("the file contains a tab; YAML forbids a tab in indentation " +
			"and a tab makes the column analysis this loader depends on unreliable")
	}
	text = strings.TrimPrefix(text, "\uFEFF")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if strings.ContainsRune(text, '\r') {
		return nil, errors.New("the file contains a bare carriage return, which is neither " +
			"a line ending this loader recognises nor a character a template needs")
	}

	var keys []Protocol
	contentSeen := false

	for i, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimRight(line, " ")
		if trimmed == "" {
			continue
		}
		if line[0] == ' ' {
			// Indented: part of some column-0 key's value. Not our business.
			contentSeen = true
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "---" || trimmed == "..." {
			if contentSeen {
				return nil, fmt.Errorf("line %d begins a second YAML document; two documents "+
					"in one file is two templates under one path, and this loader admits "+
					"one template per path", i+1)
			}
			continue
		}
		contentSeen = true

		key, ok := columnZeroKey(trimmed)
		if !ok {
			return nil, fmt.Errorf("line %d is at column 0 but does not parse as a top-level "+
				"`key:` mapping entry. This loader refuses what it cannot read rather than "+
				"reading it loosely, because the thing it is looking for is a protocol block "+
				"that must never run", i+1)
		}
		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil, errors.New("no top-level key was found at column 0. YAML permits a root " +
			"mapping to be indented as a whole, and such a file would present to a " +
			"column-0 scanner as a template with no protocols — an empty result that " +
			"would read as clean. It is refused instead")
	}
	return keys, nil
}

// columnZeroKey extracts the key from a column-0 mapping entry.
//
// It accepts a bare key, a single-quoted key and a double-quoted key, because
// all three are how a key can legitimately be written. It rejects anything
// else, including a flow mapping, a sequence entry and a key containing an
// escape it would have to interpret.
func columnZeroKey(line string) (Protocol, bool) {
	switch line[0] {
	case '"', '\'':
		q := line[0]
		end := strings.IndexByte(line[1:], q)
		if end < 0 {
			return ProtocolUnspecified, false
		}
		key := line[1 : 1+end]
		rest := strings.TrimLeft(line[2+end:], " ")
		if !strings.HasPrefix(rest, ":") {
			return ProtocolUnspecified, false
		}
		if strings.ContainsRune(key, '\\') {
			return ProtocolUnspecified, false
		}
		return protocolFromKey(key)
	}

	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return ProtocolUnspecified, false
	}
	key := line[:colon]
	after := line[colon+1:]
	// `key:value` with no space is a plain scalar in YAML, not a mapping
	// entry. Refuse rather than guess.
	if after != "" && after[0] != ' ' {
		return ProtocolUnspecified, false
	}
	return protocolFromKey(key)
}

// protocolFromKey validates the key's own bytes. A key that is not a plain
// lowercase identifier is refused: every top-level key in a Nuclei template
// is one, and a key that needs interpreting is a key this loader will not
// interpret.
func protocolFromKey(key string) (Protocol, bool) {
	if key == "" || len(key) > 64 {
		return ProtocolUnspecified, false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return ProtocolUnspecified, false
		}
	}
	return Protocol(key), true
}

// topLevelScalar returns the single-line scalar value of a column-0 key.
func topLevelScalar(text string, want Protocol) (string, bool) {
	text = strings.TrimPrefix(text, "\uFEFF")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimRight(line, " ")
		if trimmed == "" || line[0] == ' ' || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, ok := columnZeroKey(trimmed)
		if !ok || key != want {
			continue
		}
		colon := strings.IndexByte(trimmed, ':')
		if colon < 0 {
			return "", false
		}
		val := strings.TrimSpace(trimmed[colon+1:])
		val = strings.TrimSuffix(strings.TrimPrefix(val, `"`), `"`)
		val = strings.TrimSuffix(strings.TrimPrefix(val, `'`), `'`)
		if val == "" {
			return "", false
		}
		return val, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// TemplateSet — identity, not position
// ---------------------------------------------------------------------------

// TemplateSet is the set of templates a driver may fire.
//
// # Why the index is (id, digest) and not an index into a slice
//
// A result arriving from the engine names a template. The driver has to
// decide whether that template is one it admitted. Matching by POSITION — the
// engine's Nth result against the driver's Nth template — is defeated the
// moment the engine reorders, deduplicates, or reports a result for a
// template it loaded from somewhere else, and the failure is silent: the
// finding is attributed to a template that did not produce it.
//
// So the lookup is by IDENTITY: the declared id AND the SHA-256 of the bytes
// that were analysed. An engine that reports an id the driver admitted, but a
// digest it did not, is reporting on a different file with the same name.
type TemplateSet struct {
	byIdentity map[string]Template
	order      []Template
	sealed     bool
}

func identityKey(id, digest string) string { return id + "@" + digest }

// NewTemplateSet seals a template set. It refuses an empty one.
func NewTemplateSet(templates []Template) (TemplateSet, error) {
	if len(templates) == 0 {
		return TemplateSet{}, fmt.Errorf("engines: %w: an empty template set fires nothing "+
			"and reports clean", ErrNoTemplates)
	}
	idx := make(map[string]Template, len(templates))
	for i, t := range templates {
		if !t.Constructed() {
			return TemplateSet{}, fmt.Errorf("engines: %w: template %d was not built by "+
				"LoadTemplates", ErrUnconstructed, i)
		}
		k := identityKey(t.id, t.digest)
		if _, dup := idx[k]; dup {
			return TemplateSet{}, fmt.Errorf("engines: %w: two templates share the identity "+
				"%s", ErrRefused, k)
		}
		idx[k] = t
	}
	return TemplateSet{byIdentity: idx, order: cloneTemplates(templates), sealed: true}, nil
}

// Constructed reports whether s came from NewTemplateSet.
func (s TemplateSet) Constructed() bool { return s.sealed && len(s.byIdentity) > 0 }

// Len is the number of admitted templates.
func (s TemplateSet) Len() int { return len(s.byIdentity) }

// Templates returns the set as a FRESH SLICE.
func (s TemplateSet) Templates() []Template { return cloneTemplates(s.order) }

// Lookup returns the admitted template with this exact identity.
func (s TemplateSet) Lookup(id, digest string) (Template, bool) {
	if !s.Constructed() {
		return Template{}, false
	}
	t, ok := s.byIdentity[identityKey(id, digest)]
	return t, ok
}

// ---------------------------------------------------------------------------
// RequestProposal — a request with no capability to make itself
// ---------------------------------------------------------------------------

// ProposalFacts is what the driver knows about one request a template wants
// to make. NewRequestProposal turns it into a sealed RequestProposal.
type ProposalFacts struct {
	// Spec is the authorized destination.
	Spec TargetSpec
	// Origin is what caused the request.
	Origin authz.RequestOrigin
	// Method and Path are the request.
	Method authz.Method
	Path   string
	// Technique is gate 15's classification of what this probe does.
	Technique authz.Technique
	// TemplateID and TemplateDigest name the admitted template, by identity.
	TemplateID     string
	TemplateDigest string
	// Hop and Attempt are the redirect depth and the retry number.
	Hop     int
	Attempt int
}

// RequestProposal is one request this driver proposes to make.
//
// # It cannot make itself, and that is checked by reflection elsewhere
//
// plan/design/dynamic-tier.md exit criterion 19 requires that this type have "zero methods
// or fields capable of performing network I/O, proven by reflection/static
// analysis (the DAST model role, the DAST-model review)". Every field below is
// a string, an int, an enum string or an authz value type. There is no
// interface field, no func field, no io.Reader, no channel and no pointer. A
// proposal is a description of a request and holds nothing that could issue
// one.
type RequestProposal struct {
	spec      TargetSpec
	origin    authz.RequestOrigin
	method    authz.Method
	path      string
	technique authz.Technique
	tplID     string
	tplDigest string
	hop       int
	attempt   int
	sealed    bool
}

// proposalOrigins is the allowlist of origins this driver will propose.
//
// It is NARROWER than the kernel's, and deliberately so. The kernel
// enumerates six origins because the kernel has to be able to gate whatever
// the dynamic tier does; this driver only produces three of them, and the
// three it does not produce are the three that correspond to protocols the
// template allowlist already refuses:
//
//	OriginBrowserFetch       needs `headless:`   — not on the allowlist
//	OriginWebSocketUpgrade   needs `websocket:`  — not on the allowlist
//	OriginOutOfBandCallback  needs interactsh    — off, with no way to turn
//	                                               it on (RunPlan.interactsh)
//
// So the two halves agree, and the agreement is testable: a proposal carrying
// an origin whose protocol was refused at load is refused here too. That is
// the interactsh default made structural rather than declared — there is no
// out-of-band callback for a template to be handed, because there is no
// origin under which this driver will propose reaching one.
func proposalOrigins() []authz.RequestOrigin {
	return []authz.RequestOrigin{
		authz.OriginInitial,
		authz.OriginRedirect,
		authz.OriginTemplateURL,
	}
}

// NewRequestProposal validates the facts and seals them.
//
// # Why the destination is checked LAST
//
// Every check here refuses, so the order changes no outcome — only the
// message. It is deliberate all the same: a proposal carrying an unrecognised
// method or an unclassified technique is MALFORMED, and reporting it as "no
// authorization for this destination" would send the reader to the scope file
// to debug a typo in a verb. The destination check is the one that cannot be
// gotten wrong by accident, so it goes last and everything that CAN be gotten
// wrong by accident is named first.
func NewRequestProposal(f ProposalFacts) (RequestProposal, error) {
	allowed := false
	for _, o := range proposalOrigins() {
		if o == f.Origin {
			allowed = true
			break
		}
	}
	if !allowed {
		return RequestProposal{}, fmt.Errorf("engines: %w: this driver does not propose "+
			"requests of origin %q. Its three permitted origins correspond exactly to the "+
			"protocols the template allowlist admits; the others need `headless:`, "+
			"`websocket:` or interactsh, and none of those can be turned on here",
			ErrRefused, redactIdentifier(string(f.Origin)))
	}
	if !f.Method.Recognised() {
		return RequestProposal{}, fmt.Errorf("engines: %w: %q is not on the kernel's method "+
			"allowlist. An unknown verb is not a safe verb", ErrRefused,
			redactIdentifier(string(f.Method)))
	}
	if !f.Technique.Classified() {
		return RequestProposal{}, fmt.Errorf("engines: %w: technique %q is on neither of "+
			"gate 15's compiled-in lists. A probe whose technique nobody classified is "+
			"refused before the kernel is asked, and refused again by gate 15 if it were not",
			ErrRefused, redactIdentifier(string(f.Technique)))
	}
	if f.TemplateID == "" || f.TemplateDigest == "" {
		return RequestProposal{}, fmt.Errorf("engines: %w: the proposal names no template "+
			"identity. A request the driver cannot attribute to an admitted template is a "+
			"request whose provenance is unknown", ErrRefused)
	}
	if !f.Spec.Constructed() {
		return RequestProposal{}, fmt.Errorf("engines: %w: the proposal names a destination "+
			"that NewTargetSpec never built, so no authorization was ever checked for it",
			ErrUnconstructed)
	}
	return RequestProposal{
		spec:      f.Spec,
		origin:    f.Origin,
		method:    f.Method,
		path:      f.Path,
		technique: f.Technique,
		tplID:     f.TemplateID,
		tplDigest: f.TemplateDigest,
		hop:       f.Hop,
		attempt:   f.Attempt,
		sealed:    true,
	}, nil
}

// Constructed reports whether p came from NewRequestProposal.
func (p RequestProposal) Constructed() bool { return p.sealed && p.spec.Constructed() }

// Spec returns the authorized destination.
func (p RequestProposal) Spec() TargetSpec { return p.spec }

// Origin, Method, Path, Technique, Hop and Attempt are the request.
func (p RequestProposal) Origin() authz.RequestOrigin { return p.origin }

// Method returns the HTTP method.
func (p RequestProposal) Method() authz.Method { return p.method }

// Path returns the request path.
func (p RequestProposal) Path() string { return p.path }

// Technique returns gate 15's classification.
func (p RequestProposal) Technique() authz.Technique { return p.technique }

// TemplateIdentity returns the id and digest of the template that proposed it.
func (p RequestProposal) TemplateIdentity() (id, digest string) { return p.tplID, p.tplDigest }

// Hop returns the redirect depth.
func (p RequestProposal) Hop() int { return p.hop }

// Attempt returns the retry number.
func (p RequestProposal) Attempt() int { return p.attempt }

// ---------------------------------------------------------------------------
// Issuer — where the socket is, and where it is not
// ---------------------------------------------------------------------------

// AdmittedRequest is a request the kernel admitted, with the proof attached.
//
// It is sealed: only Fire mints one, and only after
// authz.GateAudit.AuditedAdmit returned a passing result and a held lease. An
// Issuer that receives one of these has the audit sequence the admission was
// written under and can refuse anything that does not carry it.
type AdmittedRequest struct {
	proposal RequestProposal
	auth     authz.Authorization
	seq      authz.AuditSeq
	sealed   bool
}

// Constructed reports whether r was minted by Fire.
func (r AdmittedRequest) Constructed() bool { return r.sealed && r.proposal.Constructed() }

// Proposal returns the request that was admitted.
func (r AdmittedRequest) Proposal() RequestProposal { return r.proposal }

// Authorization returns the kernel token covering the destination.
func (r AdmittedRequest) Authorization() authz.Authorization { return r.auth }

// AuditSeq returns the gate-21 row this admission was written under.
func (r AdmittedRequest) AuditSeq() authz.AuditSeq { return r.seq }

// ProbeResult is what an Issuer reports back. It carries no connection and no
// reader: the body is already consumed and already bounded by the kernel's
// gate 14 cap on the far side of this interface.
type ProbeResult struct {
	// Status is the HTTP status observed, 0 if none was.
	Status int
	// Matched is the engine's verdict for the template that proposed the
	// request.
	Matched bool
	// BodyBytes is how much of the body was read, after gate 14's cap.
	BodyBytes int64
	// Evidence is prose from the far side. It is sanitized before the driver
	// retains it.
	Evidence string
}

// Issuer is the egress layer.
//
// # Why this is an interface and not a function that dials
//
// Gate 3 tier 1: a socket constructed inside internal/dast outside
// internal/dast/authz fails the build, and there is no allowlist for it. This
// package therefore cannot dial, cannot hold an http.Client, and cannot even
// import a package that could. The implementation of this interface lives on
// the far side of that boundary — in the kernel, or in the binary that
// assembles the DAST tier — and it is handed in.
//
// An implementation MUST call authz.RequireAuthorization (or
// authz.PinnedDialAddress, which calls it) against
// AdmittedRequest.Authorization before it connects. This driver has already
// done so when it built the TargetSpec, but a token check immediately before
// the socket is what gate 3's runtime half is for, and doing it twice costs a
// comparison.
type Issuer interface {
	Issue(ctx context.Context, req AdmittedRequest) (ProbeResult, error)
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

// Config is everything a Driver needs. Every field is required; there is no
// default for any of them, because a default here would be a gate running
// against a value nobody chose.
type Config struct {
	// Governor is the kernel's per-request interceptor for this target.
	Governor *authz.Governor
	// Audit is gate 21's writer, coupled to the interceptor by
	// AuditedAdmit: an admission whose audit row did not land is not an
	// admission.
	Audit *authz.GateAudit
	// Authorization is the kernel token for Target.
	Authorization authz.Authorization
	// Target is the admitted target this driver probes.
	Target authz.Target
	// Templates is the admitted template set.
	Templates TemplateSet
	// Rejected is what LoadTemplates refused, carried through so that a
	// ScanResult can say WHY the admitted set is the size it is. A rejection
	// nobody can see is indistinguishable from a file that was never there.
	Rejected []RejectedTemplate
	// Issuer is the egress layer. A nil Issuer is legal to construct and
	// produces ErrNoEgress at Fire — refusing an admitted request rather
	// than silently reporting a clean probe.
	Issuer Issuer
	// Engine is the probe engine. A nil Engine is legal to construct and
	// produces *EngineUnavailableError at Run.
	Engine Engine
}

// Driver is the Nuclei driver.
type Driver struct {
	mu       sync.Mutex
	cfg      Config
	spec     TargetSpec
	cov      Coverage
	findings []Finding
	rejected []RejectedTemplate

	sealed bool
}

// NewDriver assembles the driver. It refuses anything the kernel did not
// build, and it builds the TargetSpec here — so a Driver that exists at all
// is one whose target passed gates 8, 9 and 10.
func NewDriver(cfg Config) (*Driver, error) {
	if !cfg.Governor.Constructed() {
		return nil, fmt.Errorf("engines: %w: the driver was handed a Governor "+
			"authz.NewGovernor never built. A nil governor enforces nothing, and enforcing "+
			"nothing is not admitting everything", ErrUnconstructed)
	}
	if !cfg.Audit.Constructed() {
		return nil, fmt.Errorf("engines: %w: the driver was handed a GateAudit "+
			"authz.NewGateAudit never built. Gate 21 requires every decision recorded, and "+
			"a driver with no audit writer records none", ErrUnconstructed)
	}
	if !cfg.Templates.Constructed() {
		return nil, fmt.Errorf("engines: %w: the driver was handed a template set "+
			"NewTemplateSet never built", ErrUnconstructed)
	}
	spec, err := NewTargetSpec(cfg.Authorization, cfg.Target)
	if err != nil {
		return nil, err
	}
	rejected := make([]RejectedTemplate, len(cfg.Rejected))
	copy(rejected, cfg.Rejected)
	return &Driver{
		cfg:  cfg,
		spec: spec,
		cov: Coverage{
			TemplatesAdmitted: cfg.Templates.Len(),
			TemplatesRejected: len(rejected),
			EngineWired:       cfg.Engine != nil,
			IssuerWired:       cfg.Issuer != nil,
		},
		rejected: rejected,
		sealed:   true,
	}, nil
}

// Constructed reports whether d came from NewDriver.
func (d *Driver) Constructed() bool { return d != nil && d.sealed }

// Spec returns the authorized destination this driver probes.
func (d *Driver) Spec() TargetSpec {
	if !d.Constructed() {
		return TargetSpec{}
	}
	return d.spec
}

// Fire routes one proposal through the kernel and, only if the kernel admits
// it, issues it.
//
// # The order, and what each step is for
//
//	1  the driver is constructed, the proposal is constructed
//	2  the proposal names a template THIS DRIVER ADMITTED, by identity
//	3  the proposal's destination is the authorized target (RequireAuthorization)
//	4  the facts become an authz.RequestIntent — which validates them again,
//	   in the kernel's own vocabulary
//	5  authz.GateAudit.AuditedAdmit runs gates 16, 17, 13, 11, 15 and 14 and
//	   writes a gate-21 row per gate. A refusal at any of them ends here.
//	6  only now does anything leave the process, and it leaves through the
//	   Issuer, which this package cannot implement.
//
// Step 2 is the one that is easy to leave out. Without it, a result-driven
// follow-up request from a template the loader REJECTED would still reach the
// kernel, and the kernel would admit it — because the kernel gates
// destinations, not provenance. `code:` templates are rejected at load, and
// step 2 is what makes "never reaches Fire" true rather than hoped for.
func (d *Driver) Fire(ctx context.Context, p RequestProposal, now authz.Clock) (Finding, error) {
	if !d.Constructed() {
		return Finding{}, fmt.Errorf("engines: %w: Fire was called on a Driver NewDriver "+
			"never built", ErrUnconstructed)
	}
	if !p.Constructed() {
		d.count(func(c *Coverage) { c.RequestsRefused++ })
		return Finding{}, fmt.Errorf("engines: %w: the proposal was not built by "+
			"NewRequestProposal", ErrUnconstructed)
	}

	id, digest := p.TemplateIdentity()
	tpl, ok := d.cfg.Templates.Lookup(id, digest)
	if !ok {
		d.count(func(c *Coverage) { c.RequestsRefused++ })
		return Finding{}, fmt.Errorf("engines: %w: no admitted template has identity %s. "+
			"A template rejected at load time — every `code:` template, among others — "+
			"cannot reach the kernel through this path, because the lookup is by identity "+
			"and a rejected template has no entry", ErrRefused, redactedIdentity(id, digest))
	}

	if err := authz.RequireAuthorization(d.cfg.Authorization, p.spec.Target()); err != nil {
		d.count(func(c *Coverage) { c.RequestsRefused++ })
		return Finding{}, fmt.Errorf("engines: %w: %w", ErrRefused, err)
	}

	intent, err := authz.NewRequestIntent(authz.RequestFacts{
		Origin:   p.origin,
		Admitted: d.cfg.Target,
		Next:     p.spec.Target(),
		Method:   p.method,
		Path:     p.path,
		Hop:      p.hop,
		Attempt:  p.attempt,
	})
	if err != nil {
		d.count(func(c *Coverage) { c.RequestsRefused++ })
		return Finding{}, fmt.Errorf("engines: %w: %w", ErrRefused, err)
	}

	lease, res := d.cfg.Audit.AuditedAdmit(d.cfg.Governor, intent, p.technique, now)
	if !res.Passed() {
		d.count(func(c *Coverage) { c.RequestsRefused++ })
		return Finding{}, fmt.Errorf("engines: %w: the kernel refused this request at %s: %w",
			ErrRefused, res.Gate(), res.Err())
	}
	defer lease.Release()

	// The gate-21 row the admission was written under. AuditedAdmit records
	// one row per gate consulted and releases the lease if any write failed,
	// so reaching here means every row landed and LastSeq names the last of
	// them.
	seq := d.cfg.Audit.LastSeq()

	if d.cfg.Issuer == nil {
		d.count(func(c *Coverage) { c.RequestsAdmitted++ })
		return Finding{}, fmt.Errorf("engines: %w: the kernel admitted a request to %s and "+
			"there is nowhere to send it. This is a refusal and not a clean probe: gate 3 "+
			"forbids this package from constructing the socket itself, so an unwired "+
			"Issuer means the probe DID NOT RUN", ErrNoEgress, p.spec.URL())
	}

	req := AdmittedRequest{proposal: p, auth: d.cfg.Authorization, seq: seq, sealed: true}
	out, ierr := d.cfg.Issuer.Issue(ctx, req)
	if ierr != nil {
		d.count(func(c *Coverage) { c.RequestsAdmitted++ })
		return Finding{}, fmt.Errorf("engines: issuing an admitted request to %s: %w",
			p.spec.URL(), ierr)
	}

	evidence, stats := scrub(out.Evidence)
	d.count(func(c *Coverage) {
		c.RequestsAdmitted++
		c.RequestsIssued++
		c.Evidence.Merge(stats)
		if out.Matched {
			c.Matches++
		}
	})

	f := Finding{
		TemplateID:     tpl.ID(),
		TemplateDigest: tpl.Digest(),
		TemplatePath:   tpl.Path(),
		Target:         p.spec.Target().String(),
		Method:         p.method,
		Path:           p.path,
		Technique:      p.technique,
		Origin:         p.origin,
		Status:         out.Status,
		Matched:        out.Matched,
		BodyBytes:      out.BodyBytes,
		Evidence:       evidence,
		AuditSeq:       seq,
		At:             now.Instant(),
	}
	if out.Matched {
		d.mu.Lock()
		d.findings = append(d.findings, f)
		d.mu.Unlock()
	}
	return f, nil
}

// Run executes the engine over the whole admitted template set.
//
// # What it does NOT do, and why that is the point
//
// It does not increment Coverage.RequestsIssued. Run hands a plan to an
// engine on the far side of an interface and reads results back; it does not
// observe what that engine put on the wire, and counting a request it did not
// see would be inventing the one number
// ScanResult.AssertNotSilentlyEmpty rests on.
//
// The consequence is deliberate and it is the honest one: a scan driven
// ONLY through Run comes back with RequestsIssued == 0, and
// AssertNotSilentlyEmpty therefore REFUSES to let it be read as clean. The
// only way to a reportable clean result is for the engine's requests to have
// come back through Fire — which is where the kernel is. An engine that
// bypasses the Issuer does not get a quieter result; it gets a refusal.
//
// # What it DOES do to every result, which Fire's path also does
//
// It scrubs. The callback is handed a result whose Evidence, Severity, Method
// and Path have been through scrubEngineResult, and Coverage.Evidence carries
// the count of what came off. Run is the only route from an Engine to a
// caller, so a result that skipped this would be engine-authored bytes
// travelling to a record and an agent's context unbounded and unstripped.
func (d *Driver) Run(ctx context.Context, cb func(EngineResult, Template) error) error {
	if !d.Constructed() {
		return fmt.Errorf("engines: %w: Run was called on a Driver NewDriver never built",
			ErrUnconstructed)
	}
	if d.cfg.Engine == nil {
		return &EngineUnavailableError{
			Name: EngineName,
			Detail: "the driver was constructed with no Engine, so ExecuteCallbackWithCtx " +
				"was never called and no template was ever executed",
		}
	}
	plan, err := NewRunPlan([]TargetSpec{d.spec}, d.cfg.Templates.Templates())
	if err != nil {
		return err
	}
	return d.cfg.Engine.ExecuteCallbackWithCtx(ctx, plan, func(r EngineResult) error {
		tpl, ok := d.cfg.Templates.Lookup(r.TemplateID, r.TemplateDigest)
		if !ok {
			// An unattributable result is dropped LOUDLY. The engine is
			// reporting on a template this driver did not admit, or on a
			// different file bearing an admitted id — and either way the
			// finding would be filed under a template that did not produce
			// it.
			//
			// Both halves of the identity came from the engine and neither
			// has passed anything, so the message quotes them REDACTED.
			return fmt.Errorf("engines: %w: the engine reported a result for template "+
				"identity %s, which this driver did not admit. Results are attributed by "+
				"identity and never by position, so there is no fallback to guess at",
				ErrRefused, redactedIdentity(r.TemplateID, r.TemplateDigest))
		}
		// SCRUB BEFORE THE CALLER SEES IT. This is the only route an
		// EngineResult takes out of the driver, the prose on it was written
		// by a process outside Anvil, and where it is heading is a record and
		// eventually an agent's context (the spine's record and safety sections). It is
		// scrubbed before the nil-callback check so that Coverage.Evidence
		// records what the engine sent whether or not anybody was listening.
		clean, stats := scrubEngineResult(r)
		d.count(func(c *Coverage) { c.Evidence.Merge(stats) })
		if cb == nil {
			return nil
		}
		return cb(clean, tpl)
	})
}

func (d *Driver) count(f func(*Coverage)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(&d.cov)
}

// Result returns what this driver has done so far.
func (d *Driver) Result() ScanResult {
	if !d.Constructed() {
		return ScanResult{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := ScanResult{
		Coverage: d.cov,
		Target:   d.spec.Target().String(),
	}
	if d.findings != nil {
		out.Findings = make([]Finding, len(d.findings))
		copy(out.Findings, d.findings)
	}
	if d.rejected != nil {
		out.Rejected = make([]RejectedTemplate, len(d.rejected))
		copy(out.Rejected, d.rejected)
	}
	return out
}

// ---------------------------------------------------------------------------
// Findings and the coverage predicate
// ---------------------------------------------------------------------------

// Finding is one probe outcome, attributed to the template that produced it.
type Finding struct {
	// TemplateID, TemplateDigest and TemplatePath identify the template BY
	// IDENTITY, not by position in any list.
	TemplateID     string
	TemplateDigest string
	TemplatePath   string
	// Target is the kernel's rendering of the target, pinned address
	// included.
	Target string
	// Method, Path, Technique and Origin are the request that produced it.
	Method    authz.Method
	Path      string
	Technique authz.Technique
	Origin    authz.RequestOrigin
	// Status, Matched and BodyBytes are the observation.
	Status    int
	Matched   bool
	BodyBytes int64
	// Evidence is sanitized prose from outside Anvil.
	Evidence string
	// AuditSeq is the gate-21 row the admission was written under. A finding
	// that cannot be joined back to an audited admission is not a finding
	// this driver produced.
	AuditSeq authz.AuditSeq
	// At is the instant from the Clock the decision was made against.
	At time.Time
}

// Coverage is what actually ran. It is the difference between "the target is
// clean" and "nothing probed it".
type Coverage struct {
	// TemplatesAdmitted is how many templates the driver may fire.
	TemplatesAdmitted int
	// TemplatesRejected is how many LoadTemplates refused.
	TemplatesRejected int
	// RequestsAdmitted is how many proposals the kernel let through.
	RequestsAdmitted int
	// RequestsRefused is how many it refused, plus those this driver refused
	// before asking.
	RequestsRefused int
	// RequestsIssued is how many actually left the process. It is the number
	// that decides whether an empty finding list means anything.
	RequestsIssued int
	// Matches is how many issued requests the engine called a match.
	Matches int
	// EngineWired and IssuerWired record whether the two seams had
	// implementations at all.
	EngineWired bool
	IssuerWired bool
	// Evidence is the merged report from every external string this driver
	// passed through scrub. Non-zero counts mean engine-authored prose
	// carried invisible or bidirectional characters — worth surfacing, since
	// the spine's safety section puts prompt-injection defence at ingest.
	Evidence EvidenceStats
}

// ProbedNothing reports whether this run put no request on the wire.
//
// This is the predicate that separates "clean" from "nothing ran". It is TRUE
// for the zero value, which is the fail-closed direction: a Coverage nobody
// filled in describes a scan nobody ran.
func (c Coverage) ProbedNothing() bool {
	return c.TemplatesAdmitted == 0 || c.RequestsIssued == 0
}

// ScanResult is one driver's run.
type ScanResult struct {
	// Findings is the driver's output. Empty means the driver issued at
	// least RequestsIssued requests and matched nothing — and only that,
	// provided AssertNotSilentlyEmpty returns nil.
	Findings []Finding
	// Rejected is every template that did not load, by name and reason.
	Rejected []RejectedTemplate
	// Coverage is populated on every run, including the zero-findings case.
	Coverage Coverage
	// Target is the kernel's rendering of the target.
	Target string
}

// AssertNotSilentlyEmpty refuses to let a caller read "no findings" as "no
// vulnerabilities" when in fact nothing was probed.
//
// Call it before reporting a clean target. It returns nil only when at least
// one template was admitted AND at least one request actually left the
// process — at which point an empty Findings slice means what it appears to
// mean.
//
// It is the same shape, and the same refusal, as
// internal/collector/repo.ScanResult.AssertNotSilentlyEmpty. That precedent
// exists because an SCA collector whose tool was missing returned a finding
// list byte-identical to a clean repository's. A probe engine that was never
// installed does exactly the same thing, and this is the guard that stops the
// two being reported alike.
func (r ScanResult) AssertNotSilentlyEmpty() error {
	c := r.Coverage
	switch {
	case !c.EngineWired && c.RequestsIssued == 0:
		return fmt.Errorf("%w: no probe engine was wired and %d request(s) were issued "+
			"against %q. `%s` is not installed on this host and this driver registers no "+
			"default adapter, so an empty finding list here records the absence of a "+
			"scanner, not the absence of findings",
			ErrNothingProbed, c.RequestsIssued, r.Target, EngineName)
	case c.TemplatesAdmitted == 0:
		return fmt.Errorf("%w: zero templates were admitted for %q (%d rejected). An engine "+
			"with no template completes successfully having tested nothing",
			ErrNothingProbed, r.Target, len(r.Rejected))
	case c.RequestsIssued == 0:
		return fmt.Errorf("%w: %d template(s) were admitted for %q but zero requests reached "+
			"the wire (%d admitted by the kernel, %d refused). A target nothing was sent to "+
			"produces the same empty finding list as a target with no findings, and the two "+
			"must not be reported alike",
			ErrNothingProbed, c.TemplatesAdmitted, r.Target,
			c.RequestsAdmitted, c.RequestsRefused)
	}
	return nil
}
