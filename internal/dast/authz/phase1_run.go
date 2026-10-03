// Phase 1 of the Authorization Gate Sequence: RUN INITIATION, gates 4–7.
//
// Phase 0 (phase0_build.go) asked whether this binary may probe anything at
// all. Phase 1 asks whether THIS RUN may start: is there a scope file, does it
// parse strictly, is there a live attestation bound to that exact scope, was a
// mode declared, and did the trigger come from a principal with write
// authority over the repository the scope file lives in.
//
// ===========================================================================
// THIS FILE HAS TWO HALVES, AND THEY ARE NOT INTERCHANGEABLE
// ===========================================================================
//
// HALF ONE — the four run-initiation gates. CheckGate4ScopeFile,
// CheckGate5Attestation, CheckGate6ModeDeclaration and
// CheckGate7TriggerProvenance take the facts each gate is actually about
// (bytes on disk, a declared mode string, a CI trigger context) and return
// the kernel core's typed failure, GateResult. This is the same shape Phase 0 uses, and it
// is what run initiation's design expected-output schema asks for: "Four gate
// functions matching the kernel core's typed-failure convention."
//
// InitiateRun runs all four in one call and, if every one passes, mints the
// Scope, the Attestation, the ModeDeclaration and the DastEnablement that the
// rest of the run is built from. It is the only function here that produces a
// DastEnablement, and it produces one by calling EnableDAST, which gives that
// type the consumer the kernel-types review correctly observed it did not have.
//
// HALF TWO — the per-target residue, registered into the kernel's admission
// chain as gateFuncs. A gateFunc sees exactly (target, scope, attestation,
// clock) — the spine's four inputs and nothing else — so it can only
// re-assert the part of a Phase 1 gate that is a function of those four. That
// residue is real and is not a formality:
//
//	gate 4  the scope layer must permit this target's canonical host and port.
//	        A missing, malformed or unknown-field scope file never produced a
//	        Scope at all, and an empty one has no allow entries, so both yield
//	        zero permitted targets HERE, in the chain, rather than only in the
//	        loader that a future caller might forget to run.
//	gate 5  the attestation must be constructed, bound to this scope's hash,
//	        carry one of the four authorities, be live at the supplied clock,
//	        and — the part that cannot be configured around — have a lifetime
//	        no longer than the CODED MaxAttestationLifetime.
//	gate 6  a mode must be declared, and `external` may not be entered without
//	        a live attestation (research/20 gate 6: "`external` cannot be
//	        entered without gate 5").
//
// ===========================================================================
// GATE 7 IS DELIBERATELY NOT REGISTERED INTO THE ADMISSION CHAIN
// ===========================================================================
//
// Trigger provenance is not a function of (target, scope, attestation, clock).
// It is a function of the CI event, the repository, the actor and how the
// actor's permission was determined — none of which appear in gateFunc's
// signature, and gateFunc's signature is declared in the kernel core's write scope
// precisely so that it cannot be widened by a packet that finds it
// inconvenient.
//
// There were three ways out and two of them are worse:
//
//  1. Widen gateFunc, or thread a run object through Decide. That is a change
//     to the spine's "pure function of (target, scope, attestation,
//     clock)" and to the kernel core's file. Not run initiation's call, and not
//     run initiation's write scope.
//  2. Register a gate 7 that consults process-level state written at run
//     initiation. That makes Decide a function of ambient mutable state, which
//     is the same safety-section violation wearing a hat, and it makes the kernel's
//     behaviour depend on test execution order.
//  3. Register a gate 7 that permits whenever the four inputs are well formed.
//     That is a gate that has never refused anything — the exact shape
//     internal/SKIPPED-CONTROLS.md records this repository shipping twice, and
//     the reason the engineering standard "a guard that has never failed has
//     not been tested" exists.
//
// So gate 7 is implemented as a run-initiation gate that genuinely refuses
// (CheckGate7TriggerProvenance below, with tests for the fork-PR and
// pull_request_target paths), and it is not a gateFunc.
//
// THE ORCHESTRATOR RULED ON THIS. Gate 7 does not belong in the admission chain
// at all: plan/design/dynamic-tier.md:1032's own table puts it in Phase 1, it is evaluated
// ONCE PER RUN before any target exists, and widening gateFunc to carry trigger
// provenance would break the spine's pure-function property — the property that makes
// the admission decision auditable. It was removed from admissionChain, and
// kernel.go's registerInto now REFUSES to register it, so the separation is
// enforced rather than described. Gate 7's pass is a PRECONDITION of obtaining
// the Attestation the admission chain consumes: InitiateRun below runs it, and
// a run that fails it never produces the RunInitiation that carries the
// attestation forward. TestGate7CannotBeRegisteredAsAGateFunc is the tripwire.
//
// ===========================================================================
// WHY THE SCOPE AND ATTESTATION FILES ARE JSON
// ===========================================================================
//
// Not a style preference. Gate 2's import allowlist (phase0_build.go,
// kernelImportAllowlist) permits this package to import the standard library
// and internal/record and nothing else, so no YAML library is reachable and
// internal/dast/target's hand-rolled YAML reader is not importable either.
// encoding/json's DisallowUnknownFields is exactly gate 4's "unknown-field →
// zero permitted targets" rule, implemented by the standard library rather
// than by a parser written inside the authorization kernel. A hand-rolled
// parser in the kernel would be a much larger attack surface than a file
// format change.
//
// ===========================================================================
// UNTRUSTED BYTES NEVER REACH A MESSAGE
// ===========================================================================
//
// A scope file and an attestation file are `anvil/trust: untrusted` per
// the spine's record section: they originate outside Anvil. Every Detail string
// produced in this file is Anvil-authored and contains no bytes from the
// parsed document — not the unknown field's name, not the rejected host, not
// encoding/json's own error text (which quotes the offending field). Where an
// operator genuinely needs to see what was rejected, the value goes into
// Evidence through redactUntrusted, which keeps an allowlisted charset and
// bounds the length.

package authz

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// REASONS — the gate-numbered tokens Phase 1 refuses with
// ---------------------------------------------------------------------------

// Gate 4 reasons. types.go already declares ReasonScopeUnconstructed
// ("gate04.scope_not_constructed") and this file reuses it rather than
// declaring a second token for the same fact.
const (
	ReasonScopeFileMissing       Reason = "gate04.scope_file_missing"
	ReasonScopeFileUnreadable    Reason = "gate04.scope_file_unreadable"
	ReasonScopeFileTooLarge      Reason = "gate04.scope_file_too_large"
	ReasonScopeFileUnparseable   Reason = "gate04.scope_file_unparseable"
	ReasonScopeFileUnknownField  Reason = "gate04.scope_file_unknown_field"
	ReasonScopeFileDuplicateKey  Reason = "gate04.scope_file_duplicate_key"
	ReasonScopeFileTrailingBytes Reason = "gate04.scope_file_trailing_content"
	ReasonScopeFileSchemaVersion Reason = "gate04.scope_file_schema_version"
	ReasonScopeFileSchemaInvalid Reason = "gate04.scope_file_schema_invalid"
	ReasonScopeFileModeMismatch  Reason = "gate04.scope_file_mode_mismatch"
	ReasonScopeRefusesTarget     Reason = "gate04.scope_does_not_permit_target"
	ReasonScopeTargetUnbuilt     Reason = "gate04.target_not_constructed"
	ReasonScopeNoDeclaration     Reason = "gate04.no_mode_declared_to_load_scope_as"
	// ReasonScopePermitsTarget is gate 4's PERMIT token. A permitting Ruling
	// must carry a reason naming its own gate (kernel.go, Ruling.Permits),
	// so each chain gate below needs one of these; reusing a refusal token
	// for a permit would make the audit row say the opposite of what
	// happened.
	ReasonScopePermitsTarget Reason = "gate04.scope_permits_target"
)

// Gate 5 reasons. types.go already declares ReasonAttestationUnconstructed,
// ReasonClockUnconstructed and ReasonScopeAttestationMismatch.
const (
	ReasonAttestationFileMissing      Reason = "gate05.attestation_file_missing"
	ReasonAttestationFileUnreadable   Reason = "gate05.attestation_file_unreadable"
	ReasonAttestationFileTooLarge     Reason = "gate05.attestation_file_too_large"
	ReasonAttestationUnparseable      Reason = "gate05.attestation_file_unparseable"
	ReasonAttestationUnknownField     Reason = "gate05.attestation_file_unknown_field"
	ReasonAttestationDuplicateKey     Reason = "gate05.attestation_file_duplicate_key"
	ReasonAttestationTrailingBytes    Reason = "gate05.attestation_file_trailing_content"
	ReasonAttestationSchemaVersion    Reason = "gate05.attestation_file_schema_version"
	ReasonAttestationSchemaInvalid    Reason = "gate05.attestation_file_schema_invalid"
	ReasonAttestationAuthorityUnknown Reason = "gate05.attestation_authority_unknown"
	ReasonAttestationExpired          Reason = "gate05.attestation_expired"
	ReasonAttestationNotYetValid      Reason = "gate05.attestation_not_yet_valid"
	ReasonAttestationLifetimeTooLong  Reason = "gate05.attestation_lifetime_exceeds_ceiling"
	ReasonAttestationCeilingRaised    Reason = "gate05.attestation_ceiling_may_only_be_lowered"
	// ReasonAttestationLiveAndBound is gate 5's PERMIT token.
	ReasonAttestationLiveAndBound Reason = "gate05.attestation_live_and_scope_bound"
)

// Gate 6 reasons.
const (
	ReasonModeNotDeclared             Reason = "gate06.mode_not_declared"
	ReasonModeUnknown                 Reason = "gate06.mode_unknown"
	ReasonExternalRequiresAttestation Reason = "gate06.external_requires_a_live_attestation"
	// ReasonModeDeclaredForRun is gate 6's PERMIT token.
	ReasonModeDeclaredForRun Reason = "gate06.mode_declared_for_this_run"
)

// Gate 7 reasons.
const (
	ReasonTriggerContextUnconstructed Reason = "gate07.trigger_context_not_constructed"
	ReasonTriggerPolicyUnconstructed  Reason = "gate07.trigger_policy_not_constructed"
	ReasonTriggerEventUnknown         Reason = "gate07.trigger_event_unknown"
	ReasonTriggerEventNotEligible     Reason = "gate07.trigger_event_never_eligible"
	ReasonTriggerEventNotPermitted    Reason = "gate07.trigger_event_not_permitted"
	ReasonTriggerForkPullRequest      Reason = "gate07.fork_pull_request"
	ReasonTriggerRepositoryMismatch   Reason = "gate07.trigger_repository_is_not_the_scope_repo"
	ReasonTriggerNoWriteAuthority     Reason = "gate07.principal_lacks_write_authority"
	ReasonTriggerPermissionUnverified Reason = "gate07.actor_permission_was_not_verified"
)

// ---------------------------------------------------------------------------
// BOUNDS — coded constants, not config keys
// ---------------------------------------------------------------------------

// The file-size and list-length bounds are plain consts rather than Caps.
// A Cap exists so that CONFIGURATION may lower a coded floor; nothing about
// these is configurable in either direction, so a const is the stricter
// statement.
const (
	// maxScopeFileBytes bounds the scope file. A scope file is a short
	// operator-authored document; anything larger is either a mistake or an
	// attempt to make the parser the interesting part of the run.
	maxScopeFileBytes = 256 << 10
	// maxAttestationFileBytes bounds the attestation file, which is smaller
	// still — seven fields.
	maxAttestationFileBytes = 32 << 10
	// maxScopeEntries bounds each of the allow and deny lists.
	maxScopeEntries = 1024
	// maxPortsPerEntry bounds one entry's port list.
	maxPortsPerEntry = 256
	// maxJSONDepth bounds nesting. The schemas below are three deep; eight
	// leaves room without leaving the parser open to a document whose only
	// content is structure.
	maxJSONDepth = 8
	// maxRepositoryLen and maxActorLen bound the two identifiers gate 7
	// compares. Both reach a GateFailure's Evidence.
	maxRepositoryLen = 200
	maxActorLen      = 100
)

// ScopeFileSchemaVersion is the only scope-file schema version this build
// implements. A file declaring any other version is REFUSED rather than
// best-effort parsed: "written for a schema we do not implement" is exactly
// the case where guessing produces a scope that means something other than
// what its author wrote.
const ScopeFileSchemaVersion = 1

// AttestationFileSchemaVersion is the only attestation schema version this
// build implements, for the same reason.
const AttestationFileSchemaVersion = 1

// ---------------------------------------------------------------------------
// redactUntrusted — the one channel from a parsed document to a message
// ---------------------------------------------------------------------------

// redactUntrusted renders a value taken from an untrusted document safely
// enough to appear in a GateFailure's Evidence.
//
// The charset is an ALLOWLIST — the characters a canonical hostname, a port
// list or an attestation identifier can legitimately contain — and everything
// else becomes '?'. A denylist of dangerous characters would have to
// anticipate every encoding trick that might reach an agent's prompt through
// the audit log (the spine's safety section); an allowlist has to anticipate nothing.
// The result is also truncated, because length is its own payload.
func redactUntrusted(s string) string {
	const max = 64
	truncated := false
	if len(s) > max {
		s = s[:max]
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

// ---------------------------------------------------------------------------
// STRICT JSON — the three things DisallowUnknownFields does not cover
// ---------------------------------------------------------------------------

// decodeStrict decodes exactly one JSON document from raw into v.
//
// "Strictly" means four separate refusals, because encoding/json on its own
// gives only the first:
//
//  1. unknown fields (json.Decoder.DisallowUnknownFields);
//  2. DUPLICATE KEYS. encoding/json silently takes the last one, so
//     `{"mode":"lab","mode":"external"}` decodes to "external" with no error.
//     A scope file is an operator's statement about what may be probed; a
//     document with two answers to one question has not made a statement, and
//     "last one wins" is a smuggling channel;
//  3. trailing content after the document, which is how a second document
//     rides along behind the first;
//  4. nesting deeper than maxJSONDepth.
//
// The returned error is Anvil-authored per case by the caller; this function's
// own error text is used only to pick the Reason, never to build a Detail.
func decodeStrict(raw []byte, v any) (Reason, error) {
	if err := checkJSONStructure(raw); err != nil {
		return jsonStructureReason(err), err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return ReasonScopeFileUnknownField, err
		}
		return ReasonScopeFileUnparseable, err
	}
	if dec.More() {
		return ReasonScopeFileTrailingBytes, errors.New("trailing content after the document")
	}
	// A decoder that consumed the value but has bytes left that are not
	// another value (a stray "]" say) still has to be rejected.
	if _, err := dec.Token(); err != nil && !errors.Is(err, io.EOF) {
		return ReasonScopeFileTrailingBytes, err
	}
	return ReasonUnspecified, nil
}

// errDuplicateKey and errTooDeep are the two structural refusals
// checkJSONStructure raises on its own.
var (
	errDuplicateKey = errors.New("duplicate object key")
	errTooDeep      = errors.New("document nests too deeply")
)

func jsonStructureReason(err error) Reason {
	switch {
	case errors.Is(err, errDuplicateKey):
		return ReasonScopeFileDuplicateKey
	default:
		return ReasonScopeFileUnparseable
	}
}

// checkJSONStructure walks the document's token stream looking for duplicate
// object keys and excessive nesting.
//
// It is a second pass over the bytes rather than a hook inside the decode,
// because encoding/json exposes no hook. The document is bounded above by
// maxScopeFileBytes, so a second pass is cheap.
func checkJSONStructure(raw []byte) error {
	type frame struct {
		object    bool
		expectKey bool
		seen      map[string]struct{}
	}
	var stack []*frame

	consumedValue := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack) >= maxJSONDepth {
					return errTooDeep
				}
				f := &frame{object: d == '{'}
				if f.object {
					f.expectKey = true
					f.seen = map[string]struct{}{}
				}
				stack = append(stack, f)
			case '}', ']':
				if len(stack) == 0 {
					return errors.New("unbalanced delimiter")
				}
				stack = stack[:len(stack)-1]
				consumedValue()
			}
			continue
		}
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
			key, ok := tok.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, dup := stack[n-1].seen[key]; dup {
				return fmt.Errorf("%w: %s", errDuplicateKey, redactUntrusted(key))
			}
			stack[n-1].seen[key] = struct{}{}
			stack[n-1].expectKey = false
			continue
		}
		consumedValue()
	}
	if len(stack) != 0 {
		return errors.New("document ended inside an object or array")
	}
	return nil
}

// ---------------------------------------------------------------------------
// GATE 4 — the scope file
// ---------------------------------------------------------------------------

// scopeDocument is the on-disk scope-file schema.
//
// Every field that must be PRESENT is a pointer, so "absent" and "present but
// zero" are different states. A scope file that forgot to say which mode it is
// for has not said `lab`; it has said nothing, and gate 4 refuses it.
//
// allow and deny are plain slices because absent, null and [] all mean the
// same legal thing: zero entries, and therefore zero permitted targets.
// research/20 gate 4 is explicit that this is a valid scope file and not an
// error — "an empty, missing, malformed, or unknown-field scope file yields
// zero permitted targets, never 'allow all'" — so an empty allow list must
// produce a Scope that refuses everything, not a refusal to load.
type scopeDocument struct {
	SchemaVersion *int            `json:"schema_version"`
	Mode          *string         `json:"mode"`
	Allow         []scopeEntryDoc `json:"allow"`
	Deny          []scopeEntryDoc `json:"deny"`
}

type scopeEntryDoc struct {
	Host  *string `json:"host"`
	Ports []int64 `json:"ports"`
}

// ScopeHashOf is the scope hash gate 5 binds an attestation to: the SHA-256 of
// the scope file's EXACT BYTES, lowercase hex.
//
// It hashes the bytes, not the parsed document, and that is the whole point.
// A hash over the parsed form would be equal for two files that differ in
// whitespace, key order or a comment, and "editing scope silently invalidates
// the attestation" (research/20 gate 5) would stop being true for exactly the
// edits an attacker would prefer.
//
// It is the ONLY producer of a ScopeHash that any Scope carries: sealScope
// calls it on the bytes gate 4 just parsed, and there is no path on which a
// caller supplies a hash of its own. The kernel-types review raised the earlier shape,
// where NewScope took an asserted hash and never saw the bytes.
func ScopeHashOf(raw []byte) ScopeHash {
	sum := sha256.Sum256(raw)
	return ScopeHash(hex.EncodeToString(sum[:]))
}

// LoadScopeFile is gate 4's "scope file EXISTS" half: it reads the file at
// path and hands the bytes to CheckGate4ScopeFile.
//
// A missing file, an unreadable file, an empty path and a path naming a
// directory all REFUSE. None of them is "no scope restrictions".
func LoadScopeFile(path string, decl ModeDeclaration) (Scope, GateResult) {
	raw, reason, err := readBoundedFile(path, maxScopeFileBytes,
		ReasonScopeFileMissing, ReasonScopeFileUnreadable, ReasonScopeFileTooLarge)
	if err != nil {
		return Scope{}, gateFailed(Gate4ScopeFile, reason,
			"the scope file could not be read, and gate 4 treats an unreadable scope file "+
				"exactly as it treats a malformed one: zero permitted targets. There is "+
				"no path on which a missing scope file means 'no restrictions'.",
			"path: "+redactUntrusted(path),
			"read error class: "+string(reason))
	}
	return CheckGate4ScopeFile(raw, decl)
}

// CheckGate4ScopeFile is gate 4: the scope file parses strictly, is
// schema-valid, and yields zero permitted targets on anything malformed.
//
// It returns the constructed Scope and a passing GateResult, or the zero Scope
// — which permits nothing, by types.go's one rule — and the typed failure.
// There is no third outcome and no partial parse: a scope file that was 90%
// readable produces no Scope at all, because the 10% that did not parse is
// exactly where a deny entry would have been.
//
// # The caller's bytes are read exactly once
//
// An earlier shape read the caller's slice TWICE: decodeStrict parsed it, and
// then sealScope hashed it with ScopeHashOf. The build-time guard's review demonstrated the gap
// between the two reads in a scratch module — two same-length scope documents,
// 1000 entries so that the decode takes about 1.4ms, one goroutine calling
// NewScope while another rewrote the buffer — and produced a Scope whose
// ENTRIES permitted *.evil.example.com while its HASH was the benign
// document's.
//
// That is not a tidiness bug. Gate 5 binds an attestation to the scope hash,
// and that binding is the whole reason an attestation is specific to a SCOPE
// rather than merely to a session: "editing the scope file invalidates the
// attestation" (research/20 gate 5) is only true while the hash is a hash of
// the entries. A Scope carrying one document's entries under another
// document's hash defeats it exactly.
//
// So the bytes are copied ONCE, here, and everything downstream — the strict
// parse and ScopeHashOf alike — reads the copy. A concurrent writer can still
// tear the copy, and the copy is then simply a different document; what it
// cannot do is put the parse and the hash on opposite sides of a write.
//
// # The two guards, and which lane each runs in
//
// TestGate4ReadsTheCallersScopeBytesExactlyOnce (phase1_run_test.go) parses
// this file and asserts the SOURCE-LEVEL property: the parameter is rebound to
// a copy of itself before any use of it other than len. It runs in every lane,
// including -race, because it starts no goroutines. It carries five positive
// controls, one of which is `rawAlias := raw[:]` — the one-line mutation that
// defeated the earlier, denylist-shaped version of the same analysis.
//
// TestScopeBytesAreReadOnceUnderAConcurrentWriter
// (phase1_scopebytes_race_test.go) is the BEHAVIOURAL regression: a goroutine
// rewriting the caller's buffer while this function runs, asserting that every
// constructed Scope's entries and hash came from one document. Measured: 0 of
// 200 on this tree, 89 of 200 with the copy deleted, 102 of 200 with the copy
// replaced by that alias.
//
// That second one is built `!race` AND THAT IS NOT A HEDGE — it is what the
// harness is. Racing the caller's buffer is the only way to make one read of
// it differ from another, so the harness is a data race by construction, and
// `go test -race` reports it against THIS FILE'S COPY on a correct build. It
// therefore cannot run in the -race lane without failing a correct tree.
// Recorded in internal/SKIPPED-CONTROLS.md as G4-1, with the literal race
// report.
func CheckGate4ScopeFile(raw []byte, decl ModeDeclaration) (Scope, GateResult) {
	// ONE guard, not two. An earlier draft checked decl.Declared() first and
	// decl.Mode()'s error second. Declared() is true exactly when Mode()
	// returns no error, so the second branch could never be the only thing
	// refusing anything: a mutation deleting the first stayed green. The
	// subsumed branch is gone rather than commented, and its message is
	// folded in here.
	declared, err := decl.Mode()
	if err != nil {
		return Scope{}, gateFailed(Gate4ScopeFile, ReasonScopeNoDeclaration,
			"a scope file is loaded FOR a declared mode, and no mode was declared by "+
				"DeclareMode. Gate 6 has no default and no `auto`, so there is nothing "+
				"to load this scope file as.")
	}
	if len(raw) == 0 {
		return Scope{}, gateFailed(Gate4ScopeFile, ReasonScopeFileUnparseable,
			"the scope file is empty. Zero bytes is not a JSON document, and gate 4 does "+
				"not read 'the operator wrote nothing' as 'the operator permitted "+
				"everything'.")
	}
	if len(raw) > maxScopeFileBytes {
		return Scope{}, gateFailed(Gate4ScopeFile, ReasonScopeFileTooLarge,
			fmt.Sprintf("the scope file is larger than the coded bound of %d bytes.",
				maxScopeFileBytes),
			fmt.Sprintf("size: %d bytes", len(raw)))
	}

	// THE ONE READ. Everything below — decodeStrict and, through sealScope,
	// ScopeHashOf — sees this copy and never the caller's slice again, so the
	// entries and the hash come from one document. The two length checks above
	// read only the slice HEADER, which is already a copy and cannot be
	// changed by a writer holding the same backing array.
	raw = append([]byte(nil), raw...)

	var doc scopeDocument
	if reason, err := decodeStrict(raw, &doc); err != nil {
		reason = retargetReason(reason, Gate4ScopeFile)
		return Scope{}, gateFailed(Gate4ScopeFile, reason, strictParseDetail(reason,
			"scope file"))
	}

	if doc.SchemaVersion == nil {
		return Scope{}, gateFailed(Gate4ScopeFile, ReasonScopeFileSchemaVersion,
			"the scope file declares no schema_version. A document that will not say which "+
				"schema it was written against cannot be checked against one.")
	}
	if *doc.SchemaVersion != ScopeFileSchemaVersion {
		return Scope{}, gateFailed(Gate4ScopeFile, ReasonScopeFileSchemaVersion,
			fmt.Sprintf("the scope file declares a schema_version this build does not "+
				"implement. This build implements version %d only, and a file written "+
				"for another version is refused rather than best-effort parsed.",
				ScopeFileSchemaVersion),
			fmt.Sprintf("declared schema_version: %d", *doc.SchemaVersion))
	}
	if doc.Mode == nil {
		return Scope{}, gateFailed(Gate4ScopeFile, ReasonScopeFileModeMismatch,
			"the scope file names no mode. A scope file states which mode its entries were "+
				"written for, so that loading a lab scope under `external` is a refusal "+
				"and not a surprise.")
	}
	fileMode, err := ParseMode(*doc.Mode)
	if err != nil {
		return Scope{}, gateFailed(Gate4ScopeFile, ReasonScopeFileModeMismatch,
			"the scope file's mode is not one of the two modes. There is no `auto`.",
			"mode as written: "+redactUntrusted(*doc.Mode))
	}
	if fileMode != declared {
		return Scope{}, gateFailed(Gate4ScopeFile, ReasonScopeFileModeMismatch,
			fmt.Sprintf("the run declares mode %q and this scope file was written for mode "+
				"%q. The two are not reconciled; the run is refused, because a scope "+
				"authored for loopback targets means something different when it is "+
				"loaded against the public internet.", declared, fileMode))
	}

	allow, res := scopeEntriesFromDoc(doc.Allow, "allow")
	if !res.Passed() {
		return Scope{}, res
	}
	deny, res := scopeEntriesFromDoc(doc.Deny, "deny")
	if !res.Passed() {
		return Scope{}, res
	}

	scope, err := sealScope(raw, decl, allow, deny)
	if err != nil {
		return Scope{}, gateFailed(Gate4ScopeFile, ReasonScopeFileSchemaInvalid,
			"the kernel's own scope-entry schema rejected this file. The offending value is "+
				"not reproduced here: a scope file is `anvil/trust: untrusted` input "+
				"(the spine's record section) and a GateFailure's Detail is Anvil-authored text.",
			"entry rejected at: "+redactUntrusted(err.Error()))
	}
	return scope, gatePassed(Gate4ScopeFile)
}

// scopeEntriesFromDoc turns the document's entries into ScopeEntry values.
//
// Each entry is built with a FRESHLY ALLOCATED ports slice, so nothing outside
// this function ever holds a reference to the backing array. sealScope
// deep-copies again on the way in and AllowEntries/DenyEntries deep-copy on the
// way out; between them, the kernel-types review's aliasing finding is closed on every path a
// Ports array can travel.
func scopeEntriesFromDoc(entries []scopeEntryDoc, list string) ([]ScopeEntry, GateResult) {
	if len(entries) > maxScopeEntries {
		return nil, gateFailed(Gate4ScopeFile, ReasonScopeFileSchemaInvalid,
			fmt.Sprintf("the %s list has more entries than the coded bound of %d.",
				list, maxScopeEntries),
			fmt.Sprintf("entries: %d", len(entries)))
	}
	out := make([]ScopeEntry, 0, len(entries))
	for i, e := range entries {
		where := fmt.Sprintf("%s[%d]", list, i)
		if e.Host == nil {
			return nil, gateFailed(Gate4ScopeFile, ReasonScopeFileSchemaInvalid,
				"a scope entry names no host.", "at: "+where)
		}
		if len(e.Ports) == 0 {
			// An entry with no ports covers nothing (types.go: "AN EMPTY
			// SLICE COVERS NOTHING"). For an ALLOW entry that is a
			// harmless no-op; for a DENY entry it is a deny that
			// silently is not there. Refusing the whole file is the only
			// answer that is loud in both cases.
			return nil, gateFailed(Gate4ScopeFile, ReasonScopeFileSchemaInvalid,
				"a scope entry lists no ports. An empty port list covers nothing, which "+
					"would make a deny entry vanish silently, so the file is refused "+
					"rather than loaded with an entry that cannot match.",
				"at: "+where, "host: "+redactUntrusted(*e.Host))
		}
		if len(e.Ports) > maxPortsPerEntry {
			return nil, gateFailed(Gate4ScopeFile, ReasonScopeFileSchemaInvalid,
				fmt.Sprintf("a scope entry lists more ports than the coded bound of %d.",
					maxPortsPerEntry),
				"at: "+where)
		}
		ports := make([]uint16, 0, len(e.Ports))
		for _, p := range e.Ports {
			if p < 1 || p > 65535 {
				return nil, gateFailed(Gate4ScopeFile, ReasonScopeFileSchemaInvalid,
					"a scope entry lists a value that is not a TCP port. Port 0 is not a "+
						"port and neither is anything above 65535.",
					"at: "+where, fmt.Sprintf("value: %d", p))
			}
			ports = append(ports, uint16(p))
		}
		out = append(out, ScopeEntry{Host: *e.Host, Ports: ports})
	}
	return out, gatePassed(Gate4ScopeFile)
}

// ---------------------------------------------------------------------------
// GATE 5 — the attestation
// ---------------------------------------------------------------------------

// attestationDocument is the on-disk attestation schema. research/20 gate 5's
// required fields, one for one: attesting identity, the authority under which
// they attest, the exact scope-file content hash, an issue timestamp and an
// expiry.
//
// The timestamps are time.Time, so encoding/json requires RFC 3339 with an
// explicit offset. "2026-08-01" does not decode, which is the fail-closed
// direction: a date with no time and no zone is three different instants.
type attestationDocument struct {
	SchemaVersion *int       `json:"schema_version"`
	ID            *string    `json:"id"`
	Identity      *string    `json:"identity"`
	Authority     *string    `json:"authority"`
	ScopeHash     *string    `json:"scope_hash"`
	IssuedAt      *time.Time `json:"issued_at"`
	ExpiresAt     *time.Time `json:"expires_at"`
}

// AttestationCeilingFromConfig turns a configured maximum attestation lifetime
// into an AttestationCeiling, and is the ONLY function in Anvil that a config
// value may reach on its way to becoming one.
//
// plan/design/dynamic-tier.md gate 5: the expiry ceiling "may be lowered from the 30-day
// recommended default; presence/validity checking is not optional". "Lower
// only" is encoded structurally rather than checked politely:
//
//	DefaultAttestationCeiling().Lower(configured)
//
// starts at the coded MaxAttestationLifetime and can only go down. There is no
// argument to this function that produces a ceiling above 30 days, because
// Cap.Lower refuses one with ErrCapRaise. A caller who wants a longer window
// has to edit MaxAttestationLifetime in types.go — a const, in the kernel's
// vocabulary file, in a diff whose whole subject is lengthening it.
//
// Zero REFUSES rather than defaulting. A configuration that did not state a
// ceiling has not chosen the coded maximum; it has said nothing, and this
// package does not read silence as a choice. Callers that want the coded
// default pass MaxAttestationLifetime explicitly.
func AttestationCeilingFromConfig(configured time.Duration) (AttestationCeiling, GateResult) {
	if configured <= 0 {
		return AttestationCeiling{}, gateFailed(Gate5Attestation, ReasonAttestationLifetimeTooLong,
			fmt.Sprintf("no attestation lifetime ceiling was configured. Pass "+
				"MaxAttestationLifetime (%s) for the coded default or a shorter "+
				"duration; a zero or negative ceiling is not read as 'use the "+
				"default'.", MaxAttestationLifetime),
			fmt.Sprintf("configured: %s", configured))
	}
	ceiling, err := DefaultAttestationCeiling().Lower(configured)
	if err != nil {
		return AttestationCeiling{}, gateFailed(Gate5Attestation, ReasonAttestationCeilingRaised,
			fmt.Sprintf("the configured attestation lifetime ceiling is longer than the "+
				"coded ceiling of %s. Configuration may only LOWER a coded cap. No "+
				"config key, environment variable, CLI flag or model-authored value "+
				"raises this one.", MaxAttestationLifetime),
			fmt.Sprintf("configured: %s", configured),
			fmt.Sprintf("coded ceiling: %s", MaxAttestationLifetime))
	}
	return ceiling, gatePassed(Gate5Attestation)
}

// LoadAttestationFile is gate 5's "attestation PRESENT" half.
func LoadAttestationFile(path string, scope Scope, clock Clock, ceiling AttestationCeiling) (Attestation, GateResult) {
	raw, reason, err := readBoundedFile(path, maxAttestationFileBytes,
		ReasonAttestationFileMissing, ReasonAttestationFileUnreadable,
		ReasonAttestationFileTooLarge)
	if err != nil {
		return Attestation{}, gateFailed(Gate5Attestation, reason,
			"the attestation file could not be read. Gate 5 refuses to probe any target "+
				"Anvil does not itself own without a live attestation, and a file that "+
				"is not there is not one.",
			"path: "+redactUntrusted(path),
			"read error class: "+string(reason))
	}
	return CheckGate5Attestation(raw, scope, clock, ceiling)
}

// CheckGate5Attestation is gate 5: an affirmative attestation, present, valid,
// unexpired, and bound to THIS scope's hash.
//
// The scope-hash binding is the reason this function takes the Scope rather
// than a hash: the hash it compares against is the one the Scope was built
// with, which CheckGate4ScopeFile computed from the scope file's bytes. Edit
// one byte of the scope file and the hash changes and this function refuses.
// That is research/20 gate 5's "the attestation covers the scope hash, so
// editing scope silently invalidates it", made loud.
func CheckGate5Attestation(raw []byte, scope Scope, clock Clock, ceiling AttestationCeiling) (Attestation, GateResult) {
	if !scope.Constructed() {
		return Attestation{}, gateFailed(Gate5Attestation, ReasonScopeUnconstructed,
			"gate 5 was handed a Scope that gate 4 never produced. An attestation is bound "+
				"to a specific scope, so there is nothing here to bind it to.")
	}
	if !clock.Valid() {
		return Attestation{}, gateFailed(Gate5Attestation, ReasonClockUnconstructed,
			"gate 5 was handed a Clock that NewClock never minted. Expiry is measured "+
				"against it, and an unset clock makes every attestation look either "+
				"eternal or expired depending on which way the comparison runs.")
	}
	if _, err := ceiling.Effective(); err != nil {
		return Attestation{}, gateFailed(Gate5Attestation, ReasonAttestationLifetimeTooLong,
			"gate 5 was handed a lifetime ceiling that was never declared. An undeclared "+
				"Cap permits no lifetime at all, which is the fail-closed direction; "+
				"build one with AttestationCeilingFromConfig.")
	}
	if len(raw) == 0 {
		return Attestation{}, gateFailed(Gate5Attestation, ReasonAttestationUnparseable,
			"the attestation file is empty. Gate 5 requires an AFFIRMATIVE record; zero "+
				"bytes is not one.")
	}
	if len(raw) > maxAttestationFileBytes {
		return Attestation{}, gateFailed(Gate5Attestation, ReasonAttestationFileTooLarge,
			fmt.Sprintf("the attestation file is larger than the coded bound of %d bytes.",
				maxAttestationFileBytes),
			fmt.Sprintf("size: %d bytes", len(raw)))
	}

	var doc attestationDocument
	if reason, err := decodeStrict(raw, &doc); err != nil {
		reason = retargetReason(reason, Gate5Attestation)
		return Attestation{}, gateFailed(Gate5Attestation, reason,
			strictParseDetail(reason, "attestation file"))
	}

	if doc.SchemaVersion == nil || *doc.SchemaVersion != AttestationFileSchemaVersion {
		return Attestation{}, gateFailed(Gate5Attestation, ReasonAttestationSchemaVersion,
			fmt.Sprintf("the attestation file declares no schema_version, or one this build "+
				"does not implement. This build implements version %d only.",
				AttestationFileSchemaVersion))
	}
	missing := []string{}
	if doc.ID == nil {
		missing = append(missing, "id")
	}
	if doc.Identity == nil {
		missing = append(missing, "identity")
	}
	if doc.Authority == nil {
		missing = append(missing, "authority")
	}
	if doc.ScopeHash == nil {
		missing = append(missing, "scope_hash")
	}
	if doc.IssuedAt == nil {
		missing = append(missing, "issued_at")
	}
	if doc.ExpiresAt == nil {
		missing = append(missing, "expires_at")
	}
	if len(missing) > 0 {
		return Attestation{}, gateFailed(Gate5Attestation, ReasonAttestationSchemaInvalid,
			"the attestation file omits a field research/20 gate 5 lists as required. Every "+
				"one of them is required; an attestation missing any of them cannot say "+
				"who authorised what, over which scope, for how long.",
			"missing: "+strings.Join(missing, ", "))
	}

	authority := AttestationAuthority(*doc.Authority)
	if !authority.Valid() {
		return Attestation{}, gateFailed(Gate5Attestation, ReasonAttestationAuthorityUnknown,
			fmt.Sprintf("the attestation's authority is not one of the four research/20 "+
				"gate 5 permits (%q, %q, %q, %q). It is an allowlist: an authority "+
				"nobody enumerated is not a weaker authority, it is no authority.",
				AuthorityOwner, AuthorityOperator, AuthorityWrittenEngagement,
				AuthorityPublishedVDP),
			"authority as written: "+redactUntrusted(*doc.Authority))
	}

	// THE BINDING. Compared before construction so that a scope edit is
	// reported as a scope edit rather than as some downstream validation
	// failure.
	if ScopeHash(*doc.ScopeHash) != scope.Hash() {
		return Attestation{}, gateFailed(Gate5Attestation, ReasonScopeAttestationMismatch,
			"this attestation is bound to a different scope hash than the scope file that "+
				"was loaded. Gate 5 binds an attestation to the SHA-256 of the scope "+
				"file's exact bytes precisely so that editing the scope file "+
				"invalidates it. Re-attest against the edited scope; do not edit the "+
				"hash.",
			"attestation names: "+redactUntrusted(*doc.ScopeHash),
			"scope file hashes to: "+string(scope.Hash()))
	}

	att, err := NewAttestation(
		AttestationID(*doc.ID),
		*doc.Identity,
		authority,
		scope.Hash(),
		*doc.IssuedAt,
		*doc.ExpiresAt,
		ceiling,
	)
	if err != nil {
		reason := ReasonAttestationSchemaInvalid
		if errors.Is(err, ErrRefused) && doc.ExpiresAt.Sub(*doc.IssuedAt) > 0 &&
			!ceiling.Allows(doc.ExpiresAt.Sub(*doc.IssuedAt)) {
			reason = ReasonAttestationLifetimeTooLong
		}
		eff, _ := ceiling.Effective()
		return Attestation{}, gateFailed(Gate5Attestation, reason,
			"the kernel's attestation constructor refused this record. The offending value "+
				"is not reproduced here: an attestation file is `anvil/trust: "+
				"untrusted` input.",
			fmt.Sprintf("validity window as written: %s", doc.ExpiresAt.Sub(*doc.IssuedAt)),
			fmt.Sprintf("effective ceiling: %s", eff),
			fmt.Sprintf("coded ceiling: %s", MaxAttestationLifetime))
	}

	if res := checkAttestationLiveness(att, clock); !res.Passed() {
		return Attestation{}, res
	}
	return att, gatePassed(Gate5Attestation)
}

// checkAttestationLiveness separates "not yet valid" from "expired" so that an
// operator reading the audit can tell a clock-skew problem from a stale
// attestation. Attestation.Live collapses both into false, which is right for
// a predicate and wrong for a message.
func checkAttestationLiveness(att Attestation, clock Clock) GateResult {
	if !att.Constructed() {
		return gateFailed(Gate5Attestation, ReasonAttestationUnconstructed,
			"the attestation was not built by NewAttestation.")
	}
	if !clock.Valid() {
		return gateFailed(Gate5Attestation, ReasonClockUnconstructed,
			"the clock was not built by NewClock.")
	}
	now := clock.Instant()
	if now.Before(att.issuedAt) {
		return gateFailed(Gate5Attestation, ReasonAttestationNotYetValid,
			"the attestation's issue timestamp is in the future at the run's instant. A "+
				"record that has not been issued yet has not authorised anything yet.",
			"issued at:  "+att.issuedAt.UTC().Format(time.RFC3339),
			"run instant: "+now.UTC().Format(time.RFC3339))
	}
	if !now.Before(att.expiresAt) {
		return gateFailed(Gate5Attestation, ReasonAttestationExpired,
			"the attestation has expired at the run's instant. Gate 5 requires a LIVE "+
				"attestation; there is no grace period, because a grace period is a "+
				"configurable expiry with a friendlier name.",
			"expired at:  "+att.expiresAt.UTC().Format(time.RFC3339),
			"run instant: "+now.UTC().Format(time.RFC3339))
	}
	// There is deliberately no third `if !att.Live(clock)` branch here. It
	// would be subsumed by the two above — Attestation.Live is exactly
	// "constructed, valid clock, not before issuedAt, before expiresAt" —
	// and a mutation deleting either boundary check stayed GREEN against it,
	// because the fallback refused with the same Reason. The property the
	// fallback was gesturing at, that this function cannot disagree with the
	// kernel's own predicate, is demonstrated instead by
	// TestGate5AgreesWithTheKernelsLivenessPredicate, which sweeps the
	// window boundaries and compares the two answers.
	return gatePassed(Gate5Attestation)
}

// ---------------------------------------------------------------------------
// GATE 6 — the mode declaration
// ---------------------------------------------------------------------------

// CheckGate6ModeDeclaration is gate 6: the run's mode is declared explicitly,
// once, and is one of exactly two values.
//
// There is no `auto` here and there is no sentinel that behaves like one. The
// input is not trimmed, lowercased or otherwise repaired, because a
// declaration that needed repairing was not explicit — " external\n" is a
// configuration bug, and reading it as `external` is how a run ends up
// probing the public internet because a YAML file had a trailing space.
//
// # Irreversibility, and what actually enforces it
//
// The kernel-types review was right that nothing in the kernel ties a run to one
// declaration, because there is no run object for it to be irreversible
// within. What this file adds is a chain of bindings that makes a second,
// different declaration detectable rather than a claim in a comment:
//
//	the mode is a FIELD OF THE SCOPE FILE     (scopeDocument.Mode)
//	the scope hash is over the scope file's EXACT BYTES  (ScopeHashOf)
//	the attestation is bound to that hash     (CheckGate5Attestation)
//
// So changing the run's mode means changing the scope file, which changes its
// hash, which invalidates the attestation. A run cannot be re-declared into
// the other mode while holding the same attestation, and the audit row — keyed
// on attestation ID and scope hash — records which pair was in force.
// TestModeCannotBeChangedWithoutReattesting is the demonstration.
func CheckGate6ModeDeclaration(declared string) (ModeDeclaration, GateResult) {
	mode, err := ParseMode(declared)
	if err != nil {
		reason := ReasonModeUnknown
		if declared == "" {
			reason = ReasonModeNotDeclared
		}
		return ModeDeclaration{}, gateFailed(Gate6ModeDeclaration, reason,
			"the run's mode was not declared as exactly \"lab\" or \"external\". Gate 6 has "+
				"no default, no `auto`, and does not repair its input: inferring "+
				"lab-versus-external from the target is precisely the inference the "+
				"authorization kernel exists to refuse to make.",
			"declared as: "+redactUntrusted(declared))
	}
	decl, err := DeclareMode(mode)
	if err != nil {
		return ModeDeclaration{}, gateFailed(Gate6ModeDeclaration, ReasonModeUnknown,
			"the kernel refused to record this mode declaration.")
	}
	return decl, gatePassed(Gate6ModeDeclaration)
}

// ---------------------------------------------------------------------------
// GATE 7 — trigger provenance
// ---------------------------------------------------------------------------

// TriggerEvent names the event that started the run.
//
// The zero value names no event and is refused. Every constant here is a token
// this package RECOGNISES; recognising a token is not the same as permitting
// it, and the two sets are deliberately different sizes (see
// policyEligibleEvents).
type TriggerEvent string

// The recognised events. Everything else refuses as unknown — an event nobody
// enumerated is not a safe event, it is an unaudited one.
const (
	// TriggerEventUnset is the zero value and names no event.
	TriggerEventUnset TriggerEvent = ""

	// --- eligible: a policy MAY permit these ---

	// TriggerEventManualOperator is a human at a terminal. It is not a CI
	// event and has no CI principal; see PermissionSourceOperatorLocal.
	TriggerEventManualOperator TriggerEvent = "manual_operator"
	// TriggerEventWorkflowDispatch is GitHub's `workflow_dispatch`.
	// Dispatching requires write access to the repository.
	TriggerEventWorkflowDispatch TriggerEvent = "workflow_dispatch"
	// TriggerEventSchedule is GitHub's `schedule`. It runs from the default
	// branch and carries no outside-contributor input.
	TriggerEventSchedule TriggerEvent = "schedule"
	// TriggerEventPush is GitHub's `push`. Pushing requires write access.
	// It is eligible but is NOT in DefaultTriggerPolicy: landing code should
	// not, by default, launch a probe of somebody else's host.
	TriggerEventPush TriggerEvent = "push"

	// --- recognised and NEVER eligible ---

	// TriggerEventPullRequest is GitHub's `pull_request`. On a fork PR the
	// head is written by an outside contributor.
	TriggerEventPullRequest TriggerEvent = "pull_request"
	// TriggerEventPullRequestTarget is GitHub's `pull_request_target`: a
	// workflow that runs with the BASE repository's secrets and write token
	// while evaluating a pull request whose head an outside contributor
	// controls. It is the canonical CI privilege-escalation path and this
	// package will not run under it.
	TriggerEventPullRequestTarget TriggerEvent = "pull_request_target"
	// TriggerEventIssueComment is GitHub's `issue_comment` — the "/scan"
	// comment-bot pattern, where the trigger text is written by anyone who
	// can comment.
	TriggerEventIssueComment TriggerEvent = "issue_comment"
	// TriggerEventRepositoryDispatch carries a caller-supplied
	// client_payload.
	TriggerEventRepositoryDispatch TriggerEvent = "repository_dispatch"
	// TriggerEventWorkflowRun runs in the base context after another
	// workflow finishes, which launders the privilege of whatever triggered
	// that one.
	TriggerEventWorkflowRun TriggerEvent = "workflow_run"
	// TriggerEventWorkflowCall is a reusable workflow invoked by another
	// workflow, with the same laundering problem.
	TriggerEventWorkflowCall TriggerEvent = "workflow_call"
)

// policyEligibleEvents is the ALLOWLIST of events a TriggerPolicy may contain.
//
// plan/design/dynamic-tier.md gate 7: "Which trigger sources are permitted is
// configurable; whether provenance is checked is not." This constant is where
// that line is drawn. Configuration chooses a SUBSET of this list; it cannot
// add to it, because NewTriggerPolicy refuses to construct a policy naming
// anything else and there is no other constructor.
//
// The events left out are not a denylist bolted on afterwards — they are
// simply not members. That matters: a denylist of dangerous events would have
// to keep pace with every event GitHub adds, and a new event type would arrive
// permitted. Here a new event type arrives unrecognised, which refuses.
//
// Run initiation's forbidden actions name this explicitly: "No relaxation of gate 7's
// provenance check for a documented 'trusted fork' exception." There is no
// argument to NewTriggerPolicy that produces one.
var policyEligibleEvents = []TriggerEvent{
	TriggerEventManualOperator,
	TriggerEventWorkflowDispatch,
	TriggerEventSchedule,
	TriggerEventPush,
}

// recognisedEvents is every token this package can name. It exists so that a
// refusal for `pull_request_target` says "this event is never eligible"
// instead of "unknown event", which is a materially more useful message and
// costs nothing: both refuse.
var recognisedEvents = []TriggerEvent{
	TriggerEventManualOperator,
	TriggerEventWorkflowDispatch,
	TriggerEventSchedule,
	TriggerEventPush,
	TriggerEventPullRequest,
	TriggerEventPullRequestTarget,
	TriggerEventIssueComment,
	TriggerEventRepositoryDispatch,
	TriggerEventWorkflowRun,
	TriggerEventWorkflowCall,
}

// Recognised reports whether e is a token this package knows.
func (e TriggerEvent) Recognised() bool {
	for _, k := range recognisedEvents {
		if e == k {
			return true
		}
	}
	return false
}

// PolicyEligible reports whether a TriggerPolicy may name e. False for the
// zero value and for every never-eligible event.
func (e TriggerEvent) PolicyEligible() bool {
	for _, k := range policyEligibleEvents {
		if e == k {
			return true
		}
	}
	return false
}

// ActorPermission is the permission the triggering principal holds over the
// repository the scope file lives in.
type ActorPermission string

// The permission levels, in GitHub's vocabulary. Only the first three are
// write authority.
const (
	// ActorPermissionUnset is the zero value and is not a permission.
	ActorPermissionUnset ActorPermission = ""
	// ActorPermissionAdmin, ActorPermissionMaintain and
	// ActorPermissionWrite are write authority over the repository.
	ActorPermissionAdmin    ActorPermission = "admin"
	ActorPermissionMaintain ActorPermission = "maintain"
	ActorPermissionWrite    ActorPermission = "write"
	// ActorPermissionTriage, ActorPermissionRead and ActorPermissionNone
	// are not.
	ActorPermissionTriage ActorPermission = "triage"
	ActorPermissionRead   ActorPermission = "read"
	ActorPermissionNone   ActorPermission = "none"
)

// Recognised reports whether p is one of the six levels.
func (p ActorPermission) Recognised() bool {
	switch p {
	case ActorPermissionAdmin, ActorPermissionMaintain, ActorPermissionWrite,
		ActorPermissionTriage, ActorPermissionRead, ActorPermissionNone:
		return true
	}
	return false
}

// IsWriteAuthority reports whether p is write authority. It is an allowlist of
// three, so the zero value and any unrecognised string are both false.
func (p ActorPermission) IsWriteAuthority() bool {
	switch p {
	case ActorPermissionAdmin, ActorPermissionMaintain, ActorPermissionWrite:
		return true
	}
	return false
}

// PermissionSource says HOW the actor's permission was determined, and it is a
// gate in its own right.
//
// In a GitHub Actions run the webhook payload carries fields that look
// authoritative — `github.event.pull_request.author_association`,
// `github.event.sender` — and are written by, or derivable from, the party
// that opened the pull request. A gate that reads permission from the payload
// is checking a claim the attacker supplied. So the payload is a RECOGNISED
// source and it always refuses; only a permission read back from an
// authenticated API call, or an operator running locally, is accepted.
type PermissionSource string

// The permission sources.
const (
	// PermissionSourceUnset is the zero value and refuses.
	PermissionSourceUnset PermissionSource = ""
	// PermissionSourceVerifiedAPI means the permission was read from an
	// authenticated repository-collaborator API call made by Anvil.
	PermissionSourceVerifiedAPI PermissionSource = "verified_api"
	// PermissionSourceOperatorLocal means there is no CI principal because
	// there is no CI: a human ran the binary. It is accepted ONLY for
	// TriggerEventManualOperator.
	PermissionSourceOperatorLocal PermissionSource = "operator_local"
	// PermissionSourceEventPayload means the value came out of the webhook
	// payload. Recognised so the refusal can say why; never accepted.
	PermissionSourceEventPayload PermissionSource = "event_payload"
)

// TriggerFacts is the inert input struct NewTriggerContext validates.
//
// Its fields are exported because target provisioning's CI adapter has to fill them in from
// the environment. That is safe for the same reason ScopeEntry's fields are
// exported: the struct on its own authorises nothing, and the only way its
// contents reach gate 7 is through NewTriggerContext, which validates every
// field.
type TriggerFacts struct {
	// Event is the CI event, or TriggerEventManualOperator for a local run.
	Event TriggerEvent
	// Repository is the repository the workflow ran in, "owner/name".
	Repository string
	// HeadRepository is the repository the changes came from, "owner/name".
	// Empty for events that have no head repository (schedule, dispatch, a
	// local run). If it is set and differs from Repository, the run is a
	// FORK run and is refused.
	HeadRepository string
	// Actor is the principal that triggered the run.
	Actor string
	// ActorPermission is that principal's permission over Repository.
	ActorPermission ActorPermission
	// PermissionSource is how ActorPermission was determined.
	PermissionSource PermissionSource
}

// TriggerContext is a validated trigger provenance record.
//
// Unexported fields, no setters: the zero value describes no trigger and gate
// 7 refuses it, and a composite literal in another package will not compile.
type TriggerContext struct {
	event      TriggerEvent
	repository string
	headRepo   string
	actor      string
	permission ActorPermission
	source     PermissionSource
	sealed     bool
}

// NewTriggerContext validates the facts target provisioning measured about the trigger.
//
// It validates SHAPE only — that the event is a token this package recognises,
// that the repository names are well formed, that the permission and its
// source are recognised values. Whether those facts are ACCEPTABLE is
// CheckGate7TriggerProvenance's question, and keeping the two apart is what
// lets the gate refuse a perfectly well-formed fork-PR context with a message
// that says "fork" instead of "malformed".
func NewTriggerContext(f TriggerFacts) (TriggerContext, error) {
	if !f.Event.Recognised() {
		if f.Event == TriggerEventUnset {
			return TriggerContext{}, fmt.Errorf("trigger: %w: no trigger event was "+
				"recorded. Gate 7 checks the provenance of every run; a run that "+
				"cannot say how it started has no provenance to check", ErrRefused)
		}
		return TriggerContext{}, fmt.Errorf("trigger: %w: %q is not an event this build "+
			"recognises. The recognised set is an allowlist, so a new or unenumerated "+
			"event refuses rather than arriving permitted", ErrRefused,
			redactUntrusted(string(f.Event)))
	}
	if err := validateRepositoryName(f.Repository, "repository"); err != nil {
		return TriggerContext{}, err
	}
	if f.HeadRepository != "" {
		if err := validateRepositoryName(f.HeadRepository, "head repository"); err != nil {
			return TriggerContext{}, err
		}
	}
	if err := validateActorName(f.Actor); err != nil {
		return TriggerContext{}, err
	}
	if !f.ActorPermission.Recognised() {
		return TriggerContext{}, fmt.Errorf("trigger: %w: %q is not one of the six "+
			"repository permission levels. An unrecognised permission is not a low "+
			"one, it is an unmeasured one", ErrRefused,
			redactUntrusted(string(f.ActorPermission)))
	}
	switch f.PermissionSource {
	case PermissionSourceVerifiedAPI, PermissionSourceOperatorLocal, PermissionSourceEventPayload:
		// Recognised. Whether it is ACCEPTED is gate 7's call.
	default:
		return TriggerContext{}, fmt.Errorf("trigger: %w: %q is not a permission source "+
			"this build recognises. Gate 7 needs to know HOW the actor's permission was "+
			"determined, because a permission read out of a webhook payload is a claim "+
			"the payload's author made", ErrRefused,
			redactUntrusted(string(f.PermissionSource)))
	}
	return TriggerContext{
		event:      f.Event,
		repository: f.Repository,
		headRepo:   f.HeadRepository,
		actor:      f.Actor,
		permission: f.ActorPermission,
		source:     f.PermissionSource,
		sealed:     true,
	}, nil
}

// Constructed reports whether this context came from NewTriggerContext.
func (t TriggerContext) Constructed() bool { return t.sealed && t.event.Recognised() }

// Event returns the trigger event.
func (t TriggerContext) Event() TriggerEvent { return t.event }

// Repository returns the repository the workflow ran in.
func (t TriggerContext) Repository() string { return t.repository }

// Fork reports whether the changes came from a different repository than the
// one the workflow ran in.
//
// WHAT THIS DOES NOT ESTABLISH, stated rather than implied: an EMPTY head
// repository returns false. That is correct for every event a TriggerPolicy
// may permit — push, schedule, workflow_dispatch and a local operator run all
// execute in the repository they belong to and have no head repository — and
// it is safe today only because every event that DOES have one
// (pull_request, pull_request_target) is refused earlier by
// policyEligibleEvents. If a future event both becomes eligible and carries a
// head repository, an adapter that forgot to fill HeadRepository would read
// here as "not a fork". The fork check is kept as a second, independent layer
// for exactly that reason, and this comment is the honest bound on it.
func (t TriggerContext) Fork() bool {
	return t.headRepo != "" && t.headRepo != t.repository
}

// TriggerPolicy is the configurable half of gate 7: which of the eligible
// trigger sources this deployment permits.
//
// The zero value permits NOTHING — not "everything", and not "the defaults".
// A deployment that did not state a trigger policy has not authorised any
// trigger, and gate 7 refuses. That is the direction a policy type has to fail
// in, because the alternative is a config parse failure silently widening what
// may start a probe.
type TriggerPolicy struct {
	permitted map[TriggerEvent]struct{}
	sealed    bool
}

// NewTriggerPolicy builds a policy permitting exactly the named events.
//
// It REFUSES any event outside policyEligibleEvents, including every
// recognised-but-never-eligible one. This is the structural form of "whether
// provenance is checked is not configurable": there is no argument to this
// function, and no config file that reaches it, that produces a policy
// permitting `pull_request_target`.
//
// An empty policy is legal to construct and permits nothing.
func NewTriggerPolicy(events ...TriggerEvent) (TriggerPolicy, error) {
	p := TriggerPolicy{permitted: map[TriggerEvent]struct{}{}, sealed: true}
	for _, e := range events {
		if !e.PolicyEligible() {
			if e.Recognised() {
				return TriggerPolicy{}, fmt.Errorf("trigger policy: %w: %q may never be "+
					"permitted to authorise probing. It is an event whose inputs, head "+
					"ref or privilege an outside contributor can influence, and "+
					"Run initiation's design forbids a documented exception for it",
					ErrRefused, string(e))
			}
			return TriggerPolicy{}, fmt.Errorf("trigger policy: %w: %q is not an event "+
				"this build recognises, so it cannot be permitted", ErrRefused,
				redactUntrusted(string(e)))
		}
		p.permitted[e] = struct{}{}
	}
	return p, nil
}

// DefaultTriggerPolicy is the policy a deployment gets if it configures
// nothing but still asks for a default explicitly.
//
// It is manual operator runs, `workflow_dispatch` and `schedule`: the three
// eligible events that cannot be initiated by anyone without write access and
// carry no outside-contributor input. `push` is eligible but is left out, so
// that turning "merging a branch launches an external probe" on is a decision
// somebody made in writing.
//
// It is a FUNCTION, not a package-level var, because a var would be mutable
// from anywhere in the package.
func DefaultTriggerPolicy() TriggerPolicy {
	p, err := NewTriggerPolicy(
		TriggerEventManualOperator,
		TriggerEventWorkflowDispatch,
		TriggerEventSchedule,
	)
	if err != nil {
		// Unreachable: every event above is in policyEligibleEvents. If it
		// ever becomes reachable, the fail-closed answer is the zero
		// policy, which permits nothing.
		return TriggerPolicy{}
	}
	return p
}

// Constructed reports whether the policy came from NewTriggerPolicy.
func (p TriggerPolicy) Constructed() bool { return p.sealed && p.permitted != nil }

// Permits reports whether the policy permits an event. False for the zero
// policy, for every event.
func (p TriggerPolicy) Permits(e TriggerEvent) bool {
	if !p.Constructed() || !e.PolicyEligible() {
		return false
	}
	_, ok := p.permitted[e]
	return ok
}

// CheckGate7TriggerProvenance is gate 7: the run was started by a principal
// with write authority over the repository the scope file lives in, through an
// event that may authorise probing.
//
// The checks, in the order they refuse:
//
//  1. the context and the policy were constructed;
//  2. the scope repository was named;
//  3. the event is recognised AND eligible AND permitted by the policy;
//  4. THE RUN IS NOT A FORK RUN. This is checked independently of the event
//     so that it holds even if a future eligible event turns out to have a
//     head repository;
//  5. the trigger's repository is the scope file's repository;
//  6. the actor's permission was determined by a means that is not the
//     event payload;
//  7. the actor holds write authority.
//
// Every one of them refuses; none of them can be turned off. Which events are
// permitted is the configurable part, and it is configurable only downward
// from policyEligibleEvents.
func CheckGate7TriggerProvenance(tc TriggerContext, policy TriggerPolicy, scopeRepository string) GateResult {
	if !tc.Constructed() {
		return gateFailed(Gate7TriggerProvenance, ReasonTriggerContextUnconstructed,
			"no trigger context was recorded for this run. Gate 7 is not skipped when the "+
				"provenance is unknown; unknown provenance is the case it exists for.")
	}
	if !policy.Constructed() {
		return gateFailed(Gate7TriggerProvenance, ReasonTriggerPolicyUnconstructed,
			"no trigger policy was configured. The zero policy permits no trigger source "+
				"at all, which is what a deployment that has not decided should get.")
	}
	if err := validateRepositoryName(scopeRepository, "scope repository"); err != nil {
		return gateFailed(Gate7TriggerProvenance, ReasonTriggerRepositoryMismatch,
			"the repository the scope file belongs to was not named, or is not a well-formed "+
				"\"owner/name\". Gate 7 verifies write authority over THAT repository, "+
				"so without it there is nothing to verify authority against.")
	}
	if !tc.event.Recognised() {
		return gateFailed(Gate7TriggerProvenance, ReasonTriggerEventUnknown,
			"the trigger event is not one this build recognises.",
			"event: "+redactUntrusted(string(tc.event)))
	}
	if !tc.event.PolicyEligible() {
		return gateFailed(Gate7TriggerProvenance, ReasonTriggerEventNotEligible,
			"this trigger event may never authorise probing, whatever the configured "+
				"policy says. `pull_request` and `pull_request_target` put an outside "+
				"contributor in control of the head ref while the workflow holds the "+
				"base repository's privilege; `issue_comment`, `repository_dispatch`, "+
				"`workflow_run` and `workflow_call` launder the privilege of whatever "+
				"triggered them. No configuration adds any of them.",
			"event: "+string(tc.event))
	}
	if !policy.Permits(tc.event) {
		return gateFailed(Gate7TriggerProvenance, ReasonTriggerEventNotPermitted,
			"this trigger event is eligible but is not permitted by the configured trigger "+
				"policy. The policy is an allowlist and it did not name this event.",
			"event: "+string(tc.event))
	}
	if tc.Fork() {
		return gateFailed(Gate7TriggerProvenance, ReasonTriggerForkPullRequest,
			"the changes that started this run came from a different repository than the "+
				"one the workflow ran in — a FORK run. research/20 gate 7 refuses it "+
				"outright, and run initiation's forbidden actions rule out a 'trusted fork' "+
				"exception: the whole content of a fork run is written by somebody "+
				"without write access to the scope file.",
			"workflow repository: "+redactUntrusted(tc.repository),
			"head repository:     "+redactUntrusted(tc.headRepo))
	}
	if tc.repository != scopeRepository {
		return gateFailed(Gate7TriggerProvenance, ReasonTriggerRepositoryMismatch,
			"the run was triggered in one repository and the scope file belongs to another. "+
				"Write authority over some other repository authorises nothing here.",
			"trigger repository: "+redactUntrusted(tc.repository),
			"scope repository:   "+redactUntrusted(scopeRepository))
	}
	switch tc.source {
	case PermissionSourceVerifiedAPI:
		// Measured against the API. Accepted for every eligible event.
	case PermissionSourceOperatorLocal:
		if tc.event != TriggerEventManualOperator {
			return gateFailed(Gate7TriggerProvenance, ReasonTriggerPermissionUnverified,
				"the actor's permission was asserted as a local operator's, but this run "+
					"was started by a CI event. In CI the permission must be read "+
					"back from an authenticated API call.",
				"event: "+string(tc.event))
		}
	default:
		return gateFailed(Gate7TriggerProvenance, ReasonTriggerPermissionUnverified,
			"the actor's permission was not established by a means gate 7 accepts. A "+
				"permission taken from the webhook payload is a claim written by the "+
				"party that opened the pull request, not a measurement, and it is "+
				"refused however plausible it looks.",
			"permission source: "+redactUntrusted(string(tc.source)))
	}
	if !tc.permission.IsWriteAuthority() {
		return gateFailed(Gate7TriggerProvenance, ReasonTriggerNoWriteAuthority,
			"the principal that started this run does not hold write authority over the "+
				"repository the scope file lives in. research/20 gate 7 requires it, "+
				"because the scope file is the document that says what may be probed "+
				"and somebody who cannot edit it cannot authorise probing under it.",
			"actor:      "+redactUntrusted(tc.actor),
			"permission: "+string(tc.permission))
	}
	return gatePassed(Gate7TriggerProvenance)
}

// validateRepositoryName enforces "owner/name" with an allowlisted charset.
func validateRepositoryName(s, what string) error {
	if s == "" {
		return fmt.Errorf("trigger: %w: no %s was recorded", ErrRefused, what)
	}
	if len(s) > maxRepositoryLen {
		return fmt.Errorf("trigger: %w: the %s is %d bytes; the cap is %d",
			ErrRefused, what, len(s), maxRepositoryLen)
	}
	owner, name, found := strings.Cut(s, "/")
	if !found || owner == "" || name == "" || strings.Contains(name, "/") {
		return fmt.Errorf("trigger: %w: the %s is not of the form \"owner/name\"",
			ErrRefused, what)
	}
	for _, part := range []string{owner, name} {
		for i := 0; i < len(part); i++ {
			c := part[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'
			if !ok {
				return fmt.Errorf("trigger: %w: the %s contains a byte outside the "+
					"allowed set [A-Za-z0-9._-]", ErrRefused, what)
			}
		}
	}
	return nil
}

// validateActorName bounds and charset-restricts the actor. GitHub's bot
// actors are of the form "github-actions[bot]", so the brackets are in the
// allowlist.
func validateActorName(s string) error {
	if s == "" {
		return fmt.Errorf("trigger: %w: no actor was recorded, so gate 7 has no principal "+
			"whose write authority it could verify", ErrRefused)
	}
	if len(s) > maxActorLen {
		return fmt.Errorf("trigger: %w: the actor is %d bytes; the cap is %d",
			ErrRefused, len(s), maxActorLen)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' ||
			c == '[' || c == ']'
		if !ok {
			return fmt.Errorf("trigger: %w: the actor contains a byte outside the allowed "+
				"set [A-Za-z0-9._%s-]", ErrRefused, "[]")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// RUN INITIATION — all four gates, once, in one place
// ---------------------------------------------------------------------------

// RunRequest is everything Phase 1 needs to decide whether a run may start.
//
// Its fields are exported because target provisioning fills them in from files and the
// environment. Nothing here authorises anything: the only thing that reads a
// RunRequest is InitiateRun, and it validates every field through the four
// gates.
type RunRequest struct {
	// Artifact must be ArtifactDAST. The core binary can never enable DAST
	// (the two-artifact split), and EnableDAST is what enforces it.
	Artifact Artifact
	// Mode is the operator's literal mode declaration (gate 6). It is not
	// trimmed or repaired.
	Mode string
	// ScopeFile is the scope file's exact bytes (gate 4). The scope hash is
	// computed from them.
	ScopeFile []byte
	// AttestationFile is the attestation's exact bytes (gate 5).
	AttestationFile []byte
	// AttestationLifetimeCeiling is the configured maximum attestation
	// lifetime. It may be LOWER than MaxAttestationLifetime and may not be
	// higher; zero refuses rather than defaulting.
	AttestationLifetimeCeiling time.Duration
	// Trigger is the measured trigger provenance (gate 7).
	Trigger TriggerContext
	// TriggerPolicy is the configured allowlist of trigger events.
	TriggerPolicy TriggerPolicy
	// ScopeRepository is the "owner/name" of the repository the scope file
	// lives in. Gate 7 verifies write authority over this repository.
	ScopeRepository string
	// Clock is the run's instant. Expiry is measured against it.
	Clock Clock
}

// RunInitiation is a run that passed all four Phase 1 gates.
//
// Unexported fields and no setters. The zero value is not an initiated run:
// Initiated() is false, every accessor refuses, and the DastEnablement it
// would have carried is the zero one, which reports Enabled() == false.
type RunInitiation struct {
	decl       ModeDeclaration
	scope      Scope
	att        Attestation
	trigger    TriggerContext
	enablement DastEnablement
	clock      Clock
	sealed     bool
}

// InitiateRun runs gates 6, 4, 5 and 7 and, only if every one passes, mints
// the run.
//
// # Why the execution order is 6, 4, 5, 7 and not 4, 5, 6, 7
//
// The gate NUMBERS are identifiers, not a schedule. NewScope requires a
// ModeDeclaration, so the declaration has to exist before the scope file can
// be loaded as anything; and the attestation is bound to the scope's hash, so
// the scope has to exist before the attestation can be checked against it.
// Gate 7 is independent of all three and runs last. Every gate runs before any
// run is minted, and the FIRST refusal is returned — so a bad mode string is
// reported as a gate 6 refusal, which is what it is.
//
// The returned GateResult names the gate that refused. On success it is
// gate 7's pass, because that is the last gate consulted.
func InitiateRun(req RunRequest) (RunInitiation, GateResult) {
	decl, res := CheckGate6ModeDeclaration(req.Mode)
	if !res.Passed() {
		return RunInitiation{}, res
	}
	scope, res := CheckGate4ScopeFile(req.ScopeFile, decl)
	if !res.Passed() {
		return RunInitiation{}, res
	}
	ceiling, res := AttestationCeilingFromConfig(req.AttestationLifetimeCeiling)
	if !res.Passed() {
		return RunInitiation{}, res
	}
	att, res := CheckGate5Attestation(req.AttestationFile, scope, req.Clock, ceiling)
	if !res.Passed() {
		return RunInitiation{}, res
	}
	if res := CheckGate7TriggerProvenance(req.Trigger, req.TriggerPolicy, req.ScopeRepository); !res.Passed() {
		return RunInitiation{}, res
	}

	enablement, err := EnableDAST(req.Artifact, decl, scope, att, req.Clock)
	if err != nil {
		return RunInitiation{}, gateFailed(Gate1DastShipsDisabled, ReasonWrongArtifact,
			"all four Phase 1 gates passed and gate 1's EnableDAST still refused to enable "+
				"DAST for this run. Gates 4, 5 and 6 have already checked the scope, "+
				"the attestation and the mode, so what is left is the artifact: only "+
				"`anvil-dast` may probe, and no configuration changes that "+
				"(the two-artifact split).",
			"artifact declared: "+redactUntrusted(string(req.Artifact)))
	}
	if !enablement.Enabled() {
		return RunInitiation{}, gateFailed(Gate1DastShipsDisabled, ReasonWrongArtifact,
			"EnableDAST returned a DastEnablement that reports itself disabled. A run is "+
				"not initiated on a disabled enablement.")
	}

	return RunInitiation{
		decl:       decl,
		scope:      scope,
		att:        att,
		trigger:    req.Trigger,
		enablement: enablement,
		clock:      req.Clock,
		sealed:     true,
	}, gatePassed(Gate7TriggerProvenance)
}

// Initiated reports whether this run passed Phase 1. False for the zero value.
func (r RunInitiation) Initiated() bool {
	return r.sealed && r.enablement.Enabled() && r.scope.Constructed() &&
		r.att.Constructed() && r.decl.Declared() && r.trigger.Constructed() &&
		r.clock.Valid()
}

// RunClock returns THE run's clock: the instant this run was initiated at,
// sealed so that no caller can mint another one.
//
// This is the only exported route to a RunClock in the package, which is what
// makes Phase 4's embargo comparisons comparisons against a run rather than
// against whatever instant the next call was handed. See types.go's RunClock
// for the defeat that made it necessary, and phase4_disclosure.go's header for
// the sequence it refuses.
func (r RunInitiation) RunClock() (RunClock, error) {
	if !r.Initiated() {
		return RunClock{}, fmt.Errorf("run: %w", ErrUnconstructed)
	}
	return sealRunClock(r.clock), nil
}

// Scope returns the run's scope, or an error if the run was never initiated.
func (r RunInitiation) Scope() (Scope, error) {
	if !r.Initiated() {
		return Scope{}, fmt.Errorf("run: %w", ErrUnconstructed)
	}
	return r.scope, nil
}

// Attestation returns the run's attestation.
func (r RunInitiation) Attestation() (Attestation, error) {
	if !r.Initiated() {
		return Attestation{}, fmt.Errorf("run: %w", ErrUnconstructed)
	}
	return r.att, nil
}

// Mode returns the run's one irreversible mode declaration.
func (r RunInitiation) Mode() (Mode, error) {
	if !r.Initiated() {
		return ModeUnset, fmt.Errorf("run: %w", ErrUnconstructed)
	}
	return r.decl.Mode()
}

// Enablement returns the DastEnablement EnableDAST minted for this run.
func (r RunInitiation) Enablement() (DastEnablement, error) {
	if !r.Initiated() {
		return DastEnablement{}, fmt.Errorf("run: %w", ErrUnconstructed)
	}
	return r.enablement, nil
}

// Trigger returns the verified trigger provenance.
func (r RunInitiation) Trigger() (TriggerContext, error) {
	if !r.Initiated() {
		return TriggerContext{}, fmt.Errorf("run: %w", ErrUnconstructed)
	}
	return r.trigger, nil
}

// ---------------------------------------------------------------------------
// THE CHAIN HALF — gates 4, 5 and 6 as gateFuncs
// ---------------------------------------------------------------------------

// init installs the three Phase 1 gates whose content is a function of
// (target, scope, attestation, clock).
//
// Gate 7 is absent because it is not a per-target gate. See the file header:
// it is a Phase 1 run-initiation gate, it runs once per run before any target
// exists, and kernel.go's registerInto refuses it outright — so this init could
// not add it even if a future contributor wanted to.
func init() {
	register(Gate4ScopeFile, gate4ScopeFile)
	register(Gate5Attestation, gate5Attestation)
	register(Gate6ModeDeclaration, gate6ModeDeclaration)
}

// gate4ScopeFile is gate 4's per-target residue: the scope layer must permit
// this target's canonical host and port.
//
// This is where "malformed scope file → zero permitted targets" becomes
// observable through Decide rather than only through the loader. A scope file
// that did not parse produced no Scope, and the zero Scope permits nothing; a
// scope file that parsed but listed nothing produced a Scope with no allow
// entries, which also permits nothing. Both arrive here and both refuse.
//
// The match is on the CANONICAL form only, which is what ScopeEntry.Covers
// does and what gate 8 produces. A literal that has not been canonicalised
// simply fails to match — the fail-closed direction — and gate 8 independently
// refuses a target whose canonical form diverges from its literal form.
func gate4ScopeFile(target Target, scope Scope, _ Attestation, _ Clock) Ruling {
	if !scope.Constructed() {
		return refuse(Gate4ScopeFile, ReasonScopeUnconstructed,
			"no scope was loaded for this run, and the zero Scope permits nothing. A "+
				"missing or malformed scope file yields zero permitted targets, never "+
				"'allow all'")
	}
	if !target.Constructed() {
		return refuse(Gate4ScopeFile, ReasonScopeTargetUnbuilt,
			"gate 4 was handed a Target that NewTarget never built, so there is no "+
				"canonical host or port to match against the scope")
	}
	if !scope.Permits(target.Canonical(), target.Port()) {
		return refuse(Gate4ScopeFile, ReasonScopeRefusesTarget,
			"the scope layer does not permit this host and port. Either no allow entry "+
				"covers it, or a deny entry does and deny beats allow unconditionally")
	}
	return permit(Gate4ScopeFile, ReasonScopePermitsTarget,
		"an allow entry in the loaded scope covers this canonical host and port, and no "+
			"deny entry does")
}

// gate5Attestation is gate 5's per-target residue.
//
// # The coded ceiling re-check, and why it is here
//
// The kernel-types review demonstrated that NewAttestation compares an attestation's
// lifetime against a CALLER-SUPPLIED ceiling, and that NewCap is an exported
// constructor, so `NewCap(10*365*24*time.Hour)` produces a ceiling that admits
// a ten-year attestation. That is a hole in the kernel core's contract and the
// kernel core's file is outside this packet's write scope.
//
// What IS inside this packet's scope is refusing such an attestation HERE, in
// the admission chain, against the compiled-in const:
//
//	lifetime > MaxAttestationLifetime  ->  refuse
//
// MaxAttestationLifetime is a const in types.go. There is no ceiling argument
// to this function, no config value that reaches it, and no Cap involved — so
// an attestation forged through a raised ceiling still cannot be probed under.
// AttestationCeilingFromConfig closes the same hole on the loading path by
// never letting a config value become anything but a LOWERED default; this is
// the second, independent layer, and
// TestTheCriticsForgedTenYearCeilingIsRefusedAtConstruction is the test that a
// ten-year attestation is refused HERE as well as at the constructor.
func gate5Attestation(_ Target, scope Scope, att Attestation, clock Clock) Ruling {
	if !att.Constructed() {
		return refuse(Gate5Attestation, ReasonAttestationUnconstructed,
			"no attestation was presented. Gate 5 refuses to probe any target Anvil does "+
				"not itself own without a live attestation")
	}
	if !clock.Valid() {
		return refuse(Gate5Attestation, ReasonClockUnconstructed,
			"gate 5 was handed a Clock that NewClock never minted, so expiry cannot be "+
				"measured")
	}
	if !scope.Constructed() {
		return refuse(Gate5Attestation, ReasonScopeUnconstructed,
			"gate 5 has no scope to check this attestation's binding against")
	}
	if !att.CoversScope(scope) {
		return refuse(Gate5Attestation, ReasonScopeAttestationMismatch,
			"the attestation is bound to a different scope hash than the scope in force. "+
				"Editing the scope file invalidates the attestation, which is what "+
				"binding it to the file's hash is for")
	}
	if !att.Authority().Valid() {
		return refuse(Gate5Attestation, ReasonAttestationAuthorityUnknown,
			"the attestation names no recognised authority. The four are owner, operator, "+
				"written engagement and published VDP")
	}
	if life := att.expiresAt.Sub(att.issuedAt); life > MaxAttestationLifetime {
		return refuse(Gate5Attestation, ReasonAttestationLifetimeTooLong,
			fmt.Sprintf("the attestation's validity window is %s and the CODED ceiling is "+
				"%s. This comparison is against a compiled-in constant, not against a "+
				"ceiling anybody passed in, so no configuration and no forged Cap "+
				"raises it", life, MaxAttestationLifetime))
	}
	now := clock.Instant()
	if now.Before(att.issuedAt) {
		return refuse(Gate5Attestation, ReasonAttestationNotYetValid,
			"the attestation has not been issued yet at the run's instant")
	}
	if !now.Before(att.expiresAt) {
		return refuse(Gate5Attestation, ReasonAttestationExpired,
			"the attestation has expired at the run's instant. There is no grace period")
	}
	// No `if !att.Live(clock)` fallback: see checkAttestationLiveness for why
	// a subsumed third branch was removed rather than kept.
	return permit(Gate5Attestation, ReasonAttestationLiveAndBound,
		"a live attestation, under one of the four authorities, bound to this scope's "+
			"hash, with a validity window inside the coded ceiling")
}

// gate6ModeDeclaration is gate 6's per-target residue: a mode was declared,
// and `external` was not entered without gate 5.
func gate6ModeDeclaration(_ Target, scope Scope, att Attestation, clock Clock) Ruling {
	if !scope.Constructed() {
		return refuse(Gate6ModeDeclaration, ReasonModeNotDeclared,
			"no scope was loaded, so no mode was declared for this run. Gate 6 has no "+
				"default and no `auto`")
	}
	mode, err := scope.Mode()
	if err != nil || !mode.Valid() {
		return refuse(Gate6ModeDeclaration, ReasonModeNotDeclared,
			"this run has no mode declaration. Gate 6 refuses if absent; there is no "+
				"`auto` value and no default")
	}
	if mode == ModeExternal && !att.Live(clock) {
		return refuse(Gate6ModeDeclaration, ReasonExternalRequiresAttestation,
			"the run declares `external` and has no live attestation. research/20 gate 6: "+
				"`external` cannot be entered without gate 5")
	}
	return permit(Gate6ModeDeclaration, ReasonModeDeclaredForRun,
		"the run carries one explicit mode declaration, and `external` was not entered "+
			"without a live attestation")
}

// ---------------------------------------------------------------------------
// SHARED HELPERS
// ---------------------------------------------------------------------------

// readBoundedFile reads a file, refusing a missing one, an unreadable one and
// one larger than the bound. It stats before reading so that an enormous file
// is refused rather than read into memory first.
func readBoundedFile(path string, max int64, missing, unreadable, tooLarge Reason) ([]byte, Reason, error) {
	if path == "" {
		return nil, missing, fmt.Errorf("%w: no path", ErrRefused)
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, missing, err
		}
		return nil, unreadable, err
	}
	if info.IsDir() {
		return nil, unreadable, fmt.Errorf("%w: path names a directory", ErrRefused)
	}
	if info.Size() > max {
		return nil, tooLarge, fmt.Errorf("%w: %d bytes exceeds the bound of %d",
			ErrRefused, info.Size(), max)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, unreadable, err
	}
	if int64(len(raw)) > max {
		return nil, tooLarge, fmt.Errorf("%w: %d bytes exceeds the bound of %d",
			ErrRefused, len(raw), max)
	}
	return raw, ReasonUnspecified, nil
}

// retargetReason maps decodeStrict's gate-4-flavoured Reason onto the gate
// that is actually reporting, so that a gate 5 refusal never carries a gate 4
// token. gateFailed would otherwise fold the mismatch into the message, and a
// mismatch that is expected is a mismatch nobody reads.
func retargetReason(r Reason, g GateID) Reason {
	if g == Gate4ScopeFile {
		return r
	}
	switch r {
	case ReasonScopeFileUnknownField:
		return ReasonAttestationUnknownField
	case ReasonScopeFileDuplicateKey:
		return ReasonAttestationDuplicateKey
	case ReasonScopeFileTrailingBytes:
		return ReasonAttestationTrailingBytes
	default:
		return ReasonAttestationUnparseable
	}
}

// strictParseDetail is the Anvil-authored explanation for each strict-parse
// refusal. The parsed document's own bytes never appear in it — not the
// unknown field's name, not encoding/json's error text, which quotes it.
func strictParseDetail(r Reason, what string) string {
	switch r {
	case ReasonScopeFileUnknownField, ReasonAttestationUnknownField:
		return "the " + what + " contains a field this schema does not define. An unknown " +
			"field is refused rather than ignored: research/20 gate 4 requires that an " +
			"unknown-field scope file yield zero permitted targets, because the " +
			"commonest cause is a misspelled `deny` that silently became nothing. The " +
			"field's name is not reproduced here; it is untrusted input."
	case ReasonScopeFileDuplicateKey, ReasonAttestationDuplicateKey:
		return "the " + what + " names the same key twice in one object. encoding/json " +
			"would silently take the last one, so `{\"mode\":\"lab\",\"mode\":" +
			"\"external\"}` would decode as external with no error. A document with " +
			"two answers to one question has not answered it."
	case ReasonScopeFileTrailingBytes, ReasonAttestationTrailingBytes:
		return "the " + what + " has content after the end of the document. A second " +
			"document riding behind the first is not parsed, and a file that contains " +
			"one is not loaded."
	default:
		return "the " + what + " is not a well-formed JSON document of this schema. It is " +
			"refused whole: a partially parsed scope file is exactly the case where the " +
			"part that did not parse was the deny list."
	}
}
