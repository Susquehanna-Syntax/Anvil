// This file is target reset: the reset lifecycle between scan phases.
//
// # What this file exists to prevent
//
// A probe that changes target state makes every subsequent probe's result
// meaningless, and the failure is SILENT. The second probe returns a result;
// it is simply a result about a different application than the one the first
// probe saw. Reset is what turns a sequence of probes into a set of
// INDEPENDENT OBSERVATIONS. Which is why a reset that partially succeeded and
// reported success is worse than one that failed loudly: the loud one stops
// the run, the quiet one poisons every number downstream of it.
//
// # Destroy and recreate. Never snapshot.
//
// research/19-target-environment-and-sandboxing.md, concrete v1 stack step 5:
// "reset by destroy-and-recreate (`docker compose down -v`), not by snapshot.
// Reserve snapshot/restore for the Firecracker tier, and never restore a
// snapshot holding a real credential". There is no snapshot path in this file
// and no option that introduces one. The target manifest makes `reset.strategy` a REQUIRED,
// never-defaulted manifest key with destroy_recreate as its only allowlisted
// value, and this file re-checks it rather than assuming the target manifest ran.
//
// # VERIFIED, not assumed -- the four things that are actually checked
//
// `ComposeDown` returning nil proves nothing. A runner that does nothing and
// returns nil is indistinguishable, at the seam, from one that destroyed the
// world. So a reset here is not the absence of an error, it is four positive
// observations:
//
//  1. AFTER the destroy, the project's container listing is EMPTY. A survivor
//     means the destroy did not happen; its writable layer still holds
//     whatever the last probe wrote there.
//  2. AFTER the destroy, the project's VOLUME listing is EMPTY. This is the
//     check the container listing cannot make: `docker compose down` WITHOUT
//     `-v` removes containers and keeps named volumes, so the database rows
//     the last probe wrote survive into the next one, in a project whose
//     containers are all provably new. That is the exact silent-clean shape
//     this packet exists to catch, and a check that cannot see it is not a
//     check. It is why ResetSeam widens Docker rather than reusing it.
//  3. The re-provision goes through target provisioning's Provision UNCHANGED -- every
//     containment assertion, the runsc check, the digest pin, the probe-side
//     reachability probe. Reset does not have a second, laxer path to a live
//     target.
//  4. The fresh Target is compared against the one that was destroyed, field
//     by field, and BOTH DIRECTIONS ARE ASSERTED:
//     -- same project, service, image ref, image DIGEST, health URL, runtime,
//     platform and provisioning path. A digest that MOVED across a reset
//     means the two probe phases faced two different applications, and
//     comparing their findings is meaningless. Loud refusal, not a note.
//     -- DIFFERENT container ID, for the authorized service AND for every
//     other container in the project. An ID that survived is a container
//     that survived, which is a writable layer that survived. This is the
//     half that a same-digest check alone cannot see.
//
// # Fail closed, everywhere
//
//   - ResetStage's zero value is ResetStageUnset and Provenance() refuses it.
//   - No ResetStage maps to record.TargetProvenanceBootedClean. There is no
//     route from a reset FAILURE to a provenance that reads as a clean boot,
//     and TestNoResetStageCanBeReadAsScannedClean sweeps every stage against
//     every record.HalfStatus to pin that as a RELATION.
//   - A seam that cannot list volumes cannot support a verified reset, so
//     NewResetter REFUSES it at construction. It does not degrade to the
//     container-listing check alone and note the gap in a comment.
//   - A manifest that declares a `seed:` is refused at construction, because
//     a destroy-and-recreate discards the seed's effects and nothing in this
//     tree can replay them. Returning an unseeded target and calling it "the
//     declared initial state" is the silent lie this packet is about. Named,
//     with what would settle it, in internal/SKIPPED-CONTROLS.md U3.
//
// # A failed reset stops the run for that target, structurally
//
// Every failure path returns a nil *Target, and every path that has begun the
// destroy INVALIDATES the Target it was handed -- Constructed() goes false, so
// a caller that ignores the error still cannot present it as a live, sealed,
// booted-clean target to anything downstream. The success path invalidates it
// too: the container it names has been destroyed, and a handle to a destroyed
// container is not a target.
//
// In the record, that failure is *ResetError, which carries the ResetStage
// (operator-actionable), a record.TargetProvenance (the frozen fact) and
// record.HalfStatusFailed. Its DastStatus() derives through
// record.DeriveDastStatus, so this file writes no record enum literal and the
// derived status can never be DastStatusCompletedClean.

package containment

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/target"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// resetVerifyGrace bounds the post-destroy verification listings. It is a cap
// on how long the evidence-gathering may take, never a wait: an unbounded
// listing on the reset path is how a run hangs between probes.
const resetVerifyGrace = 30 * time.Second

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// The typed reset refusals. Each is joined with ErrRefused inside a
// *ResetError, exactly as the provisioning refusals are, so a caller can
// errors.Is against one package-wide sentinel.
var (
	// ErrResetNotConstructed: Reset was called with a nil or unsealed
	// Target, or on a Resetter that NewResetter did not build.
	ErrResetNotConstructed = errors.New("reset was asked to act on a target that was never sealed by Provision")

	// ErrResetForeignTarget: the Target handed to Reset does not belong to
	// this Resetter's manifest. Re-provisioning would bring up a DIFFERENT
	// project and hand it back as though it were this one, and tearing the
	// handed-in one down would aim `down -v` at a project this Resetter does
	// not own.
	ErrResetForeignTarget = errors.New("target does not belong to this resetter's manifest")

	// ErrResetStrategyUnsupported: the manifest's reset.strategy is not
	// destroy_recreate. The target manifest already refuses this at parse time; this is the
	// re-check, because a hand-built &target.Manifest{} has an empty
	// strategy and a Go zero value must never mean "permitted".
	ErrResetStrategyUnsupported = errors.New("reset.strategy is not the only strategy v1 supports")

	// ErrResetSeedNotReplayable: the manifest declares a seed, whose effects
	// a destroy-and-recreate discards and which nothing in this tree can
	// replay.
	ErrResetSeedNotReplayable = errors.New("manifest declares a seed that this package cannot replay after a destroy")

	// ErrResetSeamIncomplete: the Docker seam cannot list project volumes,
	// so the destroy cannot be verified.
	ErrResetSeamIncomplete = errors.New("container runtime seam cannot list project volumes")

	// ErrDestroyFailed: the teardown itself returned an error.
	ErrDestroyFailed = errors.New("destroy-and-recreate teardown failed")

	// ErrDestroyUnverified: the teardown returned no error and the evidence
	// says it did not destroy. Containers survived, volumes survived, or the
	// listing could not be taken at all.
	ErrDestroyUnverified = errors.New("teardown reported success and the target's state survived it")

	// ErrReprovisionFailed: the destroy was verified and the target did not
	// come back. The underlying *ProvisionError is the cause and carries its
	// own stage and provenance.
	ErrReprovisionFailed = errors.New("target did not come back up after a verified destroy")

	// ErrResetNotVerified: the target came back and is not the declared
	// initial state -- a moved image digest, a surviving container ID, or a
	// changed identity.
	ErrResetNotVerified = errors.New("re-provisioned target is not indistinguishable from a first provision")
)

// ---------------------------------------------------------------------------
// ResetStage
// ---------------------------------------------------------------------------

// ResetStage is where a reset attempt ended. It is the reset half of the same
// split Stage makes for provisioning: the stage carries the
// operator-actionable detail, record.TargetProvenance carries the frozen
// record fact, and ResetStage.Provenance() is the one mapping between them.
//
// FAIL CLOSED: ResetStageUnset is the zero value, is not a legal stage, and
// Provenance() refuses it.
type ResetStage string

// The reset stages. Read the Provenance() switch below with this list: every
// stage appears there exactly once.
const (
	// ResetStageUnset is the zero value and is not a legal outcome.
	ResetStageUnset ResetStage = ""

	// ResetStagePreflight: nothing was touched. A nil or unsealed target, an
	// unconstructed resetter, or a target belonging to another manifest.
	ResetStagePreflight ResetStage = "preflight"

	// ResetStageStrategy: the manifest's reset.strategy is not
	// destroy_recreate. Nothing was touched.
	ResetStageStrategy ResetStage = "strategy"

	// ResetStageDestroy: the teardown returned an error.
	ResetStageDestroy ResetStage = "destroy"

	// ResetStageDestroyUnverified: the teardown returned no error and the
	// evidence contradicts it.
	ResetStageDestroyUnverified ResetStage = "destroy_unverified"

	// ResetStageReprovision: the destroy was verified and target provisioning's Provision
	// refused to bring the target back.
	ResetStageReprovision ResetStage = "reprovision"

	// ResetStageVerify: the target came back and is not the declared initial
	// state.
	ResetStageVerify ResetStage = "verify"
)

// ResetStageValues returns every legal ResetStage, excluding the zero value.
//
// TestResetStageValuesCoversEveryDeclaredStage reads this file's own source,
// so a stage added to the const block above and forgotten here is caught
// rather than silently absent from every sweep that walks this list.
func ResetStageValues() []ResetStage {
	return []ResetStage{
		ResetStagePreflight,
		ResetStageStrategy,
		ResetStageDestroy,
		ResetStageDestroyUnverified,
		ResetStageReprovision,
		ResetStageVerify,
	}
}

// Valid reports whether s is one of the legal reset stages. ResetStageUnset is
// not.
func (s ResetStage) Valid() bool {
	for _, v := range ResetStageValues() {
		if s == v {
			return true
		}
	}
	return false
}

// Provenance maps a reset stage onto the record.TargetProvenance it means.
//
// EVERY STAGE MAPS TO record.TargetProvenanceBootFailed, and that is a
// deliberate floor rather than an oversight, so read the reasoning before
// changing it:
//
// After ANY failed reset, the true statement about the target is "there is no
// target in a known state for the next probe to run against". Of the five
// frozen literals, boot_failed is the only one that says that. build_failed
// would blame the repo's Dockerfile for a teardown that did not happen;
// unreachable_at_scan_time would claim a healthy target behind a broken
// network; no_target_declared would claim there was nothing to scan, which is
// false in every case that reaches this function -- a Resetter cannot be built
// without a manifest. booted_clean is unreachable here BY CONSTRUCTION and
// TestNoResetStageCanBeReadAsScannedClean pins that.
//
// ResetStageReprovision is the one stage whose provenance can be NARROWED past
// this floor: Provision's own *ProvisionError already decided between
// build_failed, boot_failed and unreachable_at_scan_time, and refuseReprovision
// carries that decision through instead of flattening it. The floor is what
// happens when it cannot.
//
// WHAT THAT COSTS, STATED RATHER THAN HIDDEN: a run that failed because the
// container engine dropped its teardown and a run that failed because the
// image would not restart both record boot_failed. The ResetStage carries the
// difference, it is in the *ResetError's message, and it is what an operator
// reads. The alternative -- a sixth provenance literal such as
// `reset_failed` -- is a change to an enum frozen by the first plan's
// target-provenance split in the record area, and is not
// this packet's to make. Reported to the orchestrator.
func (s ResetStage) Provenance() (record.TargetProvenance, error) {
	switch s {
	case ResetStagePreflight,
		ResetStageStrategy,
		ResetStageDestroy,
		ResetStageDestroyUnverified,
		ResetStageReprovision,
		ResetStageVerify:
		return record.TargetProvenanceBootFailed, nil

	case ResetStageUnset:
		return "", fmt.Errorf("containment: the zero ResetStage names no outcome; a "+
			"reset refusal must say which of the %d stages it ended at",
			len(ResetStageValues()))

	default:
		return "", fmt.Errorf("containment: %q is not a legal ResetStage", string(s))
	}
}

// ---------------------------------------------------------------------------
// ResetError
// ---------------------------------------------------------------------------

// ResetError is every reset refusal. Like *ProvisionError it carries three
// facts that cannot disagree, because the provenance is derived from the stage
// at construction and is never set by hand -- except where a *ProvisionError
// has already made a NARROWER decision, which refuseReprovision carries
// through under validation.
type ResetError struct {
	stage      ResetStage
	provenance record.TargetProvenance
	sentinel   error
	detail     string

	// cause is the underlying *ProvisionError for ResetStageReprovision, and
	// nil otherwise. It is exposed so a caller can errors.As past this error
	// to the provisioning stage that actually refused.
	cause error

	// teardown is a non-nil teardown failure that happened while cleaning up
	// after the primary refusal. Reported; never changes the provenance.
	teardown error
}

// refuseReset builds a *ResetError from a stage. It is the only constructor
// for the stage-derived cases, so a reset refusal cannot exist without a
// stage, and a stage that names no provenance turns into a loud internal
// refusal rather than an empty record field.
func refuseReset(stage ResetStage, sentinel error, format string, args ...any) *ResetError {
	prov, err := stage.Provenance()
	if err != nil {
		// A stage this file did not map. Fail closed onto boot_failed --
		// never onto booted_clean -- and say so.
		return &ResetError{
			stage:      ResetStageVerify,
			provenance: record.TargetProvenanceBootFailed,
			sentinel:   ErrResetNotVerified,
			detail: fmt.Sprintf("internal: %v (original refusal: %s)",
				err, fmt.Sprintf(format, args...)),
		}
	}
	return &ResetError{
		stage:      stage,
		provenance: prov,
		sentinel:   sentinel,
		detail:     fmt.Sprintf(format, args...),
	}
}

// refuseReprovision builds the ResetStageReprovision refusal, carrying the
// underlying *ProvisionError's own provenance rather than the stage floor --
// but only after validating it.
//
// THE TWO PROVENANCES IT REFUSES TO CARRY, and why each would be a lie:
//
//   - booted_clean would say the target came up when Provision just refused.
//     It is the silent-clean reading, arriving through the one door that is
//     not a Stage.
//   - no_target_declared would say there was nothing to scan. A Resetter
//     cannot be built without a manifest, so a Provision that reports it is
//     contradicting the resetter that called it.
//
// Either substitutes the boot_failed floor and says so in the detail, rather
// than propagating a value that would derive a misleading DastStatus.
func refuseReprovision(cause error) *ResetError {
	floor, err := ResetStageReprovision.Provenance()
	if err != nil {
		// Unreachable while ResetStageReprovision is in the switch above;
		// still fails closed rather than returning an empty provenance.
		floor = record.TargetProvenanceBootFailed
	}
	prov := floor
	note := ""

	var pe *ProvisionError
	if errors.As(cause, &pe) {
		switch p := pe.Provenance(); p {
		case record.TargetProvenanceBootedClean:
			note = fmt.Sprintf("; the re-provision refused and reported provenance %q, "+
				"which would read as a clean boot, so %q was recorded instead",
				string(p), string(floor))
		case record.TargetProvenanceNoTargetDeclared:
			note = fmt.Sprintf("; the re-provision reported provenance %q against a "+
				"resetter that holds a manifest, which is a contradiction, so %q was "+
				"recorded instead", string(p), string(floor))
		default:
			if err := record.ValidateTargetProvenance(string(p)); err != nil {
				note = fmt.Sprintf("; the re-provision reported provenance %q, which the "+
					"frozen enum rejects (%v), so %q was recorded instead",
					string(p), err, string(floor))
			} else {
				prov = p
			}
		}
	}

	return &ResetError{
		stage:      ResetStageReprovision,
		provenance: prov,
		sentinel:   ErrReprovisionFailed,
		cause:      cause,
		detail: fmt.Sprintf("the destroy was verified and the target did not come back: "+
			"%v%s", cause, note),
	}
}

// Error renders stage, provenance and detail together, because an operator
// reading one log line has only the message.
func (e *ResetError) Error() string {
	msg := fmt.Sprintf("containment: reset refused at stage %q (target.provenance=%q): %v: %s",
		string(e.stage), string(e.provenance), e.sentinel, e.detail)
	if e.teardown != nil {
		msg += fmt.Sprintf(" [teardown also failed: %v]", e.teardown)
	}
	return msg
}

// Unwrap exposes ErrRefused, the typed sentinel and the underlying cause, so
// errors.Is works against any of them and errors.As reaches a
// *ProvisionError.
func (e *ResetError) Unwrap() []error {
	out := []error{ErrRefused, e.sentinel}
	if e.cause != nil {
		out = append(out, e.cause)
	}
	return out
}

// Stage returns where the reset ended.
func (e *ResetError) Stage() ResetStage { return e.stage }

// Provenance returns the frozen anvil/target.provenance literal for this
// refusal. It is never empty and never booted_clean.
func (e *ResetError) Provenance() record.TargetProvenance { return e.provenance }

// HalfStatus returns the anvil/status literal a reset failure gives the DAST
// half. A reset that failed mid-run is a half that FAILED -- not one that
// covered part of the surface, and not one that was skipped.
func (e *ResetError) HalfStatus() record.HalfStatus { return record.HalfStatusFailed }

// DastStatus derives the audit-level outcome through record.DeriveDastStatus,
// so this package writes no anvil/dastStatus literal and cannot drift from the
// frozen enum. It can never return DastStatusCompletedClean, which
// TestNoResetStageCanBeReadAsScannedClean pins as a relation over every stage
// and every half status.
func (e *ResetError) DastStatus() (record.DastStatus, error) {
	return record.DeriveDastStatus(e.HalfStatus(), record.DastOutcome{
		TierInstalled: true,
		Provenance:    e.provenance,
	})
}

// TeardownError returns a teardown failure that happened while cleaning up
// after the primary refusal, or nil.
func (e *ResetError) TeardownError() error { return e.teardown }

// ---------------------------------------------------------------------------
// The volume half of the seam
// ---------------------------------------------------------------------------

// Volume is the recorded shape of one entry of `docker volume ls` reduced to
// what the destroy verification decides on.
type Volume struct {
	// Name is the engine's volume name.
	Name string

	// Project is the com.docker.compose.project label. A volume without it
	// is not one Compose created for the project, and the verification says
	// so rather than assuming.
	Project string

	// Driver is recorded for the audit trail and is not asserted on.
	Driver string
}

// VolumeInspector is the ONE thing a reset needs that provisioning does not.
//
// WHY THIS IS NOT OPTIONAL. `docker compose down` removes containers and
// KEEPS named volumes; only `down -v` removes them. A runner that drops the
// `-v` -- or an engine that refuses to remove a volume still referenced by
// something outside the project -- produces a project whose containers are all
// provably new and whose DATABASE ROWS ARE THE PREVIOUS PROBE'S. Every check
// available through the Docker interface alone passes on that world. So a seam
// that cannot answer this question cannot support a verified reset, and
// NewResetter refuses it rather than degrading to the checks that can't see
// the damage.
//
// THE CONTRACT AN IMPLEMENTATION OWES, stated here because the compiler
// cannot:
//
//  1. ProjectVolumes must list every volume Compose created for the project,
//     including ones whose removal was refused, and must populate the
//     com.docker.compose.project label. A volume omitted from this list is a
//     volume whose survival is never noticed -- which is the whole failure
//     mode this interface exists for, so an implementation that returns an
//     empty slice on error is worse than one that returns the error.
//  2. An error means "the question could not be answered", and the reset
//     refuses on it. It must never be used to mean "there are none".
type VolumeInspector interface {
	ProjectVolumes(ctx context.Context, project string) ([]Volume, error)
}

// ResetSeam is Docker widened by the volume listing. A Provisioner whose seam
// satisfies it can be reset; one whose seam does not, cannot.
type ResetSeam interface {
	Docker
	VolumeInspector
}

// ---------------------------------------------------------------------------
// Resetter
// ---------------------------------------------------------------------------

// Resetter performs destroy-and-recreate resets of ONE manifest's target.
//
// It holds the manifest rather than taking one per call, so that a Reset
// cannot bring up a different target than the one it destroyed: the manifest
// is fixed at construction, and Reset re-derives the expected project name
// from it and refuses a Target that does not match.
//
// There is deliberately no Options struct and no functional option. Nothing
// about the verification is configurable, and a key that turns one of the four
// observations off is a snapshot-restore path wearing a different hat.
type Resetter struct {
	p    *Provisioner
	m    *target.Manifest
	seam ResetSeam
}

// NewResetter builds a Resetter, or refuses.
//
// Every refusal here is a condition under which a reset could not be VERIFIED,
// so each is caught once at construction rather than being discovered halfway
// through a probe sequence with the target already destroyed:
//
//   - a nil or unconstructed Provisioner, which has no seam to act through;
//   - a nil manifest, without which there is nothing to re-provision from;
//   - a reset.strategy that is not destroy_recreate -- the zero value of a
//     hand-built &target.Manifest{} included, because a Go zero value must
//     never mean "permitted";
//   - a manifest declaring a seed, whose effects a destroy discards and which
//     nothing in this tree replays;
//   - a seam that cannot list volumes.
func NewResetter(p *Provisioner, m *target.Manifest) (*Resetter, error) {
	if p == nil || p.docker == nil || strings.TrimSpace(p.repoRoot) == "" {
		return nil, fmt.Errorf("containment: %w: resetter needs a provisioner built by "+
			"NewProvisioner; re-provisioning goes through target provisioning's Provision unchanged and "+
			"there is no second path to a live target", ErrRefused)
	}
	if m == nil {
		return nil, fmt.Errorf("containment: %w: resetter needs the manifest it will "+
			"re-provision from; a reset that cannot rebuild the target can only destroy it",
			ErrRefused)
	}
	if m.AuthorizedService().IsZero() {
		return nil, fmt.Errorf("containment: %w: the manifest names no authorized "+
			"service, so there is no identity to check a re-provisioned target against",
			ErrRefused)
	}
	if m.Reset.Strategy != target.ResetStrategyDestroyRecreate {
		return nil, fmt.Errorf("containment: %w: %w: reset.strategy is %q and v1 accepts "+
			"%q only. research/19 reserves snapshot/restore for a future Firecracker tier "+
			"and calls resuming from the same state more than once insecure; there is no "+
			"snapshot path in this package",
			ErrRefused, ErrResetStrategyUnsupported,
			m.Reset.Strategy, target.ResetStrategyDestroyRecreate)
	}
	if m.Seed != nil {
		return nil, fmt.Errorf("containment: %w: %w: the manifest declares seed.command "+
			"%v, which runs once after health passes and before any probe fires. A "+
			"destroy-and-recreate discards its effects and nothing in this tree can "+
			"replay it, so the target this would hand back is NOT the declared initial "+
			"state -- it is an unseeded one. Refusing loudly beats returning it and "+
			"calling the next probe independent. internal/SKIPPED-CONTROLS.md U3 names "+
			"what would settle this",
			ErrRefused, ErrResetSeedNotReplayable, m.Seed.Command)
	}
	seam, ok := p.docker.(ResetSeam)
	if !ok {
		return nil, fmt.Errorf("containment: %w: %w: the seam %T implements Docker and "+
			"not VolumeInspector. `docker compose down` WITHOUT -v keeps named volumes, "+
			"so the previous probe's database rows survive into a project whose "+
			"containers are all new -- and every check Docker alone can make passes on "+
			"that world. A reset that cannot see it is not verified",
			ErrRefused, ErrResetSeamIncomplete, p.docker)
	}
	return &Resetter{p: p, m: m, seam: seam}, nil
}

// Manifest returns the manifest this Resetter re-provisions from.
func (r *Resetter) Manifest() *target.Manifest {
	if r == nil {
		return nil
	}
	return r.m
}

// Strategy returns the reset strategy this Resetter enforces. It is the target manifest's
// constant, never a literal spelled here.
func (r *Resetter) Strategy() string {
	if r == nil {
		return ""
	}
	return r.m.Reset.Strategy
}

// ---------------------------------------------------------------------------
// The identity a reset must reproduce
// ---------------------------------------------------------------------------

// resetIdentity is everything about a Target that a reset must REPRODUCE, plus
// the one thing it must CHANGE. It is captured before the destroy, because
// after the destroy there is nothing left to read it from.
type resetIdentity struct {
	project      string
	service      string
	imageRef     string
	imageDigest  string
	healthURL    string
	runtime      string
	platform     string
	provisioning record.TargetProvisioning

	// containerID is the authorized service's container, and containerIDs is
	// every container in the project including it. Both must be GONE.
	containerID  string
	containerIDs []string
}

// captureIdentity reads the sealed facts off a Target before it is destroyed.
//
// It reads Container.ID and NOTHING ELSE off Containers(). That is deliberate
// and is not an oversight to tidy up later: Containers() takes a SHALLOW copy,
// so every slice field of the returned Container (Mounts, SecurityOpt,
// CapDrop, CapAdd, Devices, RepoDigests) still aliases the sealed Target's own
// backing arrays. ID is a string, which the shallow copy does copy. Reported
// to the orchestrator against provision.go:854; this file works with the code
// as it is and reads only the field that is actually safe to read.
func captureIdentity(t *Target) resetIdentity {
	id := resetIdentity{
		project:      t.Project(),
		service:      t.AuthorizedService().Name(),
		imageRef:     t.ImageRef(),
		imageDigest:  t.ImageDigest(),
		healthURL:    t.HealthURL(),
		runtime:      t.Runtime(),
		platform:     t.Platform(),
		provisioning: t.Provisioning(),
		containerID:  t.ContainerID(),
	}
	for _, c := range t.Containers() {
		id.containerIDs = append(id.containerIDs, c.ID)
	}
	sort.Strings(id.containerIDs)
	return id
}

// invalidate unseals a Target so that Constructed() is false for it.
//
// A caller that ignores Reset's error still holds a pointer to the Target it
// passed in, and after a destroy that pointer names a container that no longer
// exists -- or, worse, one whose existence is exactly what is in doubt. This
// is what makes "a failed reset stops the run for that target" structural
// rather than a sentence in a doc comment: an unsealed Target reports
// Constructed() false and Provenance() "", which record.ValidateTargetProvenance
// rejects, so it cannot be written into a record as booted_clean.
//
// It is called on the SUCCESS path too. The old handle names a destroyed
// container either way.
//
// NOT SAFE FOR CONCURRENT USE with any other reader of the same Target. That
// is not a limitation in practice: plan/design/dynamic-tier.md places target reset in the SERIAL
// group, one target is reset between probe phases, and there is no code path
// in this package that resets two targets at once.
func invalidate(t *Target) {
	if t == nil {
		return
	}
	t.sealed = false
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

// Reset destroys the target and brings it back, and refuses unless it can
// PROVE the result is indistinguishable from a first provision.
//
// The order below is the contract:
//
//  1. preflight            -> nothing touched, old target invalidated
//  2. strategy re-check    -> nothing touched, old target invalidated
//  3. destroy (`down -v`)  -> old target invalidated from here on, always
//  4. verify the destroy   -> containers AND volumes gone, or refuse
//  5. re-provision         -> target provisioning's Provision, unchanged
//  6. verify the result    -> same declared state, different instance
//  7. otherwise            -> the fresh sealed Target
//
// On every failure it returns a nil *Target. On step 6 it also destroys the
// target it just brought up, because an unverified live target is one a probe
// could still be pointed at.
func (r *Resetter) Reset(ctx context.Context, tgt *Target) (*Target, error) {
	// 1. Preflight. The Resetter itself first: a zero-value &Resetter{} is
	// not one NewResetter built, and it must not reach the seam.
	if r == nil || r.p == nil || r.m == nil || r.seam == nil {
		invalidate(tgt)
		return nil, refuseReset(ResetStagePreflight, ErrResetNotConstructed,
			"Reset was called on a resetter that NewResetter did not build; every "+
				"refusal NewResetter makes is a condition under which a reset could not "+
				"be verified, and skipping it is skipping all of them")
	}

	if tgt == nil {
		return nil, refuseReset(ResetStagePreflight, ErrResetNotConstructed,
			"Reset was called with a nil target. There is nothing to destroy and "+
				"nothing whose identity a re-provision could be checked against; "+
				"bringing a target up from here would be a Provision wearing a reset's "+
				"name")
	}
	if !tgt.Constructed() {
		invalidate(tgt)
		return nil, refuseReset(ResetStagePreflight, ErrResetNotConstructed,
			"Reset was called with a target that is not sealed (constructed=%v "+
				"provenance=%q). Only a Target that came out of a successful Provision "+
				"carries the identity a reset must reproduce",
			tgt.Constructed(), string(tgt.Provenance()))
	}

	before := captureIdentity(tgt)

	// The target must belong to THIS resetter's manifest. Checked by
	// recomputing the project name from the manifest rather than by trusting
	// the handle: a Target from another manifest would be destroyed here and
	// a DIFFERENT project handed back as its replacement.
	svc := r.m.AuthorizedService()
	wantProject := projectName(r.p.repoRoot, r.m.ComposeFile, svc.Name())
	if before.project != wantProject || !svc.Authorizes(before.service) {
		// Deliberately NOT torn down: `down -v` destroys volumes, and this
		// is a project this Resetter does not own. Invalidated all the same,
		// because a reset was requested for it and did not happen.
		invalidate(tgt)
		return nil, refuseReset(ResetStagePreflight, ErrResetForeignTarget,
			"the target names project %q service %q and this resetter's manifest "+
				"derives project %q service %q. The target was NOT torn down -- `down -v` "+
				"destroys volumes and this resetter does not own that project -- and it "+
				"was invalidated, so it can no longer be presented as a live target. Tear "+
				"it down through the Provisioner that created it",
			before.project, before.service, wantProject, svc.Name())
	}

	// 2. reset.strategy, re-checked. The target manifest refuses anything else at parse time
	// and NewResetter refuses it again; this is the third check, because the
	// manifest is a pointer and this is the last moment before a destroy.
	if r.m.Reset.Strategy != target.ResetStrategyDestroyRecreate {
		invalidate(tgt)
		return nil, refuseReset(ResetStageStrategy, ErrResetStrategyUnsupported,
			"reset.strategy is %q and v1 accepts %q only; nothing was destroyed",
			r.m.Reset.Strategy, target.ResetStrategyDestroyRecreate)
	}

	// From here on the target is gone or in doubt, so the handle dies no
	// matter which way this call exits.
	invalidate(tgt)

	// 3. Destroy. teardown() is target provisioning's, so `down -v` -- volumes included --
	// is spelled in exactly one place in this package.
	if err := teardown(ctx, r.seam, before.project); err != nil {
		return nil, refuseReset(ResetStageDestroy, ErrDestroyFailed,
			"`down -v` on project %q failed: %v. The run stops for this target: its "+
				"state is now neither the initial one nor a known one, and any probe "+
				"after this point measures an application nobody can name",
			before.project, err)
	}

	// 4. Verify the destroy. This is the step that separates a reset from a
	// hopeful call to ComposeDown.
	if err := r.verifyDestroyed(ctx, before.project); err != nil {
		return nil, refuseReset(ResetStageDestroyUnverified, ErrDestroyUnverified, "%v", err)
	}

	// 5. Re-provision through target provisioning, unchanged. Every containment assertion,
	// the runsc preflight, the digest pin and the probe-side reachability
	// check run again -- a target that was contained an hour ago is not
	// evidence about the one that just came up.
	fresh, err := r.p.Provision(ctx, r.m)
	if err != nil {
		return nil, refuseReprovision(err)
	}

	// 6. Verify the result against what was destroyed.
	if err := verifyFresh(before, fresh); err != nil {
		re := refuseReset(ResetStageVerify, ErrResetNotVerified, "%v", err)
		// An unverified target that is still UP is one a probe could be
		// pointed at. Destroy it, and invalidate the handle, before
		// returning.
		re.teardown = teardown(context.WithoutCancel(ctx), r.seam, fresh.Project())
		invalidate(fresh)
		return nil, re
	}

	return fresh, nil
}

// verifyDestroyed is observation 1 and observation 2: after `down -v`, the
// project has no containers and no volumes.
//
// Both listings FAIL CLOSED. An error from either means the question could not
// be answered, and "could not be answered" is not "there are none" -- an
// implementation that swallows its error and returns an empty slice turns this
// whole function into a no-op, which is why the seam contract says so in
// words.
func (r *Resetter) verifyDestroyed(ctx context.Context, project string) error {
	// The caller's context is honoured rather than detached: a cancelled or
	// expired run makes the listings fail, and a listing that failed refuses.
	// That is the fail-closed reading -- "we could not look" is never "there
	// was nothing there".
	vctx, cancel := context.WithTimeout(ctx, resetVerifyGrace)
	defer cancel()

	survivors, err := r.seam.ProjectContainers(vctx, project)
	if err != nil {
		return fmt.Errorf("`down -v` on project %q returned no error and the container "+
			"listing that would confirm it could not be taken: %v. A destroy whose "+
			"success is inferred from the absence of an error is not a verified destroy",
			project, err)
	}
	if len(survivors) > 0 {
		return fmt.Errorf("`down -v` on project %q returned no error and %d container(s) "+
			"survived it: %s. Each surviving container is a surviving writable layer, "+
			"holding whatever the last probe wrote there; the next probe would not be an "+
			"independent observation",
			project, len(survivors), strings.Join(describeContainers(survivors), ", "))
	}

	volumes, err := r.seam.ProjectVolumes(vctx, project)
	if err != nil {
		return fmt.Errorf("`down -v` on project %q returned no error and the volume "+
			"listing that would confirm it could not be taken: %v. The container listing "+
			"cannot see a surviving volume, so this is not a gap that the other check "+
			"covers",
			project, err)
	}
	if len(volumes) > 0 {
		return fmt.Errorf("`down -v` on project %q returned no error, every container is "+
			"gone, and %d volume(s) survived it: %s. This is the shape a `down` WITHOUT "+
			"-v leaves behind: brand-new containers mounting the previous probe's "+
			"database rows. Every check the Docker interface alone can make passes on it",
			project, len(volumes), strings.Join(describeVolumes(volumes), ", "))
	}
	return nil
}

// verifyFresh is observation 4: the target that came back is the DECLARED
// INITIAL STATE, and it is a DIFFERENT INSTANCE of it.
//
// Both halves are required and neither implies the other:
//
//   - Same identity, same image digest. A digest that moved across a reset
//     means probe phase 1 and probe phase 2 faced two different applications.
//     Their findings are then not comparable and merging them into one record
//     is the silent failure this packet exists to prevent -- it is not a
//     smaller problem than a surviving container, it is the same problem from
//     the other side.
//   - Different container IDs, for every container in the project. A
//     surviving ID is a surviving writable layer. Checked over the WHOLE
//     project, not just the authorized service: a sibling database that was
//     never recreated is exactly as poisonous as an authorized service that
//     was not, and probing the authorized service is how its rows get read.
func verifyFresh(before resetIdentity, fresh *Target) error {
	if fresh == nil {
		return errors.New("Provision returned no error and a nil target; a reset cannot " +
			"be verified against nothing")
	}
	if !fresh.Constructed() {
		return fmt.Errorf("Provision returned no error and an unsealed target "+
			"(constructed=%v provenance=%q)", fresh.Constructed(), string(fresh.Provenance()))
	}

	after := captureIdentity(fresh)

	var problems []string
	same := func(field, was, is string) {
		if was != is {
			problems = append(problems, fmt.Sprintf(
				"%s was %q before the reset and is %q after; the declared initial state "+
					"did not come back", field, was, is))
		}
	}
	same("project", before.project, after.project)
	same("authorized service", before.service, after.service)
	same("image ref", before.imageRef, after.imageRef)
	same("image digest", before.imageDigest, after.imageDigest)
	same("health url", before.healthURL, after.healthURL)
	same("runtime", before.runtime, after.runtime)
	same("gvisor platform", before.platform, after.platform)
	same("provisioning", string(before.provisioning), string(after.provisioning))

	if after.containerID == before.containerID {
		problems = append(problems, fmt.Sprintf(
			"the authorized service's container is still %s. A destroy-and-recreate "+
				"produces a NEW container; the same id means the old one was reused, and "+
				"its writable layer holds whatever the last probe wrote",
			shortID(after.containerID)))
	}

	if survivors := intersect(before.containerIDs, after.containerIDs); len(survivors) > 0 {
		short := make([]string, 0, len(survivors))
		for _, id := range survivors {
			short = append(short, shortID(id))
		}
		problems = append(problems, fmt.Sprintf(
			"%d container(s) of project %q carry an id that was present before the reset "+
				"(%s). Every container in the project is destroyed and recreated, not "+
				"only the authorized service: a sibling database that survived holds the "+
				"previous probe's rows, and the authorized service is how they get read",
			len(survivors), after.project, strings.Join(short, ", ")))
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("%d verification failure(s) after re-provisioning project %q:\n  %s",
		len(problems), after.project, strings.Join(problems, "\n  "))
}

// intersect returns the sorted ids present in both lists.
func intersect(a, b []string) []string {
	inA := make(map[string]bool, len(a))
	for _, s := range a {
		inA[s] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range b {
		if inA[s] && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func describeContainers(cs []Container) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, fmt.Sprintf("%s (service %q, project %q, state %q)",
			shortID(c.ID), c.Service, c.Project, string(c.State)))
	}
	sort.Strings(out)
	return out
}

func describeVolumes(vs []Volume) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, fmt.Sprintf("%q (project %q, driver %q)", v.Name, v.Project, v.Driver))
	}
	sort.Strings(out)
	return out
}
