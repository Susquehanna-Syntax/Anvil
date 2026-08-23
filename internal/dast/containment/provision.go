// Package containment provisions and holds the ephemeral target a DAST scan
// runs against.
//
// This file is packet D.10: given the DECLARED manifest that
// internal/dast/target already parsed, bring up the operator's Compose project
// under gVisor `runsc`, wait on the declared healthcheck with a hard timeout,
// prove the thing that came up is actually contained, resolve the image
// DIGEST of the one authorized service, and hand back a sealed Target -- or
// refuse, naming exactly which of the five record.TargetProvenance outcomes
// this attempt was.
//
// # The distinction this file exists to keep
//
// record.TargetProvenance has five literals and they are five DIFFERENT
// FACTS. plan/00-SPINE.md S6 requires that "a target that failed to boot must
// be distinguishable from 'scanned clean'", and the same argument applies
// between the failures themselves:
//
//   - build_failed             the image never came into existence, so no boot
//     was attempted. The operator fixes a build.
//   - boot_failed              the image existed and the container would not
//     start, would not go healthy, or came up UNCONTAINED. The operator fixes
//     a runtime.
//   - unreachable_at_scan_time the container is healthy by its own
//     healthcheck and the probe side still cannot reach it. The operator fixes
//     a network.
//   - no_target_declared       there was nothing to provision. Not a failure.
//   - booted_clean             all of the above passed.
//
// Collapsing any two of those loses the fact the operator needs, and reporting
// any of the four failures as booted_clean is the silent-clean reading S6
// forbids. So every exit path from Provision goes through exactly one Stage,
// Stage.Provenance() is a TOTAL function over the stages, and
// TestEveryStageNamesOneProvenance plus TestNoStageCanBeReadAsScannedClean pin
// both halves of that.
//
// # Why there is a seam in front of Docker
//
// Docker is not installed on every host that builds Anvil -- it is not
// installed on the host this packet was written on, which is recorded in
// internal/SKIPPED-CONTROLS.md as entry U2, along with the three things that
// would settle it in order of decreasing cost. The Docker interface below is
// the ONE boundary between
// this logic and the container runtime, so the decision logic -- the
// containment assertions, the identity lookup, the digest resolution, the five
// provenance outcomes -- is driven in tests by RECORDED SHAPES of what `docker
// inspect` and `docker compose` return, and is proven here in full. What is
// not proven here is that a real Docker implementation of that interface
// produces those shapes faithfully. That gap is named, not papered over.
//
// # Fail closed, everywhere
//
// No Go zero value in this package means "permitted":
//
//   - Container.State must equal StateRunning; the zero value "" does not.
//   - Container.Health must equal HealthHealthy; the zero value "" does not,
//     which is what catches a Compose service that declares no healthcheck at
//     all and therefore satisfies `--wait` instantly.
//   - UpStatus's zero value is UpStatusUnreported, which REFUSES. The success
//     literal is UpStatusUp and a runner has to say it.
//   - Stage's zero value is StageUnset and Stage.Provenance() errors on it.
//   - Target's zero value is unsealed and Constructed() is false for it.
//
// # Allowlists, by identity
//
// The containment assertions are allowlists keyed on identity, never denylists
// and never position:
//
//   - The authorized service's container is found by matching the Compose
//     service label against target.AuthorizedService.Authorizes -- never by
//     taking containers[0].
//   - Mount types are allowlisted to {volume, tmpfs}. That is what excludes a
//     docker.sock mount, and it excludes EVERY spelling of it --
//     /var/run/docker.sock, /run/docker.sock, a symlink to either, and the
//     Windows named pipe -- because all of them arrive as a bind or an npipe.
//     A denylist of the path string loses to the second spelling.
//   - SecurityOpt entries are allowlisted to one exact string. That is what
//     excludes `seccomp=unconfined` without ever naming it.
//   - NetworkMode must name a network of THIS Compose project, which excludes
//     host, none, bridge, an external network, and container: sharing.
//
// # Forbidden, per plan/50-dast.md:349-378
//
// There is no fallback to a non-gVisor runtime. If `runsc` is not configured,
// or is configured on a platform other than the declared one, provisioning
// refuses before any container starts -- TestRunscUnavailableStartsNothing
// asserts the runner was never called. There is no flag, option or environment
// variable in this package that relaxes any assertion in it; widening one is a
// visible edit to this file.
package containment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/target"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// Declared constants
// ---------------------------------------------------------------------------

const (
	// RuntimeName is the ONLY container runtime a target may run under.
	// research/19-target-environment-and-sandboxing.md, concrete v1 stack
	// step 2: gVisor `runsc`. plan/50-dast.md forbids a fallback to any
	// other runtime, so this is a single constant and not a list.
	RuntimeName = "runsc"

	// RuntimePlatform is the ONLY gVisor platform accepted. `systrap`
	// requires no /dev/kvm and works inside nested VMs and CI runners
	// (research 19 step 2). `kvm` is refused today -- not because it is
	// unsafe but because it is undeclared, and admitting an undeclared
	// platform is how a runtime assumption stops being checked.
	RuntimePlatform = "systrap"

	// ComposeProjectLabel and ComposeServiceLabel are the labels Compose
	// stamps on every container it creates. The service label is the
	// IDENTITY the authorized service is matched on.
	ComposeProjectLabel = "com.docker.compose.project"
	ComposeServiceLabel = "com.docker.compose.service"

	// projectPrefix namespaces every Compose project Anvil creates, so that
	// a teardown (`down -v`, which destroys volumes) can never be aimed at a
	// project the operator created.
	projectPrefix = "anvil-"

	// projectHashHexLen is how much of the project fingerprint appears in
	// the project name. Compose project names have to stay short and
	// [a-z0-9-]; 16 hex characters is 64 bits of the SHA-256.
	projectHashHexLen = 16

	// digestHexLen is the length of a sha256 hex digest.
	digestHexLen = 64

	// digestPrefix is the only digest algorithm this package accepts. An
	// image identified by anything else is an image we cannot pin, and
	// research 19 risk #3 is explicit that the record carries the digest and
	// not the tag.
	digestPrefix = "sha256:"

	// teardownGrace bounds how long a destroy-and-recreate teardown may take
	// after a failure. It is a cap, never a wait.
	teardownGrace = 60 * time.Second

	// DefaultBuildBudget bounds BUILD, PULL, CREATE and START -- everything
	// before the health wait begins.
	//
	// IT IS A SEPARATE BUDGET FROM health.timeout_seconds, AND THAT IS THE
	// FIX. The declared health timeout used to be the total budget for the
	// whole `compose up`, which collapsed two failures with two different
	// operator fixes into one:
	//
	//   - a slow image build is the ORDINARY case on a cold cache. Spending
	//     the health budget on `docker build` leaves the health wait whatever
	//     is left, which on a cold cache is nothing, so a target that boots
	//     perfectly well is recorded boot_failed and the operator is sent to
	//     debug a healthcheck that never ran.
	//   - the manifest field is called health.timeout_seconds. D.1 validates
	//     it against health.interval_seconds -- "the health check would never
	//     poll" -- so D.1 already treats it as a POLLING budget. Using it as
	//     a build budget here is this package disagreeing with the type that
	//     owns the field.
	//
	// NOTHING ENFORCES THE SPLIT AT THE PHASE BOUNDARY, because the boundary
	// is inside `docker compose up` and no implementation of the Docker seam
	// exists. The two budgets are a contract stated in that interface's doc,
	// and internal/SKIPPED-CONTROLS.md U2a records that nobody has honoured
	// it yet, along with the fixture that would settle it.
	//
	// It is a compiled-in constant and not a manifest field on purpose:
	// nothing in this package is configurable (see Provisioner), and D.1's
	// schema is not this packet's to extend. It is a POLICY BOUND, chosen and
	// not measured -- no cold-cache build was timed on this host, because
	// this host has no Docker -- and it is deliberately generous, because the
	// failure direction of a budget that is too large is a slow refusal while
	// the failure direction of one that is too small is a correct target
	// recorded as broken.
	DefaultBuildBudget = 15 * time.Minute
)

// allowedSecurityOpt is the complete set of `--security-opt` values a
// contained container may carry. It is an allowlist of exact strings: anything
// not in it refuses, including `seccomp=unconfined`, which this package
// therefore never has to name.
var allowedSecurityOpt = map[string]bool{
	"no-new-privileges:true": true,
}

// allowedMountTypes is the complete set of mount types a contained container
// may carry. `bind` and `npipe` are absent, which is what makes a docker.sock
// mount structurally impossible rather than string-matched.
var allowedMountTypes = map[string]bool{
	"volume": true,
	"tmpfs":  true,
}

// allowedIpcModes is the complete set of IPC modes. `shareable` is absent: it
// lets a container outside the assertion set join this one's IPC namespace.
var allowedIpcModes = map[string]bool{
	"":        true,
	"private": true,
}

// requiredDroppedCapability is the capability set every contained container
// must drop. research 19 step 2: `--cap-drop=ALL` underneath gVisor
// regardless.
const requiredDroppedCapability = "ALL"

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

// ErrRefused wraps every refusal this package produces, so a caller can
// errors.Is against one sentinel instead of string-matching diagnostics.
var ErrRefused = errors.New("containment: provisioning refused")

// The typed refusals. Each is joined with ErrRefused inside a *ProvisionError,
// which also carries the Stage and the record.TargetProvenance.
//
// ErrHealthTimeout and ErrRunscUnavailable are the two plan/50-dast.md:349-378
// names verbatim; the rest exist because the plan's two names cannot express
// five distinct provenance outcomes, and collapsing them is the thing this
// packet must not do.
var (
	// ErrNoTargetDeclared: Provision was called with no manifest. Provenance
	// no_target_declared. NOT a boot failure and NOT an internal error --
	// this is the D.1 skip path arriving here so that the record fields are
	// produced in one place.
	ErrNoTargetDeclared = errors.New("no target manifest was declared")

	// ErrManifestIncomplete: a manifest arrived that names no authorized
	// service or no health definition. plan/50-dast.md: "No health
	// definition means no DAST -- provisioning aborts."
	ErrManifestIncomplete = errors.New("target manifest declares no authorized service or no health check")

	// ErrDockerUnavailable: the container engine could not be queried.
	ErrDockerUnavailable = errors.New("container engine is unavailable")

	// ErrRunscUnavailable: gVisor runsc is not configured, or is configured
	// on an undeclared platform. There is no fallback.
	ErrRunscUnavailable = errors.New("gVisor runsc is not available on the declared platform")

	// ErrComposeFileMissing: the declared Compose file is not on disk.
	ErrComposeFileMissing = errors.New("declared compose file does not exist")

	// ErrBuildFailed: the image never built or pulled.
	ErrBuildFailed = errors.New("target image never built")

	// ErrStartFailed: the image existed and the container would not start.
	ErrStartFailed = errors.New("target container would not start")

	// ErrHealthTimeout: the declared health timeout elapsed before the
	// authorized service reported healthy. A timeout, never a hang.
	//
	// IT IS RETURNED ONLY WHEN THE RUNNER SAYS SO. A deadline that elapsed
	// while the runner reported nothing is ErrUpBudgetExhausted, because
	// "the health wait timed out" is a claim about a phase and the clock
	// cannot see phases.
	ErrHealthTimeout = errors.New("target never became healthy within the declared timeout")

	// ErrUpBudgetExhausted: the whole `up` budget elapsed and the runner
	// returned no status at all, so WHICH phase consumed it is unknown.
	//
	// It exists because collapsing this into ErrHealthTimeout was a guess
	// presented as a diagnosis: an ordinary cold-cache image build that
	// overran was recorded as a target that would not go healthy, and the
	// operator was sent to debug a healthcheck that had not yet run.
	ErrUpBudgetExhausted = errors.New("the container runner's whole up budget elapsed without a reported phase")

	// ErrNotHealthy: the runner reported the project up, and the authorized
	// service's container is not running-and-healthy. This is what catches a
	// Compose service with no healthcheck, which satisfies `--wait`
	// instantly and would otherwise read as a clean boot.
	ErrNotHealthy = errors.New("authorized service is not running and healthy")

	// ErrRunnerContract: the runner returned a shape this package cannot
	// interpret -- no status, an unknown status, or a project it claims is
	// up with no containers in it.
	ErrRunnerContract = errors.New("container runner returned an uninterpretable result")

	// ErrServiceNotFound: no container in the project carries the authorized
	// service's Compose label.
	ErrServiceNotFound = errors.New("authorized service has no container in the project")

	// ErrServiceAmbiguous: more than one container carries it. Picking one
	// would be an allowlist matched by position.
	ErrServiceAmbiguous = errors.New("authorized service resolves to more than one container")

	// ErrForeignContainer: a container appeared in the project listing whose
	// project label is not this project. Asserting containment on it, or
	// tearing it down, would be acting on somebody else's container.
	ErrForeignContainer = errors.New("container listing contains a container from another project")

	// ErrContainmentViolated: a container in the project is not contained.
	// Runtime, privilege, capabilities, mounts, namespaces or rootfs.
	ErrContainmentViolated = errors.New("project container is not contained")

	// ErrDigestUnresolved: the authorized service's image cannot be pinned
	// to a sha256 digest. research 19 risk #3: the record carries the
	// digest, not the tag -- an unpinnable image makes the record
	// uninterpretable, so it refuses rather than recording a tag.
	ErrDigestUnresolved = errors.New("authorized service image has no resolvable sha256 digest")

	// ErrUnreachable: the target is healthy by its own healthcheck and the
	// probe side cannot reach its declared health URL. Provenance
	// unreachable_at_scan_time, which is neither a boot failure nor clean.
	ErrUnreachable = errors.New("target is healthy but its health URL is not reachable from the probe side")
)

// ---------------------------------------------------------------------------
// Stage -- every exit path, and the one provenance it names
// ---------------------------------------------------------------------------

// Stage is where a provisioning attempt ended. It exists because
// record.TargetProvenance has five values and provisioning has more than five
// ways to fail: the Stage carries the operator-actionable detail, the
// provenance carries the frozen record fact, and Stage.Provenance() is the one
// mapping between them.
//
// FAIL CLOSED: StageUnset is the zero value, is not a legal stage, and
// Provenance() refuses it.
type Stage string

// The stages. Read the Provenance() switch below with this list: every stage
// appears there exactly once.
const (
	// StageUnset is the zero value and is not a legal outcome.
	StageUnset Stage = ""

	// StageNoTargetDeclared: nothing to provision.
	StageNoTargetDeclared Stage = "no_target_declared"

	// StagePreflightManifest: a manifest arrived that cannot be provisioned
	// from -- no authorized service, or no health definition.
	StagePreflightManifest Stage = "preflight_manifest"

	// StagePreflightEngine: the container engine could not be queried.
	StagePreflightEngine Stage = "preflight_engine"

	// StagePreflightRuntime: runsc is absent or on an undeclared platform.
	StagePreflightRuntime Stage = "preflight_runtime"

	// StagePreflightComposeFile: the declared Compose file is not on disk.
	StagePreflightComposeFile Stage = "preflight_compose_file"

	// StageBuild: the image never built or pulled.
	StageBuild Stage = "build"

	// StageStart: the image existed and the container would not start.
	StageStart Stage = "start"

	// StageHealth: the health timeout elapsed, or the authorized service is
	// not running-and-healthy once the runner claimed the project was up.
	StageHealth Stage = "health"

	// StageUpBudget: the whole `up` budget elapsed with the runner reporting
	// no phase, so which phase consumed it is unknown. Distinct from
	// StageBuild, StageStart and StageHealth precisely because it is the
	// stage that does not know which of them it was.
	StageUpBudget Stage = "up_budget"

	// StageRunnerContract: the runner returned something uninterpretable.
	StageRunnerContract Stage = "runner_contract"

	// StageEnumerate: the project's containers could not be listed.
	StageEnumerate Stage = "enumerate"

	// StageContainment: a container in the project is not contained.
	StageContainment Stage = "containment"

	// StageIdentifyService: the authorized service resolves to zero or to
	// more than one container.
	StageIdentifyService Stage = "identify_service"

	// StageDigest: the authorized service's image cannot be pinned.
	StageDigest Stage = "digest"

	// StageReachability: healthy, and not reachable from the probe side.
	StageReachability Stage = "reachability"
)

// StageValues returns every legal Stage, excluding the zero value.
//
// TestEveryStageNamesOneProvenance walks this list, so a stage added to the
// constants above and forgotten here is caught by
// TestStageValuesCoversEveryDeclaredStage, which reads this file's own source.
func StageValues() []Stage {
	return []Stage{
		StageNoTargetDeclared,
		StagePreflightManifest,
		StagePreflightEngine,
		StagePreflightRuntime,
		StagePreflightComposeFile,
		StageBuild,
		StageStart,
		StageHealth,
		StageUpBudget,
		StageRunnerContract,
		StageEnumerate,
		StageContainment,
		StageIdentifyService,
		StageDigest,
		StageReachability,
	}
}

// Valid reports whether s is one of the legal stages. StageUnset is not.
func (s Stage) Valid() bool {
	for _, v := range StageValues() {
		if s == v {
			return true
		}
	}
	return false
}

// Provenance maps a stage onto the one record.TargetProvenance literal it
// means. This is the function the whole packet turns on.
//
// THE BUILD/BOOT SPLIT IS THE POINT, and the line is drawn at "did a container
// process of the target ever exist":
//
//   - Everything BEFORE the runner is asked to bring the project up maps to
//     build_failed. record.TargetProvenanceBuildFailed reads "the target image
//     never built, so a boot was never attempted", which is exactly true of a
//     missing engine, a missing runsc, a missing Compose file and an
//     unprovisionable manifest: no image was produced and no boot was tried.
//   - Everything AFTER maps to boot_failed, because by then an image existed.
//
// WHAT THAT COSTS, STATED RATHER THAN HIDDEN: a scanning host with no Docker
// and a repo with a broken Dockerfile both record build_failed. Those are
// different problems with different fixes, and the frozen five-value enum has
// no literal for "the scanning host lacks the runtime". The Stage carries the
// difference (StagePreflightEngine versus StageBuild), it is on the
// *ProvisionError and in its message, and it is what an operator reads. The
// alternative -- inventing a sixth provenance literal -- is a change to a
// frozen enum in area 40 and is not this packet's to make. Reported to the
// orchestrator.
//
// StageReachability is the ONLY stage that maps to unreachable_at_scan_time,
// and StageNoTargetDeclared is the only one that maps to no_target_declared.
// No stage maps to booted_clean: that literal is reachable only by returning a
// sealed Target from Provision.
func (s Stage) Provenance() (record.TargetProvenance, error) {
	switch s {
	case StageNoTargetDeclared:
		return record.TargetProvenanceNoTargetDeclared, nil

	case StagePreflightManifest,
		StagePreflightEngine,
		StagePreflightRuntime,
		StagePreflightComposeFile,
		StageBuild:
		return record.TargetProvenanceBuildFailed, nil

	case StageStart,
		StageHealth,
		StageUpBudget,
		StageRunnerContract,
		StageEnumerate,
		StageContainment,
		StageIdentifyService,
		StageDigest:
		return record.TargetProvenanceBootFailed, nil

	case StageReachability:
		return record.TargetProvenanceUnreachableAtScanTime, nil

	case StageUnset:
		return "", fmt.Errorf("containment: the zero Stage names no outcome; a refusal "+
			"must say which of the %d stages it ended at", len(StageValues()))

	default:
		return "", fmt.Errorf("containment: %q is not a legal Stage", string(s))
	}
}

// ---------------------------------------------------------------------------
// ProvisionError
// ---------------------------------------------------------------------------

// ProvisionError is every refusal. It carries the Stage, the frozen
// record.TargetProvenance that stage means, and the typed sentinel, so that a
// caller can switch on any of the three and none of them can disagree --
// provenance is derived from stage at construction and is never set directly.
type ProvisionError struct {
	stage      Stage
	provenance record.TargetProvenance
	sentinel   error
	detail     string

	// teardown is a non-nil teardown failure that happened while cleaning up
	// after the primary refusal. It is reported and it never changes the
	// provenance: the primary failure is the operator's story.
	teardown error
}

// refuse builds a *ProvisionError. It is the only constructor, so a refusal
// cannot exist without a stage, and a stage that names no provenance turns
// into a loud internal refusal rather than an empty record field.
func refuse(stage Stage, sentinel error, format string, args ...any) *ProvisionError {
	prov, err := stage.Provenance()
	if err != nil {
		// A stage this file did not map. Fail closed onto boot_failed --
		// never onto booted_clean -- and say so.
		return &ProvisionError{
			stage:      StageRunnerContract,
			provenance: record.TargetProvenanceBootFailed,
			sentinel:   ErrRunnerContract,
			detail: fmt.Sprintf("internal: %v (original refusal: %s)",
				err, fmt.Sprintf(format, args...)),
		}
	}
	return &ProvisionError{
		stage:      stage,
		provenance: prov,
		sentinel:   sentinel,
		detail:     fmt.Sprintf(format, args...),
	}
}

// Error renders stage, provenance and detail together, because an operator
// reading a log line needs all three.
func (e *ProvisionError) Error() string {
	msg := fmt.Sprintf("containment: refused at stage %q (target.provenance=%q): %v: %s",
		string(e.stage), string(e.provenance), e.sentinel, e.detail)
	if e.teardown != nil {
		msg += fmt.Sprintf(" [teardown also failed: %v]", e.teardown)
	}
	return msg
}

// Unwrap exposes both ErrRefused and the typed sentinel, so errors.Is works
// against either.
func (e *ProvisionError) Unwrap() []error { return []error{ErrRefused, e.sentinel} }

// Stage returns where the attempt ended.
func (e *ProvisionError) Stage() Stage { return e.stage }

// Provenance returns the frozen anvil/target.provenance literal for this
// refusal. It is never empty and never booted_clean.
func (e *ProvisionError) Provenance() record.TargetProvenance { return e.provenance }

// TeardownError returns a teardown failure that happened while cleaning up, or
// nil. Callers that need to alert on leaked containers read this.
func (e *ProvisionError) TeardownError() error { return e.teardown }

// Provisioning returns which provisioning path was taken.
//
// It returns an error for StageNoTargetDeclared, and that is deliberate:
// record.TargetProvisioning has exactly two literals and both of them assert
// that a target existed. There was no provisioning path when no target was
// declared, so this refuses to name one rather than writing a false
// ephemeral_manifest into the record. The caller omits the field.
func (e *ProvisionError) Provisioning() (record.TargetProvisioning, error) {
	if e.stage == StageNoTargetDeclared {
		return "", fmt.Errorf("containment: no provisioning path was taken (%w); "+
			"anvil/target.provisioning has no literal for that and must be omitted",
			ErrNoTargetDeclared)
	}
	return record.TargetProvisioningEphemeralManifest, nil
}

// ---------------------------------------------------------------------------
// The Docker seam
// ---------------------------------------------------------------------------

// Docker is the ONE boundary between this package and the container runtime.
//
// Nothing in this package shells out, opens a socket, or imports a client. A
// real implementation of this interface is a separate concern and is NOT
// provided here -- see internal/SKIPPED-CONTROLS.md entry U2 for what remains
// unproven without one and exactly what would settle it.
//
// THE CONTRACT AN IMPLEMENTATION OWES, stated here because the compiler cannot
// state it:
//
//  1. EngineInfo must report the runtimes the ENGINE is actually configured
//     with, and must leave RuntimeInfo.Platform empty when it cannot determine
//     the platform. An empty platform refuses. Guessing `systrap` because it
//     is the gVisor default is the failure mode this sentence exists to
//     forbid.
//  2. ComposeUp must apply UpRequest.Runtime to EVERY service in the project,
//     not just the authorized one. A sibling database running under runc is an
//     uncontained process on the same host. This package does not trust that:
//     it re-checks the observed Runtime of every container afterwards, which
//     is the check that can see the damage if the implementation gets it
//     wrong.
//  3. ComposeUp must classify its failure into an UpStatus. Returning
//     UpStatusUnreported refuses.
//  4. ProjectContainers must return every container Compose created for the
//     project, including ones that have exited, and must populate the Compose
//     project and service labels. A container omitted from this list is a
//     container whose containment is never asserted.
//  5. ProbeHealth must issue its probe from where the PROBE ENGINE lives, not
//     from inside the target container. Compose healthchecks run inside the
//     container; a container can be healthy by its own healthcheck and
//     unreachable from the probe side, and that difference is the whole reason
//     record.TargetProvenanceUnreachableAtScanTime exists.
type Docker interface {
	// EngineInfo reports the engine's configured runtimes. An error means
	// the engine is unavailable.
	EngineInfo(ctx context.Context) (EngineInfo, error)

	// ComposeUp brings the project up and waits for health. It must respect
	// ctx, which always carries the declared hard timeout.
	ComposeUp(ctx context.Context, req UpRequest) (UpResult, error)

	// ProjectContainers lists every container Compose created for project.
	ProjectContainers(ctx context.Context, project string) ([]Container, error)

	// ComposeDown destroys the project. Volumes included when requested.
	ComposeDown(ctx context.Context, req DownRequest) error

	// ProbeHealth issues one liveness probe at healthURL from the probe
	// side. A nil error means reachable.
	ProbeHealth(ctx context.Context, healthURL string) error
}

// EngineInfo is the recorded shape of an engine capability query.
type EngineInfo struct {
	// Runtimes is keyed by runtime name. A nil map refuses, which is the
	// fail-closed reading of "the engine told us nothing".
	Runtimes map[string]RuntimeInfo
}

// RuntimeInfo is one configured runtime.
type RuntimeInfo struct {
	// Path is the runtime binary as the engine has it configured. Recorded
	// for the audit trail; not asserted on, because the path is not the
	// identity -- the name and the platform are.
	Path string

	// Platform is the gVisor platform this runtime is configured for,
	// derived by the implementation from the engine's runtime args. EMPTY
	// MEANS UNKNOWN AND REFUSES.
	Platform string
}

// UpRequest is exactly what this package asks the runner to do. Its fields are
// asserted in TestUpRequestIsFailClosed, because the request is the other half
// of the containment story: the observed containers prove what happened, the
// request proves what was asked for.
type UpRequest struct {
	// Project is Anvil's own Compose project name. Always projectPrefix +
	// fingerprint, so a teardown cannot be aimed at an operator's project.
	Project string

	// ComposeFile is the absolute path to the operator's declared file.
	ComposeFile string

	// Runtime is always RuntimeName. There is no code path that sets it to
	// anything else and no option that changes it.
	Runtime string

	// RuntimePlatform is always RuntimePlatform.
	RuntimePlatform string

	// WaitForHealthy is always true: `up -d --wait`, blocking on
	// healthcheck and depends_on: condition: service_healthy.
	WaitForHealthy bool

	// BuildTimeout is the budget for BUILD, PULL, CREATE and START -- always
	// DefaultBuildBudget. It is NOT the operator's health timeout; see that
	// constant for why the two are separate.
	BuildTimeout time.Duration

	// Timeout is the manifest's declared health timeout, and it is the budget
	// for the HEALTH WAIT ALONE.
	//
	// The context passed to ComposeUp carries BuildTimeout+Timeout, so a
	// runner that ignores both fields is still bounded and cannot hang this
	// call. That outer deadline is a backstop, not the contract: an
	// implementation is expected to apply the two budgets to the two phases,
	// because only the implementation knows where the boundary is.
	Timeout time.Duration

	// ForceRecreate is always true. reset.strategy is destroy_recreate and
	// it is the only strategy v1 has; reusing a container from a previous
	// scan would be a snapshot restore by accident.
	ForceRecreate bool

	// RemoveOrphans is always true, so a container left by an earlier
	// version of the operator's Compose file is destroyed rather than left
	// running uncontained inside the project.
	RemoveOrphans bool
}

// DownRequest is a destroy. RemoveVolumes is always true: research 19 step 5,
// reset by destroy-and-recreate (`docker compose down -v`), never by snapshot.
type DownRequest struct {
	Project       string
	RemoveVolumes bool
}

// UpStatus is how a ComposeUp attempt ended.
//
// FAIL CLOSED: the zero value is UpStatusUnreported and it REFUSES. Success is
// the non-zero literal UpStatusUp, so a runner that returns an empty
// UpResult{} cannot be read as having brought anything up.
type UpStatus string

// The up statuses.
const (
	// UpStatusUnreported is the zero value. Not success.
	UpStatusUnreported UpStatus = ""
	// UpStatusUp: every service is up and the waited-on services are
	// healthy.
	UpStatusUp UpStatus = "up"
	// UpStatusBuildFailed: an image never built or pulled. No boot was
	// attempted.
	UpStatusBuildFailed UpStatus = "build_failed"
	// UpStatusStartFailed: an image existed and a container would not start.
	UpStatusStartFailed UpStatus = "start_failed"
	// UpStatusHealthTimeout: containers started and the wait elapsed.
	UpStatusHealthTimeout UpStatus = "health_timeout"
)

// UpResult is the recorded shape a runner returns.
type UpResult struct {
	Status UpStatus
	// Detail is runner diagnostics, carried into the refusal message.
	Detail string
}

// ContainerState is the observed lifecycle state.
//
// FAIL CLOSED: the zero value is StateUnknown and it is not running.
type ContainerState string

// The container states this package distinguishes.
const (
	StateUnknown ContainerState = ""
	StateCreated ContainerState = "created"
	StateRunning ContainerState = "running"
	StateExited  ContainerState = "exited"
	StateDead    ContainerState = "dead"
	StateRemoved ContainerState = "removed"
)

// Health is the observed healthcheck state.
//
// FAIL CLOSED: the zero value is HealthNone -- which is what `docker inspect`
// reports for a container with NO healthcheck at all -- and it is not healthy.
// That is the check that catches a Compose service without a healthcheck,
// which satisfies `up --wait` instantly and would otherwise boot clean.
type Health string

// The health states.
const (
	HealthNone      Health = ""
	HealthStarting  Health = "starting"
	HealthHealthy   Health = "healthy"
	HealthUnhealthy Health = "unhealthy"
)

// Container is the recorded shape of one `docker inspect` result, reduced to
// the fields this package decides on. Every field here is either an identity
// (labels, image) or something a containment assertion reads.
type Container struct {
	ID      string
	Name    string
	Project string // com.docker.compose.project
	Service string // com.docker.compose.service

	Image       string   // the tag, as written. Recorded, never recorded ALONE.
	ImageID     string   // sha256:... content address
	RepoDigests []string // repo@sha256:... entries, when the image came from a registry

	Runtime string
	State   ContainerState
	Health  Health

	Privileged     bool
	CapAdd         []string
	CapDrop        []string
	SecurityOpt    []string
	ReadonlyRootfs bool
	NetworkMode    string
	PidMode        string
	IpcMode        string
	UsernsMode     string
	Devices        []string
	Mounts         []Mount
}

// Mount is one entry of a container's Mounts array.
//
// EVERY FIELD IS A VALUE. If one ever stops being -- a slice of options, a
// pointer to a source -- Container.clone below must deep-copy it too, and
// TestContainerCloneCoversEveryReferenceField is what turns that omission into
// a failure instead of an aliasing bug.
type Mount struct {
	Type        string
	Source      string
	Destination string
	ReadOnly    bool
}

// clone returns a Container that shares NO memory with the receiver.
//
// THIS IS THE Scope.Ports DEFECT, AND IT HAPPENED TWICE.
//
// Containers() used to be `copy(out, t.containers)`, which is a shallow copy:
// the Container structs were duplicated and every SLICE INSIDE them -- Mounts,
// SecurityOpt, CapDrop, CapAdd, Devices, RepoDigests -- still pointed at the
// sealed Target's backing arrays. A caller holding the "copy" could rewrite
// the audit trail containment was asserted against, and demonstrably did:
// against the suite's own healthyWorld fixture, writing through the returned
// value made the sealed Target report a docker.sock bind mount,
// seccomp=unconfined, and CapDrop of nothing.
//
// It survived review for the same reason the identical defect survived in
// authz's Scope.Ports: the test mutated ONE STRING FIELD -- the single place
// where a shallow copy happens to be real -- and passed. A test that mutates
// only where the copy is real proves nothing.
//
// So: every reference-typed field is cloned here, TestContainersReturnsACopy
// mutates EVERY field of the returned value including every slice element, and
// TestContainerCloneCoversEveryReferenceField walks the struct by reflection so
// that a field added later cannot be forgotten in both places at once.
func (c Container) clone() Container {
	out := c
	out.RepoDigests = cloneStrings(c.RepoDigests)
	out.CapAdd = cloneStrings(c.CapAdd)
	out.CapDrop = cloneStrings(c.CapDrop)
	out.SecurityOpt = cloneStrings(c.SecurityOpt)
	out.Devices = cloneStrings(c.Devices)
	if c.Mounts != nil {
		// Mount is all value fields (see its doc), so element assignment is a
		// complete copy of each entry.
		out.Mounts = make([]Mount, len(c.Mounts))
		copy(out.Mounts, c.Mounts)
	}
	return out
}

// cloneStrings preserves the nil/empty distinction. A nil slice that came back
// as an empty one would be a difference a caller could observe, and an audit
// trail that reports `CapAdd: []` where the container reported `CapAdd: null`
// is reporting something that did not happen.
func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// cloneContainers deep-copies a whole listing.
func cloneContainers(in []Container) []Container {
	if in == nil {
		return nil
	}
	out := make([]Container, len(in))
	for i := range in {
		out[i] = in[i].clone()
	}
	return out
}

// ---------------------------------------------------------------------------
// Target
// ---------------------------------------------------------------------------

// Target is a live, contained, health-proven, digest-pinned target.
//
// FAIL CLOSED: the zero value is unsealed. Constructed() is false for it and
// Provenance() returns the empty string, which record.ValidateTargetProvenance
// refuses -- so a Target that was never returned by Provision cannot be
// written into a record as booted_clean.
//
// EXACTLY ONE SERVICE, STRUCTURALLY: the authorized service is held as a
// target.AuthorizedService, which is D.1's one-service-by-type. There is no
// slice of services anywhere in this struct or its API. Every other container
// in the project was provisioned for realistic dependencies, had its
// containment asserted, and is not a probe target; Containers() returns them
// for the audit trail and returns them as a COPY.
type Target struct {
	sealed bool

	docker  Docker
	service target.AuthorizedService

	project     string
	containerID string
	imageRef    string
	imageDigest string
	runtime     string
	platform    string
	healthURL   string

	containers []Container

	provenance   record.TargetProvenance
	provisioning record.TargetProvisioning
}

// Constructed reports whether this Target came out of a successful Provision.
func (t *Target) Constructed() bool {
	return t != nil && t.sealed && t.provenance == record.TargetProvenanceBootedClean
}

// AuthorizedService returns the single service Anvil may probe. It is D.1's
// type, so a caller cannot widen it to a set.
func (t *Target) AuthorizedService() target.AuthorizedService {
	if t == nil {
		return target.AuthorizedService{}
	}
	return t.service
}

// Project returns Anvil's Compose project name for this target.
func (t *Target) Project() string {
	if t == nil {
		return ""
	}
	return t.project
}

// ContainerID returns the authorized service's container ID.
func (t *Target) ContainerID() string {
	if t == nil {
		return ""
	}
	return t.containerID
}

// ImageDigest returns the resolved sha256 digest of the authorized service's
// image. research 19 risk #3: this, not the tag, is what the record carries.
func (t *Target) ImageDigest() string {
	if t == nil {
		return ""
	}
	return t.imageDigest
}

// ImageRef returns the image reference as written in the Compose file. It is
// context for a human and is never a substitute for ImageDigest.
func (t *Target) ImageRef() string {
	if t == nil {
		return ""
	}
	return t.imageRef
}

// Runtime returns the observed container runtime, which Provision has already
// asserted equals RuntimeName.
func (t *Target) Runtime() string {
	if t == nil {
		return ""
	}
	return t.runtime
}

// Platform returns the gVisor platform the engine has runsc configured for,
// which Provision has already asserted equals RuntimePlatform.
func (t *Target) Platform() string {
	if t == nil {
		return ""
	}
	return t.platform
}

// HealthURL returns the manifest's declared health URL.
func (t *Target) HealthURL() string {
	if t == nil {
		return ""
	}
	return t.healthURL
}

// Containers returns a DEEP copy of every container in the project, for the
// audit trail. It is a copy so that a caller cannot mutate what containment was
// asserted against, and it is emphatically NOT a list of probe targets.
//
// "Copy" here means Container.clone, not `copy`. Read that function before
// changing this one: the shallow version satisfied this doc comment's wording
// and did not satisfy its claim.
func (t *Target) Containers() []Container {
	if t == nil || len(t.containers) == 0 {
		return nil
	}
	return cloneContainers(t.containers)
}

// Provenance returns record.TargetProvenanceBootedClean for a sealed Target
// and the empty string otherwise.
func (t *Target) Provenance() record.TargetProvenance {
	if !t.Constructed() {
		return ""
	}
	return t.provenance
}

// Provisioning returns which provisioning path produced this target. It is
// D.1's value, taken from the manifest, not re-derived here.
func (t *Target) Provisioning() record.TargetProvisioning {
	if !t.Constructed() {
		return ""
	}
	return t.provisioning
}

// Teardown destroys the project, volumes included. reset.strategy
// destroy_recreate is the only v1 strategy and this is it.
func (t *Target) Teardown(ctx context.Context) error {
	if t == nil || !t.sealed {
		return fmt.Errorf("containment: %w: teardown of an unsealed target", ErrRefused)
	}
	return teardown(ctx, t.docker, t.project)
}

// ---------------------------------------------------------------------------
// Provisioner
// ---------------------------------------------------------------------------

// Provisioner brings declared targets up. It holds the Docker seam and the
// repo root that Compose paths resolve against.
//
// There is deliberately no Options struct and no functional option: nothing
// about the containment assertions, the runtime, or the platform is
// configurable. plan/50-dast.md forbids a fallback to a non-gVisor runtime,
// and a config key that turns an assertion off is that fallback wearing a
// different hat.
type Provisioner struct {
	docker   Docker
	repoRoot string
}

// NewProvisioner refuses a nil seam and an empty repo root, so a Provisioner
// that exists is one that can decide.
func NewProvisioner(d Docker, repoRoot string) (*Provisioner, error) {
	if d == nil {
		return nil, fmt.Errorf("containment: %w: no container runtime seam", ErrRefused)
	}
	if strings.TrimSpace(repoRoot) == "" {
		return nil, fmt.Errorf("containment: %w: empty repo root; compose_file is "+
			"resolved against it and there is nothing to resolve against", ErrRefused)
	}
	return &Provisioner{docker: d, repoRoot: repoRoot}, nil
}

// Provision brings up the declared target and returns it sealed, or refuses
// with a *ProvisionError naming one of the five record.TargetProvenance
// outcomes.
//
// WHAT booted_clean DOES NOT MEAN. This function proves the container came up
// under gVisor with no host bind mounts, no added capabilities, no host
// namespaces and a read-only rootfs. It does NOT install the default-deny
// egress ruleset and it does NOT run the containment canary -- netns.go's
// SetupNetns and AssertContainment are separate exported functions and nothing
// in the tree calls either. A caller that fires probes on the strength of
// booted_clean alone is asserting a network containment nobody established.
// Recorded in internal/SKIPPED-CONTROLS.md as U1c; wiring it belongs to the
// integration packet.
//
// The order below is the contract, and it is ordered so that nothing starts
// before everything that could refuse has refused:
//
//  1. no manifest              -> no_target_declared, nothing called
//  2. manifest unprovisionable -> build_failed,       nothing called
//  3. engine unavailable       -> build_failed,       nothing started
//  4. runsc unavailable        -> build_failed,       nothing started
//  5. compose file missing     -> build_failed,       nothing started
//  6. up: build failed         -> build_failed
//  7. up: start failed         -> boot_failed
//  8. up: health timed out     -> boot_failed
//  9. containers unlistable    -> boot_failed
//  10. any container uncontained -> boot_failed
//  11. service not found / ambiguous -> boot_failed
//  12. service not running+healthy   -> boot_failed
//  13. image unpinnable         -> boot_failed
//  14. health URL unreachable   -> unreachable_at_scan_time
//  15. otherwise                -> booted_clean
//
// Steps 6 onward tear the project down before returning. Steps 1-5 have
// nothing to tear down and call nothing, which
// TestRunscUnavailableStartsNothing asserts directly against the seam's call
// log.
func (p *Provisioner) Provision(ctx context.Context, m *target.Manifest) (*Target, error) {
	if p == nil || p.docker == nil {
		return nil, refuse(StagePreflightEngine, ErrDockerUnavailable,
			"provisioner was never constructed by NewProvisioner")
	}

	// 1. No target declared. This is D.1's skip path arriving here so that
	// the record fields are produced in exactly one place.
	if m == nil {
		return nil, refuse(StageNoTargetDeclared, ErrNoTargetDeclared,
			"Provision was called with no manifest; the DAST half has nothing to scan "+
				"and this is not a boot failure")
	}

	// 2. A manifest that cannot be provisioned from. target.Load cannot
	// produce one, but target.Parse and a hand-built &target.Manifest{} can,
	// and a zero-value manifest must not read as a provisionable one.
	svc := m.AuthorizedService()
	if svc.IsZero() {
		return nil, refuse(StagePreflightManifest, ErrManifestIncomplete,
			"the manifest names no authorized service; exactly one service is "+
				"authorized and no code path here picks one")
	}
	if strings.TrimSpace(m.Health.URL) == "" {
		return nil, refuse(StagePreflightManifest, ErrManifestIncomplete,
			"the manifest declares no health.url for service %q; no health definition "+
				"means no DAST", svc.Name())
	}
	if m.Health.TimeoutSeconds <= 0 {
		return nil, refuse(StagePreflightManifest, ErrManifestIncomplete,
			"the manifest declares health.timeout_seconds=%d for service %q; a "+
				"non-positive hard timeout is an unbounded wait",
			m.Health.TimeoutSeconds, svc.Name())
	}

	// 3. The engine.
	info, err := p.docker.EngineInfo(ctx)
	if err != nil {
		return nil, refuse(StagePreflightEngine, ErrDockerUnavailable,
			"the container engine could not be queried: %v. No image was built and no "+
				"boot was attempted; the stage, not the provenance, is what says the "+
				"scanning host is the problem rather than the repo", err)
	}

	// 4. gVisor. No fallback: refused here, before anything starts.
	if err := checkRuntime(info); err != nil {
		return nil, refuse(StagePreflightRuntime, ErrRunscUnavailable, "%v", err)
	}

	// 5. The declared Compose file, on disk.
	composePath := m.ComposeFilePath(p.repoRoot)
	if _, err := os.Stat(composePath); err != nil {
		return nil, refuse(StagePreflightComposeFile, ErrComposeFileMissing,
			"compose_file %q resolves to %q, which cannot be read: %v",
			m.ComposeFile, composePath, err)
	}

	project := projectName(p.repoRoot, m.ComposeFile, svc.Name())
	req := UpRequest{
		Project:         project,
		ComposeFile:     composePath,
		Runtime:         RuntimeName,
		RuntimePlatform: RuntimePlatform,
		WaitForHealthy:  true,
		BuildTimeout:    DefaultBuildBudget,
		Timeout:         time.Duration(m.Health.TimeoutSeconds) * time.Second,
		ForceRecreate:   true,
		RemoveOrphans:   true,
	}

	// 6-8. Bring it up under a HARD deadline. The deadline is enforced here
	// as well as passed to the runner, so a runner that ignores its context
	// still cannot hang this call -- it can only leak, and the teardown
	// below is what addresses that.
	//
	// THE DEADLINE IS THE SUM OF THE TWO BUDGETS, not the health budget
	// alone. Cutting the whole `compose up` off at health.timeout_seconds is
	// what used to make an ordinary cold-cache build indistinguishable from a
	// target that would not go healthy. See DefaultBuildBudget.
	upCtx, cancel := context.WithTimeout(ctx, req.BuildTimeout+req.Timeout)
	defer cancel()

	res, upErr := p.docker.ComposeUp(upCtx, req)
	if upErr != nil || res.Status != UpStatusUp {
		return nil, p.refuseAfterUp(ctx, project, req, res, upErr, upCtx.Err())
	}

	// 9. Enumerate. A project the runner says is up with nothing in it is a
	// silent no-op, and a silent no-op is the exact failure mode this
	// packet's checks exist to catch.
	containers, err := p.docker.ProjectContainers(ctx, project)
	if err != nil {
		return nil, p.tearDownAndRefuse(ctx, project, StageEnumerate, ErrRunnerContract,
			"the project's containers could not be listed: %v", err)
	}
	if len(containers) == 0 {
		return nil, p.tearDownAndRefuse(ctx, project, StageEnumerate, ErrRunnerContract,
			"the runner reported project %q up and it contains no containers; a "+
				"provisioning step that reports success and does nothing is the "+
				"silent no-op every check in this file exists to catch", project)
	}

	// 10. Containment, on EVERY container -- the authorized service and each
	// dependency alike. A sibling database under runc is an uncontained
	// process on the same host, and it is uncontained whether or not it is
	// still running, so exited containers are asserted too.
	if err := assertProjectContained(project, containers); err != nil {
		return nil, p.tearDownAndRefuseErr(ctx, project, StageContainment,
			ErrContainmentViolated, err)
	}

	// 11. Identify the authorized service BY IDENTITY. Never containers[0].
	authorized, err := selectAuthorized(svc, containers)
	if err != nil {
		sentinel := ErrServiceNotFound
		if errors.Is(err, errAmbiguous) {
			sentinel = ErrServiceAmbiguous
		}
		return nil, p.tearDownAndRefuseErr(ctx, project, StageIdentifyService, sentinel, err)
	}

	// 12. Running AND healthy. Health is the zero-value trap: a Compose
	// service with no healthcheck reports HealthNone and satisfies `--wait`
	// instantly.
	if authorized.State != StateRunning || authorized.Health != HealthHealthy {
		return nil, p.tearDownAndRefuse(ctx, project, StageHealth, ErrNotHealthy,
			"authorized service %q is state=%q health=%q; it must be state=%q "+
				"health=%q. An empty health means the service declares no healthcheck, "+
				"which satisfies `up --wait` instantly and would otherwise read as a "+
				"clean boot", svc.Name(), string(authorized.State),
			string(authorized.Health), string(StateRunning), string(HealthHealthy))
	}

	// 13. Pin the image by digest, never by tag.
	digest, err := resolveDigest(authorized)
	if err != nil {
		return nil, p.tearDownAndRefuseErr(ctx, project, StageDigest, ErrDigestUnresolved, err)
	}

	// 14. Reachability from the PROBE side. Healthy-by-its-own-healthcheck
	// and reachable-by-the-probe are different facts, and this is the only
	// path to unreachable_at_scan_time.
	if err := p.docker.ProbeHealth(ctx, m.Health.URL); err != nil {
		return nil, p.tearDownAndRefuse(ctx, project, StageReachability, ErrUnreachable,
			"service %q reports healthy and its declared health URL %q is not "+
				"reachable from the probe side: %v", svc.Name(), m.Health.URL, err)
	}

	// 15. Sealed.
	//
	// The snapshot is a DEEP copy on the way IN as well as on the way out.
	// `containers` came from the Docker seam, which is an interface this
	// package does not implement: an implementation that retains and later
	// rewrites the slices it handed over would otherwise be editing the
	// sealed Target's audit trail after containment was asserted against it.
	// The seam is the untrusted half here, exactly as the canary is on the
	// netns side.
	snapshot := cloneContainers(containers)

	return &Target{
		sealed:       true,
		docker:       p.docker,
		service:      svc,
		project:      project,
		containerID:  authorized.ID,
		imageRef:     authorized.Image,
		imageDigest:  digest,
		runtime:      authorized.Runtime,
		platform:     info.Runtimes[RuntimeName].Platform,
		healthURL:    m.Health.URL,
		containers:   snapshot,
		provenance:   record.TargetProvenanceBootedClean,
		provisioning: m.Provisioning(),
	}, nil
}

// refuseAfterUp turns a failed ComposeUp into the right stage.
//
// THE RUNNER'S OWN STATUS IS CONSULTED BEFORE THE CLOCK, and the previous order
// was a defect rather than a preference.
//
// The deadline used to be checked first, so ANY failure that surfaced after the
// budget elapsed was recorded as a health timeout -- boot_failed -- including a
// runner that returned UpStatusBuildFailed. Demonstrated: a seam answering
// UpStatusBuildFailed at timeout+200ms was recorded boot_failed. A slow image
// build is not an exotic input; it is the normal case on a cold cache, and the
// two outcomes send the operator to two different files.
//
// The runner watched the build. The clock watched a stopwatch. When they
// disagree about which phase failed, the one that was there is better evidence,
// and it is not close.
//
// The clock still decides when the runner names NO phase -- UpStatusUnreported
// with the deadline blown -- and in that case this function says so rather than
// guessing: see StageUpBudget, which records boot_failed while stating in the
// message that WHICH phase exhausted the budget is unknown, because nothing
// observed it. A guess dressed as a diagnosis is worse than a stated unknown.
func (p *Provisioner) refuseAfterUp(
	ctx context.Context,
	project string,
	req UpRequest,
	res UpResult,
	upErr error,
	deadlineErr error,
) *ProvisionError {
	deadlineBlown := errors.Is(deadlineErr, context.DeadlineExceeded) ||
		errors.Is(upErr, context.DeadlineExceeded)

	switch {
	case res.Status == UpStatusBuildFailed:
		return p.tearDownAndRefuse(ctx, project, StageBuild, ErrBuildFailed,
			"the runner reported a build failure: %s (err=%v, deadline_blown=%v). No boot was "+
				"attempted. The runner watched the build and the clock did not, so a build "+
				"failure that surfaced after the budget elapsed is still a build failure",
			res.Detail, upErr, deadlineBlown)

	case res.Status == UpStatusStartFailed:
		return p.tearDownAndRefuse(ctx, project, StageStart, ErrStartFailed,
			"the image existed and a container would not start: %s (err=%v, deadline_blown=%v). "+
				"This is NOT a build failure and the remediation is different",
			res.Detail, upErr, deadlineBlown)

	case res.Status == UpStatusHealthTimeout:
		return p.tearDownAndRefuse(ctx, project, StageHealth, ErrHealthTimeout,
			"the runner reported the health wait elapsed after the declared %s: %s (err=%v)",
			req.Timeout, res.Detail, upErr)

	case res.Status == UpStatusUnreported && deadlineBlown:
		// THE ONLY PLACE THE CLOCK DECIDES, and it decides only because
		// nothing else answered. The runner named no phase, so which of build,
		// pull, create, start or health consumed the budget is UNKNOWN, and
		// this refusal says that instead of asserting one.
		return p.tearDownAndRefuse(ctx, project, StageUpBudget, ErrUpBudgetExhausted,
			"the whole `up` budget of %s elapsed (%s to build, pull, create and start, plus the "+
				"manifest's declared %s health wait) and the runner returned NO status. Which "+
				"phase exhausted it is unknown -- nothing observed the boundary -- so this is "+
				"recorded as a boot failure without claiming the image built. If this recurs on "+
				"a cold cache, the build budget is the first thing to look at, not the "+
				"healthcheck. This is a timeout and not a hang: it is enforced here as well as "+
				"passed to the runner (err=%v, detail=%q)",
			req.BuildTimeout+req.Timeout, req.BuildTimeout, req.Timeout, upErr, res.Detail)

	case res.Status == UpStatusUnreported:
		return p.tearDownAndRefuse(ctx, project, StageRunnerContract, ErrRunnerContract,
			"the runner returned no status (err=%v, detail=%q). The zero UpStatus is "+
				"not success: a runner has to say UpStatusUp", upErr, res.Detail)

	case res.Status != UpStatusUp:
		return p.tearDownAndRefuse(ctx, project, StageRunnerContract, ErrRunnerContract,
			"the runner returned status %q, which this package does not recognise "+
				"(err=%v, detail=%q)", string(res.Status), upErr, res.Detail)

	default:
		// res.Status == UpStatusUp with a non-nil error. The runner is
		// contradicting itself; refuse rather than pick the optimistic half.
		return p.tearDownAndRefuse(ctx, project, StageRunnerContract, ErrRunnerContract,
			"the runner reported %q and returned error %v; a success status with an "+
				"error is a contradiction and the optimistic half is not the one to "+
				"believe", string(res.Status), upErr)
	}
}

// tearDownAndRefuse destroys the project and returns the refusal. A teardown
// failure is attached to the refusal and never replaces it.
func (p *Provisioner) tearDownAndRefuse(
	ctx context.Context,
	project string,
	stage Stage,
	sentinel error,
	format string,
	args ...any,
) *ProvisionError {
	pe := refuse(stage, sentinel, format, args...)
	pe.teardown = teardown(context.WithoutCancel(ctx), p.docker, project)
	return pe
}

// tearDownAndRefuseErr is tearDownAndRefuse for an error that already carries
// its own message.
func (p *Provisioner) tearDownAndRefuseErr(
	ctx context.Context,
	project string,
	stage Stage,
	sentinel error,
	cause error,
) *ProvisionError {
	return p.tearDownAndRefuse(ctx, project, stage, sentinel, "%v", cause)
}

// teardown destroys a project, volumes included.
//
// It uses its own bounded context: teardown runs on the failure path, and the
// context that failed is frequently the one that just expired. A destroy that
// is skipped because the deadline already passed leaves containers running.
func teardown(ctx context.Context, d Docker, project string) error {
	if d == nil {
		return fmt.Errorf("containment: no seam to tear down project %q with", project)
	}
	tctx, cancel := context.WithTimeout(ctx, teardownGrace)
	defer cancel()
	return d.ComposeDown(tctx, DownRequest{Project: project, RemoveVolumes: true})
}

// ---------------------------------------------------------------------------
// Preflight: the runtime
// ---------------------------------------------------------------------------

// checkRuntime refuses unless the engine has RuntimeName configured on
// RuntimePlatform. Both halves matter: a runsc configured on an undeclared
// platform is a runtime assumption nobody checked.
func checkRuntime(info EngineInfo) error {
	if len(info.Runtimes) == 0 {
		return fmt.Errorf("the engine reports no configured runtimes; %q is required "+
			"and plan/50-dast.md forbids a fallback to any other runtime", RuntimeName)
	}
	rt, ok := info.Runtimes[RuntimeName]
	if !ok {
		return fmt.Errorf("the engine has no %q runtime configured (it has: %s). There "+
			"is no fallback: a target that cannot run under gVisor does not run",
			RuntimeName, strings.Join(sortedKeys(info.Runtimes), ", "))
	}
	if rt.Platform == "" {
		return fmt.Errorf("the engine has %q configured and its gVisor platform is "+
			"unknown; %q is required. An unknown platform refuses rather than assuming "+
			"the default, because assuming it is how the assumption stops being checked",
			RuntimeName, RuntimePlatform)
	}
	if rt.Platform != RuntimePlatform {
		return fmt.Errorf("the engine has %q configured on platform %q; %q is the "+
			"declared platform", RuntimeName, rt.Platform, RuntimePlatform)
	}
	return nil
}

func sortedKeys(m map[string]RuntimeInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Identity: which container is the authorized service
// ---------------------------------------------------------------------------

// errAmbiguous marks the more-than-one case so the caller can pick the right
// sentinel without string matching.
var errAmbiguous = errors.New("ambiguous")

// selectAuthorized finds THE container for the authorized service.
//
// BY IDENTITY, NOT POSITION. The match is target.AuthorizedService.Authorizes
// against the Compose service label. There is no containers[0], no "the first
// one that looks right", and no fallback to the only running container.
// Exactly one match is required: zero refuses and more than one refuses,
// because a scaled service (`deploy.replicas: 2`) gives two containers and
// picking either would be an allowlist matched by position.
func selectAuthorized(svc target.AuthorizedService, containers []Container) (Container, error) {
	var matches []Container
	for _, c := range containers {
		if svc.Authorizes(c.Service) {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return Container{}, fmt.Errorf("no container in the project carries compose "+
			"service label %q=%q. Present services: %s", ComposeServiceLabel, svc.Name(),
			strings.Join(serviceNames(containers), ", "))
	default:
		ids := make([]string, 0, len(matches))
		for _, c := range matches {
			ids = append(ids, c.ID)
		}
		sort.Strings(ids)
		return Container{}, fmt.Errorf("%w: %d containers carry compose service label "+
			"%q=%q (%s). Exactly one service is authorized and exactly one container "+
			"must answer to it; choosing among them would be an allowlist matched by "+
			"position", errAmbiguous, len(matches), ComposeServiceLabel, svc.Name(),
			strings.Join(ids, ", "))
	}
}

func serviceNames(containers []Container) []string {
	out := make([]string, 0, len(containers))
	for _, c := range containers {
		out = append(out, fmt.Sprintf("%q", c.Service))
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Containment assertions
// ---------------------------------------------------------------------------

// assertProjectContained asserts containment on every container in the
// project, and asserts that every container IS in the project.
//
// It reports ALL violations, not the first: an operator fixing a Compose file
// needs the whole list, and a check that reports one of six problems makes the
// other five invisible until the next run.
func assertProjectContained(project string, containers []Container) error {
	var problems []string
	foreign := false
	for _, c := range containers {
		// A container from another project must not be here. Asserting
		// containment on it would be judging somebody else's container, and
		// -- worse -- teardown would destroy it.
		if c.Project != project {
			foreign = true
			problems = append(problems, fmt.Sprintf(
				"container %s (%q): %v: label %s=%q, expected %q",
				shortID(c.ID), c.Service, ErrForeignContainer,
				ComposeProjectLabel, c.Project, project))
			continue
		}
		for _, v := range containmentViolations(project, c) {
			problems = append(problems, fmt.Sprintf("container %s (%q): %s",
				shortID(c.ID), c.Service, v))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	// A foreign container is wrapped by identity, not only described, because
	// it is the one violation whose remediation is not "fix the compose file":
	// it means the listing itself is wrong, and teardown is about to run
	// `down -v` against whatever is in it.
	if foreign {
		return fmt.Errorf("%w: %d containment violation(s) in project %q:\n  %s",
			ErrForeignContainer, len(problems), project, strings.Join(problems, "\n  "))
	}
	return fmt.Errorf("%d containment violation(s) in project %q:\n  %s",
		len(problems), project, strings.Join(problems, "\n  "))
}

// containmentViolations returns every way c is not contained.
//
// Each check is an ALLOWLIST BY IDENTITY. None of them names a forbidden
// value: `seccomp=unconfined`, `/var/run/docker.sock` and `--network=host`
// appear nowhere in this function, because a denylist that names them loses to
// the second spelling of each. What appears instead is the complete set of
// permitted values, and everything outside it refuses.
func containmentViolations(project string, c Container) []string {
	var out []string

	// gVisor. plan/50-dast.md: no fallback to a non-gVisor runtime, for ANY
	// service in the project. This is the check that can see the damage if
	// the Docker implementation applies the runtime to only one service.
	if c.Runtime != RuntimeName {
		out = append(out, fmt.Sprintf("runtime is %q, must be %q", c.Runtime, RuntimeName))
	}

	if c.Privileged {
		out = append(out, "privileged is true, must be false")
	}

	// Capabilities: drop ALL, add nothing. Both halves -- dropping ALL and
	// then adding NET_ADMIN back is a container with NET_ADMIN.
	if !containsFold(c.CapDrop, requiredDroppedCapability) {
		out = append(out, fmt.Sprintf("cap_drop is %v, must contain %q",
			c.CapDrop, requiredDroppedCapability))
	}
	if len(c.CapAdd) > 0 {
		out = append(out, fmt.Sprintf("cap_add is %v, must be empty", c.CapAdd))
	}

	// SecurityOpt: an allowlist of exact strings.
	for _, so := range c.SecurityOpt {
		if !allowedSecurityOpt[so] {
			out = append(out, fmt.Sprintf("security_opt %q is not in the allowlist %v",
				so, sortedStringSet(allowedSecurityOpt)))
		}
	}

	// Mounts: an allowlist of TYPES. This is what excludes every spelling of
	// a docker.sock mount -- a bind of /var/run/docker.sock, of
	// /run/docker.sock, of a symlink to either, and the Windows named pipe
	// -- because all of them arrive as type bind or type npipe.
	//
	// THE COST, STATED: a legitimate `./src:/app` bind mount is refused too.
	// For a scan target that is the correct answer -- the target should be
	// built into its image rather than assembled from the scanning host's
	// filesystem -- and the refusal is loud and named. There is no option
	// here that widens it.
	for _, mnt := range c.Mounts {
		if !allowedMountTypes[mnt.Type] {
			out = append(out, fmt.Sprintf(
				"mount %q -> %q has type %q, and only %v are permitted",
				mnt.Source, mnt.Destination, mnt.Type, sortedStringSet(allowedMountTypes)))
		}
	}

	// Network: must be a network of THIS project. Compose names project
	// networks "<project>_<network>", so this one prefix check excludes
	// host, none, bridge, an external network and container: sharing --
	// without naming any of them.
	if !strings.HasPrefix(c.NetworkMode, project+"_") {
		out = append(out, fmt.Sprintf(
			"network_mode is %q, which is not a network of project %q "+
				"(expected prefix %q)", c.NetworkMode, project, project+"_"))
	}

	// Namespaces. Empty is Compose's default and is the only permitted value
	// for the PID and user namespaces; IPC additionally permits the explicit
	// "private" that some engines report.
	if c.PidMode != "" {
		out = append(out, fmt.Sprintf("pid_mode is %q, must be unset", c.PidMode))
	}
	if !allowedIpcModes[c.IpcMode] {
		out = append(out, fmt.Sprintf("ipc_mode is %q, and only %v are permitted",
			c.IpcMode, sortedStringSet(allowedIpcModes)))
	}
	if c.UsernsMode != "" {
		out = append(out, fmt.Sprintf("userns_mode is %q, must be unset", c.UsernsMode))
	}

	// research 19 step 2: read-only rootfs is part of the runc hygiene that
	// applies underneath gVisor regardless.
	if !c.ReadonlyRootfs {
		out = append(out, "readonly_rootfs is false, must be true")
	}

	// Device passthrough hands the container a host device. There is no
	// device a scan target needs.
	if len(c.Devices) > 0 {
		out = append(out, fmt.Sprintf("devices is %v, must be empty", c.Devices))
	}

	return out
}

func containsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(strings.TrimSpace(h), needle) {
			return true
		}
	}
	return false
}

func sortedStringSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, fmt.Sprintf("%q", k))
	}
	sort.Strings(out)
	return out
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	if id == "" {
		return "<no-id>"
	}
	return id
}

// ---------------------------------------------------------------------------
// Digest resolution
// ---------------------------------------------------------------------------

// resolveDigest pins the authorized service's image to a sha256 digest.
//
// research/19-target-environment-and-sandboxing.md risk #3: the record carries
// the resolved DIGEST, not the tag. A tag is a mutable pointer, so a record
// that names one cannot answer "what did we actually scan" a week later.
//
// Two sources, in order of authority:
//
//  1. RepoDigests, the registry digest -- the strongest identity, because it
//     is what a third party can re-fetch. When there is more than one entry
//     they are usually the same image under several repository names, so the
//     DIGESTS must all agree; if they disagree the inspect shape is describing
//     two different images and this refuses rather than choosing one. Choosing
//     RepoDigests[0] would be an allowlist matched by position.
//  2. ImageID, the local content address. An image built from a Dockerfile has
//     never been pushed and therefore has no RepoDigest at all; its content
//     address is still a digest and is still immutable.
//
// If neither yields a well-formed sha256, this refuses. An image that cannot
// be pinned makes the record uninterpretable, and recording the tag instead is
// the thing risk #3 forbids.
func resolveDigest(c Container) (string, error) {
	seen := map[string]bool{}
	for _, rd := range c.RepoDigests {
		at := strings.LastIndex(rd, "@")
		if at < 0 {
			return "", fmt.Errorf("repo digest %q for image %q has no %q separator",
				rd, c.Image, "@")
		}
		d := rd[at+1:]
		if !wellFormedDigest(d) {
			return "", fmt.Errorf("repo digest %q for image %q is not a %s<%d hex> digest",
				rd, c.Image, digestPrefix, digestHexLen)
		}
		seen[d] = true
	}
	switch len(seen) {
	case 1:
		for d := range seen {
			return d, nil
		}
	case 0:
		// No registry digest. Fall through to the content address.
	default:
		list := make([]string, 0, len(seen))
		for d := range seen {
			list = append(list, d)
		}
		sort.Strings(list)
		return "", fmt.Errorf("image %q reports %d disagreeing repo digests (%s); the "+
			"inspect shape is describing more than one image and choosing among them "+
			"would be an allowlist matched by position", c.Image, len(list),
			strings.Join(list, ", "))
	}

	if wellFormedDigest(c.ImageID) {
		return c.ImageID, nil
	}
	return "", fmt.Errorf("image %q has no repo digest and its image id %q is not a "+
		"%s<%d hex> digest; the tag alone is a mutable pointer and is not what the "+
		"record carries", c.Image, c.ImageID, digestPrefix, digestHexLen)
}

// wellFormedDigest accepts exactly sha256: followed by 64 lowercase hex
// characters. Uppercase is refused rather than normalised: two spellings of
// one digest is two record values for one image.
func wellFormedDigest(d string) bool {
	if !strings.HasPrefix(d, digestPrefix) {
		return false
	}
	hexPart := d[len(digestPrefix):]
	if len(hexPart) != digestHexLen {
		return false
	}
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Project naming
// ---------------------------------------------------------------------------

// projectName derives Anvil's own Compose project name.
//
// It is NOT the directory name, which is Compose's default, and that is the
// point: teardown runs `down -v`, which DESTROYS VOLUMES, and it must be
// impossible to aim that at a project the operator created by hand. Every
// project this package touches starts with projectPrefix.
//
// The name is deterministic in (repoRoot, composeFile, service), so the same
// repo tears down and rebuilds the same project rather than accumulating one
// per run. Inputs are length-prefixed before hashing so that
// ("ab","c") and ("a","bc") cannot collide.
func projectName(repoRoot, composeFile, service string) string {
	h := sha256.New()
	for _, part := range []string{repoRoot, composeFile, service} {
		fmt.Fprintf(h, "%d:%s|", len(part), part)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return projectPrefix + sum[:projectHashHexLen]
}
