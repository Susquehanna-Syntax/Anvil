package containment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/target"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// The fake Docker seam
//
// Every test in this file drives provisioning through RECORDED SHAPES of what
// `docker info`, `docker compose up` and `docker inspect` return. Docker is
// not installed on the host this packet was written on -- verified, and
// recorded in internal/SKIPPED-CONTROLS.md D10-1..D10-3 with what would settle
// each -- so the decision logic is proven here in full and the fidelity of a
// real implementation's shapes is not.
//
// The fake records a CALL LOG, because several controls in this file are about
// what was NOT called: "runsc unavailable starts nothing" is only a control if
// the test can see that ComposeUp never happened.
// ---------------------------------------------------------------------------

type callName string

const (
	callEngineInfo        callName = "EngineInfo"
	callComposeUp         callName = "ComposeUp"
	callProjectContainers callName = "ProjectContainers"
	callComposeDown       callName = "ComposeDown"
	callProbeHealth       callName = "ProbeHealth"
)

type fakeDocker struct {
	mu    sync.Mutex
	calls []callName

	// Recorded arguments, for the request-shape assertions.
	lastUp   UpRequest
	lastDown DownRequest

	engine    EngineInfo
	engineErr error

	// upBlocks makes ComposeUp wait on the context instead of returning,
	// which is how the hard-timeout test proves a timeout and not a hang.
	upBlocks bool
	upResult UpResult
	upErr    error

	containers    []Container
	containersErr error

	downErr error

	probeErr error
}

func (f *fakeDocker) record(n callName) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, n)
}

func (f *fakeDocker) log() []callName {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]callName, len(f.calls))
	copy(out, f.calls)
	return out
}

func (f *fakeDocker) called(n callName) bool {
	for _, c := range f.log() {
		if c == n {
			return true
		}
	}
	return false
}

func (f *fakeDocker) EngineInfo(ctx context.Context) (EngineInfo, error) {
	f.record(callEngineInfo)
	return f.engine, f.engineErr
}

func (f *fakeDocker) ComposeUp(ctx context.Context, req UpRequest) (UpResult, error) {
	f.record(callComposeUp)
	f.mu.Lock()
	f.lastUp = req
	blocks := f.upBlocks
	f.mu.Unlock()
	if blocks {
		<-ctx.Done()
		return UpResult{}, ctx.Err()
	}
	return f.upResult, f.upErr
}

func (f *fakeDocker) ProjectContainers(ctx context.Context, project string) ([]Container, error) {
	f.record(callProjectContainers)
	return f.containers, f.containersErr
}

func (f *fakeDocker) ComposeDown(ctx context.Context, req DownRequest) error {
	f.record(callComposeDown)
	f.mu.Lock()
	f.lastDown = req
	f.mu.Unlock()
	return f.downErr
}

func (f *fakeDocker) ProbeHealth(ctx context.Context, healthURL string) error {
	f.record(callProbeHealth)
	return f.probeErr
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const (
	fixtureComposeRel = "./docker-compose.anvil.yaml"
	fixtureService    = "web"
	fixtureSibling    = "db"
	fixtureHealthURL  = "http://web:8080/healthz"
)

// fixtureManifestYAML is a minimal VALID `.anvil/target.yaml`. It goes through
// target.Parse rather than being hand-built, because target.Manifest's
// authorized service is unexported -- D.1 made "exactly one service" a type,
// and this file does not get to reach around that.
func fixtureManifestYAML(timeoutSeconds int) string {
	// D.1 refuses an interval that exceeds the timeout ("the health check
	// would never poll"), so the interval tracks the timeout here.
	interval := 5
	if timeoutSeconds < interval {
		interval = timeoutSeconds
	}
	return fmt.Sprintf(`schema_version: 1
compose_file: %s
service: %s
health:
  url: %s
  timeout_seconds: %d
  interval_seconds: %d
reset:
  strategy: destroy_recreate
`, fixtureComposeRel, fixtureService, fixtureHealthURL, timeoutSeconds, interval)
}

type fixture struct {
	repoRoot string
	manifest *target.Manifest
	project  string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	return newFixtureWithTimeout(t, 120)
}

func newFixtureWithTimeout(t *testing.T, timeoutSeconds int) fixture {
	t.Helper()
	root := t.TempDir()
	compose := filepath.Join(root, "docker-compose.anvil.yaml")
	if err := os.WriteFile(compose, []byte("services:\n  web: {}\n"), 0o600); err != nil {
		t.Fatalf("writing compose fixture: %v", err)
	}
	m, err := target.Parse([]byte(fixtureManifestYAML(timeoutSeconds)))
	if err != nil {
		t.Fatalf("the fixture manifest must parse; D.1 refused it: %v", err)
	}
	return fixture{
		repoRoot: root,
		manifest: m,
		project:  projectName(root, fixtureComposeRel, fixtureService),
	}
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return digestPrefix + hex.EncodeToString(sum[:])
}

// contained is a container that passes every containment assertion.
func contained(project, service string) Container {
	return Container{
		ID:             "container-" + service + "-000000000000",
		Name:           "/" + project + "-" + service + "-1",
		Project:        project,
		Service:        service,
		Image:          service + ":latest",
		ImageID:        digestOf(service),
		RepoDigests:    []string{"registry.example/" + service + "@" + digestOf(service)},
		Runtime:        RuntimeName,
		State:          StateRunning,
		Health:         HealthHealthy,
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges:true"},
		ReadonlyRootfs: true,
		NetworkMode:    project + "_default",
		IpcMode:        "private",
		Mounts: []Mount{
			{Type: "volume", Source: service + "-data", Destination: "/data"},
			{Type: "tmpfs", Source: "", Destination: "/tmp"},
		},
	}
}

// healthyEngine is an engine with runsc on the declared platform.
func healthyEngine() EngineInfo {
	return EngineInfo{Runtimes: map[string]RuntimeInfo{
		"runc":      {Path: "/usr/bin/runc"},
		RuntimeName: {Path: "/usr/local/bin/runsc", Platform: RuntimePlatform},
	}}
}

// healthyWorld is the everything-works fake: engine with runsc, project up,
// two contained containers (the authorized service and one dependency),
// reachable health URL.
func healthyWorld(project string) *fakeDocker {
	sibling := contained(project, fixtureSibling)
	// A dependency need not declare a healthcheck of its own; only the
	// authorized service must be healthy.
	sibling.Health = HealthNone
	return &fakeDocker{
		engine:     healthyEngine(),
		upResult:   UpResult{Status: UpStatusUp},
		containers: []Container{sibling, contained(project, fixtureService)},
	}
}

func newProvisioner(t *testing.T, d Docker, repoRoot string) *Provisioner {
	t.Helper()
	p, err := NewProvisioner(d, repoRoot)
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	return p
}

// mustRefuse asserts a refusal at a given stage with a given provenance and
// sentinel, and returns it.
func mustRefuse(
	t *testing.T,
	tgt *Target,
	err error,
	wantStage Stage,
	wantProv record.TargetProvenance,
	wantSentinel error,
) *ProvisionError {
	t.Helper()
	if tgt != nil {
		t.Fatalf("a refusal returned a non-nil Target (constructed=%v, provenance=%q); "+
			"a caller that ignores the error would scan it",
			tgt.Constructed(), string(tgt.Provenance()))
	}
	var pe *ProvisionError
	if !errors.As(err, &pe) {
		t.Fatalf("want *ProvisionError, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrRefused) {
		t.Errorf("refusal does not wrap ErrRefused: %v", err)
	}
	if wantSentinel != nil && !errors.Is(err, wantSentinel) {
		t.Errorf("refusal does not wrap %v: %v", wantSentinel, err)
	}
	if pe.Stage() != wantStage {
		t.Errorf("stage = %q, want %q (err: %v)", string(pe.Stage()), string(wantStage), err)
	}
	if pe.Provenance() != wantProv {
		t.Errorf("provenance = %q, want %q (err: %v)",
			string(pe.Provenance()), string(wantProv), err)
	}
	if err := record.ValidateTargetProvenance(string(pe.Provenance())); err != nil {
		t.Errorf("refusal produced a provenance the frozen record enum rejects: %v", err)
	}
	return pe
}

// ---------------------------------------------------------------------------
// Stage -> provenance: the mapping this whole packet turns on
// ---------------------------------------------------------------------------

// stageProvenance is the DECLARED expectation, written out by hand rather than
// read from Stage.Provenance(), so that a change to the mapping is a test
// failure and not a silently-agreeing tautology.
var stageProvenance = map[Stage]record.TargetProvenance{
	StageNoTargetDeclared:     record.TargetProvenanceNoTargetDeclared,
	StagePreflightManifest:    record.TargetProvenanceBuildFailed,
	StagePreflightEngine:      record.TargetProvenanceBuildFailed,
	StagePreflightRuntime:     record.TargetProvenanceBuildFailed,
	StagePreflightComposeFile: record.TargetProvenanceBuildFailed,
	StageBuild:                record.TargetProvenanceBuildFailed,
	StageStart:                record.TargetProvenanceBootFailed,
	StageHealth:               record.TargetProvenanceBootFailed,
	StageRunnerContract:       record.TargetProvenanceBootFailed,
	StageEnumerate:            record.TargetProvenanceBootFailed,
	StageContainment:          record.TargetProvenanceBootFailed,
	StageIdentifyService:      record.TargetProvenanceBootFailed,
	StageDigest:               record.TargetProvenanceBootFailed,
	StageReachability:         record.TargetProvenanceUnreachableAtScanTime,
}

func TestEveryStageNamesOneProvenance(t *testing.T) {
	for _, s := range StageValues() {
		want, declared := stageProvenance[s]
		if !declared {
			t.Fatalf("stage %q has no declared provenance in this test's table. A stage "+
				"whose outcome nobody wrote down is a stage that can land any of the "+
				"five values in the record", string(s))
		}
		got, err := s.Provenance()
		if err != nil {
			t.Fatalf("stage %q: Provenance() errored: %v", string(s), err)
		}
		if got != want {
			t.Errorf("stage %q: provenance = %q, want %q", string(s), string(got), string(want))
		}
		if err := record.ValidateTargetProvenance(string(got)); err != nil {
			t.Errorf("stage %q produced a provenance the frozen enum rejects: %v", string(s), err)
		}
		if !s.Valid() {
			t.Errorf("stage %q is in StageValues() and Valid() says otherwise", string(s))
		}
	}
	if len(stageProvenance) != len(StageValues()) {
		t.Errorf("this test declares %d stages and StageValues() has %d",
			len(stageProvenance), len(StageValues()))
	}
}

// TestStageValuesCoversEveryDeclaredStage reads this package's own source, so
// that a stage added to the const block and forgotten in StageValues() is
// caught here rather than by never being tested. A list that has to be
// maintained by hand needs something that can see when it was not.
func TestStageValuesCoversEveryDeclaredStage(t *testing.T) {
	src, err := os.ReadFile("provision.go")
	if err != nil {
		t.Fatalf("reading provision.go: %v", err)
	}
	re := regexp.MustCompile(`\n\tStage\w*\s+Stage = "([a-z_]*)"`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("found no Stage constant declarations in provision.go; this test can no " +
			"longer see the thing it checks")
	}
	declared := map[Stage]bool{}
	for _, m := range matches {
		declared[Stage(m[1])] = true
	}
	if !declared[StageUnset] {
		t.Error("StageUnset is not declared in the const block; the zero value must be " +
			"named and refused, not implicit")
	}
	for s := range declared {
		if s == StageUnset {
			continue
		}
		if !s.Valid() {
			t.Errorf("stage %q is declared in provision.go and is not in StageValues()",
				string(s))
		}
	}
	// 14 legal stages plus StageUnset.
	if len(declared) != len(StageValues())+1 {
		t.Errorf("provision.go declares %d Stage constants; StageValues()+StageUnset is %d",
			len(declared), len(StageValues())+1)
	}
}

func TestZeroStageRefuses(t *testing.T) {
	if _, err := StageUnset.Provenance(); err == nil {
		t.Fatal("the zero Stage produced a provenance. A Go zero value must never mean a " +
			"legal outcome, and \"\" would be written straight into the record")
	}
	if _, err := Stage("invented_later").Provenance(); err == nil {
		t.Fatal("an unrecognised Stage produced a provenance")
	}
	if StageUnset.Valid() {
		t.Error("StageUnset.Valid() is true")
	}
}

// TestNoStageCanBeReadAsScannedClean pins the RELATION, not the values:
// whatever the mapping says, no provisioning failure may derive a DastStatus
// that reads as "dynamically scanned, no findings". plan/00-SPINE.md S6.
func TestNoStageCanBeReadAsScannedClean(t *testing.T) {
	halves := []record.HalfStatus{
		record.HalfStatusRunning, record.HalfStatusSealed, record.HalfStatusFailed,
		record.HalfStatusTimedOut, record.HalfStatusSkipped,
	}
	for _, s := range StageValues() {
		prov, err := s.Provenance()
		if err != nil {
			t.Fatalf("stage %q: %v", string(s), err)
		}
		for _, half := range halves {
			got, err := record.DeriveDastStatus(half, record.DastOutcome{
				TierInstalled: true,
				Provenance:    prov,
				FindingCount:  0,
			})
			if err != nil {
				t.Fatalf("stage %q half %q: DeriveDastStatus: %v",
					string(s), string(half), err)
			}
			if got.MeansDynamicallyScannedClean() {
				t.Errorf("stage %q (provenance %q) with half %q derives dast_status %q, "+
					"which reads as dynamically scanned clean. A provisioning failure "+
					"must never be readable as an absence of vulnerabilities",
					string(s), string(prov), string(half), string(got))
			}
		}
	}
}

// TestStageDerivesTheExpectedDastStatus pins the exact derived status per
// stage, through record.DeriveDastStatus rather than by writing a literal.
// Standing order (1): never a string literal for these enums.
func TestStageDerivesTheExpectedDastStatus(t *testing.T) {
	want := map[Stage]record.DastStatus{
		StageNoTargetDeclared:     record.DastStatusSkippedNoManifest,
		StagePreflightManifest:    record.DastStatusTargetBootFailed,
		StagePreflightEngine:      record.DastStatusTargetBootFailed,
		StagePreflightRuntime:     record.DastStatusTargetBootFailed,
		StagePreflightComposeFile: record.DastStatusTargetBootFailed,
		StageBuild:                record.DastStatusTargetBootFailed,
		StageStart:                record.DastStatusTargetBootFailed,
		StageHealth:               record.DastStatusTargetBootFailed,
		StageRunnerContract:       record.DastStatusTargetBootFailed,
		StageEnumerate:            record.DastStatusTargetBootFailed,
		StageContainment:          record.DastStatusTargetBootFailed,
		StageIdentifyService:      record.DastStatusTargetBootFailed,
		StageDigest:               record.DastStatusTargetBootFailed,
		StageReachability:         record.DastStatusTargetUnreachable,
	}
	for _, s := range StageValues() {
		prov, err := s.Provenance()
		if err != nil {
			t.Fatalf("stage %q: %v", string(s), err)
		}
		got, err := record.DeriveDastStatus(record.HalfStatusFailed, record.DastOutcome{
			TierInstalled: true,
			Provenance:    prov,
		})
		if err != nil {
			t.Fatalf("stage %q: %v", string(s), err)
		}
		if got != want[s] {
			t.Errorf("stage %q: dast_status = %q, want %q", string(s), string(got), string(want[s]))
		}
	}
}

// TestBootedCleanIsTheOnlyRouteToCompletedClean is the other half of the same
// relation: booted_clean plus a sealed, finding-free half is the ONLY way
// completed_clean is reachable.
func TestBootedCleanIsTheOnlyRouteToCompletedClean(t *testing.T) {
	got, err := record.DeriveDastStatus(record.HalfStatusSealed, record.DastOutcome{
		TierInstalled: true,
		Provenance:    record.TargetProvenanceBootedClean,
		FindingCount:  0,
	})
	if err != nil {
		t.Fatalf("DeriveDastStatus: %v", err)
	}
	if !got.MeansDynamicallyScannedClean() {
		t.Fatalf("booted_clean + sealed + 0 findings derives %q, which does not read as "+
			"scanned clean", string(got))
	}
}

// ---------------------------------------------------------------------------
// One test per record.TargetProvenance value
// ---------------------------------------------------------------------------

func TestProvenanceNoTargetDeclared(t *testing.T) {
	f := &fakeDocker{}
	fx := newFixture(t)
	p := newProvisioner(t, f, fx.repoRoot)

	tgt, err := p.Provision(t.Context(), nil)
	pe := mustRefuse(t, tgt, err, StageNoTargetDeclared,
		record.TargetProvenanceNoTargetDeclared, ErrNoTargetDeclared)

	if len(f.log()) != 0 {
		t.Errorf("no manifest declared and the seam was still called: %v", f.log())
	}
	// anvil/target.provisioning has no literal for "no path was taken", so it
	// refuses to name one rather than writing a false ephemeral_manifest.
	if _, err := pe.Provisioning(); err == nil {
		t.Error("Provisioning() named a provisioning path for a scan that never " +
			"provisioned anything; both legal literals assert a target existed")
	}
}

func TestProvenanceBuildFailed(t *testing.T) {
	cases := []struct {
		name     string
		stage    Stage
		sentinel error
		// mutate the world so that this stage is the one that refuses.
		setup func(t *testing.T, f *fakeDocker, fx *fixture)
	}{
		{
			name:     "engine unavailable",
			stage:    StagePreflightEngine,
			sentinel: ErrDockerUnavailable,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.engineErr = errors.New("cannot connect to the docker daemon")
			},
		},
		{
			name:     "engine reports no runtimes at all",
			stage:    StagePreflightRuntime,
			sentinel: ErrRunscUnavailable,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.engine = EngineInfo{}
			},
		},
		{
			name:     "runsc not configured",
			stage:    StagePreflightRuntime,
			sentinel: ErrRunscUnavailable,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.engine = EngineInfo{Runtimes: map[string]RuntimeInfo{
					"runc": {Path: "/usr/bin/runc"},
				}}
			},
		},
		{
			name:     "runsc configured on an undeclared platform",
			stage:    StagePreflightRuntime,
			sentinel: ErrRunscUnavailable,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.engine = EngineInfo{Runtimes: map[string]RuntimeInfo{
					RuntimeName: {Path: "/usr/local/bin/runsc", Platform: "ptrace"},
				}}
			},
		},
		{
			name:     "runsc platform unknown",
			stage:    StagePreflightRuntime,
			sentinel: ErrRunscUnavailable,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.engine = EngineInfo{Runtimes: map[string]RuntimeInfo{
					RuntimeName: {Path: "/usr/local/bin/runsc"},
				}}
			},
		},
		{
			name:     "declared compose file is not on disk",
			stage:    StagePreflightComposeFile,
			sentinel: ErrComposeFileMissing,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				if err := os.Remove(filepath.Join(fx.repoRoot, "docker-compose.anvil.yaml")); err != nil {
					t.Fatalf("removing compose fixture: %v", err)
				}
			},
		},
		{
			name:     "image never built",
			stage:    StageBuild,
			sentinel: ErrBuildFailed,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.upResult = UpResult{Status: UpStatusBuildFailed, Detail: "npm ci exited 1"}
				f.upErr = errors.New("compose up failed")
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := newFixture(t)
			f := healthyWorld(fx.project)
			c.setup(t, f, &fx)
			p := newProvisioner(t, f, fx.repoRoot)

			tgt, err := p.Provision(t.Context(), fx.manifest)
			pe := mustRefuse(t, tgt, err, c.stage, record.TargetProvenanceBuildFailed, c.sentinel)

			prov, provErr := pe.Provisioning()
			if provErr != nil {
				t.Errorf("Provisioning(): %v", provErr)
			}
			if prov != record.TargetProvisioningEphemeralManifest {
				t.Errorf("provisioning = %q, want %q", string(prov),
					string(record.TargetProvisioningEphemeralManifest))
			}
		})
	}
}

func TestProvenanceBootFailed(t *testing.T) {
	cases := []struct {
		name     string
		stage    Stage
		sentinel error
		setup    func(t *testing.T, f *fakeDocker, fx *fixture)
	}{
		{
			name:     "image built and container would not start",
			stage:    StageStart,
			sentinel: ErrStartFailed,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.upResult = UpResult{Status: UpStatusStartFailed, Detail: "exec: no such file"}
			},
		},
		{
			name:     "runner reports the health wait elapsed",
			stage:    StageHealth,
			sentinel: ErrHealthTimeout,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.upResult = UpResult{Status: UpStatusHealthTimeout, Detail: "web is unhealthy"}
			},
		},
		{
			name:     "runner reports nothing at all",
			stage:    StageRunnerContract,
			sentinel: ErrRunnerContract,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.upResult = UpResult{}
			},
		},
		{
			name:     "runner reports an unknown status",
			stage:    StageRunnerContract,
			sentinel: ErrRunnerContract,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.upResult = UpResult{Status: UpStatus("mostly_up")}
			},
		},
		{
			name:     "runner reports success and returns an error",
			stage:    StageRunnerContract,
			sentinel: ErrRunnerContract,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.upResult = UpResult{Status: UpStatusUp}
				f.upErr = errors.New("compose exited 1")
			},
		},
		{
			name:     "containers cannot be listed",
			stage:    StageEnumerate,
			sentinel: ErrRunnerContract,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.containersErr = errors.New("docker ps: connection reset")
			},
		},
		{
			name:     "project reported up and contains nothing",
			stage:    StageEnumerate,
			sentinel: ErrRunnerContract,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.containers = nil
			},
		},
		{
			name:     "the authorized service runs under a non-gVisor runtime",
			stage:    StageContainment,
			sentinel: ErrContainmentViolated,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.containers[1].Runtime = "runc"
			},
		},
		{
			name:     "a dependency runs under a non-gVisor runtime",
			stage:    StageContainment,
			sentinel: ErrContainmentViolated,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.containers[0].Runtime = "runc"
			},
		},
		{
			name:     "a container from another project appears in the listing",
			stage:    StageContainment,
			sentinel: ErrContainmentViolated,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				stray := contained("someone-elses-project", "postgres")
				stray.Project = "someone-elses-project"
				f.containers = append(f.containers, stray)
			},
		},
		{
			name:     "authorized service has no container",
			stage:    StageIdentifyService,
			sentinel: ErrServiceNotFound,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.containers = f.containers[:1] // the dependency only
			},
		},
		{
			name:     "authorized service resolves to two containers",
			stage:    StageIdentifyService,
			sentinel: ErrServiceAmbiguous,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				replica := contained(fx.project, fixtureService)
				replica.ID = "container-web-000000000002"
				f.containers = append(f.containers, replica)
			},
		},
		{
			name:     "authorized service is not running",
			stage:    StageHealth,
			sentinel: ErrNotHealthy,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.containers[1].State = StateExited
			},
		},
		{
			name:     "authorized service declares no healthcheck at all",
			stage:    StageHealth,
			sentinel: ErrNotHealthy,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.containers[1].Health = HealthNone
			},
		},
		{
			name:     "authorized service is unhealthy",
			stage:    StageHealth,
			sentinel: ErrNotHealthy,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.containers[1].Health = HealthUnhealthy
			},
		},
		{
			name:     "authorized service image cannot be pinned to a digest",
			stage:    StageDigest,
			sentinel: ErrDigestUnresolved,
			setup: func(t *testing.T, f *fakeDocker, fx *fixture) {
				f.containers[1].RepoDigests = nil
				f.containers[1].ImageID = "web:latest"
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := newFixture(t)
			f := healthyWorld(fx.project)
			c.setup(t, f, &fx)
			p := newProvisioner(t, f, fx.repoRoot)

			tgt, err := p.Provision(t.Context(), fx.manifest)
			mustRefuse(t, tgt, err, c.stage, record.TargetProvenanceBootFailed, c.sentinel)

			// Everything at or after ComposeUp must destroy what it started.
			if !f.called(callComposeDown) {
				t.Errorf("a failure after the project came up did not tear it down; "+
					"call log: %v", f.log())
			}
			if !f.lastDown.RemoveVolumes {
				t.Error("teardown did not remove volumes; reset.strategy is " +
					"destroy_recreate and `down` without -v leaves state behind")
			}
			if f.lastDown.Project != fx.project {
				t.Errorf("teardown aimed at project %q, want %q", f.lastDown.Project, fx.project)
			}
		})
	}
}

func TestProvenanceUnreachableAtScanTime(t *testing.T) {
	fx := newFixture(t)
	f := healthyWorld(fx.project)
	// Healthy by its own healthcheck, which runs INSIDE the container, and
	// not reachable from where the probe engine lives.
	f.probeErr = errors.New("dial tcp: i/o timeout")
	p := newProvisioner(t, f, fx.repoRoot)

	tgt, err := p.Provision(t.Context(), fx.manifest)
	mustRefuse(t, tgt, err, StageReachability,
		record.TargetProvenanceUnreachableAtScanTime, ErrUnreachable)

	if !f.called(callProbeHealth) {
		t.Fatalf("the probe-side reachability check never ran; call log: %v", f.log())
	}
	if !f.called(callComposeDown) {
		t.Errorf("an unreachable target was left running; call log: %v", f.log())
	}
}

func TestProvenanceBootedClean(t *testing.T) {
	fx := newFixture(t)
	f := healthyWorld(fx.project)
	p := newProvisioner(t, f, fx.repoRoot)

	tgt, err := p.Provision(t.Context(), fx.manifest)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !tgt.Constructed() {
		t.Fatal("a returned Target is not Constructed()")
	}
	if tgt.Provenance() != record.TargetProvenanceBootedClean {
		t.Errorf("provenance = %q, want %q", string(tgt.Provenance()),
			string(record.TargetProvenanceBootedClean))
	}
	if err := record.ValidateTargetProvenance(string(tgt.Provenance())); err != nil {
		t.Errorf("provenance is not a legal record literal: %v", err)
	}
	// TWO SEPARATE FIELDS. target.provisioning is not target.provenance, and
	// this value comes from D.1's manifest rather than being re-derived here.
	if tgt.Provisioning() != fx.manifest.Provisioning() {
		t.Errorf("provisioning = %q, want the manifest's %q", string(tgt.Provisioning()),
			string(fx.manifest.Provisioning()))
	}
	if err := record.ValidateTargetProvisioning(string(tgt.Provisioning())); err != nil {
		t.Errorf("provisioning is not a legal record literal: %v", err)
	}
	if string(tgt.Provenance()) == string(tgt.Provisioning()) {
		t.Error("provenance and provisioning carry the same literal; they are two " +
			"different measurements and IMPLEMENTATION-PLAN.md section 6 G4+G7 split them")
	}

	if !tgt.AuthorizedService().Authorizes(fixtureService) {
		t.Errorf("the sealed target does not authorize %q", fixtureService)
	}
	if tgt.AuthorizedService().Authorizes(fixtureSibling) {
		t.Errorf("the sealed target authorizes the dependency %q; exactly one service "+
			"is a probe target", fixtureSibling)
	}
	if tgt.ImageDigest() != digestOf(fixtureService) {
		t.Errorf("image digest = %q, want %q", tgt.ImageDigest(), digestOf(fixtureService))
	}
	if tgt.Runtime() != RuntimeName {
		t.Errorf("runtime = %q, want %q", tgt.Runtime(), RuntimeName)
	}
	if tgt.Platform() != RuntimePlatform {
		t.Errorf("platform = %q, want %q", tgt.Platform(), RuntimePlatform)
	}
	if tgt.HealthURL() != fixtureHealthURL {
		t.Errorf("health URL = %q, want %q", tgt.HealthURL(), fixtureHealthURL)
	}
	if !strings.HasPrefix(tgt.Project(), projectPrefix) {
		t.Errorf("project %q is not namespaced with %q", tgt.Project(), projectPrefix)
	}
	if f.called(callComposeDown) {
		t.Errorf("a clean boot tore the project down; call log: %v", f.log())
	}
	// A dependency with no healthcheck of its own must not block a clean
	// boot -- only the authorized service has to be healthy.
	if len(tgt.Containers()) != 2 {
		t.Errorf("Containers() = %d entries, want 2", len(tgt.Containers()))
	}
}

// ---------------------------------------------------------------------------
// No fallback: nothing starts when the sandbox is unavailable
// ---------------------------------------------------------------------------

// TestRunscUnavailableStartsNothing is the control behind plan/50-dast.md's
// "No fallback to a non-gVisor runtime". A refusal that happened AFTER the
// containers started would have already run the target unsandboxed, so the
// assertion is on the call log and not on the error.
func TestRunscUnavailableStartsNothing(t *testing.T) {
	fx := newFixture(t)
	f := healthyWorld(fx.project)
	f.engine = EngineInfo{Runtimes: map[string]RuntimeInfo{"runc": {Path: "/usr/bin/runc"}}}
	p := newProvisioner(t, f, fx.repoRoot)

	tgt, err := p.Provision(t.Context(), fx.manifest)
	mustRefuse(t, tgt, err, StagePreflightRuntime,
		record.TargetProvenanceBuildFailed, ErrRunscUnavailable)

	for _, c := range f.log() {
		if c != callEngineInfo {
			t.Fatalf("runsc was unavailable and the seam call %q still happened "+
				"(full log: %v). Anything past EngineInfo means the target ran "+
				"before the sandbox was checked", string(c), f.log())
		}
	}
}

// TestPreflightRefusalsStartAndTearDownNothing: the five stages that refuse
// before ComposeUp have nothing to destroy, and must not issue a `down -v`
// against a project that was never created.
func TestPreflightRefusalsStartAndTearDownNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, f *fakeDocker, fx *fixture)
	}{
		{"engine unavailable", func(t *testing.T, f *fakeDocker, fx *fixture) {
			f.engineErr = errors.New("no daemon")
		}},
		{"runsc unavailable", func(t *testing.T, f *fakeDocker, fx *fixture) {
			f.engine = EngineInfo{}
		}},
		{"compose file missing", func(t *testing.T, f *fakeDocker, fx *fixture) {
			if err := os.Remove(filepath.Join(fx.repoRoot, "docker-compose.anvil.yaml")); err != nil {
				t.Fatalf("removing compose fixture: %v", err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := newFixture(t)
			f := healthyWorld(fx.project)
			c.setup(t, f, &fx)
			p := newProvisioner(t, f, fx.repoRoot)

			if _, err := p.Provision(t.Context(), fx.manifest); err == nil {
				t.Fatal("want a refusal")
			}
			if f.called(callComposeUp) {
				t.Errorf("a preflight refusal still started the project: %v", f.log())
			}
			if f.called(callComposeDown) {
				t.Errorf("a preflight refusal issued `down -v` against a project it "+
					"never created: %v", f.log())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The hard timeout is a timeout, not a hang
// ---------------------------------------------------------------------------

func TestHealthTimeoutIsATimeoutNotAHang(t *testing.T) {
	fx := newFixtureWithTimeout(t, 1)
	f := healthyWorld(fx.project)
	f.upBlocks = true // a runner that never returns on its own
	p := newProvisioner(t, f, fx.repoRoot)

	start := time.Now()
	tgt, err := p.Provision(t.Context(), fx.manifest)
	elapsed := time.Since(start)

	mustRefuse(t, tgt, err, StageHealth, record.TargetProvenanceBootFailed, ErrHealthTimeout)

	if elapsed > 20*time.Second {
		t.Fatalf("the declared timeout was 1s and Provision took %s", elapsed)
	}
	if elapsed < 900*time.Millisecond {
		t.Errorf("Provision returned in %s, before the declared 1s timeout could have "+
			"elapsed; the deadline is not the thing that ended the wait", elapsed)
	}
	// The context that expired is the one teardown would inherit. It must
	// still run, or a timed-out project is left running.
	if !f.called(callComposeDown) {
		t.Errorf("a timed-out project was not torn down; call log: %v", f.log())
	}
}

func TestUpRequestCarriesTheDeclaredTimeout(t *testing.T) {
	fx := newFixtureWithTimeout(t, 45)
	f := healthyWorld(fx.project)
	p := newProvisioner(t, f, fx.repoRoot)

	if _, err := p.Provision(t.Context(), fx.manifest); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if got, want := f.lastUp.Timeout, 45*time.Second; got != want {
		t.Errorf("UpRequest.Timeout = %s, want the manifest's %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// The request is the other half of the containment story
// ---------------------------------------------------------------------------

func TestUpRequestIsFailClosed(t *testing.T) {
	fx := newFixture(t)
	f := healthyWorld(fx.project)
	p := newProvisioner(t, f, fx.repoRoot)

	if _, err := p.Provision(t.Context(), fx.manifest); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	req := f.lastUp

	if req.Runtime != RuntimeName {
		t.Errorf("UpRequest.Runtime = %q, want %q", req.Runtime, RuntimeName)
	}
	if req.RuntimePlatform != RuntimePlatform {
		t.Errorf("UpRequest.RuntimePlatform = %q, want %q", req.RuntimePlatform, RuntimePlatform)
	}
	if !req.WaitForHealthy {
		t.Error("UpRequest.WaitForHealthy is false; `up -d` without --wait returns " +
			"before the healthcheck has ever run")
	}
	if !req.ForceRecreate {
		t.Error("UpRequest.ForceRecreate is false; reset.strategy is destroy_recreate " +
			"and reusing a previous scan's container is a snapshot restore by accident")
	}
	if !req.RemoveOrphans {
		t.Error("UpRequest.RemoveOrphans is false; a container left by an earlier " +
			"compose file stays running inside the project with nobody asserting on it")
	}
	if req.Project != fx.project {
		t.Errorf("UpRequest.Project = %q, want %q", req.Project, fx.project)
	}
	if !filepath.IsAbs(req.ComposeFile) {
		t.Errorf("UpRequest.ComposeFile = %q, which is not absolute", req.ComposeFile)
	}
}

// ---------------------------------------------------------------------------
// Containment assertions, one broken guard at a time
// ---------------------------------------------------------------------------

func TestContainmentGuards(t *testing.T) {
	const project = "anvil-0123456789abcdef"

	cases := []struct {
		name       string
		mutate     func(c *Container)
		wantSubstr string
	}{
		{"non-gVisor runtime", func(c *Container) { c.Runtime = "runc" }, "runtime is \"runc\""},
		{"empty runtime", func(c *Container) { c.Runtime = "" }, "runtime is \"\""},
		{"privileged", func(c *Container) { c.Privileged = true }, "privileged is true"},
		{"capabilities not dropped", func(c *Container) { c.CapDrop = nil }, "cap_drop"},
		{"capabilities dropped then added back", func(c *Container) {
			c.CapAdd = []string{"NET_ADMIN"}
		}, "cap_add"},
		{"unconfined seccomp", func(c *Container) {
			c.SecurityOpt = []string{"seccomp=unconfined"}
		}, "security_opt \"seccomp=unconfined\""},
		{"apparmor disabled", func(c *Container) {
			c.SecurityOpt = []string{"apparmor=unconfined"}
		}, "security_opt \"apparmor=unconfined\""},
		{"docker.sock bind, unix", func(c *Container) {
			c.Mounts = append(c.Mounts, Mount{
				Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock",
			})
		}, "type \"bind\""},
		{"docker.sock bind, the other unix spelling", func(c *Container) {
			c.Mounts = append(c.Mounts, Mount{
				Type: "bind", Source: "/run/docker.sock", Destination: "/var/run/docker.sock",
			})
		}, "type \"bind\""},
		{"docker engine named pipe", func(c *Container) {
			c.Mounts = append(c.Mounts, Mount{
				Type: "npipe", Source: `\\.\pipe\docker_engine`, Destination: `\\.\pipe\docker_engine`,
			})
		}, "type \"npipe\""},
		{"an ordinary host bind mount", func(c *Container) {
			c.Mounts = append(c.Mounts, Mount{
				Type: "bind", Source: "/home/dev/src", Destination: "/app",
			})
		}, "type \"bind\""},
		{"host network", func(c *Container) { c.NetworkMode = "host" }, "network_mode is \"host\""},
		{"default bridge", func(c *Container) { c.NetworkMode = "bridge" }, "network_mode is \"bridge\""},
		{"another container's network", func(c *Container) {
			c.NetworkMode = "container:abc123"
		}, "network_mode is \"container:abc123\""},
		{"a network belonging to another project", func(c *Container) {
			c.NetworkMode = "someone-else_default"
		}, "network_mode is \"someone-else_default\""},
		{"host pid namespace", func(c *Container) { c.PidMode = "host" }, "pid_mode is \"host\""},
		{"shareable ipc namespace", func(c *Container) { c.IpcMode = "shareable" }, "ipc_mode is \"shareable\""},
		{"host ipc namespace", func(c *Container) { c.IpcMode = "host" }, "ipc_mode is \"host\""},
		{"host user namespace", func(c *Container) { c.UsernsMode = "host" }, "userns_mode is \"host\""},
		{"writable rootfs", func(c *Container) { c.ReadonlyRootfs = false }, "readonly_rootfs is false"},
		{"device passthrough", func(c *Container) { c.Devices = []string{"/dev/kvm"} }, "devices is"},
	}

	// The control: the unmutated fixture must produce NO violations. Without
	// this, a guard that rejects everything would pass every case above.
	if v := containmentViolations(project, contained(project, fixtureService)); len(v) != 0 {
		t.Fatalf("the contained fixture reports violations, so every case below is "+
			"meaningless: %v", v)
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctr := contained(project, fixtureService)
			c.mutate(&ctr)
			got := containmentViolations(project, ctr)
			if len(got) == 0 {
				t.Fatalf("no violation reported for %q", c.name)
			}
			joined := strings.Join(got, "; ")
			if !strings.Contains(joined, c.wantSubstr) {
				t.Errorf("violation %q does not name the problem; want a substring %q",
					joined, c.wantSubstr)
			}
		})
	}
}

// TestContainmentReportsEveryViolationNotJustTheFirst: an operator fixing a
// Compose file needs the whole list. A check that reports one of six problems
// makes the other five invisible until the next run.
func TestContainmentReportsEveryViolationNotJustTheFirst(t *testing.T) {
	const project = "anvil-0123456789abcdef"
	c := contained(project, fixtureService)
	c.Runtime = "runc"
	c.Privileged = true
	c.CapDrop = nil
	c.ReadonlyRootfs = false
	c.NetworkMode = "host"

	got := containmentViolations(project, c)
	if len(got) < 5 {
		t.Fatalf("five guards were broken and %d violations were reported: %v", len(got), got)
	}
}

// TestForeignContainerIsNeverJudgedOrDestroyed: a container carrying another
// project's label refuses the whole run. Asserting containment on it would be
// judging somebody else's container, and teardown runs `down -v`.
func TestForeignContainerIsNeverJudgedOrDestroyed(t *testing.T) {
	const project = "anvil-0123456789abcdef"
	stray := contained("someone-elses-project", "postgres")
	err := assertProjectContained(project, []Container{
		contained(project, fixtureService),
		stray,
	})
	if err == nil {
		t.Fatal("a container from another project passed the project assertion")
	}
	if !errors.Is(err, ErrForeignContainer) {
		t.Errorf("error does not wrap ErrForeignContainer: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Identity, not position
// ---------------------------------------------------------------------------

// TestAuthorizedServiceIsMatchedByIdentityNotPosition puts the authorized
// service LAST and a decoy first. An implementation that took containers[0]
// would pick the decoy and probe the wrong service.
func TestAuthorizedServiceIsMatchedByIdentityNotPosition(t *testing.T) {
	const project = "anvil-0123456789abcdef"
	fx := newFixture(t)
	svc := fx.manifest.AuthorizedService()

	decoy := contained(project, "webhook-listener") // similar name, not authorized
	other := contained(project, fixtureSibling)
	real := contained(project, fixtureService)

	got, err := selectAuthorized(svc, []Container{decoy, other, real})
	if err != nil {
		t.Fatalf("selectAuthorized: %v", err)
	}
	if got.Service != fixtureService {
		t.Fatalf("selected service %q, want %q. Position-based selection would have "+
			"picked %q", got.Service, fixtureService, decoy.Service)
	}
	if got.ID != real.ID {
		t.Errorf("selected container %q, want %q", got.ID, real.ID)
	}
}

func TestSelectAuthorizedRefusesZeroAndMany(t *testing.T) {
	const project = "anvil-0123456789abcdef"
	fx := newFixture(t)
	svc := fx.manifest.AuthorizedService()

	if _, err := selectAuthorized(svc, []Container{contained(project, fixtureSibling)}); err == nil {
		t.Error("selectAuthorized accepted a project with no container for the " +
			"authorized service")
	}
	a := contained(project, fixtureService)
	b := contained(project, fixtureService)
	b.ID = "container-web-000000000002"
	_, err := selectAuthorized(svc, []Container{a, b})
	if err == nil {
		t.Fatal("selectAuthorized picked one of two replicas; choosing among them is " +
			"an allowlist matched by position")
	}
	if !errors.Is(err, errAmbiguous) {
		t.Errorf("a two-replica refusal is not marked ambiguous: %v", err)
	}
}

// TestEmptyServiceLabelIsNeverAuthorized: a container whose Compose service
// label did not come through must not match. D.1's AuthorizedService refuses
// "" and this is the consequence at this layer.
func TestEmptyServiceLabelIsNeverAuthorized(t *testing.T) {
	const project = "anvil-0123456789abcdef"
	fx := newFixture(t)
	svc := fx.manifest.AuthorizedService()

	unlabelled := contained(project, fixtureService)
	unlabelled.Service = ""
	if _, err := selectAuthorized(svc, []Container{unlabelled}); err == nil {
		t.Fatal("a container with no compose service label was accepted as the " +
			"authorized service")
	}
}

// ---------------------------------------------------------------------------
// Digest, not tag
// ---------------------------------------------------------------------------

func TestResolveDigest(t *testing.T) {
	good := digestOf("web")
	other := digestOf("other")

	cases := []struct {
		name    string
		c       Container
		want    string
		wantErr bool
	}{
		{
			name: "registry digest wins",
			c:    Container{Image: "web:1.2", ImageID: other, RepoDigests: []string{"r.io/web@" + good}},
			want: good,
		},
		{
			name: "several repo names, one digest",
			c: Container{Image: "web:1.2", RepoDigests: []string{
				"r.io/web@" + good, "ghcr.io/org/web@" + good,
			}, ImageID: other},
			want: good,
		},
		{
			name: "locally built image falls back to the content address",
			c:    Container{Image: "web:latest", ImageID: good},
			want: good,
		},
		{
			name: "disagreeing repo digests refuse",
			c: Container{Image: "web:1.2", ImageID: good, RepoDigests: []string{
				"r.io/web@" + good, "ghcr.io/org/web@" + other,
			}},
			wantErr: true,
		},
		{
			name:    "repo digest with no separator refuses",
			c:       Container{Image: "web:1.2", RepoDigests: []string{"r.io/web" + good}},
			wantErr: true,
		},
		{
			name:    "a tag is not a digest",
			c:       Container{Image: "web:1.2", ImageID: "web:1.2"},
			wantErr: true,
		},
		{
			name:    "nothing at all refuses",
			c:       Container{Image: "web:1.2"},
			wantErr: true,
		},
		{
			name:    "a truncated digest refuses",
			c:       Container{Image: "web:1.2", ImageID: digestPrefix + "abcdef"},
			wantErr: true,
		},
		{
			name:    "an uppercase digest refuses rather than being normalised",
			c:       Container{Image: "web:1.2", ImageID: strings.ToUpper(good[len(digestPrefix):])},
			wantErr: true,
		},
		{
			name:    "a non-sha256 algorithm refuses",
			c:       Container{Image: "web:1.2", ImageID: "sha512:" + strings.Repeat("a", 64)},
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveDigest(c.c)
			if c.wantErr {
				if err == nil {
					t.Fatalf("want a refusal, got digest %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveDigest: %v", err)
			}
			if got != c.want {
				t.Errorf("digest = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSealedTargetRecordsTheDigestAndNotOnlyTheTag: research 19 risk #3.
func TestSealedTargetRecordsTheDigestAndNotOnlyTheTag(t *testing.T) {
	fx := newFixture(t)
	f := healthyWorld(fx.project)
	p := newProvisioner(t, f, fx.repoRoot)

	tgt, err := p.Provision(t.Context(), fx.manifest)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !wellFormedDigest(tgt.ImageDigest()) {
		t.Fatalf("ImageDigest() = %q, which is not a %s<%d hex> digest",
			tgt.ImageDigest(), digestPrefix, digestHexLen)
	}
	if tgt.ImageDigest() == tgt.ImageRef() {
		t.Error("the digest and the tag are the same string; a tag is a mutable " +
			"pointer and cannot answer \"what did we scan\" a week later")
	}
}

// ---------------------------------------------------------------------------
// Project naming: teardown destroys volumes and must never aim at an
// operator's own project
// ---------------------------------------------------------------------------

func TestProjectNameIsNamespacedAndDeterministic(t *testing.T) {
	a := projectName("/repo", "./compose.yaml", "web")
	b := projectName("/repo", "./compose.yaml", "web")
	if a != b {
		t.Fatalf("projectName is not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, projectPrefix) {
		t.Errorf("project %q is not namespaced with %q; `down -v` destroys volumes and "+
			"must be impossible to aim at a project the operator created", a, projectPrefix)
	}
	if len(a) != len(projectPrefix)+projectHashHexLen {
		t.Errorf("project %q has length %d, want %d", a, len(a), len(projectPrefix)+projectHashHexLen)
	}
	for i := len(projectPrefix); i < len(a); i++ {
		ch := a[i]
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			t.Errorf("project %q contains %q, which is not a compose-safe character",
				a, string(ch))
		}
	}
}

// TestProjectNameInputsAreUnambiguous: the inputs are length-prefixed before
// hashing, so two different (repoRoot, composeFile, service) triples cannot
// concatenate to the same bytes and share a project -- which would make one
// scan's teardown destroy another's volumes.
func TestProjectNameInputsAreUnambiguous(t *testing.T) {
	a := projectName("/repo/ab", "c.yaml", "web")
	b := projectName("/repo/a", "bc.yaml", "web")
	if a == b {
		t.Fatalf("two different inputs share project %q", a)
	}
	if projectName("/repo", "c.yaml", "web") == projectName("/repo", "c.yaml", "api") {
		t.Fatal("two different authorized services share a project")
	}
}

// ---------------------------------------------------------------------------
// Fail closed on zero values
// ---------------------------------------------------------------------------

func TestZeroTargetIsNotBooted(t *testing.T) {
	var z Target
	if z.Constructed() {
		t.Error("the zero Target reports Constructed()")
	}
	if z.Provenance() != "" {
		t.Errorf("the zero Target reports provenance %q", string(z.Provenance()))
	}
	if err := record.ValidateTargetProvenance(string(z.Provenance())); err == nil {
		t.Error("the zero Target's provenance is a legal record literal; it would be " +
			"written straight into a record")
	}
	if z.Provisioning() != "" {
		t.Errorf("the zero Target reports provisioning %q", string(z.Provisioning()))
	}
	if !z.AuthorizedService().IsZero() {
		t.Error("the zero Target authorizes a service")
	}
	if z.AuthorizedService().Authorizes(fixtureService) {
		t.Error("the zero Target authorizes a named service")
	}
	if err := z.Teardown(t.Context()); err == nil {
		t.Error("the zero Target tore something down")
	}

	var np *Target
	if np.Constructed() {
		t.Error("a nil *Target reports Constructed()")
	}
	if np.ImageDigest() != "" || np.Runtime() != "" || np.Project() != "" {
		t.Error("a nil *Target reports populated fields")
	}
}

// TestForgedTargetIsNotConstructed: a Target built by hand inside this package
// -- the only place that can -- with booted_clean set but no seal is still not
// Constructed. sealed and provenance must BOTH hold.
func TestForgedTargetIsNotConstructed(t *testing.T) {
	forged := &Target{provenance: record.TargetProvenanceBootedClean}
	if forged.Constructed() {
		t.Error("an unsealed Target carrying booted_clean reports Constructed()")
	}
	if forged.Provenance() != "" {
		t.Errorf("an unsealed Target reports provenance %q", string(forged.Provenance()))
	}

	sealedButFailed := &Target{sealed: true, provenance: record.TargetProvenanceBootFailed}
	if sealedButFailed.Constructed() {
		t.Error("a sealed Target carrying boot_failed reports Constructed()")
	}
}

func TestZeroUpStatusIsNotSuccess(t *testing.T) {
	if UpStatusUnreported != "" {
		t.Fatal("UpStatusUnreported is no longer the zero value")
	}
	if UpStatusUp == UpStatusUnreported {
		t.Fatal("the success status is the zero value; an empty UpResult{} would read " +
			"as a project that came up")
	}
}

func TestZeroContainerStateAndHealthAreNotPermissive(t *testing.T) {
	if StateUnknown == StateRunning {
		t.Fatal("the zero ContainerState is running")
	}
	if HealthNone == HealthHealthy {
		t.Fatal("the zero Health is healthy")
	}
}

// TestNewProvisionerRefusesAnIncompleteHarness.
func TestNewProvisionerRefusesAnIncompleteHarness(t *testing.T) {
	if _, err := NewProvisioner(nil, "/repo"); err == nil {
		t.Error("NewProvisioner accepted a nil seam")
	}
	if _, err := NewProvisioner(&fakeDocker{}, "  "); err == nil {
		t.Error("NewProvisioner accepted a blank repo root")
	}
}

// TestManifestWithoutAServiceOrHealthRefuses: target.Load cannot produce one,
// target.Parse and a hand-built &target.Manifest{} can, and a zero-value
// manifest must not read as provisionable. plan/50-dast.md: "No health
// definition means no DAST -- provisioning aborts."
func TestManifestWithoutAServiceOrHealthRefuses(t *testing.T) {
	fx := newFixture(t)
	f := healthyWorld(fx.project)
	p := newProvisioner(t, f, fx.repoRoot)

	tgt, err := p.Provision(t.Context(), &target.Manifest{})
	mustRefuse(t, tgt, err, StagePreflightManifest,
		record.TargetProvenanceBuildFailed, ErrManifestIncomplete)

	if len(f.log()) != 0 {
		t.Errorf("an unprovisionable manifest still reached the seam: %v", f.log())
	}
}

func TestManifestWithNonPositiveTimeoutRefuses(t *testing.T) {
	fx := newFixture(t)
	m := fx.manifest
	m.Health.TimeoutSeconds = 0
	f := healthyWorld(fx.project)
	p := newProvisioner(t, f, fx.repoRoot)

	tgt, err := p.Provision(t.Context(), m)
	mustRefuse(t, tgt, err, StagePreflightManifest,
		record.TargetProvenanceBuildFailed, ErrManifestIncomplete)
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

func TestTeardownFailureIsReportedAndDoesNotChangeTheProvenance(t *testing.T) {
	fx := newFixture(t)
	f := healthyWorld(fx.project)
	f.upResult = UpResult{Status: UpStatusStartFailed, Detail: "exec format error"}
	f.downErr = errors.New("docker compose down: permission denied")
	p := newProvisioner(t, f, fx.repoRoot)

	tgt, err := p.Provision(t.Context(), fx.manifest)
	pe := mustRefuse(t, tgt, err, StageStart, record.TargetProvenanceBootFailed, ErrStartFailed)

	if pe.TeardownError() == nil {
		t.Fatal("a failed teardown was swallowed; leaked containers are exactly what a " +
			"caller needs to alert on")
	}
	if !strings.Contains(err.Error(), "teardown also failed") {
		t.Errorf("the refusal message does not mention the teardown failure: %v", err)
	}
}

func TestTargetTeardownDestroysVolumes(t *testing.T) {
	fx := newFixture(t)
	f := healthyWorld(fx.project)
	p := newProvisioner(t, f, fx.repoRoot)

	tgt, err := p.Provision(t.Context(), fx.manifest)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := tgt.Teardown(t.Context()); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if !f.lastDown.RemoveVolumes {
		t.Error("Teardown did not remove volumes; research 19 step 5 resets by " +
			"destroy-and-recreate, and `down` without -v leaves the target's state")
	}
	if f.lastDown.Project != fx.project {
		t.Errorf("Teardown aimed at %q, want %q", f.lastDown.Project, fx.project)
	}
}

// TestContainersReturnsACopy: the audit-trail list must not be a handle a
// caller can edit after containment was asserted against it.
func TestContainersReturnsACopy(t *testing.T) {
	fx := newFixture(t)
	f := healthyWorld(fx.project)
	p := newProvisioner(t, f, fx.repoRoot)

	tgt, err := p.Provision(t.Context(), fx.manifest)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	got := tgt.Containers()
	if len(got) == 0 {
		t.Fatal("Containers() is empty")
	}
	got[0].Runtime = "runc"
	if tgt.Containers()[0].Runtime != RuntimeName {
		t.Fatal("Containers() hands out the sealed slice; a caller edited what " +
			"containment was asserted against")
	}
}

// ---------------------------------------------------------------------------
// Package-level hygiene
// ---------------------------------------------------------------------------

// TestNothingInThisPackageReadsConfiguration: plan/50-dast.md forbids a
// fallback to a non-gVisor runtime, and a config key that turns an assertion
// off is that fallback wearing a different hat. This is the check that can see
// such a key arriving.
func TestNothingInThisPackageReadsConfiguration(t *testing.T) {
	src, err := os.ReadFile("provision.go")
	if err != nil {
		t.Fatalf("reading provision.go: %v", err)
	}
	for _, forbidden := range []string{"os.Getenv", "os.LookupEnv", "flag."} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("provision.go references %q. Nothing about the runtime, the "+
				"platform or the containment assertions is configurable; widening one "+
				"must be a visible edit to that file", forbidden)
		}
	}
}

// TestThisPackageSkipsNothing: a skipped test still lets the package print ok.
// internal/SKIPPED-CONTROLS.md exists because that has already cost this
// repository twice.
func TestThisPackageSkipsNothing(t *testing.T) {
	src, err := os.ReadFile("provision_test.go")
	if err != nil {
		t.Fatalf("reading provision_test.go: %v", err)
	}
	// The needles are assembled at runtime. Written as literals they would
	// appear in this file and the test would fail against itself, which is how
	// a self-referential guard gets deleted instead of fixed.
	tok := "t." + "Skip"
	for _, forbidden := range []string{tok + "(", tok + "f(", tok + "Now("} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("provision_test.go contains %q. If a control genuinely cannot run "+
				"here, it belongs in internal/SKIPPED-CONTROLS.md with what would "+
				"settle it -- not behind a green tick", forbidden)
		}
	}
}

// TestEveryRecordLiteralComesFromTheRecordPackage: standing order (1). The
// stale enum names -- "clean", "findings", "failed_to_boot", "partial" -- are
// rejected by name in internal/record, and this package must not carry a
// string literal for any record enum. Every provenance it can produce is
// validated by the record package here.
func TestEveryRecordLiteralComesFromTheRecordPackage(t *testing.T) {
	produced := []record.TargetProvenance{record.TargetProvenanceBootedClean}
	for _, s := range StageValues() {
		p, err := s.Provenance()
		if err != nil {
			t.Fatalf("stage %q: %v", string(s), err)
		}
		produced = append(produced, p)
	}
	for _, p := range produced {
		if err := record.ValidateTargetProvenance(string(p)); err != nil {
			t.Errorf("this package can produce %q, which the frozen enum rejects: %v",
				string(p), err)
		}
	}

	src, err := os.ReadFile("provision.go")
	if err != nil {
		t.Fatalf("reading provision.go: %v", err)
	}
	// A quoted stale literal in an assignment or comparison position. The
	// bare words appear in prose; `"failed_to_boot"` does not.
	for _, stale := range []string{`"clean"`, `"findings"`, `"failed_to_boot"`, `"partial"`} {
		if strings.Contains(string(src), stale) {
			t.Errorf("provision.go contains the stale dast_status literal %s. "+
				"internal/record rejects it by name; use the record.DastStatus* "+
				"constants", stale)
		}
	}
}

// TestProvisionErrorCarriesAllThreeFacts: stage, provenance and sentinel must
// agree, and the message must carry all three, because an operator reading one
// log line has only the message.
func TestProvisionErrorCarriesAllThreeFacts(t *testing.T) {
	fx := newFixture(t)
	f := healthyWorld(fx.project)
	f.containers[1].Runtime = "runc"
	p := newProvisioner(t, f, fx.repoRoot)

	_, err := p.Provision(t.Context(), fx.manifest)
	if err == nil {
		t.Fatal("want a refusal")
	}
	msg := err.Error()
	for _, want := range []string{
		string(StageContainment),
		string(record.TargetProvenanceBootFailed),
		"runtime is \"runc\"",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal message does not contain %q: %s", want, msg)
		}
	}
}
