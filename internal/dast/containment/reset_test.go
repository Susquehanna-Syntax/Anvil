package containment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Susquehanna-Syntax/Anvil/internal/dast/target"
	"github.com/Susquehanna-Syntax/Anvil/internal/record"
)

// ---------------------------------------------------------------------------
// The reset world
//
// Target provisioning's fakeDocker returns a FIXED container listing, which is enough to
// decide one provisioning attempt and not enough to decide a reset: a reset
// asks the same seam the same question three times and needs three different
// answers -- what is there now, what is there after `down -v`, and what is
// there after the re-provision. So this file wraps it in a small world model
// that actually destroys and actually recreates.
//
// The model carries STATE, keyed by the container or volume that holds it,
// because "no state survives a reset" is this packet's stop condition and a
// harness that cannot represent state cannot demonstrate it. A probe writes a
// marker; `down -v` destroys the container and the volume that held it; the
// re-provision creates empty ones. Each knob below turns off exactly one part
// of that and is used by exactly one red test.
// ---------------------------------------------------------------------------

const callProjectVolumes callName = "ProjectVolumes"

type resetWorld struct {
	*fakeDocker

	wmu     sync.Mutex
	project string
	gen     int

	volumes    []Volume
	volumesErr error

	// state maps "container:<id>" / "volume:<name>" onto what a probe wrote
	// there.
	state map[string]string

	// lastIDs is the previous generation's container ids, so that
	// reuseContainerIDs can hand back the containers that were already
	// there rather than merely fresh-looking ones.
	lastIDs map[string]string

	// The knobs. Each models one way a destroy-and-recreate can lie.
	downKeepsContainers  bool // `down` reported success and removed nothing
	downKeepsVolumes     bool // the runner dropped the -v
	reuseContainerIDs    bool // `up` reused the previous containers
	digestSalt           string
	postDownContainerErr error
	postUpMutate         func([]Container) []Container
}

func newResetWorld(project string) *resetWorld {
	return &resetWorld{
		fakeDocker: &fakeDocker{
			engine:   healthyEngine(),
			upResult: UpResult{Status: UpStatusUp},
		},
		project: project,
		state:   map[string]string{},
		lastIDs: map[string]string{},
	}
}

// bringUp is what a real `compose up --force-recreate` does to the world: new
// containers, with new ids, holding nothing, and a fresh empty volume.
func (w *resetWorld) bringUp() {
	w.wmu.Lock()
	w.gen++
	gen := w.gen
	reuse := w.reuseContainerIDs
	salt := w.digestSalt
	w.volumes = []Volume{{
		Name:    fmt.Sprintf("%s_%s-data-gen%d", w.project, fixtureService, gen),
		Project: w.project,
		Driver:  "local",
	}}
	w.wmu.Unlock()

	sibling := contained(w.project, fixtureSibling)
	sibling.Health = HealthNone
	svc := contained(w.project, fixtureService)

	sibling.ID = fmt.Sprintf("container-%s-gen%d-000000000000", fixtureSibling, gen)
	svc.ID = fmt.Sprintf("container-%s-gen%d-000000000000", fixtureService, gen)
	if reuse {
		if prev, ok := w.lastIDs[fixtureSibling]; ok {
			sibling.ID = prev
		}
		if prev, ok := w.lastIDs[fixtureService]; ok {
			svc.ID = prev
		}
	}
	w.lastIDs[fixtureSibling] = sibling.ID
	w.lastIDs[fixtureService] = svc.ID

	if salt != "" {
		d := digestOf(fixtureService + salt)
		svc.ImageID = d
		svc.RepoDigests = []string{"registry.example/" + fixtureService + "@" + d}
	}

	cs := []Container{sibling, svc}
	if w.postUpMutate != nil {
		cs = w.postUpMutate(cs)
	}
	w.fakeDocker.containers = cs
}

func (w *resetWorld) ComposeUp(ctx context.Context, req UpRequest) (UpResult, error) {
	res, err := w.fakeDocker.ComposeUp(ctx, req)
	if err == nil && res.Status == UpStatusUp {
		w.bringUp()
	}
	return res, err
}

func (w *resetWorld) ComposeDown(ctx context.Context, req DownRequest) error {
	if err := w.fakeDocker.ComposeDown(ctx, req); err != nil {
		return err
	}
	w.wmu.Lock()
	keepC, keepV := w.downKeepsContainers, w.downKeepsVolumes
	w.wmu.Unlock()

	if !keepC {
		for _, c := range w.fakeDocker.containers {
			delete(w.state, "container:"+c.ID)
		}
		w.fakeDocker.containers = nil
	}
	if req.RemoveVolumes && !keepV {
		w.wmu.Lock()
		for _, v := range w.volumes {
			delete(w.state, "volume:"+v.Name)
		}
		w.volumes = nil
		w.wmu.Unlock()
	}
	if w.postDownContainerErr != nil {
		w.fakeDocker.containersErr = w.postDownContainerErr
	}
	return nil
}

func (w *resetWorld) ProjectVolumes(ctx context.Context, project string) ([]Volume, error) {
	w.record(callProjectVolumes)
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if w.volumesErr != nil {
		return nil, w.volumesErr
	}
	out := make([]Volume, len(w.volumes))
	copy(out, w.volumes)
	return out, nil
}

// writeProbeState is a probe mutating the target: a file on the authorized
// service's writable layer, and a row in the volume its database keeps.
func (w *resetWorld) writeProbeState(t *testing.T, marker string) {
	t.Helper()
	w.wmu.Lock()
	vols := append([]Volume(nil), w.volumes...)
	w.wmu.Unlock()
	if len(w.fakeDocker.containers) == 0 || len(vols) == 0 {
		t.Fatalf("writeProbeState: nothing is up to write to (containers=%d volumes=%d); "+
			"this harness cannot demonstrate state survival if there is no state",
			len(w.fakeDocker.containers), len(vols))
	}
	for _, c := range w.fakeDocker.containers {
		w.state["container:"+c.ID] = marker
	}
	for _, v := range vols {
		w.state["volume:"+v.Name] = marker
	}
}

// visibleState returns every marker still reachable from what is up NOW.
func (w *resetWorld) visibleState() []string {
	seen := map[string]bool{}
	for _, c := range w.fakeDocker.containers {
		if m, ok := w.state["container:"+c.ID]; ok {
			seen[m] = true
		}
	}
	w.wmu.Lock()
	vols := append([]Volume(nil), w.volumes...)
	w.wmu.Unlock()
	for _, v := range vols {
		if m, ok := w.state["volume:"+v.Name]; ok {
			seen[m] = true
		}
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func (w *resetWorld) clearLog() {
	w.fakeDocker.mu.Lock()
	defer w.fakeDocker.mu.Unlock()
	w.fakeDocker.calls = nil
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type resetHarness struct {
	fx     fixture
	world  *resetWorld
	prov   *Provisioner
	reset  *Resetter
	target *Target
}

// newResetHarness provisions a target for real, through target provisioning's Provision, and
// returns it alongside a Resetter. The call log is cleared afterwards so that
// every assertion about calls in this file is about the RESET.
func newResetHarness(t *testing.T) *resetHarness {
	t.Helper()
	fx := newFixture(t)
	w := newResetWorld(fx.project)
	p := newProvisioner(t, w, fx.repoRoot)

	tgt, err := p.Provision(t.Context(), fx.manifest)
	if err != nil {
		t.Fatalf("the first provision must succeed before a reset can be tested: %v", err)
	}
	r, err := NewResetter(p, fx.manifest)
	if err != nil {
		t.Fatalf("NewResetter: %v", err)
	}
	w.clearLog()
	return &resetHarness{fx: fx, world: w, prov: p, reset: r, target: tgt}
}

// mustRefuseReset asserts a reset refusal at a given stage with a given
// provenance and sentinel, asserts the returned target is nil, and asserts the
// handed-in target can no longer be presented as live.
func mustRefuseReset(
	t *testing.T,
	old *Target,
	fresh *Target,
	err error,
	wantStage ResetStage,
	wantProv record.TargetProvenance,
	wantSentinel error,
) *ResetError {
	t.Helper()
	if fresh != nil {
		t.Fatalf("a reset refusal returned a non-nil Target (constructed=%v provenance=%q); "+
			"a caller that ignores the error would probe it",
			fresh.Constructed(), string(fresh.Provenance()))
	}
	var re *ResetError
	if !errors.As(err, &re) {
		t.Fatalf("want *ResetError, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrRefused) {
		t.Errorf("reset refusal does not wrap ErrRefused: %v", err)
	}
	if wantSentinel != nil && !errors.Is(err, wantSentinel) {
		t.Errorf("reset refusal does not wrap %v: %v", wantSentinel, err)
	}
	if re.Stage() != wantStage {
		t.Errorf("stage = %q, want %q (err: %v)", string(re.Stage()), string(wantStage), err)
	}
	if re.Provenance() != wantProv {
		t.Errorf("provenance = %q, want %q (err: %v)",
			string(re.Provenance()), string(wantProv), err)
	}
	if err := record.ValidateTargetProvenance(string(re.Provenance())); err != nil {
		t.Errorf("reset refusal produced a provenance the frozen enum rejects: %v", err)
	}
	if old != nil && old.Constructed() {
		t.Errorf("the target handed to a FAILED reset is still Constructed(); a caller "+
			"that ignores the error can still present it as booted_clean (provenance=%q)",
			string(old.Provenance()))
	}
	ds, derr := re.DastStatus()
	if derr != nil {
		t.Fatalf("ResetError.DastStatus(): %v", derr)
	}
	if ds.MeansDynamicallyScannedClean() {
		t.Errorf("a reset failure at stage %q derives dastStatus %q, which reads as "+
			"\"dynamically scanned, no findings\"", string(re.Stage()), string(ds))
	}
	return re
}

// ---------------------------------------------------------------------------
// ResetStage -> provenance
// ---------------------------------------------------------------------------

// resetStageProvenance is the DECLARED expectation, written by hand rather
// than read from ResetStage.Provenance(), so a change to the mapping is a test
// failure and not a silently-agreeing tautology.
var resetStageProvenance = map[ResetStage]record.TargetProvenance{
	ResetStagePreflight:         record.TargetProvenanceBootFailed,
	ResetStageStrategy:          record.TargetProvenanceBootFailed,
	ResetStageDestroy:           record.TargetProvenanceBootFailed,
	ResetStageDestroyUnverified: record.TargetProvenanceBootFailed,
	ResetStageReprovision:       record.TargetProvenanceBootFailed,
	ResetStageVerify:            record.TargetProvenanceBootFailed,
}

func TestEveryResetStageNamesOneProvenance(t *testing.T) {
	for _, s := range ResetStageValues() {
		want, declared := resetStageProvenance[s]
		if !declared {
			t.Errorf("ResetStage %q is in ResetStageValues() and this test declares no "+
				"expected provenance for it", string(s))
			continue
		}
		got, err := s.Provenance()
		if err != nil {
			t.Errorf("ResetStage %q: %v", string(s), err)
			continue
		}
		if got != want {
			t.Errorf("ResetStage %q maps to %q, want %q", string(s), string(got), string(want))
		}
		if err := record.ValidateTargetProvenance(string(got)); err != nil {
			t.Errorf("ResetStage %q produces %q, which the frozen enum rejects: %v",
				string(s), string(got), err)
		}
	}
	if len(resetStageProvenance) != len(ResetStageValues()) {
		t.Errorf("this test declares %d stages and ResetStageValues() has %d",
			len(resetStageProvenance), len(ResetStageValues()))
	}
}

// TestResetStageValuesCoversEveryDeclaredStage reads reset.go's own source, so
// a stage added to the const block and left out of ResetStageValues() -- which
// would silently drop it from every sweep in this file -- is caught.
func TestResetStageValuesCoversEveryDeclaredStage(t *testing.T) {
	src, err := os.ReadFile("reset.go")
	if err != nil {
		t.Fatalf("reading reset.go: %v", err)
	}
	re := regexp.MustCompile(`\n\tResetStage\w*\s+ResetStage = "([a-z_]*)"`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("found no ResetStage constant declarations in reset.go; this test can no " +
			"longer see the thing it checks")
	}
	declared := map[ResetStage]bool{}
	for _, m := range matches {
		declared[ResetStage(m[1])] = true
	}
	if !declared[ResetStageUnset] {
		t.Error("ResetStageUnset is not declared in the const block; the zero value must " +
			"be named and refused, not implicit")
	}
	for s := range declared {
		if s == ResetStageUnset {
			continue
		}
		if !s.Valid() {
			t.Errorf("reset stage %q is declared in reset.go and is not in "+
				"ResetStageValues()", string(s))
		}
	}
	if len(declared) != len(ResetStageValues())+1 {
		t.Errorf("reset.go declares %d ResetStage constants; ResetStageValues()+"+
			"ResetStageUnset is %d", len(declared), len(ResetStageValues())+1)
	}
}

func TestZeroResetStageRefuses(t *testing.T) {
	if _, err := ResetStageUnset.Provenance(); err == nil {
		t.Fatal("the zero ResetStage produced a provenance. A Go zero value must never " +
			"mean a legal outcome, and \"\" would be written straight into the record")
	}
	if _, err := ResetStage("invented_later").Provenance(); err == nil {
		t.Fatal("an unrecognised ResetStage produced a provenance")
	}
	if ResetStageUnset.Valid() {
		t.Error("ResetStageUnset.Valid() is true")
	}
}

// TestNoResetStageCanBeReadAsScannedClean pins the RELATION, not the values.
// The spine's record section: a target that failed to boot must be distinguishable
// from "scanned clean". A failed reset is a target that is no longer in a
// known state, and no combination of reset stage and half status may derive a
// dastStatus a consumer may read as a clean dynamic scan.
func TestNoResetStageCanBeReadAsScannedClean(t *testing.T) {
	halves := []record.HalfStatus{
		record.HalfStatusRunning, record.HalfStatusSealed, record.HalfStatusFailed,
		record.HalfStatusTimedOut, record.HalfStatusSkipped,
	}
	for _, s := range ResetStageValues() {
		prov, err := s.Provenance()
		if err != nil {
			t.Fatalf("reset stage %q: %v", string(s), err)
		}
		if prov == record.TargetProvenanceBootedClean {
			t.Errorf("reset stage %q maps to booted_clean; a reset FAILURE has no route "+
				"to a provenance that reads as a clean boot", string(s))
		}
		for _, half := range halves {
			got, err := record.DeriveDastStatus(half, record.DastOutcome{
				TierInstalled: true,
				Provenance:    prov,
			})
			if err != nil {
				t.Fatalf("reset stage %q half %q: DeriveDastStatus: %v",
					string(s), string(half), err)
			}
			if got.MeansDynamicallyScannedClean() {
				t.Errorf("reset stage %q with half status %q derives dastStatus %q, "+
					"which a consumer may read as \"dynamically scanned, no findings\"",
					string(s), string(half), string(got))
			}
		}
	}
}

// TestResetFailureDerivesTheExpectedDastStatus: the audit-level value an
// operator actually sees, derived through record.DeriveDastStatus rather than
// written as a literal here.
func TestResetFailureDerivesTheExpectedDastStatus(t *testing.T) {
	for _, s := range ResetStageValues() {
		re := refuseReset(s, ErrDestroyUnverified, "synthetic")
		if re.HalfStatus() != record.HalfStatusFailed {
			t.Errorf("reset stage %q reports half status %q; a reset that broke mid-run "+
				"is a half that FAILED, not one that covered part of the surface",
				string(s), string(re.HalfStatus()))
		}
		got, err := re.DastStatus()
		if err != nil {
			t.Fatalf("reset stage %q: DastStatus: %v", string(s), err)
		}
		if got != record.DastStatusTargetBootFailed {
			t.Errorf("reset stage %q derives dastStatus %q, want %q",
				string(s), string(got), string(record.DastStatusTargetBootFailed))
		}
	}
}

// ---------------------------------------------------------------------------
// NewResetter
// ---------------------------------------------------------------------------

// dockerOnlySeam implements Docker and NOT VolumeInspector.
type dockerOnlySeam struct{ *fakeDocker }

func TestNewResetterRefusesEveryUnverifiableConfiguration(t *testing.T) {
	fx := newFixture(t)
	w := newResetWorld(fx.project)
	good := newProvisioner(t, w, fx.repoRoot)

	seeded, err := target.Parse([]byte(`schema_version: 1
compose_file: ./docker-compose.anvil.yaml
service: web
health:
  url: http://web:8080/healthz
  timeout_seconds: 120
  interval_seconds: 5
seed:
  command: ["make", "seed"]
  timeout_seconds: 60
reset:
  strategy: destroy_recreate
`))
	if err != nil {
		t.Fatalf("the seeded fixture manifest must parse; the target manifest refused it: %v", err)
	}

	// A manifest that is valid in every respect EXCEPT its reset strategy.
	// The target manifest cannot produce one -- it refuses anything but destroy_recreate at
	// parse time -- so it is built by parsing a good one and zeroing the
	// field, which is exactly the shape a hand-built &target.Manifest{} or a
	// later-added second strategy would have.
	zeroStrategy, err := target.Parse([]byte(fixtureManifestYAML(120)))
	if err != nil {
		t.Fatalf("the fixture manifest must parse: %v", err)
	}
	zeroStrategy.Reset.Strategy = ""

	cases := []struct {
		name     string
		p        *Provisioner
		m        *target.Manifest
		sentinel error
		wantMsg  string
	}{
		{
			name: "nil provisioner",
			p:    nil,
			m:    fx.manifest,
		},
		{
			name: "provisioner not built by NewProvisioner",
			p:    &Provisioner{},
			m:    fx.manifest,
		},
		{
			name: "nil manifest",
			p:    good,
			m:    nil,
		},
		{
			name:     "manifest with the zero reset strategy",
			p:        good,
			m:        zeroStrategy,
			sentinel: ErrResetStrategyUnsupported,
		},
		{
			name:     "hand-built manifest with no authorized service",
			p:        good,
			m:        &target.Manifest{SchemaVersion: 1, ComposeFile: fixtureComposeRel},
			sentinel: nil,
			wantMsg:  "no authorized service",
		},
		{
			name:     "manifest declaring a seed this package cannot replay",
			p:        good,
			m:        seeded,
			sentinel: ErrResetSeedNotReplayable,
			wantMsg:  "make",
		},
		{
			name: "seam that cannot list volumes",
			p: newProvisioner(t,
				dockerOnlySeam{fakeDocker: &fakeDocker{engine: healthyEngine()}},
				fx.repoRoot),
			m:        fx.manifest,
			sentinel: ErrResetSeamIncomplete,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewResetter(tc.p, tc.m)
			if err == nil {
				t.Fatalf("NewResetter accepted %s; every refusal it makes is a condition "+
					"under which a reset could not be VERIFIED, and discovering one "+
					"halfway through means discovering it with the target destroyed",
					tc.name)
			}
			if r != nil {
				t.Errorf("a refused NewResetter returned a non-nil *Resetter")
			}
			if !errors.Is(err, ErrRefused) {
				t.Errorf("refusal does not wrap ErrRefused: %v", err)
			}
			if tc.sentinel != nil && !errors.Is(err, tc.sentinel) {
				t.Errorf("refusal does not wrap %v: %v", tc.sentinel, err)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("refusal message does not contain %q: %v", tc.wantMsg, err)
			}
		})
	}
}

func TestNewResetterAcceptsTheDeclaredStrategyOnly(t *testing.T) {
	fx := newFixture(t)
	w := newResetWorld(fx.project)
	p := newProvisioner(t, w, fx.repoRoot)

	r, err := NewResetter(p, fx.manifest)
	if err != nil {
		t.Fatalf("NewResetter refused the valid fixture manifest: %v", err)
	}
	if r.Strategy() != target.ResetStrategyDestroyRecreate {
		t.Errorf("Strategy() = %q, want %q", r.Strategy(), target.ResetStrategyDestroyRecreate)
	}
	if r.Manifest() != fx.manifest {
		t.Error("Manifest() did not return the manifest the resetter was built with; a " +
			"reset that re-provisions from a different manifest brings up a different " +
			"target and hands it back as this one")
	}
}

// ---------------------------------------------------------------------------
// The stop condition: no state survives a reset
// ---------------------------------------------------------------------------

// TestNoStateSurvivesAReset is target reset's design required evidence. A
// probe writes to the container's writable layer and to the database volume;
// after a reset, neither is reachable.
func TestNoStateSurvivesAReset(t *testing.T) {
	h := newResetHarness(t)
	h.world.writeProbeState(t, "probe-1-wrote-this")

	if got := h.world.visibleState(); len(got) != 1 || got[0] != "probe-1-wrote-this" {
		t.Fatalf("the harness cannot see the state it just wrote (%v); a test that cannot "+
			"see the damage is not a test", got)
	}

	fresh, err := h.reset.Reset(t.Context(), h.target)
	if err != nil {
		t.Fatalf("Reset refused a world where everything works: %v", err)
	}
	if !fresh.Constructed() {
		t.Fatalf("Reset returned an unsealed target (provenance=%q)", string(fresh.Provenance()))
	}

	if got := h.world.visibleState(); len(got) != 0 {
		t.Errorf("state written before the reset is still reachable after it: %v. Every "+
			"probe after this point measures an application the previous probe already "+
			"changed, and it does so silently", got)
	}
}

// TestTheStateSurvivalCheckCanSeeSurvivingState is the negative control for
// the test above. An assertion that state is gone proves nothing unless the
// same harness would have SEEN it survive -- so this runs the same reset
// against a world whose `down` drops the -v, and asserts both halves: the
// markers are still reachable, and the reset refused rather than handing back
// a target carrying them.
func TestTheStateSurvivalCheckCanSeeSurvivingState(t *testing.T) {
	h := newResetHarness(t)
	h.world.downKeepsVolumes = true
	h.world.writeProbeState(t, "probe-1-wrote-this")

	fresh, err := h.reset.Reset(t.Context(), h.target)
	if err == nil {
		t.Fatal("a reset that left the previous probe's volume in place reported success")
	}
	if fresh != nil {
		t.Error("a refused reset returned a target")
	}
	got := h.world.visibleState()
	if len(got) != 1 || got[0] != "probe-1-wrote-this" {
		t.Fatalf("the harness reports visible state %v after a `down` WITHOUT -v; if it "+
			"cannot see state survive, the test above is asserting nothing", got)
	}
}

// TestResetProducesADifferentInstanceOfTheSameApplication pins BOTH halves of
// the verification, because neither implies the other: same declared state,
// different instance.
func TestResetProducesADifferentInstanceOfTheSameApplication(t *testing.T) {
	h := newResetHarness(t)

	beforeID := h.target.ContainerID()
	beforeDigest := h.target.ImageDigest()
	beforeProject := h.target.Project()
	beforeIDs := map[string]bool{}
	for _, c := range h.target.Containers() {
		beforeIDs[c.ID] = true
	}
	if len(beforeIDs) < 2 {
		t.Fatalf("the fixture project has %d containers; the whole-project id check "+
			"cannot be demonstrated on fewer than two", len(beforeIDs))
	}

	fresh, err := h.reset.Reset(t.Context(), h.target)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}

	if fresh.ImageDigest() != beforeDigest {
		t.Errorf("image digest moved across the reset: %q -> %q. Two probe phases against "+
			"two different applications are not comparable", beforeDigest, fresh.ImageDigest())
	}
	if fresh.Project() != beforeProject {
		t.Errorf("project = %q, want %q", fresh.Project(), beforeProject)
	}
	if fresh.Provenance() != record.TargetProvenanceBootedClean {
		t.Errorf("a reset target's provenance is %q, want %q",
			string(fresh.Provenance()), string(record.TargetProvenanceBootedClean))
	}
	if fresh.ContainerID() == beforeID {
		t.Errorf("the authorized service's container id is unchanged (%s); a "+
			"destroy-and-recreate produces a new container", shortID(beforeID))
	}
	for _, c := range fresh.Containers() {
		if beforeIDs[c.ID] {
			t.Errorf("container %s (service %q) survived the reset; every container in "+
				"the project is destroyed and recreated, not only the authorized service",
				shortID(c.ID), c.Service)
		}
	}
}

// TestSuccessfulResetInvalidatesTheOldHandle: the old Target names a container
// that no longer exists.
func TestSuccessfulResetInvalidatesTheOldHandle(t *testing.T) {
	h := newResetHarness(t)
	old := h.target

	if _, err := h.reset.Reset(t.Context(), old); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if old.Constructed() {
		t.Error("the target handed to a SUCCESSFUL reset is still Constructed(); it names " +
			"a destroyed container, and a handle to a destroyed container is not a target")
	}
	if old.Provenance() != "" {
		t.Errorf("the old handle still reports provenance %q, which would be written into "+
			"a record as a live target's boot outcome", string(old.Provenance()))
	}
}

// TestResetAsksForVolumeRemoval: the request half. research 19 step 5 is
// `docker compose down -v`, and the observation checks below are only
// meaningful if the destroy was ASKED to remove volumes in the first place.
func TestResetAsksForVolumeRemoval(t *testing.T) {
	h := newResetHarness(t)
	if _, err := h.reset.Reset(t.Context(), h.target); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	h.world.fakeDocker.mu.Lock()
	down := h.world.fakeDocker.lastDown
	h.world.fakeDocker.mu.Unlock()

	if !down.RemoveVolumes {
		t.Error("the reset's DownRequest.RemoveVolumes is false. `down` without -v keeps " +
			"named volumes, so the previous probe's database rows survive into a project " +
			"whose containers are all new")
	}
	if down.Project != h.fx.project {
		t.Errorf("the reset aimed `down -v` at project %q, want %q", down.Project, h.fx.project)
	}
	if !strings.HasPrefix(down.Project, projectPrefix) {
		t.Errorf("the reset aimed `down -v` at project %q, which does not carry the %q "+
			"namespace; `down -v` destroys volumes and must never be aimed at a project "+
			"the operator created", down.Project, projectPrefix)
	}
}

// TestResetVerifiesTheDestroyBeforeReProvisioning pins the ORDER, which is the
// relation the whole packet turns on: destroy, then PROVE the destroy, then
// bring it back through target provisioning's Provision unchanged. A reset that re-provisions
// first and looks afterwards can no longer tell what survived.
func TestResetVerifiesTheDestroyBeforeReProvisioning(t *testing.T) {
	h := newResetHarness(t)
	if _, err := h.reset.Reset(t.Context(), h.target); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	want := []callName{
		callComposeDown,       // destroy
		callProjectContainers, // observation 1
		callProjectVolumes,    // observation 2
		callEngineInfo,        // Provision: runsc preflight
		callComposeUp,         // Provision: bring it back
		callProjectContainers, // Provision: containment on every container
		callProbeHealth,       // Provision: probe-side reachability
	}
	got := h.world.log()
	if len(got) != len(want) {
		t.Fatalf("reset call log = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reset call log = %v, want %v (differs at %d)", got, want, i)
		}
	}
}

// ---------------------------------------------------------------------------
// The failure modes -- one red test per knob
// ---------------------------------------------------------------------------

// TestASilentDestroyIsCaught: ComposeDown returns nil and removes nothing.
// This is the shape that returns a result and means nothing.
func TestASilentDestroyIsCaught(t *testing.T) {
	h := newResetHarness(t)
	h.world.downKeepsContainers = true
	h.world.writeProbeState(t, "probe-1-wrote-this")

	fresh, err := h.reset.Reset(t.Context(), h.target)
	re := mustRefuseReset(t, h.target, fresh, err, ResetStageDestroyUnverified,
		record.TargetProvenanceBootFailed, ErrDestroyUnverified)

	for _, want := range []string{"survived it", "writable layer", fixtureService} {
		if !strings.Contains(re.Error(), want) {
			t.Errorf("refusal message does not contain %q: %v", want, re)
		}
	}
	if h.world.called(callComposeUp) {
		t.Error("the reset re-provisioned after an unverified destroy; the point of " +
			"verifying the destroy is to stop before the evidence is overwritten")
	}
}

// TestASurvivingVolumeIsCaught is the check the container listing cannot make.
// `down` WITHOUT -v removes every container and keeps the named volumes: the
// containers are all provably new and they mount the previous probe's database
// rows.
func TestASurvivingVolumeIsCaught(t *testing.T) {
	h := newResetHarness(t)
	h.world.downKeepsVolumes = true
	h.world.writeProbeState(t, "probe-1-wrote-this")

	fresh, err := h.reset.Reset(t.Context(), h.target)
	re := mustRefuseReset(t, h.target, fresh, err, ResetStageDestroyUnverified,
		record.TargetProvenanceBootFailed, ErrDestroyUnverified)

	for _, want := range []string{"volume(s) survived it", "-data"} {
		if !strings.Contains(re.Error(), want) {
			t.Errorf("refusal message does not contain %q: %v", want, re)
		}
	}
	// The damage this test exists for: every container is gone, so the
	// container listing is empty and observation 1 passes on this world.
	if len(h.world.fakeDocker.containers) != 0 {
		t.Fatalf("this test is not exercising what it claims: %d container(s) remain, so "+
			"observation 1 would have caught it and observation 2 is untested",
			len(h.world.fakeDocker.containers))
	}
}

// TestAnUnanswerableDestroyCheckRefuses: "we could not look" is never "there
// was nothing there".
func TestAnUnanswerableDestroyCheckRefuses(t *testing.T) {
	t.Run("container listing fails", func(t *testing.T) {
		h := newResetHarness(t)
		h.world.postDownContainerErr = errors.New("engine socket closed")

		fresh, err := h.reset.Reset(t.Context(), h.target)
		re := mustRefuseReset(t, h.target, fresh, err, ResetStageDestroyUnverified,
			record.TargetProvenanceBootFailed, ErrDestroyUnverified)
		if !strings.Contains(re.Error(), "could not be taken") {
			t.Errorf("refusal message does not say the check could not be made: %v", re)
		}
	})

	t.Run("volume listing fails", func(t *testing.T) {
		h := newResetHarness(t)
		h.world.volumesErr = errors.New("volume driver timed out")

		fresh, err := h.reset.Reset(t.Context(), h.target)
		re := mustRefuseReset(t, h.target, fresh, err, ResetStageDestroyUnverified,
			record.TargetProvenanceBootFailed, ErrDestroyUnverified)
		if !strings.Contains(re.Error(), "volume") {
			t.Errorf("refusal message does not name the volume listing: %v", re)
		}
		if h.world.called(callComposeUp) {
			t.Error("the reset re-provisioned after an unanswerable volume check")
		}
	})
}

func TestDestroyFailureStopsTheRun(t *testing.T) {
	h := newResetHarness(t)
	h.world.fakeDocker.downErr = errors.New("compose down: exit status 1")

	fresh, err := h.reset.Reset(t.Context(), h.target)
	re := mustRefuseReset(t, h.target, fresh, err, ResetStageDestroy,
		record.TargetProvenanceBootFailed, ErrDestroyFailed)
	if !strings.Contains(re.Error(), "exit status 1") {
		t.Errorf("refusal message drops the runner's diagnostic: %v", re)
	}
	if h.world.called(callComposeUp) {
		t.Error("the reset re-provisioned after a failed destroy")
	}
}

// TestReprovisionFailureCarriesTheProvisionersOwnProvenance: the one stage
// whose provenance is NARROWED past the boot_failed floor. A build failure
// after a verified destroy is still a build failure, and flattening it sends
// the operator to debug a container that never started.
func TestReprovisionFailureCarriesTheProvisionersOwnProvenance(t *testing.T) {
	cases := []struct {
		name     string
		arrange  func(w *resetWorld)
		wantProv record.TargetProvenance
		wantPE   Stage
	}{
		{
			name: "the image no longer builds",
			arrange: func(w *resetWorld) {
				w.fakeDocker.upResult = UpResult{
					Status: UpStatusBuildFailed,
					Detail: "Dockerfile step 4 exited 1",
				}
			},
			wantProv: record.TargetProvenanceBuildFailed,
			wantPE:   StageBuild,
		},
		{
			name: "the target comes back uncontained",
			arrange: func(w *resetWorld) {
				w.postUpMutate = func(cs []Container) []Container {
					cs[1].Runtime = "runc"
					return cs
				}
			},
			wantProv: record.TargetProvenanceBootFailed,
			wantPE:   StageContainment,
		},
		{
			name: "the target comes back unreachable from the probe side",
			arrange: func(w *resetWorld) {
				w.fakeDocker.probeErr = errors.New("connection refused")
			},
			wantProv: record.TargetProvenanceUnreachableAtScanTime,
			wantPE:   StageReachability,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newResetHarness(t)
			tc.arrange(h.world)

			fresh, err := h.reset.Reset(t.Context(), h.target)
			re := mustRefuseReset(t, h.target, fresh, err, ResetStageReprovision,
				tc.wantProv, ErrReprovisionFailed)

			var pe *ProvisionError
			if !errors.As(err, &pe) {
				t.Fatalf("a re-provision refusal does not unwrap to a *ProvisionError; "+
					"the provisioning stage that actually refused is lost: %v", err)
			}
			if pe.Stage() != tc.wantPE {
				t.Errorf("underlying provision stage = %q, want %q",
					string(pe.Stage()), string(tc.wantPE))
			}
			if !strings.Contains(re.Error(), string(tc.wantPE)) {
				t.Errorf("refusal message does not name the provisioning stage %q: %v",
					string(tc.wantPE), re)
			}
		})
	}
}

// TestReprovisionNeverCarriesAProvenanceThatReadsAsCleanOrAbsent: the one door
// into this package's provenance that is not a ResetStage. A *ProvisionError
// claiming booted_clean, or claiming no target was declared, must not be
// propagated -- the first would read as a clean boot and the second as
// "nothing to scan".
func TestReprovisionNeverCarriesAProvenanceThatReadsAsCleanOrAbsent(t *testing.T) {
	cases := []struct {
		name string
		pe   *ProvisionError
	}{
		{
			name: "booted_clean",
			pe: &ProvisionError{
				stage:      StageHealth,
				provenance: record.TargetProvenanceBootedClean,
				sentinel:   ErrNotHealthy,
				detail:     "synthetic",
			},
		},
		{
			name: "no_target_declared",
			pe: &ProvisionError{
				stage:      StageNoTargetDeclared,
				provenance: record.TargetProvenanceNoTargetDeclared,
				sentinel:   ErrNoTargetDeclared,
				detail:     "synthetic",
			},
		},
		{
			name: "a provenance the frozen enum rejects",
			pe: &ProvisionError{
				stage:      StageHealth,
				provenance: record.TargetProvenance("invented_later"),
				sentinel:   ErrNotHealthy,
				detail:     "synthetic",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re := refuseReprovision(tc.pe)
			if re.Provenance() != record.TargetProvenanceBootFailed {
				t.Fatalf("provenance = %q, want the %q floor", string(re.Provenance()),
					string(record.TargetProvenanceBootFailed))
			}
			if err := record.ValidateTargetProvenance(string(re.Provenance())); err != nil {
				t.Errorf("floor provenance is not a legal literal: %v", err)
			}
			ds, err := re.DastStatus()
			if err != nil {
				t.Fatalf("DastStatus: %v", err)
			}
			if ds.MeansDynamicallyScannedClean() {
				t.Errorf("derived dastStatus %q reads as scanned-clean", string(ds))
			}
			if !strings.Contains(re.Error(), "was recorded instead") {
				t.Errorf("the substitution is silent; the message must say the reported "+
					"provenance was replaced: %v", re)
			}
		})
	}
}

// TestAReusedContainerIsCaught: `up` handed back the containers that were
// already there. Nothing errored; the writable layer is the old one.
func TestAReusedContainerIsCaught(t *testing.T) {
	h := newResetHarness(t)
	h.world.reuseContainerIDs = true
	h.world.writeProbeState(t, "probe-1-wrote-this")

	fresh, err := h.reset.Reset(t.Context(), h.target)
	re := mustRefuseReset(t, h.target, fresh, err, ResetStageVerify,
		record.TargetProvenanceBootFailed, ErrResetNotVerified)

	for _, want := range []string{"is still", "writable layer"} {
		if !strings.Contains(re.Error(), want) {
			t.Errorf("refusal message does not contain %q: %v", want, re)
		}
	}
	// An unverified target that is still up is one a probe could be pointed
	// at, so the reset destroys it before refusing.
	h.world.fakeDocker.mu.Lock()
	down := h.world.fakeDocker.lastDown
	h.world.fakeDocker.mu.Unlock()
	if !down.RemoveVolumes || down.Project != h.fx.project {
		t.Errorf("the unverified target was not destroyed before the refusal (last down: "+
			"%+v)", down)
	}
}

// TestADigestThatMovedIsCaught: the reset brought up a DIFFERENT application
// and every other check passes. Probe phase 1 and probe phase 2 would be
// compared against each other and they are not comparable.
func TestADigestThatMovedIsCaught(t *testing.T) {
	h := newResetHarness(t)
	h.world.digestSalt = "-rebuilt-under-us"

	fresh, err := h.reset.Reset(t.Context(), h.target)
	re := mustRefuseReset(t, h.target, fresh, err, ResetStageVerify,
		record.TargetProvenanceBootFailed, ErrResetNotVerified)
	if !strings.Contains(re.Error(), "image digest") {
		t.Errorf("refusal message does not name the digest: %v", re)
	}
	if !strings.Contains(re.Error(), "did not come back") {
		t.Errorf("refusal message does not say the declared initial state did not come "+
			"back: %v", re)
	}
}

// TestVerifyFreshChecksEveryDeclaredField sweeps the identity fields one at a
// time, so a field dropped from verifyFresh is caught rather than becoming a
// thing nobody compares. Each case mutates ONE field of the "after" target;
// the unmutated control asserts the comparison passes on an honest reset, so a
// verifier that rejected everything would not pass this test.
func TestVerifyFreshChecksEveryDeclaredField(t *testing.T) {
	base := func() (resetIdentity, *Target) {
		before := resetIdentity{
			project: "anvil-0123456789abcdef",
			// The zero AuthorizedService a hand-built *Target carries has an
			// empty Name(), so the service field is exercised by its own test
			// below rather than being pinned to a value this base case cannot
			// reproduce.
			service:      "",
			imageRef:     "web:latest",
			imageDigest:  digestOf("web"),
			healthURL:    fixtureHealthURL,
			runtime:      RuntimeName,
			platform:     RuntimePlatform,
			provisioning: record.TargetProvisioningEphemeralManifest,
			containerID:  "container-web-gen1",
			containerIDs: []string{"container-db-gen1", "container-web-gen1"},
		}
		after := &Target{
			sealed:       true,
			project:      before.project,
			imageRef:     before.imageRef,
			imageDigest:  before.imageDigest,
			healthURL:    before.healthURL,
			runtime:      before.runtime,
			platform:     before.platform,
			provisioning: before.provisioning,
			provenance:   record.TargetProvenanceBootedClean,
			containerID:  "container-web-gen2",
			containers: []Container{
				{ID: "container-db-gen2", Service: fixtureSibling},
				{ID: "container-web-gen2", Service: fixtureService},
			},
		}
		return before, after
	}

	// The control. If this fails, every case below is passing for the wrong
	// reason.
	before, after := base()
	if err := verifyFresh(before, after); err != nil {
		t.Fatalf("verifyFresh rejected an honest reset: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(a *Target)
		wantMsg string
	}{
		{"project", func(a *Target) { a.project = "anvil-ffffffffffffffff" }, "project"},
		{"image ref", func(a *Target) { a.imageRef = "web:2" }, "image ref"},
		{"image digest", func(a *Target) { a.imageDigest = digestOf("other") }, "image digest"},
		{"health url", func(a *Target) { a.healthURL = "http://web:9090/healthz" }, "health url"},
		{"runtime", func(a *Target) { a.runtime = "runc" }, "runtime"},
		{"platform", func(a *Target) { a.platform = "kvm" }, "gvisor platform"},
		{"provisioning", func(a *Target) {
			a.provisioning = record.TargetProvisioningLiveURLAuthorized
		}, "provisioning"},
		{"authorized container reused", func(a *Target) {
			a.containerID = "container-web-gen1"
			a.containers[1].ID = "container-web-gen1"
		}, "is still"},
		{"sibling container reused", func(a *Target) {
			a.containers[0].ID = "container-db-gen1"
		}, "present before the reset"},
		{"unsealed", func(a *Target) { a.sealed = false }, "unsealed target"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before, after := base()
			tc.mutate(after)
			err := verifyFresh(before, after)
			if err == nil {
				t.Fatalf("verifyFresh accepted a target whose %s does not match the one "+
					"that was destroyed", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("verification failure does not name %q: %v", tc.wantMsg, err)
			}
		})
	}

	t.Run("nil target", func(t *testing.T) {
		before, _ := base()
		if err := verifyFresh(before, nil); err == nil {
			t.Fatal("verifyFresh accepted a nil target")
		}
	})
}

// TestVerifyFreshRequiresTheAuthorizedServiceIdentity is separate because the
// service name lives on an unexported target.AuthorizedService that a
// hand-built *Target cannot carry, so the check is driven through the identity
// capture instead.
func TestVerifyFreshRequiresTheAuthorizedServiceIdentity(t *testing.T) {
	before := resetIdentity{
		project: "anvil-0123456789abcdef", service: fixtureService,
		imageDigest: digestOf("web"), containerID: "a", containerIDs: []string{"a"},
	}
	after := &Target{
		sealed: true, project: before.project, imageDigest: before.imageDigest,
		provenance: record.TargetProvenanceBootedClean, containerID: "b",
		containers: []Container{{ID: "b"}},
	}
	// after.service is the zero AuthorizedService, so its Name() is "".
	err := verifyFresh(before, after)
	if err == nil {
		t.Fatal("verifyFresh accepted a target whose authorized service is not the one " +
			"that was destroyed")
	}
	if !strings.Contains(err.Error(), "authorized service") {
		t.Errorf("verification failure does not name the authorized service: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

// TestAForeignTargetIsNeitherResetNorDestroyed: `down -v` destroys volumes,
// and a Resetter must never aim it at a project it does not own.
func TestAForeignTargetIsNeitherResetNorDestroyed(t *testing.T) {
	a := newResetHarness(t)
	b := newResetHarness(t)
	b.world.clearLog()

	fresh, err := b.reset.Reset(t.Context(), a.target)
	re := mustRefuseReset(t, a.target, fresh, err, ResetStagePreflight,
		record.TargetProvenanceBootFailed, ErrResetForeignTarget)

	if b.world.called(callComposeDown) {
		t.Error("a resetter aimed `down -v` at a project belonging to another manifest")
	}
	if a.world.called(callComposeDown) {
		t.Error("a resetter tore down a target it does not own")
	}
	if !strings.Contains(re.Error(), "NOT torn down") {
		t.Errorf("the refusal does not tell the operator the target was left running, "+
			"which is the leak they have to clean up: %v", re)
	}
}

func TestResetPreflightRefusals(t *testing.T) {
	t.Run("nil target", func(t *testing.T) {
		h := newResetHarness(t)
		fresh, err := h.reset.Reset(t.Context(), nil)
		mustRefuseReset(t, nil, fresh, err, ResetStagePreflight,
			record.TargetProvenanceBootFailed, ErrResetNotConstructed)
		if h.world.called(callComposeDown) {
			t.Error("a nil target reached the seam")
		}
	})

	t.Run("unsealed target", func(t *testing.T) {
		h := newResetHarness(t)
		fresh, err := h.reset.Reset(t.Context(), &Target{})
		mustRefuseReset(t, nil, fresh, err, ResetStagePreflight,
			record.TargetProvenanceBootFailed, ErrResetNotConstructed)
		if h.world.called(callComposeDown) {
			t.Error("an unsealed target reached the seam")
		}
	})

	t.Run("resetter NewResetter did not build", func(t *testing.T) {
		h := newResetHarness(t)
		var r Resetter
		fresh, err := r.Reset(t.Context(), h.target)
		mustRefuseReset(t, h.target, fresh, err, ResetStagePreflight,
			record.TargetProvenanceBootFailed, ErrResetNotConstructed)
		if h.world.called(callComposeDown) {
			t.Error("a zero-value Resetter reached the seam")
		}
	})

	t.Run("nil resetter", func(t *testing.T) {
		h := newResetHarness(t)
		var r *Resetter
		fresh, err := r.Reset(t.Context(), h.target)
		mustRefuseReset(t, h.target, fresh, err, ResetStagePreflight,
			record.TargetProvenanceBootFailed, ErrResetNotConstructed)
	})
}

// TestStrategyIsRecheckedAtTheLastMomentBeforeADestroy: the manifest is held
// by pointer, so NewResetter's check is not the last word on it. Nothing is
// destroyed when the strategy is no longer the declared one.
func TestStrategyIsRecheckedAtTheLastMomentBeforeADestroy(t *testing.T) {
	h := newResetHarness(t)
	h.reset.m.Reset.Strategy = ""

	fresh, err := h.reset.Reset(t.Context(), h.target)
	re := mustRefuseReset(t, h.target, fresh, err, ResetStageStrategy,
		record.TargetProvenanceBootFailed, ErrResetStrategyUnsupported)
	if !strings.Contains(re.Error(), "nothing was destroyed") {
		t.Errorf("the refusal does not say the target is untouched: %v", re)
	}
	if h.world.called(callComposeDown) {
		t.Error("a reset with an unsupported strategy still ran `down -v`")
	}
}

// ---------------------------------------------------------------------------
// A failed reset stops the run for that target -- structurally, over every
// failure mode there is
// ---------------------------------------------------------------------------

func TestEveryResetFailureStopsTheRunForThatTarget(t *testing.T) {
	cases := []struct {
		name    string
		arrange func(h *resetHarness)
	}{
		{"strategy", func(h *resetHarness) { h.reset.m.Reset.Strategy = "snapshot_restore" }},
		{"destroy failed", func(h *resetHarness) {
			h.world.fakeDocker.downErr = errors.New("boom")
		}},
		{"destroy silent", func(h *resetHarness) { h.world.downKeepsContainers = true }},
		{"volumes survived", func(h *resetHarness) { h.world.downKeepsVolumes = true }},
		{"destroy unverifiable", func(h *resetHarness) {
			h.world.volumesErr = errors.New("boom")
		}},
		{"reprovision failed", func(h *resetHarness) {
			h.world.fakeDocker.upResult = UpResult{Status: UpStatusStartFailed}
		}},
		{"container reused", func(h *resetHarness) { h.world.reuseContainerIDs = true }},
		{"digest moved", func(h *resetHarness) { h.world.digestSalt = "-moved" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newResetHarness(t)
			tc.arrange(h)

			fresh, err := h.reset.Reset(t.Context(), h.target)
			if err == nil {
				t.Fatal("want a refusal")
			}
			if fresh != nil {
				t.Errorf("a failed reset returned a non-nil target")
			}
			if h.target.Constructed() {
				t.Errorf("after a failed reset the old target is still Constructed(); the " +
					"run does not stop, it continues against a target nobody can name")
			}
			if h.target.Provenance() != "" {
				t.Errorf("the old handle still reports provenance %q",
					string(h.target.Provenance()))
			}
			if err := record.ValidateTargetProvenance(string(h.target.Provenance())); err == nil {
				t.Error("an invalidated target's provenance is still a legal record " +
					"literal; it could be written into a record as a boot outcome")
			}
			var re *ResetError
			if !errors.As(err, &re) {
				t.Fatalf("want *ResetError, got %T", err)
			}
			ds, derr := re.DastStatus()
			if derr != nil {
				t.Fatalf("DastStatus: %v", derr)
			}
			if ds.MeansDynamicallyScannedClean() {
				t.Errorf("dastStatus %q reads as scanned-clean", string(ds))
			}
		})
	}
}

func TestResetErrorCarriesAllThreeFacts(t *testing.T) {
	h := newResetHarness(t)
	h.world.downKeepsVolumes = true

	_, err := h.reset.Reset(t.Context(), h.target)
	if err == nil {
		t.Fatal("want a refusal")
	}
	msg := err.Error()
	for _, want := range []string{
		string(ResetStageDestroyUnverified),
		string(record.TargetProvenanceBootFailed),
		ErrDestroyUnverified.Error(),
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("reset refusal message does not contain %q: %s", want, msg)
		}
	}
}

// ---------------------------------------------------------------------------
// Standing orders
// ---------------------------------------------------------------------------

// TestNoSnapshotPathExists: target reset's design forbids a snapshot/restore
// state-reset path in this file. research 19 reserves it for a future
// Firecracker tier and calls resuming from the same state more than once
// insecure. The tripwire is on IDENTIFIERS -- a snapshot path would need a
// name -- and the prose above spells the word in lower case so the guard can
// see an added `Snapshot`/`Restore`/`Checkpoint` symbol.
func TestNoSnapshotPathExists(t *testing.T) {
	src, err := os.ReadFile("reset.go")
	if err != nil {
		t.Fatalf("reading reset.go: %v", err)
	}
	for _, forbidden := range []string{"Snapshot", "Restore", "Checkpoint", "Rollback"} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("reset.go declares or calls something named %q. research/19 reserves "+
				"snapshot/restore for a future Firecracker tier and is explicit that "+
				"resuming execution from the same state more than once is insecure; v1 "+
				"resets by destroy-and-recreate only", forbidden)
		}
	}
}

func TestResetReadsNoConfiguration(t *testing.T) {
	src, err := os.ReadFile("reset.go")
	if err != nil {
		t.Fatalf("reading reset.go: %v", err)
	}
	for _, forbidden := range []string{"os.Getenv", "os.LookupEnv", "flag."} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("reset.go references %q. Nothing about the four verification "+
				"observations is configurable; a key that turns one off is a "+
				"snapshot-restore path wearing a different hat", forbidden)
		}
	}
}

// TestResetFileSkipsNothing: a skipped test still lets the package print ok.
func TestResetFileSkipsNothing(t *testing.T) {
	src, err := os.ReadFile("reset_test.go")
	if err != nil {
		t.Fatalf("reading reset_test.go: %v", err)
	}
	// The needles are assembled at runtime; written as literals they would
	// appear in this file and the test would fail against itself.
	tok := "t." + "Skip"
	for _, forbidden := range []string{tok + "(", tok + "f(", tok + "Now("} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("reset_test.go contains %q. If a control genuinely cannot run here "+
				"it belongs in docs/controls.md with what would settle it -- "+
				"not behind a green tick", forbidden)
		}
	}
}

// TestResetWritesNoRecordLiteral: standing order (1). The stale dast_status
// names are rejected by internal/record BY NAME, and this file must carry no
// string literal for any record enum -- every value it can produce goes
// through the record package.
func TestResetWritesNoRecordLiteral(t *testing.T) {
	produced := []record.TargetProvenance{}
	for _, s := range ResetStageValues() {
		p, err := s.Provenance()
		if err != nil {
			t.Fatalf("reset stage %q: %v", string(s), err)
		}
		produced = append(produced, p)
	}
	for _, p := range produced {
		if err := record.ValidateTargetProvenance(string(p)); err != nil {
			t.Errorf("this file can produce %q, which the frozen enum rejects: %v",
				string(p), err)
		}
	}

	src, err := os.ReadFile("reset.go")
	if err != nil {
		t.Fatalf("reading reset.go: %v", err)
	}
	stale := []string{`"clean"`, `"findings"`, `"failed_to_boot"`, `"partial"`}
	for _, s := range stale {
		if strings.Contains(string(src), s) {
			t.Errorf("reset.go contains the stale dast_status literal %s; "+
				"internal/record rejects it by name", s)
		}
	}
	// The live record literals must not be spelled here either: they come
	// from the record package or they drift from it.
	live := []string{
		`"boot_failed"`, `"booted_clean"`, `"build_failed"`,
		`"unreachable_at_scan_time"`, `"no_target_declared"`,
		`"ephemeral_manifest"`, `"target_boot_failed"`, `"completed_clean"`,
	}
	for _, s := range live {
		if strings.Contains(string(src), s) {
			t.Errorf("reset.go spells the record literal %s. Use the record.* constants: "+
				"a literal here drifts from the frozen enum silently", s)
		}
	}
	// reset.strategy is the target manifest's constant, not a literal spelled twice.
	if strings.Contains(string(src), `"destroy_recreate"`) {
		t.Error(`reset.go spells "destroy_recreate". Use ` +
			`target.ResetStrategyDestroyRecreate: two spellings of the only supported ` +
			`strategy is one spelling that can drift`)
	}
}
