// This file is the record assembler: it builds the SARIFLog for one audit from
// the sealer's state and the results the audit's producers emitted.
//
// The contract names "the record assembler" as the producer of the envelope
// fields (anvil/schemaVersion, anvil/state, anvil/deadline, ...), and until
// plan node cli nothing did it: every SARIFLog in the repository was a test
// fixture. Assemble is deliberately thin. Every lifecycle field is read off
// the AuditSeal the Sealer minted, never computed here, and the result is
// passed through Validate before it is returned, so a record this function
// produces is one the contract accepts.

package record

import (
	"errors"
	"fmt"
)

// Assembly is everything Assemble needs that the AuditSeal does not hold.
type Assembly struct {
	// Seal is the Sealer's snapshot of the audit, taken after the last
	// seal. Its state, half statuses, deadline and DAST status are copied
	// verbatim.
	Seal AuditSeal

	// Version is anvil/version, the scan controller's monotonic counter.
	Version int

	Target  Target
	Trigger Trigger

	// SastTool is the SAST half's tool.driver.
	SastTool ToolComponent

	// SastExtensions are the SAST half's tool.extensions: Lane B's rule
	// corpora and native analysers, with the rules its results cite.
	SastExtensions []ToolComponent

	// SastTaxonomies are the taxonomies the SAST half's results cite in
	// result.taxa: CWE, for Lane B.
	SastTaxonomies []ToolComponent

	// SastResults are the SAST half's results, as emitted.
	SastResults []Result

	// AdvisorySnapshot identifies the advisory corpus the SAST half read.
	AdvisorySnapshot *AdvisorySnapshot

	// SpecHarvest is the SAST half's anvil/specHarvest (Lane B's spec
	// harvest); nil when no harvest ran in this scan.
	SpecHarvest *SpecHarvest
}

// ErrAssembleDastHalf means the audit's DAST half ran. Assembling a DAST run
// needs its coverage, its target and its results, which are the dynamic
// tier's to produce; the core artifact assembles only audits whose DAST half
// did not run.
var ErrAssembleDastHalf = errors.New("record: assembling a DAST half is the dynamic tier's job")

// Assemble builds and validates the record for one audit.
func Assemble(a Assembly) (*SARIFLog, error) {
	s := a.Seal
	if s.AuditID == "" {
		return nil, errors.New("record: Assemble needs a sealed audit's snapshot, and this one has no audit id")
	}
	switch s.DastStatus {
	case DastStatusNotRun, DastStatusSkippedNoManifest:
	default:
		return nil, fmt.Errorf("%w: anvil/dastStatus is %q", ErrAssembleDastHalf, s.DastStatus)
	}

	results := a.SastResults
	if results == nil {
		results = []Result{}
	}
	sast := Run{
		Tool:       Tool{Driver: a.SastTool, Extensions: a.SastExtensions},
		Taxonomies: a.SastTaxonomies,
		AutomationDetails: RunAutomationDetails{
			ID:              "anvil/" + string(HalfSast) + "/" + s.AuditID,
			CorrelationGUID: s.AuditID,
		},
		Results: results,
		Properties: RunProperties{
			Half:             HalfSast,
			Status:           s.Sast.Status,
			SealedAt:         s.Sast.SealedAt,
			AdvisorySnapshot: a.AdvisorySnapshot,
			SpecHarvest:      a.SpecHarvest,
		},
	}

	l := &SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Runs:    []Run{sast},
		Properties: AuditProperties{
			SchemaVersion: SchemaVersion,
			AuditID:       s.AuditID,
			State:         s.State,
			Version:       a.Version,
			CreatedAt:     s.StartedAt,
			Target:        a.Target,
			Trigger:       a.Trigger,
			Deadline: Deadline{
				DeadlineAt:          s.DeadlineAt,
				ClaimTimeoutSeconds: s.ClaimTimeoutSeconds,
				DastDeadlineSeconds: s.DastDeadlineSeconds,
			},
			// The three maps are empty objects, never null: the wire schema
			// types them as objects. Grouping by cluster, CWE and path is the
			// read path's to compute (Reader.ManifestFromLog), not the
			// assembler's.
			Index: Index{
				Counts:    IndexCounts{Total: len(results), Sast: len(results), Unclustered: len(results)},
				ReadOrder: DefaultReadOrder(),
				ByCluster: map[string][]string{},
				ByCwe:     map[string][]string{},
				ByPath:    map[string][]string{},
				TaskCards: DefaultTaskCardPrefix,
				Blobs:     DefaultBlobPrefix,
			},
			DastStatus: s.DastStatus,
		},
	}
	if err := l.Validate(); err != nil {
		return nil, fmt.Errorf("record: the assembled record does not validate: %w", err)
	}
	return l, nil
}
