// Package record aggregates the dynamic tier's per-tier inventory facts into the
// record-level coverage fields internal/record freezes: `dast_coverage`
// (record.DastCoverage), `endpoint_coverage`, `server_line_coverage` and
// `inventory_provenance`, plus the two target fields `target_provenance`
// (record.TargetProvenance) and `target.provisioning`
// (record.TargetProvisioning).
package record
