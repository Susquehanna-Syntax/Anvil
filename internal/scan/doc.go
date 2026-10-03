// Package scan runs one Anvil scan from start to sealed record: it is the
// production caller that wires Lane A's chain together, and the only code
// cmd/anvil calls to scan.
//
// Every link it calls lives and is tested in its own package: the trigger
// policy, the scan controller and its sealer, the host and repository
// collectors, the comparator, record emission, the store, and the payload
// codec. What this package owns is what none of them could: the joins between
// them. Until plan node cli those joins existed only inside the Lane A
// conformance harness, as test stand-ins (a cache-backed advisory source, an
// advisory-row reader, a host purl bridge), and the harness's ledger reported
// "a production caller wiring the chain together" as unproven. Those stand-ins
// are here now, as production code the harness itself calls.
package scan
