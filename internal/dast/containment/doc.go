// Package containment holds the DAST half's network containment: a dedicated
// Linux network namespace whose egress is default-deny under nftables, and an
// assertion probe that re-proves the containment ON EVERY RUN. It also provisions,
// holds and resets the ephemeral target a DAST scan runs against.
package containment
