// Package scanctl is `anvil-scanctl`: the ONE named scan controller
// the spine's one-controller rule requires, holding ONE state machine with ONE owner.
// The spine's one-controller rule exists because four research branches each specified part
// of an orchestrator (a consumption protocol with leases and ledgers, a
// correlator process, sixteen validation gates, a target-lifecycle harness),
// and "implement it as one named scan controller with one state machine and
// one owner, or it will be re-implemented inconsistently in four places."
package scanctl
