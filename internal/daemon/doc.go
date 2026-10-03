// Package daemon is `anvil daemon`: the one resident Anvil process, and a small
// one (plan node daemon). It does two things.
//
//   - It keeps the advisory feeds fresh, each on its own cadence: every tick it
//     asks delta.Syncer to sync every enabled feed, and the syncer decides from
//     the feed table alone whether the feed is due. A feed the licence gate
//     refuses is refused every tick and reported; it never stops the others.
//   - It accepts dispatched scans: JSON requests dropped in a spool directory,
//     each claimed by an atomic rename, run through scan.Run with its trigger
//     event, and answered with a result file beside it. A scheduled request runs
//     only when the trigger policy has a rule for it.
//
// Scheduled full scans are NOT a loop in here. They are one-shot `anvil scan
// --full` runs woken by a systemd timer (deploy/systemd/anvil-full-scan@.timer),
// which catches up missed runs and spreads load without the daemon holding a
// schedule, or memory, between scans.
package daemon
