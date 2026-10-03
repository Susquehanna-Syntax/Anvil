// Package settings is the operator's configuration for the anvil binary:
// where its state lives, which feed table the daemon keeps fresh, and the
// decisions an operator makes once for an installation rather than per scan.
//
// The one such decision today is the owner's accelerator ruling of 2026-10-03:
// findings decided by Trivy's own database are OFF unless trivyDB.enabled is
// true here. It lives in a file and not on a flag, because no scan flag may
// widen what a scan touches.
package settings
