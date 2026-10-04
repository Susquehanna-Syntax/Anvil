//go:build unix

package remediation

import (
	"fmt"
	"os"
	"syscall"
)

// lockDir takes an exclusive lock on dir's lock file for one group's work, so
// two workers (a timer's `anvil remediate` and a daemon, say) never reset,
// apply and commit in the same clone at once. The lock is released by the
// returned function, or by the kernel if the process dies.
func lockDir(dir string) (func(), error) {
	f, err := os.OpenFile(dir+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("remediation: locking %s: %w", dir, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
