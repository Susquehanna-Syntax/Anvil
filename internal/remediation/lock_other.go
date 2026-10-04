//go:build !unix

package remediation

import "errors"

// lockDir refuses: the remediation tier runs on Linux, where its clones are
// locked with flock.
func lockDir(string) (func(), error) {
	return nil, errors.New("remediation: the remediation tier runs only on a Unix host")
}
