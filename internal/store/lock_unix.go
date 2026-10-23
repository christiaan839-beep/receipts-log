//go:build unix

package store

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive, non-blocking advisory lock on f. The
// lock is released when f is closed.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
