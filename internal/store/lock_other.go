//go:build !unix

package store

import "os"

// lockFile is a no-op where flock(2) is unavailable. Do not open one
// data directory from two processes on such systems.
func lockFile(*os.File) error { return nil }
