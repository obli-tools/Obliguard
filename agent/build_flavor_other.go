//go:build !windows

package main

// osNeedsNT6Build: the nt6 line is Windows-only.
func osNeedsNT6Build() bool { return false }
