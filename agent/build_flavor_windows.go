//go:build windows

package main

import "golang.org/x/sys/windows"

// osNeedsNT6Build: Windows 7 SP1 / 8.1 / Server 2008 R2 / 2012 / 2012 R2
// (NT 6.x) must run the nt6 build (Go 1.20). Unknown version: false.
func osNeedsNT6Build() bool {
	major, _, _ := windowsOSVersion()
	return major != 0 && major < 10
}

// windowsOSVersion is the real OS version (RtlGetVersion ignores the
// compatibility manifest); zeros when unavailable.
func windowsOSVersion() (major, minor, build uint32) {
	if v := windows.RtlGetVersion(); v != nil {
		return v.MajorVersion, v.MinorVersion, v.BuildNumber
	}
	return 0, 0, 0
}
