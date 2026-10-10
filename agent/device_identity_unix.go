//go:build !windows

package main

// Unix half of device_identity.go — COPY VERBATIM across Obli* agents.

import (
	"os"
	"runtime"
	"strings"
	"syscall"
)

func oidPlatformDir() string { return "/etc/oblitools" }

// oidOSInstallID: Linux machine-id (regenerated on reinstall / by the regen
// script). No equivalent elsewhere.
func oidOSInstallID() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	b, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// oidHardwareUUIDRaw: the platform UUID. On Linux readMachineUUID() prefers
// machine-id, so read the DMI value directly.
func oidHardwareUUIDRaw() string {
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	return readMachineUUID()
}

func oidProtectDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		_ = os.Chown(dir, 0, 0)
	}
	return os.Chmod(dir, 0755)
}

// oidFileTrusted: owned by root and not writable by group/others.
func oidFileTrusted(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	if st.Mode().Perm()&0022 != 0 {
		return false
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return sys.Uid == 0
	}
	return false
}
