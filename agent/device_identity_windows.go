//go:build windows

package main

// Windows half of device_identity.go — COPY VERBATIM across Obli* agents.

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// SYSTEM + Administrators full control, Users read/list only, inherited by
// the files. Protected: nothing inherited from ProgramData, which lets Users
// create files in sub-directories (a planted device-id.json could otherwise
// choose the machine's ID).
const oidDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"

func oidPlatformDir() string {
	pd := os.Getenv("PROGRAMDATA")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "Oblitools")
}

// oidOSInstallID: per-installation GUID (changes on OS reinstall).
func oidOSInstallID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return v
}

// oidHardwareUUIDRaw: SMBIOS UUID, unfiltered.
func oidHardwareUUIDRaw() string { return readMachineUUID() }

// oidProtectDir creates dir and (re)applies the protected DACL.
func oidProtectDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(oidDirSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

// oidFileTrusted: the file must be owned by SYSTEM or Administrators.
func oidFileTrusted(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}
