package main

// buildFlavor selects the Windows build line of this binary. It is injected at
// build time and is "" (= modern) unless the build script says otherwise:
//
//	go build -ldflags "-X main.agentVersion=x.y.z -X main.buildFlavor=nt6" ...
//
// "nt6" = the same agent built with Go 1.20 (go120.mod) for Windows 7 SP1 /
// 8.1 / Server 2008 R2 / 2012 / 2012 R2. It only exists because Go >= 1.21
// does not support Windows < 10: os.RemoveAll and friends use POSIX delete
// semantics that NT 6.x refuses ("openfdat ...: The parameter is incorrect"
// while emptying the update directory), and a Go >= 1.21 binary may even die
// before main() on Windows 7 / 2008 R2 (ProcessPrng in bcryptprimitives.dll).
// See BUILD_NT6.txt.
var buildFlavor = ""

const buildFlavorNT6 = "nt6"

// Windows update installers (agent/dist, /api/agent/download/<name>).
const (
	agentMSIModern = "obliguard-agent.msi"
	agentMSINT6    = "obliguard-agent-nt6.msi"
)

// isNT6Build reports whether this binary is the Go 1.20 build for Windows < 10.
func isNT6Build() bool { return buildFlavor == buildFlavorNT6 }

// agentBuildName is the value reported in the heartbeat / push body as
// `agentBuild` (optional field: older servers ignore it).
func agentBuildName() string {
	if isNT6Build() {
		return buildFlavorNT6
	}
	return "modern"
}

// agentMSIName is the installer a Windows agent downloads to update itself.
// x64 only: Obliguard ships no x86 MSI (Server 2012 R2 is x64-only).
func agentMSIName(nt6 bool) string {
	if nt6 {
		return agentMSINT6
	}
	return agentMSIModern
}

// currentAgentMSIName is agentMSIName for this binary on this OS: the nt6
// build stays on the nt6 line (even on Windows 10+: it never moves itself),
// and a modern agent running on Windows NT 6.x (8.1 / 2012 / 2012 R2 installs
// made before the nt6 line) moves to it at its next update.
func currentAgentMSIName() string {
	return agentMSIName(isNT6Build() || osNeedsNT6Build())
}
