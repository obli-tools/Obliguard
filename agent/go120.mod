// go120.mod — module file of the "nt6" Windows build line (Windows 7 SP1 /
// 8.1 / Server 2008 R2 / 2012 / 2012 R2), compiled with Go 1.20.14
// (C:\Go1.20\bin\go.exe) through -modfile=go120.mod. Same module, same
// sources and same dependency versions as go.mod (which stays at go 1.22 for
// the modern build); only the `go` directive differs. KEEP IN SYNC: when a
// dependency moves in go.mod, copy the require blocks here and go.sum to
// go120.sum, and never take a version whose own go.mod needs Go > 1.20. The
// check is `C:\Go1.20\bin\go.exe build -modfile=go120.mod .` (GOOS=windows,
// GOARCH amd64 and 386).
//
// Build commands: see BUILD_NT6.txt.

module github.com/obliguard/agent

go 1.20

require (
	github.com/google/uuid v1.6.0
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/tailscale/wf v0.0.0-20240214030419-6fbb0a674ee6
	golang.org/x/sys v0.20.0
)

require (
	github.com/BurntSushi/toml v0.4.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go4.org/netipx v0.0.0-20220725152314-7e7bdc8411bf
	golang.org/x/exp/typeparams v0.0.0-20220218215828-6cf2b201936e // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/tools v0.1.11-0.20220513221640-090b14e8501f // indirect
	honnef.co/go/tools v0.3.2 // indirect
)
