package main

// ============================================================================
// Obli* device identity v2 — shared device ID.
//
// COPY VERBATIM across every Obli* agent (with device_identity_windows.go and
// device_identity_unix.go). Host requirements: readMachineUUID() and
// readSystemDiskSerial() (machine_uuid_*.go). Everything else is prefixed
// "oid" / "identity" to avoid clashing with agent code.
//
// One random ID per machine, created by whichever Obli* agent starts first,
// stored in %ProgramData%\Oblitools\device-id.json (/etc/oblitools on Unix).
// Agents keep their legacy ID until their server acknowledges the switch
// (X-Obli-Device-Id / X-Obli-Previous-Ids -> X-Obli-Device-Id-Ack), so agents
// and servers can be upgraded in any order.
// ============================================================================

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	identityFormat        = 1
	identityFileName      = "device-id.json"
	identityLockName      = "device-id.lock"
	identityOverrideName  = "device-uuid-override" // v1 opt-in override, seeds v2
	identityMaxPrevious   = 8
	identityLockStale     = 30 * time.Second
	identityLockWait      = 5 * time.Second
	identityWatchInterval = 60 * time.Second

	IdentityHeaderTarget   = "X-Obli-Device-Id"
	IdentityHeaderPrevious = "X-Obli-Previous-Ids"
	IdentityHeaderAck      = "X-Obli-Device-Id-Ack"

	identityReasonCreated  = "created"
	identityReasonOverride = "override"
	identityReasonRegen    = "regenerated"
	identityReasonClone    = "clone-detected"
)

// Test hooks: point the shared file at a temp directory, skip the owner check.
var (
	identityDirOverride   string
	identitySkipTrustTest bool
)

func identityDir() string {
	if identityDirOverride != "" {
		return identityDirOverride
	}
	return oidPlatformDir()
}

type identityFingerprint struct {
	OS   string `json:"os"`
	HW   string `json:"hw"`
	Disk string `json:"disk"`
}

type sharedIdentity struct {
	Format      int                 `json:"format"`
	DeviceID    string              `json:"deviceId"`
	PreviousIDs []string            `json:"previousIds"`
	Reason      string              `json:"reason"`
	Fingerprint identityFingerprint `json:"fingerprint"`
	CreatedAt   string              `json:"createdAt"`
	CreatedBy   string              `json:"createdBy"`
}

var oidUUIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// oidNormalise lowercases and validates a UUID; "" when malformed.
func oidNormalise(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !oidUUIDRe.MatchString(s) {
		return ""
	}
	return s
}

// oidJunkHardwareUUIDs: placeholder SMBIOS UUIDs seen in the wild. Kept
// separate from machine_uuid.go so this file stays self-contained.
var oidJunkHardwareUUIDs = map[string]bool{
	"00000000-0000-0000-0000-000000000000": true,
	"ffffffff-ffff-ffff-ffff-ffffffffffff": true,
	"12345678-1234-5678-90ab-cddeefaabbcc": true,
	"12345678-1234-5678-1234-567812345678": true,
	"03000200-0400-0500-0006-000700080009": true,
	"00020003-0004-0005-0006-000700080009": true,
	"01020304-0506-0708-090a-0b0c0d0e0f10": true,
	"4c4c4544-0000-1010-8010-c4c04f313233": true,
}

// oidHardwareUUIDIsJunk reports whether a raw SMBIOS/platform UUID cannot be
// trusted to tell machines apart (empty, malformed, placeholder, or made of
// one repeated digit).
func oidHardwareUUIDIsJunk(raw string) bool {
	u := oidNormalise(raw)
	if u == "" || oidJunkHardwareUUIDs[u] {
		return true
	}
	hexOnly := strings.ReplaceAll(u, "-", "")
	for i := 1; i < len(hexOnly); i++ {
		if hexOnly[i] != hexOnly[0] {
			return false
		}
	}
	return true
}

func oidNewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func oidHash(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:16]
}

// currentIdentityFingerprint reads the machine's identifying values. Slow on
// Windows (WMI): only called at agent start.
func currentIdentityFingerprint() (identityFingerprint, bool) {
	hwRaw := oidHardwareUUIDRaw()
	disk := strings.TrimSpace(readSystemDiskSerial())
	return identityFingerprint{
		OS:   oidHash(oidOSInstallID()),
		HW:   oidHash(hwRaw),
		Disk: oidHash(disk),
	}, oidHardwareUUIDIsJunk(hwRaw)
}

// identityLooksCloned applies the anti-clone fingerprint rule.
// A field only counts as changed when both values are known.
func identityLooksCloned(stored, current identityFingerprint, hwJunk bool) bool {
	changed := func(a, b string) bool { return a != "" && b != "" && a != b }
	if changed(stored.OS, current.OS) {
		return true
	}
	if changed(stored.HW, current.HW) {
		return true
	}
	return hwJunk && changed(stored.Disk, current.Disk)
}

// ── File I/O ─────────────────────────────────────────────────────────────────

func identityFilePath() string { return filepath.Join(identityDir(), identityFileName) }

// readIdentityFile returns the shared identity, or nil when the file is
// absent, untrusted (not written by SYSTEM / root) or unreadable.
func readIdentityFile() (*sharedIdentity, error) {
	path := identityFilePath()
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			lastErr = err
		} else {
			if !identitySkipTrustTest && !oidFileTrusted(path) {
				return nil, fmt.Errorf("%s is not owned by SYSTEM/Administrators/root: ignored", path)
			}
			data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
			var id sharedIdentity
			if err := json.Unmarshal(data, &id); err != nil {
				lastErr = err
			} else if id.DeviceID = oidNormalise(id.DeviceID); id.DeviceID == "" {
				return nil, fmt.Errorf("%s holds no valid deviceId", path)
			} else {
				id.PreviousIDs = oidCleanIDs(id.PreviousIDs, id.DeviceID)
				return &id, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, lastErr
}

func writeIdentityFile(id *sharedIdentity) error {
	id.Format = identityFormat
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	dir := identityDir()
	tmp := filepath.Join(dir, fmt.Sprintf(".%s.tmp-%s", identityFileName, oidNewUUID()[:8]))
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, identityFilePath()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// lockIdentity takes the cross-agent lock (O_EXCL lock file, stale after 30 s).
func lockIdentity() (func(), error) {
	path := filepath.Join(identityDir(), identityLockName)
	deadline := time.Now().Add(identityLockWait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err == nil {
			_, _ = f.WriteString(fmt.Sprintf("%d", os.Getpid()))
			f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if st, serr := os.Stat(path); serr == nil && time.Since(st.ModTime()) > identityLockStale {
			_ = os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out waiting for " + path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func oidCleanIDs(ids []string, exclude string) []string {
	out := make([]string, 0, len(ids))
	seen := map[string]bool{exclude: true, "": true}
	for _, raw := range ids {
		id := oidNormalise(raw)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) > identityMaxPrevious {
		out = out[:identityMaxPrevious]
	}
	return out
}

func oidReadV1Override() string {
	b, err := os.ReadFile(filepath.Join(identityDir(), identityOverrideName))
	if err != nil {
		return ""
	}
	return oidNormalise(string(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})))
}

// loadOrCreateSharedIdentity is called once at agent start: protects the
// directory, creates the file when missing, and replaces the ID when the
// machine fingerprint says this is a different machine (clone).
func loadOrCreateSharedIdentity(createdBy string) (*sharedIdentity, error) {
	protect := oidProtectDir
	if identityDirOverride != "" { // tests: plain directory
		protect = func(d string) error { return os.MkdirAll(d, 0755) }
	}
	if err := protect(identityDir()); err != nil {
		return nil, fmt.Errorf("protect %s: %w", identityDir(), err)
	}
	fp, hwJunk := currentIdentityFingerprint()

	unlock, err := lockIdentity()
	if err != nil {
		// Someone else holds the lock: read what is there, do not write.
		id, rerr := readIdentityFile()
		if id == nil && rerr == nil {
			rerr = err
		}
		return id, rerr
	}
	defer unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	id, rerr := readIdentityFile()
	if rerr != nil {
		log.Printf("Device identity: %v — recreating %s", rerr, identityFilePath())
		id = nil
	}
	if id == nil {
		id = &sharedIdentity{DeviceID: oidNewUUID(), Reason: identityReasonCreated, PreviousIDs: []string{}}
		if ov := oidReadV1Override(); ov != "" {
			id.DeviceID = ov
			id.Reason = identityReasonOverride
		}
		id.Fingerprint, id.CreatedAt, id.CreatedBy = fp, now, createdBy
		if err := writeIdentityFile(id); err != nil {
			return nil, err
		}
		log.Printf("Device identity: created shared device ID %s (%s)", id.DeviceID, id.Reason)
		return id, nil
	}

	if identityLooksCloned(id.Fingerprint, fp, hwJunk) {
		old := id.DeviceID
		id = &sharedIdentity{
			DeviceID: oidNewUUID(), PreviousIDs: []string{}, Reason: identityReasonClone,
			Fingerprint: fp, CreatedAt: now, CreatedBy: createdBy,
		}
		if err := writeIdentityFile(id); err != nil {
			return nil, err
		}
		log.Printf("Device identity: machine fingerprint changed (clone or new hardware): %s replaced by %s, no claim on the old ID", old, id.DeviceID)
		return id, nil
	}

	// Fill fingerprint fields that were unknown when the file was written.
	updated := false
	fill := func(dst *string, v string) {
		if *dst == "" && v != "" {
			*dst, updated = v, true
		}
	}
	fill(&id.Fingerprint.OS, fp.OS)
	fill(&id.Fingerprint.HW, fp.HW)
	fill(&id.Fingerprint.Disk, fp.Disk)
	if updated {
		if err := writeIdentityFile(id); err != nil {
			log.Printf("Device identity: could not update fingerprint: %v", err)
		}
	}
	return id, nil
}

// ── Runtime state ────────────────────────────────────────────────────────────

type deviceIdentityState struct {
	mu       sync.RWMutex
	current  string   // ID the server knows this agent by (sent as X-Device-UUID)
	target   string   // shared ID awaiting the server's ack ("" = none)
	claims   []string // previous IDs to hand over to target
	modTime  time.Time
	onSwitch func(newID string)
}

var devIdentity = &deviceIdentityState{}

// currentDeviceUUID is the ONLY way agent code may read the device ID.
func currentDeviceUUID() string {
	devIdentity.mu.RLock()
	defer devIdentity.mu.RUnlock()
	return devIdentity.current
}

// identityMigrationPending reports whether a switch awaits the server's ack.
func identityMigrationPending() bool {
	devIdentity.mu.RLock()
	defer devIdentity.mu.RUnlock()
	return devIdentity.target != ""
}

// setIdentityPlan computes target/claims from the shared identity.
// Caller holds the lock.
func (s *deviceIdentityState) setPlanLocked(id *sharedIdentity) {
	if id == nil || id.DeviceID == s.current {
		s.target, s.claims = "", nil
		return
	}
	s.target = id.DeviceID
	if id.Reason == identityReasonClone {
		s.claims = nil // a clone never claims the original's identity
		return
	}
	s.claims = oidCleanIDs(append([]string{s.current}, id.PreviousIDs...), id.DeviceID)
}

// initDeviceIdentity sets the runtime ID at agent start.
//   - storedV2/stored: the agent config's identityV2 flag and deviceUuid
//   - legacy: the agent's v1 resolver (only called when !storedV2)
//   - createdBy: "<agent>/<version>"
//   - onSwitch: persists the config and reconnects channels after an ack
//
// Returns the ID to use now and whether the shared ID is already in use.
func initDeviceIdentity(storedV2 bool, stored string, legacy func() string, createdBy string, onSwitch func(string)) (string, bool) {
	// First install of this agent: no ID stored yet. Nothing to keep using
	// until the server agrees — the shared ID is used right away (a legacy ID
	// may even be taken by another machine: junk BIOS UUID, clone). The legacy
	// ID is still announced as a claim until the first ack, so a reinstall
	// whose old row the server still has is re-keyed rather than duplicated.
	fresh := oidNormalise(stored) == ""
	current := oidNormalise(stored)
	if !storedV2 || current == "" {
		current = legacy()
	}
	id, err := loadOrCreateSharedIdentity(createdBy)
	if err != nil {
		log.Printf("Device identity: shared ID unavailable (%v), staying on %s", err, current)
	}

	devIdentity.mu.Lock()
	devIdentity.current = current
	devIdentity.onSwitch = onSwitch
	devIdentity.setPlanLocked(id)
	if fresh && id != nil {
		claims := devIdentity.claims
		if id.DeviceID == current {
			claims = nil
		}
		devIdentity.current = id.DeviceID
		devIdentity.target = id.DeviceID // headers sent until the first ack
		devIdentity.claims = claims
		log.Printf("Device identity: first install, using the shared device ID %s right away (claims: %v)", id.DeviceID, claims)
	}
	if st, serr := os.Stat(identityFilePath()); serr == nil {
		devIdentity.modTime = st.ModTime()
	}
	now, target, claims := devIdentity.current, devIdentity.target, devIdentity.claims
	devIdentity.mu.Unlock()

	if fresh && id != nil {
		// Persisted as the agent's ID at once (identityV2): a restart before
		// the first ack must not fall back to a legacy ID.
		return now, true
	}
	if target != "" {
		log.Printf("Device identity: switching %s -> %s once the server acknowledges (claims: %v)", current, target, claims)
	}
	return now, id != nil && target == ""
}

// applyIdentityHeaders adds the migration headers while a switch is pending.
// Call it on the main push request and on the WebSocket dial headers.
func applyIdentityHeaders(h http.Header) {
	devIdentity.mu.RLock()
	target, claims := devIdentity.target, devIdentity.claims
	devIdentity.mu.RUnlock()
	if target == "" {
		return
	}
	h.Set(IdentityHeaderTarget, target)
	if len(claims) > 0 {
		h.Set(IdentityHeaderPrevious, strings.Join(claims, ","))
	} else {
		h.Del(IdentityHeaderPrevious)
	}
}

// handleIdentityAck switches the runtime ID when the server acknowledged the
// pending target. Safe to call on every response (nil-safe). Returns true
// when a switch happened.
func handleIdentityAck(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	return acceptIdentityAck(resp.Header.Get(IdentityHeaderAck))
}

func acceptIdentityAck(ack string) bool {
	ack = oidNormalise(ack)
	if ack == "" {
		return false
	}
	devIdentity.mu.Lock()
	if devIdentity.target == "" || ack != devIdentity.target {
		devIdentity.mu.Unlock()
		return false
	}
	old := devIdentity.current
	devIdentity.current = ack
	devIdentity.target, devIdentity.claims = "", nil
	cb := devIdentity.onSwitch
	devIdentity.mu.Unlock()

	if old == ack {
		// First install: the shared ID was already in use, the ack only
		// stops the headers (the legacy claims were settled server-side).
		log.Printf("Device identity: server acknowledged the shared device ID %s", ack)
		return true
	}
	log.Printf("Device identity: server acknowledged, device ID is now %s (was %s)", ack, old)
	if cb != nil {
		cb(ack)
	}
	return true
}

// watchSharedIdentity re-reads the shared file every minute and starts a new
// migration when its deviceId changed (regen script, clone detected by
// another agent). Run in its own goroutine.
func watchSharedIdentity(stop <-chan struct{}) {
	t := time.NewTicker(identityWatchInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			checkSharedIdentityOnce()
		}
	}
}

func checkSharedIdentityOnce() {
	st, err := os.Stat(identityFilePath())
	if err != nil {
		return
	}
	devIdentity.mu.RLock()
	same := st.ModTime().Equal(devIdentity.modTime)
	devIdentity.mu.RUnlock()
	if same {
		return
	}
	id, err := readIdentityFile()
	if err != nil || id == nil {
		if err != nil {
			log.Printf("Device identity: %v", err)
		}
		return
	}
	devIdentity.mu.Lock()
	devIdentity.modTime = st.ModTime()
	prevTarget := devIdentity.target
	if id.DeviceID != prevTarget {
		devIdentity.setPlanLocked(id)
		if devIdentity.target != "" {
			log.Printf("Device identity: shared ID changed to %s (%s), switching once the server acknowledges", id.DeviceID, id.Reason)
		}
	}
	devIdentity.mu.Unlock()
}
