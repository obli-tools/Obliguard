import { AGENT_MSI, AGENT_MSI_NT6, isWindowsNt6OsInfo } from '../utils/agentUpdate';

// ── Windows "nt6" build line of the Obliguard agent (server side) ───────────
//
// Windows 7 SP1 / 8.1 / Server 2008 R2 / 2012 / 2012 R2 (NT 6.x) run the
// agent built with Go 1.20 ("nt6"): obliguard-agent-nt6.msi (agent/BUILD_NT6.txt).
// Go >= 1.21 does not support Windows < 10 (os.RemoveAll fails there with
// "openfdat ...: The parameter is incorrect", which broke the self-update of
// 2012 R2 agents in prepareUpdateDir).
//
// Agents built before the nt6 line download `obliguard-agent.msi` from
// /api/agent/download/ — an anonymous GET (no device header). On an NT 6.x
// device the server answers them with the nt6 MSI (same UpgradeCode: an
// in-place major upgrade), with the X-Content-SHA256 / X-Agent-Version of the
// file actually served.
//
// Identification: an updating agent announces itself, from the same process /
// address, right before (or around) the download:
//   - the `update_status` frame with phase 'downloading' on its WS channel
//     (sent synchronously just BEFORE the GET: agent/main.go runUpdate) —
//     the signal that matters for the agents already deployed;
//   - POST /api/agent/notifying-update (agentAuth) — sent by Obliguard agents
//     AFTER the download (just before msiexec), so it only refreshes the
//     entry for a retried download; recorded for parity with Obliance.
// Each records (client address, device, NT 6.x?) for a few minutes; the
// download of obliguard-agent.msi from that address then gets the nt6 MSI
// when EVERY recent announcement from that address comes from an NT 6.x
// device. Mixed (an NT 6.x and a Windows 10+ device updating at the same time
// behind one NAT address): the requested file is served — the modern MSI
// still installs on NT 6.x (no Windows 10 launch condition) and that agent
// moves to the nt6 line at its next update (agent osNeedsNT6Build), whereas
// an nt6 binary on Windows 10 would stay on the nt6 line for good.
//
// Agents built with the nt6 awareness ask for obliguard-agent-nt6.msi
// themselves (agent/build_flavor.go currentAgentMSIName): served as is.
//
// x64 only: Obliguard ships no x86 MSI.

/** How long an announcement counts for the download that follows it. */
export const NT6_NOTIFY_WINDOW_MS = 5 * 60_000;
/** Bound of the in-memory table (oldest dropped first). */
const MAX_ENTRIES = 5000;

interface NotifyEntry { ip: string; device: string; nt6: boolean; at: number }

let entries: NotifyEntry[] = [];

/** Tests only. */
export function __resetNt6NotifyForTests(): void { entries = []; }

function prune(now: number): void {
  if (entries.length && now - entries[0].at >= NT6_NOTIFY_WINDOW_MS) {
    entries = entries.filter((e) => now - e.at < NT6_NOTIFY_WINDOW_MS);
  }
  if (entries.length > MAX_ENTRIES) entries = entries.slice(entries.length - MAX_ENTRIES);
}

/**
 * An agent is about to download its update from `ip`. Windows devices only
 * (others never fetch an MSI). `device` identifies the device (uuid or id):
 * the latest announcement of a device replaces its previous one.
 */
export function noteAgentUpdateNotify(input: {
  ip: string | null | undefined;
  device: string | number;
  osInfo: { platform?: unknown; release?: unknown } | null | undefined;
}, now = Date.now()): void {
  const ip = String(input.ip ?? '').trim();
  const device = String(input.device ?? '').trim();
  if (!ip || !device || !input.osInfo) return;
  const platform = typeof input.osInfo.platform === 'string' ? input.osInfo.platform.trim().toLowerCase() : '';
  if (platform !== 'windows' && platform !== 'win32') return;
  prune(now);
  entries = entries.filter((e) => e.device !== device);
  entries.push({ ip, device, nt6: isWindowsNt6OsInfo(input.osInfo), at: now });
}

export interface AgentDownloadChoice {
  /** The dist file to serve. */
  file: string;
  /** True when it replaces the requested file (nt6 MSI for an NT 6.x device). */
  substituted: boolean;
  /** Why (logs, tests). */
  reason: 'as_requested' | 'nt6_device' | 'mixed_address' | 'no_notification';
}

/**
 * The file to serve for GET /api/agent/download/<requested> from `ip`. Only
 * the modern Windows MSI can be substituted (by the nt6 MSI); every other
 * name is served as requested.
 */
export function chooseAgentDownload(requested: string, ip: string | null | undefined, now = Date.now()): AgentDownloadChoice {
  if (requested !== AGENT_MSI) return { file: requested, substituted: false, reason: 'as_requested' };
  const addr = String(ip ?? '').trim();
  if (!addr) return { file: requested, substituted: false, reason: 'no_notification' };
  prune(now);
  const recent = entries.filter((e) => e.ip === addr && now - e.at < NT6_NOTIFY_WINDOW_MS);
  if (!recent.length) return { file: requested, substituted: false, reason: 'no_notification' };
  if (recent.every((e) => e.nt6)) return { file: AGENT_MSI_NT6, substituted: true, reason: 'nt6_device' };
  if (recent.some((e) => e.nt6)) return { file: requested, substituted: false, reason: 'mixed_address' };
  return { file: requested, substituted: false, reason: 'as_requested' };
}
