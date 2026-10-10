import type { IncomingHttpHeaders } from 'http';
import { db } from '../db';
import { logger } from '../utils/logger';
import { agentKeyMayActForDevice } from '../utils/agentIdentity';
import type { AgentKeyRef, DeviceBindingRow } from '../utils/agentIdentity';
import { auditService } from './audit.service';
import { obligateService } from './obligate.service';

// Obli* device identity v2 — server side (ported from Obliance
// services/deviceIdentity.service.ts).
//
// An upgraded agent keeps its legacy UUID (?uuid= on the WS dial,
// X-Device-UUID on HTTP) until we acknowledge the switch. Until then it sends
// the shared ID it wants (X-Obli-Device-Id) and the IDs it claims to have used
// before (X-Obli-Previous-Ids). A claimed row is re-keyed ("adopted") only when
// the presenting key may act for it AND the hostname matches: a machine
// sharing a junk SMBIOS UUID with another must not take over the other's
// history.
//
// Obliguard specifics: the agent's "push" is the WS heartbeat (handlePush via
// obliguardHub), so the claim is read from the upgrade request, resolved on the
// channel's first heartbeat (which carries the hostname), and acknowledged with
// an `{ type: "identity_ack", deviceId }` frame. The legacy HTTP /push answers
// the X-Obli-Device-Id-Ack header, as in Obliance.

export const IDENTITY_HEADER_TARGET = 'x-obli-device-id';
export const IDENTITY_HEADER_PREVIOUS = 'x-obli-previous-ids';
export const IDENTITY_HEADER_ACK = 'X-Obli-Device-Id-Ack';
/** WS frame type of the acknowledgement (agent/cmd_ws.go dispatch). */
export const IDENTITY_ACK_FRAME = 'identity_ack';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_CLAIMS = 8;

export interface IdentityClaim {
  target: string;
  claims: string[];
}

/** Binding columns of a row found by the shared ID or an alias, plus its current uuid. */
export type IdentityBindingRow = DeviceBindingRow & { uuid: string };

const BINDING_COLUMNS = ['id', 'uuid', 'tenant_id', 'api_key_id', 'device_type', 'status'];

function normUuid(v: unknown): string | null {
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase();
  return UUID_RE.test(s) ? s : null;
}

function shortHost(h: unknown): string {
  return typeof h === 'string' ? h.trim().toLowerCase().split('.')[0] : '';
}

function isUniqueViolation(err: unknown): boolean {
  return !!err && typeof err === 'object' && (err as { code?: unknown }).code === '23505';
}

/** uuid null = ignore the v2 headers for this push (no ack): the agent stays
 *  on its legacy ID, exactly as a v1 agent would — never worse than v1. */
export type PushIdentityResult = { uuid: string | null; adoptedFrom: string | null; deviceId: number | null };

const IGNORED: PushIdentityResult = { uuid: null, adoptedFrom: null, deviceId: null };

export const deviceIdentityService = {
  /** Reads the v2 headers (Express request or WS upgrade request); null when
   *  absent or malformed (v1 agent). */
  parseHeaders(req: { headers: IncomingHttpHeaders }): IdentityClaim | null {
    const target = normUuid(req.headers[IDENTITY_HEADER_TARGET]);
    if (!target) return null;
    const raw = req.headers[IDENTITY_HEADER_PREVIOUS];
    const list = (Array.isArray(raw) ? raw.join(',') : (raw ?? '')).split(',');
    const claims: string[] = [];
    for (const c of list) {
      const u = normUuid(c);
      if (u && u !== target && !claims.includes(u)) claims.push(u);
      if (claims.length >= MAX_CLAIMS) break;
    }
    return { target, claims };
  },

  /** Case 1 verdict: a row is already keyed by the shared ID. agent_devices.uuid
   *  is unique across tenants. */
  async _targetVerdict(key: AgentKeyRef, target: string): Promise<PushIdentityResult | null> {
    const existing = await db('agent_devices').where({ uuid: target })
      .first('id', 'tenant_id', 'api_key_id', 'device_type') as
      Pick<DeviceBindingRow, 'id' | 'tenant_id' | 'api_key_id' | 'device_type'> | undefined;
    if (!existing) return null;
    if (Number(existing.tenant_id) !== Number(key.tenant_id)) {
      logger.warn({ target, tenantId: key.tenant_id, ownerTenant: existing.tenant_id }, 'identity v2: shared ID already enrolled in another tenant — switch not acknowledged');
      return IGNORED;
    }
    if (!agentKeyMayActForDevice(key, existing)) {
      logger.warn({ deviceId: existing.id, target, apiKeyId: key.id }, 'identity v2: shared ID bound to another API key — switch not acknowledged');
      return IGNORED;
    }
    return { uuid: target, adoptedFrom: null, deviceId: existing.id };
  },

  /**
   * Decides which UUID the push is about, adopting a claimed row when
   * allowed. The caller then looks the device up / registers it under `uuid`
   * (handlePush) and acknowledges.
   */
  async resolvePush(opts: {
    key: AgentKeyRef;
    hostname: string | undefined;
    claim: IdentityClaim;
  }): Promise<PushIdentityResult> {
    const { key, hostname, claim } = opts;
    const tenantId = key.tenant_id;
    const { target, claims } = claim;

    // 1. Already keyed by the shared ID (normal case after the switch, or a
    //    replay after a lost ack).
    const direct = await this._targetVerdict(key, target);
    if (direct) return direct;

    // 2. Adopt the first claimable row.
    const host = shortHost(hostname);
    for (const old of claims) {
      const row = await db('agent_devices').where({ uuid: old, tenant_id: tenantId })
        .first('id', 'tenant_id', 'api_key_id', 'device_type', 'status', 'hostname') as
        (DeviceBindingRow & { hostname: string | null }) | undefined;
      if (!row) continue;
      if (!agentKeyMayActForDevice(key, row)) {
        logger.warn({ deviceId: row.id, old, target }, 'identity v2: claim refused (API key not bound to the claimed device)');
        await auditService.log({
          tenantId, deviceId: row.id, action: 'agent.identity_claim_refused', targetType: 'agent', targetId: row.id,
          details: { from: old, to: target, reason: 'api_key' },
        });
        continue;
      }
      if (!host || shortHost(row.hostname) !== host) {
        logger.warn({ deviceId: row.id, old, target, rowHost: row.hostname, pushHost: hostname }, 'identity v2: claim refused (hostname differs: another machine with the same legacy ID)');
        await auditService.log({
          tenantId, deviceId: row.id, action: 'agent.identity_claim_refused', targetType: 'agent', targetId: row.id,
          details: { from: old, to: target, reason: 'hostname', hostname: hostname ?? null },
        });
        continue;
      }
      let adopted: boolean;
      try {
        adopted = await db.transaction(async (trx) => {
          // Re-check under lock: two pushes racing for the same row.
          const locked = await trx('agent_devices').where({ id: row.id, uuid: old }).forUpdate().first('id');
          if (!locked) return false;
          await trx('agent_device_uuid_aliases').insert({ device_id: row.id, tenant_id: tenantId, uuid: old, reason: 'migrated' });
          await trx('agent_devices').where({ id: row.id }).update({ uuid: target, updated_at: new Date() });
          return true;
        });
      } catch (err) {
        // The shared ID got enrolled concurrently (uuid is UNIQUE): judge that row.
        if (isUniqueViolation(err)) return (await this._targetVerdict(key, target)) ?? IGNORED;
        throw err;
      }
      if (!adopted) {
        // Lost the race: the winner may have re-keyed this very row to target.
        const again = await this._targetVerdict(key, target);
        if (again) return again;
        continue;
      }
      logger.info({ deviceId: row.id, from: old, to: target }, 'identity v2: agent re-keyed to the shared Obli* device ID');
      // The live command channel (keyed by uuid) follows the row.
      try {
        const { obliguardHub } = await import('./obliguardHub.service');
        obliguardHub.rekey(old, target);
      } catch (err) {
        logger.error({ err, old, target }, 'identity v2: command channel re-key failed');
      }
      await auditService.log({
        tenantId, deviceId: row.id, action: 'agent.identity_migrated', targetType: 'agent', targetId: row.id,
        details: { from: old, to: target },
      });
      // Approved devices only (same rule as handlePush). The old link stays
      // registered: apps that have not migrated yet still match through it.
      if (row.status === 'approved') {
        obligateService.registerDeviceLink(target, `/agents/${row.id}`).catch(() => {});
      }
      return { uuid: target, adoptedFrom: old, deviceId: row.id };
    }

    // 3. Nothing adoptable: the caller registers a new row under the shared ID.
    return { uuid: target, adoptedFrom: null, deviceId: null };
  },

  /**
   * Alias fallback for every agent entry point except the push / heartbeat:
   * the row a previous uuid now belongs to, in the key's tenant, when the key
   * may act for it (pure check: no claim of an unbound row). Most recent alias
   * wins. Null when none.
   */
  async findBindingRowViaAlias(uuid: string, key: AgentKeyRef): Promise<IdentityBindingRow | null> {
    const u = normUuid(uuid);
    if (!u) return null;
    const rows = await db('agent_device_uuid_aliases as a')
      .join('agent_devices as d', 'd.id', 'a.device_id')
      .where({ 'a.uuid': u, 'a.tenant_id': key.tenant_id, 'd.tenant_id': key.tenant_id })
      .orderBy('a.created_at', 'desc')
      .limit(8)
      .select(BINDING_COLUMNS.map((c) => `d.${c}`)) as IdentityBindingRow[];
    return rows.find((r) => agentKeyMayActForDevice(key, r)) ?? null;
  },

  /**
   * WS gate, for an agent announcing a switch whose current uuid has no row:
   * the row already keyed by the shared ID, else the row its current uuid is
   * an alias of — only when the key may act for it. Null = treat the dial as
   * row-less, exactly like a v1 agent.
   */
  async findSwitchRow(currentUuid: string, claim: IdentityClaim, key: AgentKeyRef): Promise<IdentityBindingRow | null> {
    const byTarget = await db('agent_devices').where({ uuid: claim.target })
      .first(...BINDING_COLUMNS) as IdentityBindingRow | undefined;
    if (byTarget && agentKeyMayActForDevice(key, byTarget)) return byTarget;
    return this.findBindingRowViaAlias(currentUuid, key);
  },

  /** Previous UUIDs of a device (newest first). */
  async aliasesOf(deviceId: number): Promise<string[]> {
    const rows = await db('agent_device_uuid_aliases').where({ device_id: deviceId })
      .orderBy('created_at', 'desc').select('uuid') as Array<{ uuid: string }>;
    return [...new Set(rows.map((r) => r.uuid))];
  },

  /** Every UUID the device is or was known by: current first. */
  async allUuidsOf(device: { id: number; uuid: string }): Promise<string[]> {
    return [device.uuid, ...(await this.aliasesOf(device.id)).filter((u) => u !== device.uuid)];
  },
};
