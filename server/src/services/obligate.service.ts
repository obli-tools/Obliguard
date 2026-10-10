import crypto from 'crypto';
import { appConfigService } from './appConfig.service';
import { db } from '../db';
import { logger } from '../utils/logger';
import { safeEqualSecret } from '../utils/safeCompare';

/** Obliguard's brand accent (default theme --c-accent 245 166 35), announced to Obligate via self-info. */
const APP_ACCENT_COLOR = '#F5A623';

/** Obligate's public client id for an app: sha256(apiKey), hex. */
function publicClientId(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey, 'utf8').digest('hex');
}

// Whether the configured Obligate INSTANCE (keyed by its base URL) accepts the
// public (hashed) client id. A "supported" answer is a property of the
// instance and survives key rotation; an "unsupported" answer is only reused
// for the key it was established with (kid). The last conclusive answer is also
// persisted in app_config so a restart followed by an inconclusive probe (rate
// limit, outage) never falls back to exposing the raw key.
const clientIdSupport = new Map<string, { hashed: boolean; kid: string; at: number }>();
const clientIdProbeInFlight = new Map<string, Promise<boolean | null>>();
const HASHED_OK_TTL_MS = 60 * 60_000;      // re-check hourly once supported
const HASHED_UNSUPPORTED_TTL_MS = 5 * 60_000; // pick up an Obligate upgrade within 5 min
const CLIENT_ID_SUPPORT_KEY = 'obligate_public_client_id_support';

// registerDeviceLink throttle
const LINK_THROTTLE_MAX = 10_000;
const LINK_OK_TTL = 10 * 60_000;
const LINK_RETRY_MS = 60_000;
let legacyClientIdWarned = false;

/** Non-reversible fingerprint of a key (binds an "unsupported" answer to it). */
function keyFingerprint(hashed: string): string {
  return crypto.createHash('sha256').update(hashed, 'utf8').digest('hex').slice(0, 16);
}

/**
 * GET Obligate's /api/oauth/authorize (the endpoint that validates client_id;
 * the root /authorize is an unconditional alias) without a session, following
 * redirects that stay on that endpoint (scheme / canonical-host upgrades, max
 * 3 hops). A recognised client ends on Obligate's /login (or /enroll): true.
 * 400 "Invalid client_id": false. Anything else: null (inconclusive).
 */
async function probeAuthorize(base: string, clientId: string, redirectUri: string): Promise<boolean | null> {
  let url = `${base}/api/oauth/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
  try {
    for (let hop = 0; hop < 4; hop++) {
      const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(3000) });
      if (res.status >= 300 && res.status < 400) {
        await res.body?.cancel().catch(() => {});
        let next: URL;
        try { next = new URL(res.headers.get('location') ?? '', url); } catch { return null; }
        if (next.pathname === '/login' || next.pathname === '/enroll') return true;
        if (next.pathname.endsWith('/api/oauth/authorize')) { url = next.toString(); continue; }
        return null;
      }
      if (res.status === 400) {
        // Only Obligate's rejection of the id itself counts ("Missing client_id
        // or redirect_uri", e.g. a proxy that dropped the query, does not).
        const body = await res.json().catch(() => null) as { error?: string } | null;
        return body?.error === 'Invalid client_id' ? false : null;
      }
      await res.body?.cancel().catch(() => {});
      return null;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Does this Obligate recognise the key (known, app active)? Asked
 * server-to-server with the key in the Authorization header (never in a URL):
 * POST /api/oauth/token/exchange with an empty body answers 400 "Missing code
 * or redirect_uri" for a valid key (no side effect) and 401 for an unknown key
 * or an inactive app. true / false, or null when inconclusive.
 */
async function isKeyRecognised(base: string, apiKey: string): Promise<boolean | null> {
  try {
    const res = await fetch(`${base}/api/oauth/token/exchange`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: '{}',
      redirect: 'manual',
      signal: AbortSignal.timeout(3000),
    });
    await res.body?.cancel().catch(() => {});
    if (res.status === 400) return true;
    if (res.status === 401 || res.status === 403) return false;
    return null;
  } catch {
    return null;
  }
}

/**
 * true = public client ids supported; false = a pre-hash Obligate (the hash is
 * rejected while the key itself is valid); null = inconclusive — including a
 * rejected hash for a key Obligate does not recognise (rotated, mistyped, app
 * disabled), which says nothing about hash support.
 */
async function probePublicClientId(base: string, hashed: string, apiKey: string, redirectUri: string): Promise<boolean | null> {
  // A key with whitespace / control characters could hash differently from
  // what Obligate stores while still passing the Bearer check (header values
  // are trimmed): never conclude anything from it.
  if (!apiKey || /[\s\x00-\x1f\x7f]/.test(apiKey)) return null;
  const viaHash = await probeAuthorize(base, hashed, redirectUri);
  if (viaHash !== false) return viaHash;
  const keyOk = await isKeyRecognised(base, apiKey);
  if (keyOk === false) {
    logger.warn({ obligateUrl: base }, 'SSO: Obligate does not recognise the configured API key (rotated, mistyped or app disabled)');
    return null;
  }
  if (keyOk !== true) return null;
  // Key valid while the hash was rejected: confirm once (the app may have been
  // re-enabled between the two requests) before concluding "pre-hash Obligate".
  const again = await probeAuthorize(base, hashed, redirectUri);
  return again === false ? false : again === true ? true : null;
}

export interface ObligateUserAssertion {
  obligateUserId: number;
  username: string;
  email: string | null;
  displayName: string | null;
  role: string;
  tenants: Array<{
    slug: string;
    role: string;
    /** @deprecated ignored — capabilities derive from local tenant membership (permission.service.getUserCapabilities) */
    capabilities?: string[];
  }>;
  teams: string[];
  /** @deprecated ignored — capabilities derive from local tenant membership (permission.service.getUserCapabilities) */
  capabilities?: string[];
  authSource: 'local' | 'ldap';
  linkedLocalUserId: number | null;
  preferences?: {
    preferredTheme?: string;
    toastEnabled?: boolean;
    toastPosition?: string;
    profilePhotoUrl?: string | null;
    preferredLanguage?: string;
    anonymousMode?: boolean;
    appSpecific?: Record<string, string>;
  };
}

export const obligateService = {
  /**
   * Check if Obligate is configured and reachable.
   */
  async getSsoConfig(): Promise<{ obligateUrl: string | null; obligateReachable: boolean; obligateEnabled: boolean }> {
    const cfg = await appConfigService.getObligateConfig();
    if (!cfg.url || !cfg.enabled) {
      return { obligateUrl: cfg.url, obligateReachable: false, obligateEnabled: cfg.enabled };
    }

    // Quick reachability check (2s timeout)
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2000);
      const res = await fetch(`${cfg.url}/health`, { signal: controller.signal });
      clearTimeout(timeout);
      return { obligateUrl: cfg.url, obligateReachable: res.ok, obligateEnabled: true };
    } catch {
      return { obligateUrl: cfg.url, obligateReachable: false, obligateEnabled: true };
    }
  },

  /**
   * Authenticate a server-to-server call made by Obligate to this app
   * (`Authorization: Bearer <our Obligate API key>`). Constant-time, and
   * fails closed when no API key is configured.
   *
   * NOTE: an Obligate that predates public client ids still gets this same key
   * in the browser /authorize redirect (see getAuthorizeClientId), so the key
   * must not be treated as confidential: every endpoint guarded by this check
   * must stay harmless for local accounts on its own (see sso-user-sync).
   */
  async verifyInboundBearer(authHeader: string | undefined): Promise<boolean> {
    if (!authHeader?.startsWith('Bearer ')) return false;
    const raw = await appConfigService.getObligateRaw();
    return safeEqualSecret(authHeader.slice(7), raw.apiKey);
  },

  /**
   * client_id for the browser-facing /authorize redirect: ALWAYS the public id
   * sha256(apiKey) (2026-10-06). Obligate accepts it since 2026-09 and now
   * refuses the raw key (OAUTH_ACCEPT_RAW_CLIENT_ID off): the former probe that
   * fell back to the raw key on an "unsupported" answer could only expose the
   * key, which also authenticates server-to-server calls. Same rule as every
   * other Obli* app. (probePublicClientId and its cache are no longer used.)
   */
  async getAuthorizeClientId(_obligateUrl: string, apiKey: string, _redirectUri: string): Promise<string | null> {
    return publicClientId(apiKey);
  },

  /**
   * Resolve the local account linked to an Obligate identity, from OUR records
   * only: the sso_foreign_users row of that identity (pointing to an account
   * provisioned by the SSO callback), or — for an account whose link row is
   * missing — the account created for that identity (users.foreign_id).
   *
   * Obligate's `linkedLocalUserId` / `remoteUserId` must never be trusted on
   * their own: they are only Obligate's copy of what we reported through
   * report-provision, and can be stale or rewritten by any holder of the API
   * key (which older Obligate builds force through the browser redirect).
   * Returns null when no local account is linked.
   */
  async getLinkedLocalUserId(obligateUserId: number): Promise<number | null> {
    if (!Number.isInteger(obligateUserId) || obligateUserId <= 0) return null;

    const link = await db('sso_foreign_users as l')
      .join('users as u', 'u.id', 'l.local_user_id')
      .where({ 'l.foreign_source': 'obligate', 'l.foreign_user_id': obligateUserId, 'u.foreign_source': 'obligate' })
      .first('u.id') as { id: number } | undefined;
    if (link) return link.id;

    const provisioned = await db('users')
      .where({ foreign_source: 'obligate', foreign_id: obligateUserId })
      .orderBy('id', 'desc')
      .first('id') as { id: number } | undefined;
    return provisioned?.id ?? null;
  },

  /**
   * Exchange an authorization code with Obligate for user info.
   */
  async exchangeCode(code: string, redirectUri: string): Promise<ObligateUserAssertion | null> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) {
      logger.warn('Obligate exchange failed: not configured');
      return null;
    }

    try {
      const res = await fetch(`${raw.url}/api/oauth/token/exchange`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify({ code, redirect_uri: redirectUri }),
      });

      if (!res.ok) {
        logger.warn(`Obligate exchange failed: HTTP ${res.status}`);
        return null;
      }

      const data = await res.json() as { success: boolean; data?: ObligateUserAssertion };
      if (!data.success || !data.data) return null;

      return data.data;
    } catch (err) {
      logger.error(err, 'Obligate exchange error');
      return null;
    }
  },

  /**
   * Report a provisioned user back to Obligate.
   */
  async reportProvision(obligateUserId: number, remoteUserId: number): Promise<void> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;

    try {
      await fetch(`${raw.url}/api/apps/report-provision`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify({ obligateUserId, remoteUserId }),
      });
    } catch (err) {
      logger.error(err, 'Failed to report provision to Obligate');
    }
  },

  /**
   * Announce Obliguard's own branding to Obligate (POST /api/apps/self-info):
   * the accent color every app switcher in the suite shows for Obliguard.
   * Obligate always keeps the announced value. Best-effort: never throws.
   */
  async announceSelfInfo(): Promise<void> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;
    try {
      const res = await fetch(`${raw.url}/api/apps/self-info`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${raw.apiKey}` },
        body: JSON.stringify({ color: APP_ACCENT_COLOR }),
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) logger.warn(`Obligate: self-info announce failed (HTTP ${res.status})`);
    } catch (err) {
      logger.warn(err, 'Obligate: self-info announce failed');
    }
  },

  /**
   * Register app capability schemas with Obligate.
   */
  async syncCapabilitySchemas(): Promise<void> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;

    const schemas = [
      { key: 'monitor_rw', label: 'Monitor Management', sortOrder: 0 },
      { key: 'group_rw', label: 'Group Management', sortOrder: 1 },
      { key: 'whitelist', label: 'Whitelist Management', sortOrder: 2 },
      { key: 'bans', label: 'Ban Management', sortOrder: 3 },
    ];

    try {
      const res = await fetch(`${raw.url}/api/apps/sync-capability-schemas`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify({ schemas }),
      });
      if (res.ok) {
        logger.info('Obligate: capability schemas synced');
      } else {
        logger.warn(`Obligate: capability schema sync failed (HTTP ${res.status})`);
      }
    } catch (err) {
      logger.warn(err, 'Obligate: capability schema sync failed');
    }
  },

  /**
   * Register a device UUID + path with Obligate for cross-app linking.
   * Called for approved, bound devices only. Throttled per UUID: once
   * every 10 minutes after a success; an in-flight / failed attempt is retried
   * at most every 60 s (the marker is set BEFORE the fetch, which times out
   * after 10 s). The throttle map is bounded to 10 000 entries.
   */
  _linkThrottle: new Map<string, number>(),
  _recordLink(uuid: string, ts: number): void {
    this._linkThrottle.delete(uuid);
    this._linkThrottle.set(uuid, ts);
    while (this._linkThrottle.size > LINK_THROTTLE_MAX) {
      const k = this._linkThrottle.keys().next().value;
      if (k === undefined) break;
      this._linkThrottle.delete(k);
    }
  },
  async registerDeviceLink(uuid: string, appPath: string): Promise<void> {
    const now = Date.now();
    if (now - (this._linkThrottle.get(uuid) ?? 0) < LINK_OK_TTL) return;

    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;

    // In-flight / retry marker: a hanging or failing Obligate is retried at most every 60 s.
    this._recordLink(uuid, now - LINK_OK_TTL + LINK_RETRY_MS);

    try {
      const res = await fetch(`${raw.url}/api/devices/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${raw.apiKey}`,
        },
        body: JSON.stringify({ uuid, path: appPath }),
        signal: AbortSignal.timeout(10_000),
      });
      if (res.ok) this._recordLink(uuid, Date.now());
    } catch { /* non-critical — retried after LINK_RETRY_MS */ }
  },

  /**
   * Get cross-app links for a device UUID from Obligate.
   */
  async getDeviceLinks(uuid: string): Promise<Array<{ appType: string; name: string; url: string; icon: string | null; color: string | null }>> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return [];

    try {
      const res = await fetch(`${raw.url}/api/devices/links?uuid=${encodeURIComponent(uuid)}`, {
        headers: { 'Authorization': `Bearer ${raw.apiKey}` },
      });
      if (!res.ok) return [];
      const data = await res.json() as { success: boolean; data?: Array<{ appType: string; name: string; url: string; icon: string | null; color: string | null }> };
      return data.data ?? [];
    } catch {
      return [];
    }
  },

  /**
   * Fetch latest preferences from Obligate and sync to local DB.
   * Throttled: once per 60s per user. Runs in background, never throws.
   */
  _prefThrottle: new Map<number, number>(),
  async syncUserPreferences(localUserId: number, obligateUserId: number): Promise<void> {
    const now = Date.now();
    if (now - (this._prefThrottle.get(localUserId) ?? 0) < 60 * 1000) return;

    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return;

    try {
      const res = await fetch(`${raw.url}/api/apps/user-preferences/${obligateUserId}`, {
        headers: { 'Authorization': `Bearer ${raw.apiKey}` },
      });
      if (!res.ok) return;
      this._prefThrottle.set(localUserId, now);

      const { success, data } = await res.json() as { success: boolean; data?: {
        preferredTheme?: string; toastEnabled?: boolean; toastPosition?: string;
        preferredLanguage?: string; anonymousMode?: boolean; profilePhotoUrl?: string | null;
      } };
      if (!success || !data) return;

      // Sync language + avatar columns
      const colUpdate: Record<string, unknown> = {};
      if (data.preferredLanguage) colUpdate.preferred_language = data.preferredLanguage;
      if (data.profilePhotoUrl !== undefined) colUpdate.avatar = data.profilePhotoUrl;
      if (Object.keys(colUpdate).length > 0) {
        await db('users').where({ id: localUserId }).update(colUpdate);
      }

      // Sync UI prefs into preferences JSON
      const uiPrefs: Record<string, unknown> = {};
      if (data.preferredTheme) uiPrefs.preferredTheme = data.preferredTheme;
      if (data.toastEnabled !== undefined) uiPrefs.toastEnabled = data.toastEnabled;
      if (data.toastPosition) uiPrefs.toastPosition = data.toastPosition;
      if (data.anonymousMode !== undefined) uiPrefs.anonymousMode = data.anonymousMode;
      if (Object.keys(uiPrefs).length > 0) {
        const row = await db('users').where({ id: localUserId }).select('preferences').first() as { preferences: unknown } | undefined;
        const existing = (typeof row?.preferences === 'string' ? JSON.parse(row.preferences) : row?.preferences) ?? {};
        await db('users').where({ id: localUserId }).update({
          preferences: JSON.stringify({ ...existing, ...uiPrefs }),
        });
      }
    } catch { /* non-critical */ }
  },

  /**
   * Get the list of connected apps from Obligate (for cross-app nav buttons).
   */
  async getConnectedApps(
    obligateUserId?: number | null,
    opts: { timeoutMs?: number } = {},
  ): Promise<Array<{ appType: string; name: string; baseUrl: string; icon: string; color: string | null; self?: true; thirdParty?: boolean }>> {
    const raw = await appConfigService.getObligateRaw();
    if (!raw.url || !raw.apiKey) return [];

    // Scope to the user's Obligate entitlements when we know who they are.
    // Without the userId, Obligate returns EVERY connected app, so the
    // header app switcher would show apps the user has no access to.
    const url = obligateUserId
      ? `${raw.url}/api/apps/connected?userId=${encodeURIComponent(obligateUserId)}`
      : `${raw.url}/api/apps/connected`;
    try {
      const res = await fetch(url, {
        headers: { 'Authorization': `Bearer ${raw.apiKey}` },
        signal: AbortSignal.timeout(opts.timeoutMs ?? 5000),
      });
      if (!res.ok) return [];
      const data = await res.json() as { success: boolean; data?: Array<{ appType: string; name: string; baseUrl: string; icon: string; color: string | null; self?: true; thirdParty?: boolean }> };
      return data.data ?? [];
    } catch {
      return [];
    }
  },
};
