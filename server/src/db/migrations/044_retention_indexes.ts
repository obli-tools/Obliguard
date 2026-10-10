import type { Knex } from 'knex';

/**
 * 044_retention_indexes.ts
 *
 * Indexes behind the retention purges added to services/retention.service.ts,
 * built CONCURRENTLY (same rules as 040: `transaction: false`, one statement
 * at a time, an INVALID leftover of an interrupted build is dropped and
 * rebuilt).
 *
 *  - agent_commands (finished_at) WHERE finished_at IS NOT NULL: the purge of
 *    final rows (finished_at < cutoff). Migration 042 only indexed the open
 *    rows and (device_id, created_at);
 *  - notification_log (created_at): the purge by age. Schema 001 creates it
 *    under knex's default name; ensured here (IF NOT EXISTS, same name) for
 *    databases whose table predates that index.
 *
 * password_reset_tokens / m365_enrolment_tokens get no index: one live token
 * per user / device (issuing a new one drops the unused previous one), so
 * the tables stay tiny and the hourly purge scans them.
 * agent_update_attempts is not purged (see retention.service.ts).
 */
export const config = { transaction: false };

const CREATED: ReadonlyArray<{ name: string; def: string }> = [
  { name: 'idx_agent_commands_finished_at',  def: 'ON agent_commands (finished_at) WHERE finished_at IS NOT NULL' },
  { name: 'notification_log_created_at_index', def: 'ON notification_log (created_at)' },
];

/** Created by this migration only (down() leaves schema 001's index alone). */
const OWNED = new Set(['idx_agent_commands_finished_at']);

async function dropInvalid(knex: Knex, name: string): Promise<void> {
  const res = await knex.raw(
    `SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
      WHERE c.relname = ? AND NOT i.indisvalid`,
    [name],
  ) as { rows: unknown[] };
  if (res.rows.length > 0) await knex.raw(`DROP INDEX CONCURRENTLY IF EXISTS ${name}`);
}

export async function up(knex: Knex): Promise<void> {
  for (const { name, def } of CREATED) {
    await dropInvalid(knex, name);
    await knex.raw(`CREATE INDEX CONCURRENTLY IF NOT EXISTS ${name} ${def}`);
  }
}

export async function down(knex: Knex): Promise<void> {
  for (const name of OWNED) await knex.raw(`DROP INDEX CONCURRENTLY IF EXISTS ${name}`);
}
