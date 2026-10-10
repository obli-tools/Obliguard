import type { Knex } from 'knex';

/**
 * Migration 043 — Obli* device identity v2.
 *
 * Agents move from a hardware-derived UUID to a shared random Obli* device ID
 * (%ProgramData%\Oblitools\device-id.json, /etc/oblitools on Unix). When an
 * agent_devices row is re-keyed to the shared ID, its previous uuid is kept
 * here so requests in flight during the switch (notifying-update, a WS dial
 * with the old ?uuid=) and cross-app (Obligate) links keep resolving it.
 *
 * `uuid` is NOT unique: a junk SMBIOS UUID shared by several machines can end
 * up as an alias of each of them over time.
 */
export async function up(knex: Knex): Promise<void> {
  if (await knex.schema.hasTable('agent_device_uuid_aliases')) return;

  await knex.schema.createTable('agent_device_uuid_aliases', (t) => {
    t.increments('id').primary();
    t.integer('device_id').notNullable()
      .references('id').inTable('agent_devices').onDelete('CASCADE');
    t.integer('tenant_id').notNullable()
      .references('id').inTable('tenants').onDelete('CASCADE');
    t.string('uuid', 64).notNullable();
    t.string('reason', 32).notNullable().defaultTo('migrated');
    t.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    t.index(['uuid']);
    t.index(['device_id']);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('agent_device_uuid_aliases');
}
