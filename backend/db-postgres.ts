import { Pool, type PoolConfig, types as pgTypes } from 'pg'

pgTypes.setTypeParser(20, (value) => Number(value))
pgTypes.setTypeParser(21, (value) => Number(value))
pgTypes.setTypeParser(23, (value) => Number(value))
pgTypes.setTypeParser(700, (value) => Number(value))
pgTypes.setTypeParser(701, (value) => Number(value))
pgTypes.setTypeParser(1700, (value) => Number(value))

export interface D1Like {
  prepare(sql: string): D1StatementLike
  setSessionConfig?(name: string, value: string): Promise<void>
}

export interface D1StatementLike {
  bind(...args: any[]): D1StatementLike
  first<T = any>(): Promise<T | null>
  all<T = any>(): Promise<{ results: T[]; success: boolean }>
  run(): Promise<{ success: boolean; meta: { last_row_id: number; changes: number } }>
}

const TABLES_WITH_NUMERIC_ID = new Set([
  'users', 'agents', 'customers', 'suppliers', 'products', 'stock_movements',
  'murabaha_contracts', 'repayments', 'invoices', 'transactions', 'approvals',
  'transunion_checks', 'id_verifications', 'audit_logs', 'tickets', 'otp_codes',
  'payment_intents', 'change_requests',
  'merchant_keys', 'merchant_checkouts',
  'system_backups', 'import_batches', 'import_rows', 'profile_amendments',
  'nia_webhook_log',
  // Offtake / traceability / logistics (migration 0036) + governance tables (0035).
  'offtake_contracts', 'offtake_matches', 'aggregation_batches', 'traceability_events',
  'logistics_vehicles', 'logistics_shipments', 'telemetry_pings',
  'feature_flags', 'feature_flag_users', 'payment_channels', 'payment_channel_users',
  // Produce Sourcing & Contracting module (migration 0048/0046/0039).
  'buyer_tenants', 'intake_sites', 'delivery_slots', 'freight_orders', 'commodity_movements',
  'freight_trucks', 'stock_ledger', 'cashboard_bids', 'settlement_records', 'cor_declarations',
  'container_packs'
])

function convertPlaceholders(sql: string): string {
  let out = ''
  let inSingle = false
  let inDouble = false
  let index = 1
  for (let i = 0; i < sql.length; i++) {
    const char = sql[i]
    const next = sql[i + 1]
    if (char === "'" && !inDouble) {
      out += char
      if (inSingle && next === "'") {
        out += next
        i++
      } else {
        inSingle = !inSingle
      }
      continue
    }
    if (char === '"' && !inSingle) {
      inDouble = !inDouble
      out += char
      continue
    }
    if (char === '?' && !inSingle && !inDouble) {
      out += `$${index++}`
      continue
    }
    out += char
  }
  return out
}

function tableNameFromInsert(sql: string): string | null {
  const match = sql.match(/^\s*insert\s+into\s+"?([a-zA-Z0-9_\.]+)"?/i)
  return match?.[1]?.split('.').pop()?.replace(/"/g, '') || null
}

function normalizeParam(value: any): any {
  if (value === undefined) return null
  if (typeof value === 'boolean') return value ? 1 : 0
  return value
}

class PostgresStatement implements D1StatementLike {
  private params: any[] = []

  constructor(private readonly pool: Pool, private readonly rawSql: string) {}

  bind(...args: any[]): D1StatementLike {
    this.params = args.map(normalizeParam)
    return this
  }

  private async query(sqlOverride?: string) {
    const sql = convertPlaceholders(sqlOverride || this.rawSql)
    return this.pool.query(sql, this.params)
  }

  // Self-healing INSERT execution. A `<table>_pkey` duplicate-key violation
  // (SQLSTATE 23505) on a numeric-id table means the BIGSERIAL sequence lags the
  // table's MAX(id) — typically because seed/import rows carried explicit ids
  // without advancing the sequence. When that happens we realign the sequence to
  // MAX(id) and retry the insert ONCE, so a lagging sequence never surfaces to
  // the user as a 500 / "duplicate key" error. This guarantees contract / order
  // / transaction creation (murabaha_contracts included) cannot fail this way —
  // across the whole app, now and in future. The realignment uses
  // pg_get_serial_sequence so it works whether the sequence was created via
  // SERIAL/BIGSERIAL or an explicit OWNED BY.
  private async queryWithPkeyHeal(sqlOverride?: string) {
    const sql = convertPlaceholders(sqlOverride || this.rawSql)
    try {
      return await this.pool.query(sql, this.params)
    } catch (err: any) {
      const code = err?.code
      const constraint = String(err?.constraint || '')
      const detail = String(err?.message || '')
      const isInsert = /^\s*insert\s+/i.test(sqlOverride || this.rawSql)
      const isPkeyDup = code === '23505' && (/_pkey$/i.test(constraint) || /_pkey"/i.test(detail))
      if (isInsert && isPkeyDup) {
        const table = tableNameFromInsert(sqlOverride || this.rawSql)
        if (table && TABLES_WITH_NUMERIC_ID.has(table)) {
          // Realign the sequence on a DEDICATED connection carrying ADMIN RLS
          // context. CRITICAL: the app connects as a non-superuser with FORCE ROW
          // LEVEL SECURITY, so a plain `SELECT MAX(id)` with no session context
          // returns ZERO rows → MAX=NULL → the sequence would reset to 1 and the
          // retry would collide again. Setting app.current_role='admin' makes RLS
          // yield every row so MAX(id) is correct. (Server-internal only.)
          const client = await this.pool.connect()
          try {
            // Admin RLS context on THIS connection so (a) MAX(id) sees every row
            // under FORCE RLS and (b) the retried INSERT passes the ownership
            // WITH CHECK policy (admin bypasses it). The realign + retry MUST run
            // on the SAME connection, because RLS context is per-connection and a
            // different pooled connection would not carry it.
            await client.query(`SELECT set_config('app.current_role', 'admin', false)`)
            await client.query(`SELECT set_config('app.user_can_finance', 'true', false)`)
            await client.query(
              `SELECT setval(pg_get_serial_sequence($1, 'id'), GREATEST(COALESCE((SELECT MAX(id) FROM "${table}"), 1), 1), true)`,
              [table]
            )
            // Retry the original INSERT on this admin-context connection.
            return await client.query(sql, this.params)
          } catch (_) {
            /* fall through to rethrow the original error */
          } finally {
            // Always clear the role before returning the connection to the pool so
            // no admin context leaks to a later request on the same connection.
            try { await client.query(`SELECT set_config('app.current_role', '', false)`) } catch (_e) {}
            try { await client.query(`SELECT set_config('app.user_can_finance', 'false', false)`) } catch (_e) {}
            client.release()
          }
        }
      }
      throw err
    }
  }

  async first<T = any>(): Promise<T | null> {
    const result = await this.query()
    return (result.rows[0] as T) ?? null
  }

  async all<T = any>(): Promise<{ results: T[]; success: boolean }> {
    const result = await this.query()
    return { results: result.rows as T[], success: true }
  }

  async run(): Promise<{ success: boolean; meta: { last_row_id: any; changes: number } }> {
    let sql = this.rawSql.trim().replace(/;\s*$/, '')
    let lastRowId: any = 0
    if (/^insert\s+/i.test(sql) && !/\breturning\b/i.test(sql)) {
      const table = tableNameFromInsert(sql)
      if (table && TABLES_WITH_NUMERIC_ID.has(table)) sql += ' RETURNING id'
    }
    const result = await this.queryWithPkeyHeal(sql)
    const rawId = result.rows?.[0]?.id
    if (rawId != null) {
      // Normally an INTEGER id → return as a number (D1-compatible). On a shared
      // central DB the `id` may be a UUID (a sibling app created the table); in
      // that case Number(uuid) is NaN, so preserve the raw UUID string instead so
      // callers that use last_row_id as a foreign key still get a usable value.
      const n = Number(rawId)
      lastRowId = Number.isFinite(n) && String(n) === String(rawId) ? n : rawId
    }
    return {
      success: true,
      meta: {
        last_row_id: lastRowId,
        changes: result.rowCount || 0
      }
    }
  }
}

export class PostgresD1 implements D1Like {
  constructor(private readonly pool: Pool) {}

  prepare(sql: string): D1StatementLike {
    return new PostgresStatement(this.pool, sql)
  }

  /**
   * Sets a session-scoped configuration parameter (GUC) used by Row-Level
   * Security policies, e.g. app.current_marketplace_id / app.is_admin.
   * Uses set_config(name, value, is_local=false) so it applies to the whole
   * session. Tolerates non-Postgres/edge failures silently at the caller.
   */
  async setSessionConfig(name: string, value: string): Promise<void> {
    await this.pool.query('SELECT set_config($1, $2, false)', [name, value == null ? '' : String(value)])
  }

  /**
   * Run a callback on a SINGLE pinned connection under ADMIN Row-Level-Security
   * context. CRITICAL for privileged server-internal writes that must pass a
   * table's FORCE RLS WITH CHECK policy when there is NO authenticated caller
   * yet (e.g. public self sign-up inserting into the RLS-forced `customers`
   * table). One dedicated connection guarantees the admin GUC and the write
   * share the same session.
   */
  async runAsAdmin(fn) {
    const client = await this.pool.connect()
    try {
      await client.query(`SELECT set_config('app.current_role', 'admin', false)`)
      await client.query(`SELECT set_config('app.user_can_finance', 'true', false)`)
      const exec = (sql, params = []) => client.query(sql, params)
      return await fn(exec)
    } finally {
      try { await client.query(`SELECT set_config('app.current_role', '', false)`) } catch (_e) {}
      try { await client.query(`SELECT set_config('app.user_can_finance', 'false', false)`) } catch (_e) {}
      client.release()
    }
  }
}

export async function openDatabase(connectionString: string): Promise<{ d1: PostgresD1; raw: Pool }> {
  // Issue 7 (security hardening): bound the connection pool and apply
  // conservative timeouts so a slow/hostile query cannot exhaust connections
  // or hang a worker indefinitely. A statement_timeout caps runaway queries.
  const requireSsl = process.env.PGSSLMODE === 'require' || process.env.DATABASE_SSL === 'require'
  const config: PoolConfig = {
    connectionString,
    ssl: requireSsl ? { rejectUnauthorized: false } : undefined,
    max: Number(process.env.PG_POOL_MAX || 10),
    idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT_MS || 30_000),
    connectionTimeoutMillis: Number(process.env.PG_CONNECT_TIMEOUT_MS || 10_000),
    statement_timeout: Number(process.env.PG_STATEMENT_TIMEOUT_MS || 20_000),
    query_timeout: Number(process.env.PG_QUERY_TIMEOUT_MS || 20_000),
    application_name: 'farmsky'
  }
  const raw = new Pool(config)
  // Prevent an idle-client connection error from crashing the whole process.
  raw.on('error', (err) => {
    console.error('[db] idle client error (recovered):', err?.message || err)
  })
  await raw.query('SELECT 1')
  return { d1: new PostgresD1(raw), raw }
}
