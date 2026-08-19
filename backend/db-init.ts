import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import type { Pool } from 'pg'

const SERIAL_TABLES = [
  'users', 'agents', 'customers', 'suppliers', 'products', 'stock_movements',
  'murabaha_contracts', 'repayments', 'invoices', 'transactions', 'approvals',
  'transunion_checks', 'id_verifications', 'audit_logs', 'tickets', 'otp_codes',
  'payment_intents', 'change_requests', 'permission_catalog', 'role_templates',
  'merchant_keys', 'merchant_checkouts',
  'system_backups', 'import_batches', 'import_rows', 'profile_amendments',
  'nia_webhook_log'
]

function splitStatements(sql: string): string[] {
  // Split on statement-terminating semicolons, but DO NOT split inside:
  //   * dollar-quoted blocks ($$ ... $$ / $tag$ ... $tag$, used by PL/pgSQL
  //     DO blocks & functions) — a naive split on ";\n" shreds a DO block;
  //   * single-quoted string literals;
  //   * SQL line comments (-- ... EOL) which may themselves contain quotes or
  //     semicolons (e.g. "-- e.g. 'equipment', 'feed'").
  // This scanner strips comments AND is dollar-quote / quote aware in one pass.
  const out: string[] = []
  let cur = ''
  let i = 0
  let inSingle = false
  let dollarTag: string | null = null

  while (i < sql.length) {
    const ch = sql[i]

    if (dollarTag) {
      if (sql.startsWith(dollarTag, i)) {
        cur += dollarTag
        i += dollarTag.length
        dollarTag = null
        continue
      }
      cur += ch
      i++
      continue
    }

    if (inSingle) {
      cur += ch
      if (ch === "'") {
        if (sql[i + 1] === "'") { cur += "'"; i += 2; continue }
        inSingle = false
      }
      i++
      continue
    }

    // Line comment: skip from `--` to end of line (drop it entirely).
    if (ch === '-' && sql[i + 1] === '-') {
      const nl = sql.indexOf('\n', i)
      if (nl === -1) { i = sql.length } else { cur += '\n'; i = nl + 1 }
      continue
    }

    // Start of a dollar-quoted block.
    if (ch === '$') {
      const m = /^\$[A-Za-z0-9_]*\$/.exec(sql.slice(i))
      if (m) { dollarTag = m[0]; cur += dollarTag; i += dollarTag.length; continue }
    }

    if (ch === "'") { inSingle = true; cur += ch; i++; continue }

    if (ch === ';') {
      out.push(cur)
      cur = ''
      i++
      continue
    }

    cur += ch
    i++
  }
  if (cur.trim()) out.push(cur)

  return out.map((statement) => statement.trim()).filter(Boolean)
}

function transformStatement(originalStatement: string): { sql: string; conflict: boolean } {
  let sql = originalStatement.trim()
  let conflict = false
  if (/^insert\s+or\s+ignore\s+into/i.test(sql)) {
    conflict = true
    sql = sql.replace(/^insert\s+or\s+ignore\s+into/i, 'INSERT INTO')
  }
  sql = sql.replace(/\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b/gi, 'BIGSERIAL PRIMARY KEY')
  sql = sql.replace(/\bAUTOINCREMENT\b/gi, '')
  sql = sql.replace(/\bDATETIME\b/gi, 'TIMESTAMP')
  sql = sql.replace(/\bREAL\b/gi, 'DOUBLE PRECISION')
  // --------------------------------------------------------------------
  // STRIP cross-type foreign keys to `users` inside CREATE TABLE bodies.
  //
  // WHY: Equipment shares ONE central Postgres DB with sibling apps (Score).
  // When a sibling created `public.users` FIRST with a UUID primary key, an
  // Equipment table declaring `user_id INTEGER ... REFERENCES users(id)` can
  // NEVER satisfy the FK — Postgres rejects the whole CREATE TABLE with
  //   "foreign key constraint ... cannot be implemented" (42804)
  // and the resilient runner then SKIPS the entire table. That is exactly how
  // `customers` / `agents` / `change_requests` went missing in production,
  // producing "relation \"customers\" does not exist" (42P01) during signup.
  //
  // The FK to users adds no real integrity guarantee on a multi-app shared DB
  // (ids may be integer OR uuid), so we drop these inline FK clauses. The
  // columns themselves are kept and widened to TEXT by migration 0025 so they
  // work regardless of how users.id is typed. Only strips FKs that REFERENCE
  // users — all other FKs are preserved.
  if (/^\s*create\s+table/i.test(sql)) {
    // Inline column constraint: `... REFERENCES users(id) ...` (rare, no leading FOREIGN KEY)
    // Table-level constraint: `FOREIGN KEY (col) REFERENCES users(id)` possibly with trailing comma.
    sql = sql
      // table-level FOREIGN KEY (...) REFERENCES users(id) [ON ...][,]
      .replace(/,?\s*FOREIGN\s+KEY\s*\([^)]*\)\s*REFERENCES\s+users\s*\([^)]*\)(\s+ON\s+(DELETE|UPDATE)\s+\w+)*/gi, '')
      // inline column-level REFERENCES users(id) (keep the column, drop the ref)
      .replace(/\bREFERENCES\s+users\s*\([^)]*\)(\s+ON\s+(DELETE|UPDATE)\s+\w+)*/gi, '')
  }
  // Trim trailing commas accidentally left by transformations
  sql = sql.replace(/,\s*\)/g, '\n)')
  sql = sql.replace(/,\s*,/g, ',')
  return { sql, conflict }
}

// Result of trying a single statement:
//   'ok'      — executed (or benignly idempotent, e.g. duplicate column)
//   'skipped' — failed with a NON-fatal error; logged and stepped over so the
//               rest of the file (later CREATE TABLEs etc.) can still run.
type StatementResult = 'ok' | 'skipped'

async function execStatement(pool: Pool, statement: string, allowConflict: boolean): Promise<StatementResult> {
  try {
    let sql = statement
    if (allowConflict && /^insert\s+into/i.test(sql) && !/on\s+conflict/i.test(sql)) {
      sql += ' ON CONFLICT DO NOTHING'
    }
    await pool.query(sql)
    return 'ok'
  } catch (error: any) {
    const code = error?.code || ''
    const message = String(error?.message || '')
    // Idempotency guards so re-running migrations on an existing DB is safe:
    // 42701 duplicate column, 42P07 duplicate table/index, 23505 unique violation
    // (handled by ON CONFLICT), 42809 wrong object type for DROP VIEW/TABLE on
    // an object of a different kind, 42P06 duplicate schema.
    if (['42701', '42P07', '23505', '42809', '42P06'].includes(code)) return 'ok'
    if (/already exists|duplicate column|is not a|wrong (object )?type/i.test(message)) return 'ok'
    // Any OTHER error must NOT abort the rest of the file. On the shared central
    // DB a single incompatible statement (e.g. a FK whose referenced table was
    // created by a sibling app with a different id type) used to throw here and
    // prevent every subsequent CREATE TABLE in the SAME file from running —
    // leaving core tables (products, agents, customers, ...) missing and causing
    // downstream "relation does not exist" failures. Log and step over instead;
    // migrations are idempotent, so the schema converges on the next deploy.
    console.error(
      `  · statement skipped (${code || 'no-code'}): ${message} :: ${statement.slice(0, 120).replace(/\s+/g, ' ')}`
    )
    return 'skipped'
  }
}

async function applySqlFile(pool: Pool, file: string) {
  const rawSql = readFileSync(file, 'utf8')
  let skipped = 0
  for (const statement of splitStatements(rawSql)) {
    const { sql, conflict } = transformStatement(statement)
    const result = await execStatement(pool, sql, conflict)
    if (result === 'skipped') skipped++
  }
  return { skipped }
}

async function tableExists(pool: Pool, tableName: string): Promise<boolean> {
  const { rows } = await pool.query(
    `SELECT EXISTS (
      SELECT 1 FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name = $1
    ) AS present`,
    [tableName]
  )
  return Boolean(rows[0]?.present)
}

async function syncSequences(pool: Pool) {
  for (const table of SERIAL_TABLES) {
    try {
      await pool.query(
        `SELECT setval(pg_get_serial_sequence($1, 'id'), GREATEST(COALESCE((SELECT MAX(id) FROM ${table}), 1), 1), true)`,
        [table]
      )
    } catch (_) {}
  }
}

export async function initializeDatabase(pool: Pool, projectRoot: string) {
  const hasUsers = await tableExists(pool, 'users')
  const migrationsDir = join(projectRoot, 'migrations')
  if (existsSync(migrationsDir)) {
    const files = readdirSync(migrationsDir).filter((file) => file.endsWith('.sql')).sort()
    // Apply migrations in order. Resilience is now enforced at TWO levels:
    //   1. Statement level (applySqlFile/execStatement): a single incompatible
    //      statement is logged and skipped so the REST of the same file (later
    //      CREATE TABLEs etc.) still runs — this prevents the "one bad FK aborts
    //      the whole file, leaving core tables missing" class of failure.
    //   2. File level (here): a file that throws unexpectedly must NOT abort the
    //      whole chain. All our DDL is idempotent, so we log and keep going;
    //      remaining migrations still converge the schema.
    const failures: Array<{ file: string; message: string }> = []
    let skippedTotal = 0
    for (const file of files) {
      try {
        const { skipped } = await applySqlFile(pool, join(migrationsDir, file))
        skippedTotal += skipped
        if (skipped) console.warn(`Migration ${file}: ${skipped} statement(s) skipped (see logs).`)
      } catch (error: any) {
        const message = String(error?.message || error)
        console.error(`Migration ${file} error (continuing):`, message)
        failures.push({ file, message })
      }
    }
    if (failures.length || skippedTotal) {
      console.warn(
        `Database initialization completed with ${failures.length} file-level error(s) and ` +
        `${skippedTotal} skipped statement(s). The app still boots; idempotent DDL retries on next deploy.` +
        (failures.length ? ` Files: ${failures.map((f) => f.file).join(', ')}` : '')
      )
    }
  }
  if (!hasUsers) {
    const seedFile = join(projectRoot, 'seed.sql')
    if (existsSync(seedFile)) {
      await applySqlFile(pool, seedFile)
      console.log('Seed data loaded.')
    }
  }
  await syncSequences(pool)
}

export function ensureDir(): void {
  /* no-op: PostgreSQL storage is managed externally */
}
