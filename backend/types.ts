import type { MpesaEnv } from './mpesa'
import type { SmsEnv } from './sms'
import type { EmailEnv } from './email'
import type { SasaPayEnv } from './sasapay'
import type { BuniEnv } from './buni'

export type Bindings = MpesaEnv & SmsEnv & EmailEnv & SasaPayEnv & BuniEnv & {
  DB: any
  TRANSUNION_API_URL?: string
  TRANSUNION_API_KEY?: string
  TRANSUNION_CLIENT_ID?: string
  TRANSUNION_ENV?: string
  // Cross-platform (Equipment <-> Feed) configuration
  APP_TYPE?: string                 // 'equipment' | 'feed' — data-scope + payment-host context
  PUBLIC_BASE_URL?: string          // this app's public origin (hosted checkout URLs)
  CROSS_APP_URL?: string            // sibling app origin ('Shop Equipment'/'Shop Feeds' target)
  CROSS_APP_HMAC_SECRET?: string    // shared secret for cross-app SSO handoff tokens
  // score.farmsky.africa — SSO handoff target + API consumption
  SCORE_APP_URL?: string            // score.farmsky.africa origin (SSO "Open Score" button)
  SCORE_API_URL?: string            // score API base (e.g. https://score.farmsky.africa)
  SCORE_API_CLIENT?: string         // Score API client id issued to Equipment
  SCORE_API_SECRET?: string         // Score API secret (paired with the client id)
  // Phase 4 — standardized auth hashing (must match Feed values)
  AUTH_HASH_ITERATIONS?: string
  AUTH_HASH_KEYLEN?: string
  AUTH_PEPPER?: string
  // Optional explicit default tenant for user rows created outside an admin
  // session (public self-signup / bulk import). Falls back to the most-populated
  // existing org, then the oldest organizations row, when unset.
  EQUIPMENT_ORG_ID?: string
  DEFAULT_ORG_ID?: string
  // Automated backup email delivery. Both backups (system snapshot + platform
  // data export) are emailed to this recipient every 6h. Comma/;-separated for
  // multiple mailboxes. Requires EMAIL_* provider settings to also be present.
  BACKUP_EMAIL_TO?: string
  BACKUP_NOTIFY_EMAIL?: string      // alias for BACKUP_EMAIL_TO
  // Email provider (used by backend/email.ts sendEmail)
  EMAIL_PROVIDER?: string
  EMAIL_API_URL?: string
  EMAIL_API_TOKEN?: string
  EMAIL_FROM?: string
  // Token allowing an external cron/pinger to trigger POST /api/backups/run-auto
  ADMIN_TASK_TOKEN?: string
  // Per-boot nonce for the Node server's in-process 6h backup scheduler.
  INTERNAL_SCHEDULER_NONCE?: string
}

export type SessionUser = {
  id: number
  full_name: string
  phone: string
  email?: string | null
  avatar_url?: string | null
  role: string
  region?: string
  label?: string
  permissions?: Record<string, boolean>
  // Tenant scope. The central `farmsky_central_db` (shared with Score) defines
  // `users.org_id UUID NOT NULL`. Equipment must propagate the creating admin's
  // org_id onto any user it inserts. `null` on Equipment-only DB shapes (SQLite/
  // D1 dev) that predate the multitenant column.
  org_id?: string | null
}
