# Farmsky Central Payment Gateway — Integration Guide

A single endpoint that the three Farmsky marketplaces — **equipment.farmsky.africa**, **feed.farmsky.africa**, **input.farmsky.africa** — call to initiate M-Pesa, SasaPay and KCB Buni payments. Every transaction stores **`origin_app`** and **`payment_method`** so you always know where it came from and how it was paid.

---

## 1. Endpoint URLs (hosted on this app)

| Purpose | Method | URL |
|---|---|---|
| Initiate payment | `POST` | `https://equipment.farmsky.africa/api/v1/payments/initiate` |
| Check status | `GET`  | `https://equipment.farmsky.africa/api/v1/payments/status/:transaction_ref` |
| M-Pesa IPN (set in Daraja) | `POST` | `https://equipment.farmsky.africa/api/v1/payments/callbacks/mpesa` |
| SasaPay IPN (set in SasaPay portal) | `POST` | `https://equipment.farmsky.africa/api/v1/payments/callbacks/sasapay` |
| Buni IPN (set in KCB Buni portal) | `POST` | `https://equipment.farmsky.africa/api/v1/payments/callbacks/buni` |
| Admin reporting (internal) | `GET` | `https://equipment.farmsky.africa/api/v1/payments-admin/summary` |

---

## 2. Security model

1. **HMAC-SHA256 signed requests** — each marketplace has its own `hmac_secret` stored in the central DB (`app_clients` table). The marketplace signs the canonical string `client_key\ntimestamp\nnonce\nbody` and sends:
   - `X-Farmsky-Client` (e.g. `equipment`)
   - `X-Farmsky-Timestamp` (ms since epoch)
   - `X-Farmsky-Nonce` (UUID per request)
   - `X-Farmsky-Signature` (HMAC-SHA256 hex)

2. **Replay protection** — requests older than 5 minutes are rejected, and recently-seen nonces are blocked.

3. **`origin_app` cannot be spoofed** — it's read from the verified `client_key`, never from the request body.

4. **Idempotency** — optional `Idempotency-Key` header. Re-sending the same key returns the original transaction instead of double-charging.

5. **Provider callbacks bound by `provider_request_id`** — only the real provider knows the ID we got back from our outbound STK push, so spoofed IPNs cannot mark unrelated transactions as paid. Every IPN is logged in `central_callbacks` for audit.

6. **Outbound webhook signing** — when we notify your marketplace that a payment completed, we sign the notification the same way, so you can verify it came from us.

---

## 3. Database tables (run migration `0008_central_payments.sql`)

- **`app_clients`** — one row per marketplace, holds `hmac_secret`, `origin_url`, optional `callback_url`.
- **`central_transactions`** — every payment attempt across all apps + methods, with `origin_app`, `payment_method`, `status`, `provider_receipt`, `amount`.
- **`central_callbacks`** — raw IPN log for audit + replay diagnostics.

The seed inserts three rows for `equipment`, `feed`, `input` with placeholder secrets:
```sql
UPDATE app_clients SET hmac_secret='<long-random-string>' WHERE client_key='equipment';
UPDATE app_clients SET hmac_secret='<long-random-string>' WHERE client_key='feed';
UPDATE app_clients SET hmac_secret='<long-random-string>' WHERE client_key='input';
```
Generate strong secrets with `openssl rand -hex 32`. **Rotate** the same way.

If a marketplace wants async notifications instead of polling:
```sql
UPDATE app_clients SET callback_url='https://feed.farmsky.africa/api/payments/incoming' WHERE client_key='feed';
```

---

## 4. Calling the gateway from a marketplace (Node / Hono / any JS runtime)

```ts
// payments-client.ts (copy to feed/input/equipment apps)
import crypto from 'node:crypto'

const GATEWAY = 'https://equipment.farmsky.africa/api/v1/payments'
const CLIENT_KEY = process.env.FARMSKY_PAYMENTS_CLIENT_KEY!   // 'equipment' | 'feed' | 'input'
const SECRET = process.env.FARMSKY_PAYMENTS_HMAC_SECRET!      // same value as DB row

function signHeaders(body: string) {
  const timestamp = String(Date.now())
  const nonce = crypto.randomUUID()
  const message = `${CLIENT_KEY}\n${timestamp}\n${nonce}\n${body}`
  const signature = crypto.createHmac('sha256', SECRET).update(message).digest('hex')
  return {
    'X-Farmsky-Client': CLIENT_KEY,
    'X-Farmsky-Timestamp': timestamp,
    'X-Farmsky-Nonce': nonce,
    'X-Farmsky-Signature': signature,
    'Content-Type': 'application/json'
  }
}

export async function initiatePayment(opts: {
  amount: number
  phone: string
  payment_method: 'mpesa' | 'sasapay' | 'buni'
  origin_reference?: string        // your order/contract id
  description?: string
  initiated_by_user?: number
  idempotency_key?: string
}) {
  const body = JSON.stringify(opts)
  const headers: Record<string, string> = signHeaders(body)
  if (opts.idempotency_key) headers['Idempotency-Key'] = opts.idempotency_key
  const res = await fetch(`${GATEWAY}/initiate`, { method: 'POST', headers, body })
  return await res.json() as {
    success: boolean
    transaction_ref?: string
    payment_method?: string
    origin_app?: string
    simulated?: boolean
    customer_message?: string
    status?: string
    error?: string
  }
}

export async function getPaymentStatus(transaction_ref: string) {
  // For GET we sign the path
  const headers = signHeaders(transaction_ref)
  const res = await fetch(`${GATEWAY}/status/${transaction_ref}`, { headers })
  return await res.json()
}
```

### Example usage in a marketplace order checkout

```ts
const r = await initiatePayment({
  amount: 7500,
  phone: '+254712345678',
  payment_method: 'mpesa',
  origin_reference: order.id,                   // your order id
  description: 'Feed order #' + order.id,
  initiated_by_user: user.id,
  idempotency_key: 'order-' + order.id          // safe to retry
})

if (r.success) {
  saveTransactionRef(order, r.transaction_ref!) // store for later polling
  // Show user: "STK prompt sent to your phone…"
}
```

Then poll every few seconds until `status === 'SUCCESS'` or `'FAILED'`, OR set `app_clients.callback_url` to receive a signed POST as soon as we know.

---

## 5. Where did each payment come from?

Every row in `central_transactions` carries both fields, so any of these is a one-liner:

```sql
-- Per-marketplace totals
SELECT origin_app, COUNT(*), SUM(amount)
  FROM central_transactions
 WHERE status='SUCCESS'
 GROUP BY origin_app;

-- Per-payment-method totals
SELECT payment_method, COUNT(*), SUM(amount)
  FROM central_transactions
 WHERE status='SUCCESS'
 GROUP BY payment_method;

-- App × method matrix
SELECT origin_app, payment_method, COUNT(*), SUM(amount)
  FROM central_transactions
 WHERE status='SUCCESS'
 GROUP BY origin_app, payment_method
 ORDER BY origin_app, payment_method;
```

Or hit `GET /api/v1/payments-admin/summary` for a JSON version of those three queries (admin-only).

---

## 6. Operational checklist

- [ ] Apply `migrations/0008_central_payments.sql` on the central DB
- [ ] Rotate the three seed `hmac_secret` values with `openssl rand -hex 32`
- [ ] Put each secret in the corresponding marketplace's env as `FARMSKY_PAYMENTS_HMAC_SECRET`
- [ ] Set the three provider IPN URLs above in M-Pesa Daraja, SasaPay and KCB Buni dashboards
- [ ] Configure `MPESA_*`, `SASAPAY_*`, `BUNI_*` env vars on this app (see `.env.example`)
- [ ] (Optional) Set `callback_url` per app if you prefer push notifications over polling

---

## 7. Multi-tenant architecture & Single Merchant Shortcode (Instructions 6–18)

All three marketplaces — **equipment.farmsky.africa** (the **MAIN** app), **feed.farmsky.africa** and **mazao.farmsky.africa** — settle through **ONE** merchant shortcode. Payments flow through a single **Centralized Payment Gateway** service (deployable at `payment-api.farmsky.africa`), isolated from the marketplace business logic. Tenant isolation is enforced at **two independent layers**:

1. **Database layer — PostgreSQL Row-Level Security (RLS)** keyed on `marketplace_id`.
2. **Network layer — HMAC-SHA256 cryptographic payload validation** (Section 2).

### 7.1 Tenant registry & schema

`migrations/0011_central_multitenancy_rls.sql` adds:

- **`marketplaces`** — one row per tenant (`equipment` is `is_main=1`, plus `feed`, `mazao`), mapping `marketplace_key` → `domain`.
- **`marketplace_id`** columns on `central_transactions` and `central_callbacks` (back-filled from `origin_app`).
- **`payment_audit_log`** — suspicious-activity audit trail (`SIGNATURE_FAIL`, `REPLAY`, `CALLBACK_NO_MATCH`, etc. with `severity`).
- **`payment_nonces`** — `UNIQUE(client_key, nonce)` store that makes replay rejection atomic.

The gateway stamps every transaction with the tenant's `marketplace_id`, resolved from the verified `client_key` (never the request body).

### 7.2 Row-Level Security setup (run ONCE as a superuser)

```bash
psql "$SUPERUSER_DATABASE_URL" -v ON_ERROR_STOP=1 -f backend/sql/01_payment_rls_setup.sql
```

This script:

- Creates an **isolated least-privilege role** `payment_api_user` (`NOSUPERUSER NOCREATEDB NOCREATEROLE`) that can only touch the payment tables.
- **`ENABLE` + `FORCE` RLS** on `central_transactions`, `central_callbacks`, `payment_audit_log`.
- Adds tenant-isolation policies using two per-connection GUCs:
  - `app.current_marketplace_id` — the active tenant.
  - `app.is_admin` — `true` only for the MAIN app's reconciliation role (RLS bypass to read across tenants).

The gateway sets these on every request via `PostgresD1.setSessionConfig()` → `SELECT set_config('app.current_marketplace_id', …, false)`. A compromised or buggy marketplace connection **cannot read or alter another tenant's rows — the database itself refuses**.

> Change the `payment_api_user` password from `CHANGE_ME_IN_PROD` before production, and put its connection string in the payment gateway service's `DATABASE_URL`.

### 7.3 Deploying the gateway as a separate Render web service

Run the payment gateway as its own Render web service (same codebase, different DB user):

| Setting | Value |
|---|---|
| Service | `payment-api.farmsky.africa` (separate Render web service) |
| Build | `npm run build:node` |
| Start | `node dist-node/server.js` |
| `DATABASE_URL` | `postgres://payment_api_user:<pw>@<farmsky-central-db-host>/farmsky_central` |
| Providers | `MPESA_*`, `SASAPAY_*`, `BUNI_*` for the shared shortcode |

Because it connects as `payment_api_user`, RLS is *forced* even for the app's own queries — the isolation cannot be bypassed from application code.

### 7.4 Automated audits (run as the MAIN reconciliation role)

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f backend/sql/02_payment_security_audits.sql
```

Also exposed as admin JSON endpoints on the MAIN app:

| Purpose | Method | URL |
|---|---|---|
| Revenue matrix (marketplace × method) — single-shortcode attribution | `GET` | `/api/v1/payments/admin/revenue-matrix` |
| Suspicious-activity audit (signature fails, replays, integrity breaks, spoofed callbacks) | `GET` | `/api/v1/payments/admin/suspicious-activity` |

The **revenue matrix** is how a single settlement statement from the one shortcode is attributed back to each marketplace tenant.

### 7.5 Multi-tenant operational checklist

- [ ] Apply `migrations/0011_central_multitenancy_rls.sql` (auto-applied on boot)
- [ ] Run `backend/sql/01_payment_rls_setup.sql` once as superuser; change `payment_api_user` password
- [ ] Set the mazao `hmac_secret` (`UPDATE app_clients SET hmac_secret=… WHERE client_key='mazao';`)
- [ ] Deploy the gateway as a separate Render service using the `payment_api_user` `DATABASE_URL`
- [ ] Schedule `backend/sql/02_payment_security_audits.sql` (or poll the two admin endpoints)
