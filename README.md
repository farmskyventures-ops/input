# Nia by Farmsky — Input Marketplace

**Production domain:** `https://nia.farmsky.africa`
**Tenant role:** Client Tenant of the Equipment Central Payment Gateway
**Client key:** `nia_farmsky_key`

Nia by Farmsky is a **100% feature port of the Farmsky Equipment marketplace**,
re-themed for **crop inputs** (seeds, fertilizers, agrochemicals and farm
tools). Every operational module from Equipment is duplicated locally and runs
against Nia's own PostgreSQL database. **Only payment execution, wallet, and
refund settlement are delegated** to the Equipment Central Payment Gateway
(`equipment.farmsky.africa`).

---

## Architecture

```
+-------------------------------------------------------------------------+
|                        Nia Input Marketplace                            |
|                     (https://nia.farmsky.africa)                        |
|                                                                         |
|  * 100% Ported Feature Set (Catalog, Orders/Contracts, Vendors,         |
|    Logistics, Wallet UI, Disputes, Reviews, Analytics, Admin, RBAC)     |
|  * Local PostgreSQL Database (Products, Users, Contracts, Ledger, ...)  |
|  * Client Key: nia_farmsky_key                                          |
+-------------------------------------------------------------------------+
                                     |
                                     | Signed HMAC Request
                                     | POST /api/v1/payments/initiate
                                     v
+-------------------------------------------------------------------------+
|                        Equipment Central Gateway                        |
|                  (https://equipment.farmsky.africa)                     |
|  * Master Wallet Ledger & Dual Payment Rails (M-Pesa / SasaPay)         |
|  * Verifies signature via nia_farmsky_key & CROSS_APP_HMAC_SECRET       |
|  * Dispatches signed webhook on transaction settlement                  |
+-------------------------------------------------------------------------+
                                     |
                                     | Signed Webhook Callback
                                     | POST /api/v1/payment-webhook
                                     v
+-------------------------------------------------------------------------+
|                        Nia Input Marketplace                            |
|      (verifies HMAC → applyPayment → ledger / ownership / commission)   |
+-------------------------------------------------------------------------+
```

### How the port keeps 100% of the code but delegates payments

Rather than reimplementing checkout, Nia keeps the entire Equipment payment
calling surface (`payment_intents`, `/api/mpesa/*`, `/api/sasapay/*`, ledger,
commission distribution) **unchanged** and switches only the *execution rail*:

* **`backend/mpesa.ts` / `backend/sasapay.ts`** — `stkPush()` / `sasapayStkPush()`
  detect client-tenant mode (`PAYMENT_CLIENT_KEY` + `CROSS_APP_HMAC_SECRET` +
  `PAYMENT_GATEWAY_URL`) and, when set, **delegate** to the Equipment gateway
  `POST /payments/initiate` with an HMAC-SHA256 signature instead of calling
  Daraja / SasaPay directly. The gateway's `transaction_ref` is surfaced as the
  local `checkout_request_id`, so all downstream code is untouched.
* **`POST /api/v1/payment-webhook`** — verifies the gateway's signed
  `PAYMENT_COMPLETED` / `PAYMENT_FAILED` callback with `CROSS_APP_HMAC_SECRET`,
  then drives the **same** `applyPayment()` settlement path used by the M-Pesa
  callback (updates the ledger, records ownership, distributes agent
  commissions). Idempotent and replay-safe.

### HMAC signing scheme
Canonical string: `client_key\ntimestamp\nnonce\nbody`, signed with HMAC-SHA256.
Sent as headers: `X-Farmsky-Client`, `X-Farmsky-Timestamp`, `X-Farmsky-Nonce`,
`X-Farmsky-Signature`. 5-minute replay window (`payments-shared.ts`).

---

## Ported feature matrix

| Module | Ported locally | Delegated dependency |
|---|---|---|
| Catalog & Inventory (CRUD, SKU, stock, taxonomy) | ✅ Local DB | — |
| User & Role engine (RBAC, MFA, sessions) | ✅ Local DB | — |
| Orders / Murabaha contracts & lifecycle | ✅ Local DB | — |
| Logistics & dispatch | ✅ Local DB | — |
| Vendor / supplier portal & payouts UI | ✅ Local DB | Payout settle via gateway wallet |
| Disputes, tickets & refunds | ✅ Local DB | Refund execution via gateway |
| Reviews & ratings | ✅ Local DB | — |
| Analytics dashboard & ledger | ✅ Local DB | — |
| **Payment & checkout (STK, SasaPay, status)** | Calling code local | **100% delegated to gateway** |

The storefront defaults to the **`inputs`** marketplace (Seeds, Fertilizers,
Crop Protection, Soil Health).

---

## Environment

See `.env.example`. Key client-tenant variables:

```
APP_NAME="Nia by Farmsky"
PUBLIC_APP_URL="https://nia.farmsky.africa"
DATABASE_URL="postgresql://.../nia"
PAYMENT_GATEWAY_URL="https://equipment.farmsky.africa/api/v1"
PAYMENT_CLIENT_KEY="nia_farmsky_key"
CROSS_APP_HMAC_SECRET="nia_sec_..."   # MUST equal app_clients.hmac_secret on the gateway
```

## Build & run

```bash
npm install
npm run db:migrate     # apply all migrations + seed against DATABASE_URL
npm run build:node     # esbuild → dist-node/server.js (authoritative Render target)
npm run build          # vite → dist/_worker.js (Cloudflare Pages)
npm start              # node dist-node/server.js
```

Demo accounts (seed, plaintext for demo; upgraded to PBKDF2 on first login):

| Role | Phone | Password |
|---|---|---|
| Super Admin | `+254702875711` | `1224` |
| Agent | `+254729436383` | `1225` |
| Farmer (customer) | `+254716401463` | `1226` |
| Support | `+254712612489` | `1227` |

## Provisioning on the Equipment gateway

Register Nia as a client tenant on the Equipment Central Gateway so its signed
requests are accepted and settlement webhooks are dispatched:

```sql
INSERT INTO app_clients (client_key, display_name, origin_url, hmac_secret, callback_url, is_active)
VALUES (
  'nia_farmsky_key',
  'Nia by Farmsky (Input Marketplace)',
  'https://nia.farmsky.africa',
  'nia_sec_unique_secure_hmac_key_2026',           -- MUST equal CROSS_APP_HMAC_SECRET on Nia
  'https://nia.farmsky.africa/api/v1/payment-webhook',
  1
)
ON CONFLICT (client_key) DO UPDATE SET
  display_name = EXCLUDED.display_name,
  origin_url   = EXCLUDED.origin_url,
  callback_url = EXCLUDED.callback_url,
  is_active    = 1;
```

## Local delegated-payment testing

`test/mock-gateway.mjs` is a tiny local stand-in for the Equipment gateway. It
verifies the inbound HMAC exactly like production, returns a `PENDING`
transaction, then fires a signed `PAYMENT_COMPLETED` webhook back to Nia — so
the full checkout → settlement path can be exercised without the live gateway.

```bash
CROSS_APP_HMAC_SECRET=... PORT=3000 node test/mock-gateway.mjs
# then run the server with PAYMENT_GATEWAY_URL=http://127.0.0.1:3000/api/v1
```
