# Farmsky — Granular RBAC, Ownership RLS & Agent Wallet System

This document describes the operational security & finance architecture added on
top of the payment-gateway phase. It covers the split inventory/finance
permission model, relationship-based (ownership) Row-Level Security, the new user
types, and the double-entry agent wallet system.

---

## 1. Setup / Apply Order

1. **Migrations auto-apply on boot.** `backend/db-init.ts` runs every
   `migrations/*.sql` (idempotently) when the server starts, including
   `migrations/0012_rbac_ownership_wallet.sql`.
2. **Run the RLS/trigger blueprint ONCE as a Postgres superuser** (or the DB
   owner) after the schema exists:

   ```bash
   psql "$SUPERUSER_DATABASE_URL" -f backend/sql/03_ownership_rls_setup.sql
   ```

   This installs the session-context functions, ownership RLS policies, the
   split-data finance guard trigger, and the wallet double-entry triggers.

3. **Run the app under a NON-superuser role.** RLS `FORCE` applies to the table
   owner but Postgres *superusers bypass RLS entirely*. The application DB user
   must be `NOSUPERUSER` for the isolation guarantees to hold.

> **Verify isolation any time:** `GET /api/security/rls-check` (super_admin only)
> clears the session context and probes the protected tables. It must report
> `isolation_ok: true` — i.e. **zero rows visible without a user context**.

---

## 2. Permission Matrix (Instruction 1)

Two new granular permissions decouple *who drafts inventory* from *who authorizes
the money*:

| Permission | Grants |
|---|---|
| `can_manage_inventory` | Add/edit core product details, reorder thresholds, **cash** pricing & payment availability |
| `can_manage_finance_settings` | Add/edit **finance** pricing, markups, rates, discounts, terms, legal agreements, PAYGO |
| `view_wallet` | See own wallet balance, ledger & earnings |
| `manage_wallets` | Assign wallets, set earning rules, disburse payouts, view global analytics |

**Default grants (role_templates):**

| Role | inventory | finance | view_wallet | manage_wallets |
|---|:-:|:-:|:-:|:-:|
| super_admin / admin | ✅ | ✅ | ✅ | ✅ |
| operations_finance | – | ✅ | – | – |
| agent | ✅ | – | ✅ | – |

Enforced in `backend/index.tsx` via `hasPermission()` /
`requirePermission(...perms)` (OR semantics) and mirrored in `builtinDefaults()`.

---

## 3. Split-Data Listing Workflow (Instructions 2, 3, 4)

A base user (agent) drafts a product; an authorized finance user completes the
financial components. Enforced at **two layers**:

* **App layer** — `POST /api/products` requires `can_manage_inventory`. If the
  author lacks `can_manage_finance_settings`, all finance fields are neutralized
  (`credit_markup_pct=0`, `financing_enabled=0`, …) and the row is saved with
  `finance_status='pending_finance'`. `PUT /api/products/:id` splits editable
  columns by permission.
* **DB layer (defence-in-depth)** — the `guard_product_finance_columns` trigger
  blocks any INSERT/UPDATE to finance columns from a session without
  `app.user_can_finance='true'`, even if the API is bypassed
  (`ERROR: Not authorized to modify financial components`).

**Finance workflow endpoints:**

| Endpoint | Purpose |
|---|---|
| `GET /api/products/finance-queue` | Products awaiting financial setup (finance-authorized only) |
| `PUT /api/products/:id/finance` | Supply markup/rate/PAYGO/agreement, publish to storefront |
| `GET /api/products/finance-audit` | Diagnostic of products hidden from storefront + reminder + `notify_roles` |

`finance_status`: `draft` → `pending_finance` → `published`. The storefront
(`GET /api/products?shop=1`) only shows `published` products.

**Frontend:** `viewFinanceQueue()` renders the approval queue + audit feed;
`financeModal()` supplies the finance components; `productForm()` disables finance
fields and shows a lock notice for non-finance users; `viewInventory()` shows
`finance_status` badges and gates the "Add inventory" button on
`can_manage_inventory`.

---

## 4. Relationship-Based Access Control (Instruction 5)

Ownership columns (migration 0012): `products.created_by`,
`customers.onboarded_by` (backfilled from `agent_id`),
`murabaha_contracts.created_by`.

**RLS policies** (`backend/sql/03…`), keyed on `current_app_user_id()`:

| Table | A user may see a row when… | Admin |
|---|---|:-:|
| `customers` | `onboarded_by` or `agent_id` = current user | bypass |
| `murabaha_contracts` | `created_by`/`agent_id` = user, or its farmer was onboarded by the user | bypass |
| `products` | `created_by` = user | bypass |

**Session context** is set per request in `requireAuth` via
`setUserContext(c, user)` → `set_config('app.current_user_id'|'app.current_role'|'app.user_can_finance', …)`.
Admin-wide reads (storefront, checkout, wallet management, finance queue) run
inside `withAdminContext(c, fn)` which temporarily elevates the context.

**Security rule:** a query with **no** `app.current_user_id` returns **zero
rows** for general users — verified by `GET /api/security/rls-check`.

---

## 5. Extended User Types (Instruction 6)

New `role_templates`: **Lender**, **Investor**, **M & E** (`mne`), **Partner** —
alongside Super Admin, Admin, Agent, Operations & Finance, Support, Farmer.
Surfaced in the User dropdown (`userRoleOptions`), `roleLabel`, and given
read-oriented nav (`navItems`).

---

## 6. Agent Wallet System (Instruction 7)

**Schema (migration 0012):**

* `wallets` — one per user (`user_id UNIQUE`), `balance`, `status`, `assigned_by`.
* `wallet_ledger` — append-only double-entry log: `entry_type` (credit|debit),
  `amount` (CHECK > 0), `balance_after` snapshot, `category`, `reference`.
* `earning_rules` — per-user compensation criteria (2% commission, KES 5,000
  retainer, transport, per-diem …): `calc_method` (percentage|fixed), `rate`,
  `fixed_amount`, `applies_to`.
* `payout_batches` — batch disbursal audit.

**Integrity triggers (`backend/sql/03…`):**

* `wallet_ledger_immutable` — blocks UPDATE/DELETE on ledger rows
  (`ERROR: wallet_ledger rows are immutable`).
* `wallet_ledger_apply` — the **only** sanctioned balance mover: locks the wallet
  `FOR UPDATE`, computes the new balance (with insufficient-funds check on
  debits), stamps `balance_after`, and syncs `wallets.balance` atomically.

**Endpoints:**

| Endpoint | Role | Purpose |
|---|---|---|
| `GET /api/wallet` | view_wallet | Own balance, ledger, earning rules |
| `GET /api/wallets` | manage_wallets | All wallets (global) |
| `POST /api/wallets` | manage_wallets | Assign/authorize a wallet |
| `GET/POST/PUT /api/earning-rules[/:id]` | manage_wallets | CRUD earning criteria |
| `POST /api/wallet/payouts` | manage_wallets | Batch disbursal (user_ids / user_id / `target:all_agents`) |
| `GET /api/wallet/analytics` | view_wallet | RLS-scoped: agent=self, admin=global |

**Dynamic commission** — `distributeCommission()` fires when a contract status
becomes `completed` (hooked in `applyPayment`): it evaluates the agent's active
`applies_to='completed_order'` rules and credits the wallet (idempotent per
contract+rule).

**Frontend:** `viewMyWallet()` (agent statement), `viewWallets()` (admin: wallet
grid, assign, earning rules, single & batch payouts, analytics).

---

## 7. Test Summary (local Postgres, non-superuser app role)

* ✅ Migration 0012 objects + jsonb permission grants applied.
* ✅ `rls-check` → `isolation_ok: true` (0 rows without context).
* ✅ Agent product create → `pending_finance`, finance fields neutralized, `created_by` set.
* ✅ Agent scoped to own products/customers/contracts; admin sees all.
* ✅ Agent 403 on finance-queue; admin publishes → appears in storefront; audit clears.
* ✅ Finance-column guard blocks agent DB tamper; finance user succeeds.
* ✅ Wallet: assign, earning rules, payouts; running balance & `balance_after` correct.
* ✅ Ledger immutability (UPDATE/DELETE rejected).
* ✅ Analytics scope: agent=self, admin=global.
