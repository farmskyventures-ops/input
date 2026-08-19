# SasaPay — Production Payment Integration

Farm Sky's SasaPay integration is **production-ready** and drives real money movement end-to-end:
secure checkout (mobile money + **all** SasaPay banks), wallet disbursals, withdrawals to a
user's registered mobile/bank, admin direct payments, and balance confirmation — all with
signed, IP-whitelisted callbacks and an append-only double-entry ledger.

Until live credentials are supplied the whole stack runs in a **safe simulation mode** (no real
network calls, deterministic fake receipts), so the app is fully demoable without money moving.

---

## 1. Configuration

Set these environment variables (Cloudflare secrets / `.env` for Node). Either `CLIENT_*` or
`CONSUMER_*` naming works — `server.ts` aliases them automatically.

| Variable | Required | Purpose |
| --- | --- | --- |
| `SASAPAY_CLIENT_ID` (or `SASAPAY_CONSUMER_KEY`) | yes | OAuth2 client id (also the HMAC signature secret) |
| `SASAPAY_CLIENT_SECRET` (or `SASAPAY_CONSUMER_SECRET`) | yes | OAuth2 client secret |
| `SASAPAY_MERCHANT_CODE` | yes | Your SasaPay merchant/short code |
| `SASAPAY_ENV` | no | `production` or `sandbox` (default sandbox) |
| `SASAPAY_CALLBACK_URL` | yes (live) | C2B payin **payload** callback URL |
| `SASAPAY_B2C_CALLBACK_URL` | no | B2C payout callback (falls back to `SASAPAY_CALLBACK_URL`) |

The integration is considered **LIVE** only when `CLIENT_ID` + `CLIENT_SECRET` + `MERCHANT_CODE`
are all present. Otherwise it transparently runs in simulation.

Base URLs: `production → https://api.sasapay.app`, otherwise `https://sandbox.sasapay.app`.

---

## 2. Supported channels (ALL SasaPay banks)

`GET /api/sasapay/channels` returns the complete catalogue — **40 channels: 35 banks + 4 mobile
networks + SasaPay wallet**. The frontend selectors are populated dynamically from this endpoint,
so every bank SasaPay supports is selectable (not just a hard-coded few).

- **Wallet**: `0` SasaPay Wallet (OTP flow)
- **Mobile**: `63902` M-PESA, `63903` Airtel Money, `63907` T-Kash, `97` Telkom Kenya
- **Banks** (channel codes): `01` KCB, `02` Standard Chartered, `03` Absa, `07` NCBA, `10` Prime,
  `11` Co-operative, `12` National, `14` M-Oriental, `16` Citibank, `18` Middle East, `19` Bank of
  Africa, `23` Consolidated, `25` Credit, `31` Stanbic, `35` ABC, `36` Choice MFB, `43` Eco,
  `50` Paramount, `51` Kingdom, `53` Guaranty, `54` Victoria, `55` Guardian, `57` I&M, `61` HFC,
  `63` DTB, `65` Mayfair, `66` Sidian, `68` Equity, `70` Family, `72` Gulf African,
  `74` First Community, `75` DIB, `76` UBA, `78` KWFT, `89` Stima Sacco.

---

## 3. Money flows & endpoints

### 3.1 Secure checkout (C2B — pay for listed items on cash or credit)

| Endpoint | Description |
| --- | --- |
| `POST /api/sasapay/stkpush` | Initiate a payin against a contract. Body: `contract_id`, `amount`, `phone`, `channel_code`, and `account_number` for banks. Returns `needs_otp` for the SasaPay wallet channel. |
| `POST /api/sasapay/process` | Complete a **wallet** checkout by submitting the OTP (`checkout_request_id`, `verification_code`). |
| `POST /api/sasapay/confirm` | Poll / confirm status; settles the contract via the double-entry ledger + `applyPayment`. |

Flow: `stkpush` → (wallet only) `process` OTP → callback / `confirm` → contract paid.

### 3.2 Disbursal to wallets

- **Commission / retainer / per-diem** credits accrue via earning rules (`distributeCommission`)
  and `POST /api/wallet/payouts` (batch, internal `wallet_credit`).
- Balances are held in an append-only `wallet_ledger` — a Postgres trigger stamps `balance_after`
  and rejects debits that exceed the balance, so a wallet can never go negative.

### 3.3 Withdrawal to registered mobile / bank (B2C)

| Endpoint | Description |
| --- | --- |
| `GET/POST/DELETE /api/payout-accounts` | Register & manage validated mobile/bank destinations. |
| `POST /api/wallet/withdraw` | Debit the caller's wallet, then push a real SasaPay B2C payout to a saved account or an inline `channel_code` + `account_number`. On failure the debit is auto-reversed. |
| `GET /api/wallet/withdrawals` | Withdrawal / disbursal history. |

### 3.4 Direct payments to individuals (admin/assigned user)

`POST /api/wallet/direct-pay` (`manage_wallets`): pay a person directly, either
- `destination: "wallet"` → credit an internal user's wallet, or
- `destination: "external"` → SasaPay B2C to a mobile/bank number.

### 3.5 Account validation & balance confirmation

| Endpoint | Description |
| --- | --- |
| `POST /api/sasapay/validate-account` | Confirm the holder name of a mobile/bank/wallet before paying it. |
| `GET /api/sasapay/balance` (`manage_wallets`) | Confirm merchant float across Working / Utility / Bulk accounts. |

---

## 4. Callbacks & security

SasaPay posts results to Farm Sky. Per SasaPay's guide:

- **Payins** use **two** callback URLs: an **IPN** (successful payins only) and the **payload**
  callback (both success *and* failure).
  - `POST /api/sasapay/callback` — payload callback (both outcomes).
  - `POST /api/sasapay/ipn` — successful-payin IPN.
- **Payouts** use **only** the payload callback: `POST /api/sasapay/b2c-callback`.

**Security controls (enforced when live):**
1. **IP whitelist** — the 10 published SasaPay callback IPs (`isTrustedSasapayIp`, handles
   `X-Forwarded-For`).
2. **HMAC-SHA512 signature** in `X-SasaPay-Signature`:
   `message = transaction_code-merchant_code-account_number-payment_reference-amount`,
   `secret = Merchant API Client ID`, compared with a timing-safe check (`verifySasapaySignature`).
   Uses Web Crypto (`crypto.subtle`) so it works identically on Cloudflare Workers and Node.
3. **Idempotency** — a callback only acts on a still-`pending`/`processing` record, so
   duplicate deliveries never double-apply a payment or double-refund a payout.

A callback that is neither from a trusted IP nor carries a valid signature is rejected `403`
(and audited) in production. In simulation mode these checks are relaxed so the demo works.

---

## 5. Data model (migration `0013`)

- `payment_intents` gains `provider`, `direction` (`payin`/`payout`), `channel_code`,
  `channel_name`, `account_number`, `transaction_reference`, `transaction_code`, `needs_otp`.
- `payout_accounts` — a user's registered, SasaPay-validated withdrawal destinations.
- `wallet_withdrawals` — full life-cycle tracking of every B2C disbursal (withdrawal + direct-pay):
  `pending → processing → success | failed | reversed`, with `ledger_debited` for safe reversals.
- `payout_batches.payment_method` — distinguishes internal `wallet_credit` from `sasapay_b2c`.

Row-Level Security scopes `payout_accounts` and `wallet_withdrawals` to their owner; admins see all.

---

## 6. Simulation vs live

| | Simulation (no creds) | Live (creds set) |
| --- | --- | --- |
| Network calls | none | real SasaPay REST |
| Receipts | deterministic fakes | real transaction codes |
| Callback signature/IP | relaxed | **enforced** |
| Wallet ledger | fully functional | fully functional |

To go live: set the env vars in §1, register the callback URLs (§4) in your SasaPay dashboard,
and restart. The status endpoint `GET /api/sasapay/status` reports `live`/`mode`.
