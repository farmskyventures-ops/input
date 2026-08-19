# Farmsky Score Integration (score.farmsky.africa)

Equipment is the **central host** for Farmsky Score's data and payments, and
consumes Score's APIs for identity + credit decisioning.

## 1. Dedicated database tables (migration `0021_score_platform.sql`)

Score's data lives in its **own** tables, separate from Equipment's own
customer/KYC data:

| Table | Purpose |
|-------|---------|
| `score_subscriptions` | Subscription plans + billing state pushed from Score |
| `score_verifications` | ID verification + liveness results retrieved from Score |
| `score_iprs_checks` | IPRS government-registry lookups |
| `score_credit_evaluations` | Full credit-evaluation decisions |

The migration also registers a `score` row in `app_clients` so Score can call
the central payment gateway.

## 2. Subscription payments from Score

Score's subscription checkout is sent to the **same** central gateway the other
marketplaces use:

```
POST /api/v1/payments/initiate     (HMAC-signed with the 'score' app_clients secret)
```

When the initiate body carries a `subscription` (or `plan`) context, the gateway
records/updates a row in `score_subscriptions`. On settlement, `notifyOriginApp`
calls `syncScoreSubscription` to flip the subscription to `active` (or
`past_due`) and set `current_period_end`.

## 3. Single sign-on (no second login)

The **"Open Score"** button in the Equipment header opens Score with the current
session:

1. Equipment `GET /api/cross/handoff?target=score` mints a short-lived (2 min)
   HMAC-signed token carrying `{phone, email, name}` and returns
   `${SCORE_APP_URL}/sso?token=...`.
2. Score's `GET /sso` verifies the HMAC + freshness, resolves/creates the
   account by **email**, issues a Score session, and drops the user straight
   into the Score console — no re-login.

The shared `CROSS_APP_HMAC_SECRET` must be identical on both apps.

## 4. Consuming Score's APIs for verification + credit

`backend/score-client.ts` calls Score's `/v3/*` endpoints
(`Authorization: Bearer <client_id>:<secret>` + HMAC request signing) for:

- **ID verification + liveness** → `POST /v3/kyc` (falls back to
  `POST /v3/biometrics/verify`)
- **IPRS** → `POST /v3/iprs/verify`
- **Credit evaluation** → `POST /v3/credit/evaluations`

These are wired into `POST /api/customers/:id/verify`. When Score is configured,
the real results are used and mirrored into the `score_*` tables; otherwise the
endpoint falls back to the local deterministic simulation so the flow always
completes.

> Identity, liveness and IPRS on the Score platform are backed by MetaMap
> (`api.getmati.com` OAuth + GovChecks), verified against
> <https://docs.metamap.com>. Equipment itself does **not** call MetaMap
> directly — it delegates to Score.

## 5. Environment variables

```
CROSS_APP_HMAC_SECRET=<shared with Score>
SCORE_APP_URL=https://score.farmsky.africa
SCORE_API_URL=https://score.farmsky.africa
SCORE_API_CLIENT=<API client id Score issued to Equipment>
SCORE_API_SECRET=<paired secret>
```
