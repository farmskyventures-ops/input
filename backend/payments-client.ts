// =====================================================================
// Nia → Equipment Central Gateway — unified payment service module
// ---------------------------------------------------------------------
// Nia is a CLIENT TENANT. It does NOT run M-Pesa / SasaPay itself. When a
// buyer checks out, Nia calls the Equipment Central Gateway
//   POST {CENTRAL_HOST_GATEWAY}/payments/initiate
// with an HMAC-SHA256 signed request (same canonical scheme the gateway
// verifies against its app_clients row for `nia_farmsky_key`).
//
// Env consumed (see .env.example):
//   PAYMENT_CLIENT_KEY      -> 'nia_farmsky_key'  (X-Farmsky-Client)
//   CROSS_APP_HMAC_SECRET   -> shared secret (nia_sec_...) — must equal the
//                              hmac_secret stored on the gateway for this key
//   CENTRAL_HOST_GATEWAY    -> https://equipment.farmsky.africa/api/v1
// =====================================================================

import { signRequest } from './payments-shared'
import type { Bindings } from './types'

export interface InitiateOpts {
  amount: number
  phone: string
  payment_method?: 'mpesa' | 'sasapay'
  origin_reference?: string     // our order_ref
  description?: string
  initiated_by_user?: number | string | null
  idempotency_key?: string
}

export interface InitiateResult {
  success: boolean
  transaction_ref?: string
  payment_method?: string
  origin_app?: string
  simulated?: boolean
  needs_otp?: boolean
  customer_message?: string
  status?: string
  idempotent_replay?: boolean
  error?: string
}

function clientKey(env: Bindings): string {
  return (env.PAYMENT_CLIENT_KEY as string) || 'nia_farmsky_key'
}
function hmacSecret(env: Bindings): string {
  return (env.CROSS_APP_HMAC_SECRET as string) || ''
}
function gatewayBase(env: Bindings): string {
  // Always talk to the /api/v1 root of the Equipment central gateway.
  const base = (env.CENTRAL_HOST_GATEWAY as string) || 'https://equipment.farmsky.africa/api/v1'
  return base.replace(/\/+$/, '')
}

/**
 * Delegated checkout: initiate a payment on the Equipment Central Gateway.
 * Returns the gateway's transaction_ref which Nia stores on the order so the
 * inbound webhook (and any status poll) can be matched back to it.
 */
export async function initiatePayment(env: Bindings, opts: InitiateOpts): Promise<InitiateResult> {
  const secret = hmacSecret(env)
  const key = clientKey(env)
  if (!secret) return { success: false, error: 'CROSS_APP_HMAC_SECRET is not configured on Nia' }

  const payload = {
    amount: opts.amount,
    phone: opts.phone,
    payment_method: opts.payment_method || 'mpesa',
    origin_reference: opts.origin_reference,
    description: opts.description,
    initiated_by_user: opts.initiated_by_user ?? null
  }
  const body = JSON.stringify(payload)
  const { timestamp, nonce, signature } = await signRequest(secret, key, body)
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Farmsky-Client': key,
    'X-Farmsky-Timestamp': timestamp,
    'X-Farmsky-Nonce': nonce,
    'X-Farmsky-Signature': signature
  }
  if (opts.idempotency_key) headers['Idempotency-Key'] = opts.idempotency_key

  try {
    const res = await fetch(`${gatewayBase(env)}/payments/initiate`, { method: 'POST', headers, body })
    const json = (await res.json()) as InitiateResult
    return json
  } catch (e: any) {
    return { success: false, error: e?.message || 'Gateway unreachable' }
  }
}

/**
 * Poll a delegated transaction's status on the gateway (fallback to the
 * asynchronous webhook). GET signs the path segment (transaction_ref).
 */
export async function getPaymentStatus(env: Bindings, transaction_ref: string): Promise<any> {
  const secret = hmacSecret(env)
  const key = clientKey(env)
  if (!secret) return { success: false, error: 'CROSS_APP_HMAC_SECRET is not configured on Nia' }
  const { timestamp, nonce, signature } = await signRequest(secret, key, transaction_ref)
  try {
    const res = await fetch(`${gatewayBase(env)}/payments/status/${encodeURIComponent(transaction_ref)}`, {
      headers: {
        'X-Farmsky-Client': key,
        'X-Farmsky-Timestamp': timestamp,
        'X-Farmsky-Nonce': nonce,
        'X-Farmsky-Signature': signature
      }
    })
    return await res.json()
  } catch (e: any) {
    return { success: false, error: e?.message || 'Gateway unreachable' }
  }
}
