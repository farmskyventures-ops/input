// Minimal mock of the Equipment Central Gateway for local E2E testing of Nia's
// delegated checkout. Verifies the inbound HMAC exactly like the real gateway,
// returns a PENDING transaction_ref, then (after a short delay) fires a SIGNED
// PAYMENT_COMPLETED webhook back to Nia — mirroring notifyOriginApp().
import { createServer } from 'node:http'
import crypto from 'node:crypto'

const SECRET = process.env.CROSS_APP_HMAC_SECRET || 'nia_sec_testsecret_0123456789abcdef'
const NIA_WEBHOOK = process.env.NIA_WEBHOOK || 'http://127.0.0.1:8791/api/v1/payment-webhook'
const PORT = Number(process.env.PORT || 3000)

function hmac(secret, msg) { return crypto.createHmac('sha256', secret).update(msg).digest('hex') }
function canonical(key, ts, nonce, body) { return `${key}\n${ts}\n${nonce}\n${body}` }

function readBody(req) {
  return new Promise((resolve) => { let d = ''; req.on('data', c => d += c); req.on('end', () => resolve(d)) })
}

async function fireWebhook(originRef, txRef, amount) {
  const payload = JSON.stringify({
    transaction_ref: txRef,
    origin_reference: originRef,
    payment_method: 'mpesa',
    status: 'SUCCESS',
    provider_receipt: 'QK' + Math.random().toString(36).slice(2, 10).toUpperCase(),
    amount,
    currency: 'KES',
    result_code: 0,
    result_desc: 'The service request is processed successfully.',
    completed_at: new Date().toISOString()
  })
  const ts = Date.now().toString()
  const nonce = crypto.randomUUID()
  const sig = hmac(SECRET, canonical('nia_farmsky_key', ts, nonce, payload))
  const res = await fetch(NIA_WEBHOOK, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Farmsky-Client': 'nia_farmsky_key',
      'X-Farmsky-Timestamp': ts,
      'X-Farmsky-Nonce': nonce,
      'X-Farmsky-Signature': sig
    },
    body: payload
  })
  console.log('[mock-gateway] webhook →', res.status, await res.text())
}

const server = createServer(async (req, res) => {
  const body = await readBody(req)
  const key = req.headers['x-farmsky-client'] || ''
  const ts = req.headers['x-farmsky-timestamp'] || ''
  const nonce = req.headers['x-farmsky-nonce'] || ''
  const sig = req.headers['x-farmsky-signature'] || ''
  const expected = hmac(SECRET, canonical(key, ts, nonce, body))
  const valid = key === 'nia_farmsky_key' && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))

  if (req.url.startsWith('/api/v1/payments/initiate')) {
    if (!valid) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ success: false, error: 'Invalid signature' })) }
    const parsed = JSON.parse(body)
    const txRef = 'CENTRAL-TX-' + Date.now()
    console.log('[mock-gateway] initiate OK', parsed.origin_reference, '→', txRef)
    res.writeHead(200, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify({
      success: true, transaction_ref: txRef, payment_method: parsed.payment_method,
      origin_app: 'nia_farmsky_key', simulated: true, needs_otp: false,
      customer_message: 'STK push sent (simulated).', status: 'PENDING'
    }))
    // Simulate the async settlement + signed webhook after 1.5s.
    setTimeout(() => fireWebhook(parsed.origin_reference, txRef, parsed.amount).catch(e => console.error('[mock-gateway] webhook err', e.message)), 1500)
    return
  }
  if (req.url.startsWith('/api/v1/payments/status/')) {
    if (!valid) { res.writeHead(401); return res.end(JSON.stringify({ success: false, error: 'Invalid signature' })) }
    res.writeHead(200, { 'Content-Type': 'application/json' })
    return res.end(JSON.stringify({ success: true, status: 'SUCCESS', provider_receipt: 'QKPOLLED123' }))
  }
  res.writeHead(404); res.end('not found')
})
server.listen(PORT, () => console.log(`[mock-gateway] listening on :${PORT} → webhook target ${NIA_WEBHOOK}`))
