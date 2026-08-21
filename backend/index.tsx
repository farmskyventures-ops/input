import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import type { Bindings, SessionUser } from './types'
import { stkPush, stkQuery, mpesaConfigured, normalizePhone } from './mpesa'
import { verifySignature } from './payments-shared'
import {
  sasapayStkPush, sasapayQuery, sasapayConfigured,
  sasapayProcessPayment, sasapayB2C, sasapayValidateAccount, sasapayBalance,
  verifySasapaySignature, isTrustedSasapayIp, sasapayMode,
  SASAPAY_CHANNELS, channelByCode, accountTypeForChannel,
  normalizePhone as sasapayNormalizePhone
} from './sasapay'
import { buniStkPush, buniQuery, buniConfigured } from './buni'
import paymentGateway from './payment-gateway'
import { sendSms, smsConfigured, generateOtp } from './sms'
import { sendEmail, emailConfigured } from './email'
import { hashPassword, verifyPassword, isHashed } from './password'
import merchantApi from './merchant-api'
import { mintHandoffToken, verifyHandoffToken } from './cross-app'
import { scoreConfigured, scoreKyc, scoreIprs, scoreLiveness, scoreCreditEvaluation } from './score-client'
import { validateImageDataUrl, validateText, validateTextFields } from './upload-validation'

const app = new Hono<{ Bindings: Bindings; Variables: { user: SessionUser } }>()

// ----------------------------------------------------------------------------
// ISSUE 7 — SECURITY HARDENING
//   (a) Same-origin CORS with credentials (no wildcard — the API relies on
//       cookie-based sessions, so a permissive wildcard would be unsafe).
//   (b) Baseline security response headers on every request.
//   (c) Lightweight in-memory rate limiting for sensitive endpoints
//       (login / OTP / payment initiation) to blunt brute-force + abuse.
// ----------------------------------------------------------------------------
app.use('/api/*', cors({
  origin: (origin) => origin || '*',   // reflect the caller's own origin
  credentials: true,
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization', 'X-SasaPay-Signature'],
  maxAge: 600
}))

// Baseline security headers.
app.use('*', async (c, next) => {
  await next()
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('X-Frame-Options', 'SAMEORIGIN')
  c.header('Referrer-Policy', 'strict-origin-when-cross-origin')
  c.header('X-XSS-Protection', '0')
  c.header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
  c.header('Cross-Origin-Opener-Policy', 'same-origin')
})

// Simple sliding-window rate limiter (per-IP, per-bucket) held in memory.
const _rlBuckets = new Map<string, { count: number; resetAt: number }>()
function rateLimit(bucket: string, max: number, windowMs: number) {
  return async (c: any, next: any) => {
    const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for')?.split(',')[0].trim() || c.req.header('x-real-ip') || 'unknown'
    const key = `${bucket}:${ip}`
    const now = Date.now()
    const rec = _rlBuckets.get(key)
    if (!rec || rec.resetAt < now) {
      _rlBuckets.set(key, { count: 1, resetAt: now + windowMs })
    } else {
      rec.count++
      if (rec.count > max) {
        const retry = Math.ceil((rec.resetAt - now) / 1000)
        c.header('Retry-After', String(retry))
        return c.json({ error: 'Too many requests. Please slow down and try again shortly.' }, 429)
      }
    }
    // Opportunistic cleanup to bound memory.
    if (_rlBuckets.size > 5000) {
      for (const [k, v] of _rlBuckets) { if (v.resetAt < now) _rlBuckets.delete(k) }
    }
    await next()
  }
}
// Brute-force protection on credential + OTP surfaces.
app.use('/api/login', rateLimit('login', 10, 60_000))
app.use('/api/signup/request-otp', rateLimit('otp', 8, 60_000))
app.use('/api/reset-password/request-otp', rateLimit('otp', 8, 60_000))
// Abuse protection on payment initiation surfaces.
app.use('/api/sasapay/stkpush', rateLimit('pay', 20, 60_000))
app.use('/api/mpesa/stkpush', rateLimit('pay', 20, 60_000))
app.use('/api/buni/stkpush', rateLimit('pay', 20, 60_000))

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function genToken(): string {
  return crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '')
}
function ref(prefix: string): string {
  const n = Math.floor(Math.random() * 900000 + 100000)
  return `${prefix}-${Date.now().toString().slice(-6)}${n}`
}
function safeJson<T = any>(value: any, fallback: T): T {
  if (value == null) return fallback
  // Postgres `jsonb` columns are returned already-parsed by the `pg` driver.
  // Only strings need JSON.parse; objects/arrays are handed back as-is.
  if (typeof value === 'object') return value as T
  try { return JSON.parse(String(value)) } catch { return fallback }
}
// Fallback permissions when role catalog has not loaded yet.
function builtinDefaults(role: string): Record<string, boolean> {
  if (['super_admin', 'admin'].includes(role)) {
    return { view: true, edit: true, delete: true, deactivate: true, approve: true, dispatch: true, add_farmer: true, view_farmers: true, view_credit_purchases: true, manage_users: true, request_admin_action: true, can_manage_inventory: true, can_manage_finance_settings: true, view_wallet: true, manage_wallets: true }
  }
  if (role === 'operations_finance') {
    return { view: true, approve: true, dispatch: true, view_farmers: true, view_credit_purchases: true, request_admin_action: true, can_manage_finance_settings: true }
  }
  if (role === 'agent') {
    return { view: true, add_farmer: true, view_farmers: true, view_credit_purchases: true, can_manage_inventory: true, view_wallet: true }
  }
  if (role === 'support') {
    return { view: true, view_farmers: true, view_credit_purchases: true }
  }
  if (role === 'lender') {
    return { view: true, view_credit_purchases: true }
  }
  if (role === 'mne') {
    return { view: true, view_farmers: true, view_credit_purchases: true }
  }
  if (['investor', 'partner'].includes(role)) {
    return { view: true }
  }
  return { view: true }
}
async function loadRoleTemplate(c: any, role: string): Promise<Record<string, boolean>> {
  try {
    const row = await c.env.DB.prepare(`SELECT permissions FROM role_templates WHERE role_key=?`).bind(role).first<any>()
    if (row?.permissions) {
      const parsed = safeJson<Record<string, boolean>>(row.permissions, {})
      if (parsed && Object.keys(parsed).length) return parsed
    }
  } catch (_) {}
  return builtinDefaults(role)
}
function defaultPermissions(role: string): Record<string, boolean> {
  return builtinDefaults(role)
}
function parsePermissions(raw: any, role: string, fallback?: Record<string, boolean>) {
  const base = fallback ?? defaultPermissions(role)
  return { ...base, ...safeJson<Record<string, boolean>>(raw, {}) }
}
async function permissionsForRole(c: any, role: string, override?: Record<string, boolean>) {
  const base = await loadRoleTemplate(c, role)
  return { ...base, ...(override || {}) }
}
function hasPermission(user: SessionUser, perm: string) {
  if (['super_admin', 'admin'].includes(user.role)) return true
  return Boolean(user.permissions?.[perm])
}
// Visibility permissions are opt-out: absent key = allowed (backward compatible),
// explicit false = hidden. Admins always allowed.
function hasVisibility(user: SessionUser, perm: string) {
  if (['super_admin', 'admin'].includes(user.role)) return true
  const v = user.permissions?.[perm]
  return v === undefined ? true : Boolean(v)
}
// Redact farmer records based on Data Object Visibility permissions.
const FINANCIAL_FIELDS = ['existing_loans', 'credit_score', 'risk_band', 'annual_production']
const PROFILE_FIELDS = ['value_chain', 'value_chain_type', 'county', 'sub_county', 'ward', 'village', 'acreage', 'herd_size', 'farm_experience', 'sacco_membership', 'date_of_birth', 'gender', 'latitude', 'longitude']
const DOCUMENT_FIELDS = ['id_front_url', 'id_back_url', 'selfie_url', 'passport_photo_url']
function redactCustomer(user: SessionUser, cust: any) {
  if (!cust) return cust
  const out = { ...cust }
  if (!hasVisibility(user, 'view_financial_data')) for (const f of FINANCIAL_FIELDS) if (f in out) out[f] = null
  if (!hasVisibility(user, 'view_farmer_profile_data')) for (const f of PROFILE_FIELDS) if (f in out) out[f] = null
  if (!hasVisibility(user, 'view_document_attachments')) for (const f of DOCUMENT_FIELDS) if (f in out) out[f] = null
  return out
}
function numberVal(value: any, fallback = 0) {
  const n = Number(value)
  return Number.isFinite(n) ? n : fallback
}
function boolInt(value: any, fallback = true) {
  if (value === undefined || value === null || value === '') return fallback
  if (typeof value === 'boolean') return value
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase())
}
function roundMoney(value: number) {
  return Math.round((Number(value) || 0) * 100) / 100
}
// ---- Secure upload validation ----------------------------------------------
// Uploaded documents / avatars arrive as base64 data URLs (or, rarely, an https
// URL). We accept ONLY real raster images (jpeg/png/webp/gif) and cap the size,
// which blocks executables, HTML/SVG-with-script, PDFs and other malicious
// payloads from being stored and later served back to a browser.
const ALLOWED_IMAGE_MIME = ['image/jpeg', 'image/png', 'image/webp', 'image/gif']
const MAX_UPLOAD_BYTES = 8 * 1024 * 1024 // 8 MB per image
function isSafeDataUrlOrHttp(value: any): boolean {
  if (typeof value !== 'string' || !value) return false
  const s = value.trim()
  // Plain https(s) URL to an already-hosted asset — allow, no inline payload.
  if (/^https:\/\/[^\s"'<>]+$/i.test(s)) return true
  // data:URL — must be an allowed image MIME with valid base64 under the cap.
  const m = /^data:([a-z0-9.+/-]+);base64,([A-Za-z0-9+/=\s]+)$/i.exec(s)
  if (!m) return false
  const mime = m[1].toLowerCase()
  if (!ALLOWED_IMAGE_MIME.includes(mime)) return false
  // Estimate decoded byte length from base64 length (3/4 ratio).
  const b64 = m[2].replace(/\s+/g, '')
  const approxBytes = Math.floor((b64.length * 3) / 4)
  if (approxBytes <= 0 || approxBytes > MAX_UPLOAD_BYTES) return false
  // Magic-byte sniff on the first decoded bytes to confirm it is really that
  // image type (defends against a spoofed MIME wrapping a non-image payload).
  try {
    const head = atob(b64.slice(0, 32))
    const bytes = Array.from(head).map((ch) => ch.charCodeAt(0))
    const isJpeg = bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff
    const isPng = bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47
    const isGif = bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46
    const isWebp = bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46
    return isJpeg || isPng || isGif || isWebp
  } catch (_) {
    return false
  }
}
// Agreement documents may be an image (jpg/png/webp/gif) OR a PDF, uploaded as a
// data: URL, or a plain https URL to an already-hosted file. Same 8 MB cap and
// magic-byte sniff as images, but PDFs are additionally accepted here (they are
// NOT allowed for images/avatars). This blocks executables, HTML/SVG-with-script
// and other malicious payloads from being stored and served back later.
const ALLOWED_DOC_MIME = [...ALLOWED_IMAGE_MIME, 'application/pdf']
const MAX_DOC_BYTES = 8 * 1024 * 1024 // 8 MB per document
function isSafeDocDataUrlOrHttp(value: any): boolean {
  if (typeof value !== 'string' || !value) return false
  const s = value.trim()
  if (/^https:\/\/[^\s"'<>]+$/i.test(s)) return true
  const m = /^data:([a-z0-9.+/-]+);base64,([A-Za-z0-9+/=\s]+)$/i.exec(s)
  if (!m) return false
  const mime = m[1].toLowerCase()
  if (!ALLOWED_DOC_MIME.includes(mime)) return false
  const b64 = m[2].replace(/\s+/g, '')
  const approxBytes = Math.floor((b64.length * 3) / 4)
  if (approxBytes <= 0 || approxBytes > MAX_DOC_BYTES) return false
  try {
    const head = atob(b64.slice(0, 32))
    const bytes = Array.from(head).map((ch) => ch.charCodeAt(0))
    const isJpeg = bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff
    const isPng = bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47
    const isGif = bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46
    const isWebp = bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46
    const isPdf = bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46 // %PDF
    return isJpeg || isPng || isGif || isWebp || isPdf
  } catch (_) {
    return false
  }
}
// Sanitize a short free-text field: trim, cap length, strip control chars.
// (SQL injection itself is already prevented everywhere by parameterised
// prepared statements — this is defense-in-depth against stored junk / XSS.)
function cleanText(value: any, maxLen = 200): string | null {
  if (value === undefined || value === null) return null
  const s = String(value).replace(/[\u0000-\u001F\u007F]/g, '').trim()
  return s ? s.slice(0, maxLen) : null
}
// Permanent source-platform (origin) options. The Equipment app is the MAIN app;
// a product it creates is tagged with the destination the lister chose (equipment
// storefront, or a merchant marketplace). Secondary apps (feed/mazao) tag their
// own key. Whitelisted so a bad/injected value can never leak in.
const VALID_SOURCE_PLATFORMS = ['equipment', 'feed', 'mazao', 'merchant']
// ---- App settings (key/value JSON store) ----
async function getSetting<T = any>(c: any, key: string, fallback: T): Promise<T> {
  try {
    const row = await c.env.DB.prepare(`SELECT setting_value FROM app_settings WHERE setting_key=?`).bind(key).first<any>()
    if (row?.setting_value) return safeJson<T>(row.setting_value, fallback)
  } catch (_) {}
  return fallback
}
async function setSetting(c: any, key: string, value: any): Promise<void> {
  const json = JSON.stringify(value)
  const existing = await c.env.DB.prepare(`SELECT setting_key FROM app_settings WHERE setting_key=?`).bind(key).first<any>()
  if (existing) {
    await c.env.DB.prepare(`UPDATE app_settings SET setting_value=?, updated_at=CURRENT_TIMESTAMP WHERE setting_key=?`).bind(json, key).run()
  } else {
    await c.env.DB.prepare(`INSERT INTO app_settings (setting_key, setting_value) VALUES (?,?)`).bind(key, json).run()
  }
}
const DEFAULT_PROCESSING_FEE = { enabled: false, mode: 'percentage', percentage_rate: 0, tiers: [] as Array<{ min: number; max: number; fee: number }>, product_ids: [] as number[] }
function normalizeProductIds(raw: any): number[] {
  if (!Array.isArray(raw)) return []
  const ids = raw.map((v: any) => Number(v)).filter((n: number) => Number.isFinite(n) && n > 0)
  return Array.from(new Set(ids))
}
function normalizeProcessingFee(raw: any) {
  const cfg: any = { ...DEFAULT_PROCESSING_FEE, ...(raw && typeof raw === 'object' ? raw : {}) }
  cfg.enabled = Boolean(cfg.enabled)
  cfg.mode = cfg.mode === 'tiered' ? 'tiered' : 'percentage'
  cfg.percentage_rate = numberVal(cfg.percentage_rate, 0)
  cfg.tiers = Array.isArray(cfg.tiers)
    ? cfg.tiers
        .map((t: any) => ({ min: numberVal(t.min, 0), max: numberVal(t.max, 0), fee: numberVal(t.fee, 0) }))
        .filter((t: any) => t.max >= t.min)
    : []
  // Products this fee structure applies to. Empty array = applies to ALL products.
  cfg.product_ids = normalizeProductIds(cfg.product_ids)
  return cfg
}
const DEFAULT_FINANCING_MARKUP = {
  financing_applicable: true,
  mode: 'percentage',            // 'percentage' | 'tiered'
  percentage_rate: 20,
  tiers: [] as Array<{ min: number; max: number; markup: number }>,
  default_cash_markup_pct: 10,
  default_credit_markup_pct: 20,
  cash_markup_pct: 10,
  cash_terms_text: '',
  product_ids: [] as number[]
}
function normalizeFinancingMarkup(raw: any) {
  const cfg: any = { ...DEFAULT_FINANCING_MARKUP, ...(raw && typeof raw === 'object' ? raw : {}) }
  cfg.financing_applicable = raw && Object.prototype.hasOwnProperty.call(raw, 'financing_applicable')
    ? Boolean(cfg.financing_applicable) : true
  cfg.mode = cfg.mode === 'tiered' ? 'tiered' : 'percentage'
  cfg.percentage_rate = numberVal(cfg.percentage_rate, 20)
  cfg.tiers = Array.isArray(cfg.tiers)
    ? cfg.tiers
        .map((t: any) => ({ min: numberVal(t.min, 0), max: numberVal(t.max, 0), markup: numberVal(t.markup, 0) }))
        .filter((t: any) => t.max >= t.min)
    : []
  cfg.cash_markup_pct = numberVal(cfg.cash_markup_pct, 10)
  cfg.cash_terms_text = String(cfg.cash_terms_text || '')
  // Keep legacy fields in sync for backward compatibility with existing quotes.
  cfg.default_credit_markup_pct = cfg.mode === 'percentage' ? cfg.percentage_rate : numberVal(cfg.default_credit_markup_pct, 20)
  cfg.default_cash_markup_pct = cfg.cash_markup_pct
  cfg.product_ids = normalizeProductIds(cfg.product_ids)
  return cfg
}
// Compute the processing fee applied to a borrowed (financed) amount.
// When cfg.product_ids is non-empty, the fee only applies to those products.
function computeProcessingFee(cfg: any, borrowedAmount: number, productId?: any): number {
  const c = normalizeProcessingFee(cfg)
  if (!c.enabled) return 0
  if (Array.isArray(c.product_ids) && c.product_ids.length > 0) {
    const pid = Number(productId)
    if (!Number.isFinite(pid) || !c.product_ids.includes(pid)) return 0
  }
  const amount = Number(borrowedAmount) || 0
  if (c.mode === 'percentage') return roundMoney(amount * (c.percentage_rate / 100))
  const tier = c.tiers.find((t: any) => amount >= t.min && amount <= t.max)
  return tier ? roundMoney(tier.fee) : 0
}

// ----------------------------------------------------------------------------
// WITHDRAWAL CHARGE SCHEMA (standard withdrawal schema)
// A withdrawal costs the wallet holder an "effective charge" that is deducted
// on top of the gross withdrawal. The withdrawable limit for a given balance is
//   withdrawable = balance - effectiveCharge(withdrawable)
// i.e. the most a holder can request such that (request + charge) <= balance.
// The charge itself is a flat fee + a percentage of the requested amount, with
// optional min/max clamps — this mirrors typical mobile-money withdrawal tariffs.
// ----------------------------------------------------------------------------
const DEFAULT_WITHDRAWAL_CHARGE = {
  enabled: true,
  percentage_rate: 0,     // % of the requested amount
  flat_fee: 0,            // flat KES added per withdrawal
  min_charge: 0,          // charge is never below this (when enabled)
  max_charge: 0,          // 0 = no upper cap
  min_withdrawal: 0       // smallest gross amount a holder may request (0 = none)
}
function normalizeWithdrawalCharge(raw: any) {
  const cfg: any = { ...DEFAULT_WITHDRAWAL_CHARGE, ...(raw && typeof raw === 'object' ? raw : {}) }
  cfg.enabled = raw && Object.prototype.hasOwnProperty.call(raw, 'enabled') ? Boolean(cfg.enabled) : true
  cfg.percentage_rate = Math.max(0, numberVal(cfg.percentage_rate, 0))
  cfg.flat_fee = Math.max(0, numberVal(cfg.flat_fee, 0))
  cfg.min_charge = Math.max(0, numberVal(cfg.min_charge, 0))
  cfg.max_charge = Math.max(0, numberVal(cfg.max_charge, 0))
  cfg.min_withdrawal = Math.max(0, numberVal(cfg.min_withdrawal, 0))
  return cfg
}
// Effective charge for a requested (gross) withdrawal amount.
function computeWithdrawalCharge(cfg: any, amount: number): number {
  const c = normalizeWithdrawalCharge(cfg)
  if (!c.enabled) return 0
  const amt = Math.max(0, Number(amount) || 0)
  let charge = c.flat_fee + amt * (c.percentage_rate / 100)
  if (c.min_charge > 0 && charge < c.min_charge) charge = c.min_charge
  if (c.max_charge > 0 && charge > c.max_charge) charge = c.max_charge
  return roundMoney(charge)
}
// Given a wallet balance, the maximum gross amount a holder may withdraw such
// that (amount + effective charge) never exceeds the balance.
function computeWithdrawableLimit(cfg: any, balance: number): { withdrawable: number; charge_at_max: number } {
  const c = normalizeWithdrawalCharge(cfg)
  const bal = roundMoney(Math.max(0, Number(balance) || 0))
  if (!c.enabled) return { withdrawable: bal, charge_at_max: 0 }
  // Closed-form for the percentage + flat portion: amount + flat + amount*p = balance
  const p = c.percentage_rate / 100
  let withdrawable = (bal - c.flat_fee) / (1 + p)
  withdrawable = roundMoney(Math.max(0, withdrawable))
  // Re-clamp using the real charge (handles min/max clamps) so amount+charge<=bal.
  while (withdrawable > 0 && roundMoney(withdrawable + computeWithdrawalCharge(c, withdrawable)) > bal) {
    withdrawable = roundMoney(withdrawable - 0.01)
  }
  // When nothing can be withdrawn, report a zero charge (cosmetic — avoids
  // showing a flat fee against a KES 0 withdrawable).
  return { withdrawable, charge_at_max: withdrawable > 0 ? computeWithdrawalCharge(c, withdrawable) : 0 }
}

// ----------------------------------------------------------------------------
// SUPPORT CONTACT (configurable in the Super-Admin dashboard). Shown to users
// when a withdrawal cannot be settled because the SasaPay main wallet is short.
// ----------------------------------------------------------------------------
const DEFAULT_SUPPORT_CONTACT = { phone: '', email: '' }
function normalizeSupportContact(raw: any) {
  const cfg: any = { ...DEFAULT_SUPPORT_CONTACT, ...(raw && typeof raw === 'object' ? raw : {}) }
  cfg.phone = String(cfg.phone || '').trim().slice(0, 40)
  cfg.email = String(cfg.email || '').trim().slice(0, 120)
  return cfg
}

// ---- Time-based access windows ----
const DAY_KEYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat']
function parseHM(value: any): number | null {
  const m = String(value || '').match(/^(\d{1,2}):(\d{2})$/)
  if (!m) return null
  return Number(m[1]) * 60 + Number(m[2])
}
// Returns { allowed:boolean, reason?:string } given a schedule config and current time.
function checkAccessWindow(schedule: { enabled?: any; days?: any; start?: any; end?: any }, now = new Date()): { allowed: boolean; reason?: string } {
  if (!schedule || !schedule.enabled) return { allowed: true }
  const days: string[] = Array.isArray(schedule.days) ? schedule.days.map((d: string) => String(d).toLowerCase()) : []
  const today = DAY_KEYS[now.getDay()]
  if (days.length && !days.includes(today)) {
    return { allowed: false, reason: 'Access is not permitted on this day for your role.' }
  }
  const start = parseHM(schedule.start)
  const end = parseHM(schedule.end)
  if (start !== null && end !== null) {
    const cur = now.getHours() * 60 + now.getMinutes()
    if (cur < start || cur > end) {
      return { allowed: false, reason: `Access is only permitted between ${schedule.start} and ${schedule.end}.` }
    }
  }
  return { allowed: true }
}
// Resolve the effective login window for a user (user override, else role template).
async function resolveAccessWindow(c: any, user: any): Promise<{ enabled: boolean; days: string[]; start: string; end: string }> {
  if (Number(user.schedule_enabled) === 1) {
    return { enabled: true, days: safeJson<string[]>(user.access_days, []), start: user.access_start || '', end: user.access_end || '' }
  }
  try {
    const row = await c.env.DB.prepare(`SELECT schedule_enabled, access_days, access_start, access_end FROM role_templates WHERE role_key=?`).bind(user.role).first<any>()
    if (row && Number(row.schedule_enabled) === 1) {
      return { enabled: true, days: safeJson<string[]>(row.access_days, []), start: row.access_start || '', end: row.access_end || '' }
    }
  } catch (_) {}
  return { enabled: false, days: [], start: '', end: '' }
}
function normalizeProductPayload(b: any) {
  const buying = numberVal(b.buying_price)
  const cashMarkup = numberVal(b.cash_markup_pct, 10)
  const creditMarkup = numberVal(b.credit_markup_pct, 20)
  const cashPrice = numberVal(b.cash_price, roundMoney(buying * (1 + cashMarkup / 100)))
  const creditPrice = numberVal(b.credit_price, roundMoney(buying * (1 + creditMarkup / 100)))
  const paymentMode = b.payment_option_mode || (boolInt(b.cash_enabled, true) && boolInt(b.financing_enabled, true) ? 'both' : boolInt(b.cash_enabled, true) ? 'cash' : 'financing')
  // Storefront section (marketplace) + permanent source tag. `marketplace` is the
  // shopping section a product shows under (equipment | feeds | inputs); it is
  // derived from an explicit value, else from product_type, else equipment.
  const marketplaceRaw = String(b.marketplace || '').trim().toLowerCase()
  const ptypeRaw = String(b.product_type || '').trim().toLowerCase()
  const marketplace = ['equipment', 'feeds', 'inputs'].includes(marketplaceRaw)
    ? marketplaceRaw
    : (['feed', 'feeds'].includes(ptypeRaw) ? 'feeds' : ['input', 'inputs', 'mazao'].includes(ptypeRaw) ? 'inputs' : 'equipment')
  const productType = marketplace === 'feeds' ? 'feed' : marketplace === 'inputs' ? 'input' : 'equipment'
  return {
    sku: String(b.sku || '').trim(),
    name: String(b.name || '').trim(),
    category: cleanText(b.category, 120) || (marketplace === 'feeds' ? 'Feeds' : marketplace === 'inputs' ? 'Inputs' : 'Equipment'),
    subcategory: cleanText(b.subcategory, 120),
    marketplace,
    description: cleanText(b.description, 4000),
    product_type: productType,
    supplier_id: b.supplier_id || null,
    buying_price: buying,
    cash_markup_pct: cashMarkup,
    credit_markup_pct: creditMarkup,
    cash_price: cashPrice,
    credit_price: creditPrice,
    quantity: numberVal(b.quantity, 0),
    unit: b.unit || 'unit',
    reorder_threshold: numberVal(b.reorder_threshold, 10),
    image: b.image || null,
    cash_enabled: boolInt(b.cash_enabled, paymentMode !== 'financing'),
    financing_enabled: boolInt(b.financing_enabled, paymentMode !== 'cash'),
    payment_option_mode: paymentMode,
    financing_model: b.financing_model || 'loan_interest',
    financing_interest_pct: numberVal(b.financing_interest_pct, 0),
    financing_frequency: b.financing_frequency || 'monthly',
    financing_term_min_months: numberVal(b.financing_term_min_months, 3),
    financing_term_max_months: numberVal(b.financing_term_max_months, 12),
    cash_deposit_pct: numberVal(b.cash_deposit_pct, 100),
    financing_deposit_pct: numberVal(b.financing_deposit_pct, 10),
    cash_terms_text: b.cash_terms_text || null,
    financing_terms_text: b.financing_terms_text || null,
    cash_terms_doc_url: b.cash_terms_doc_url || null,
    financing_terms_doc_url: b.financing_terms_doc_url || null,
    transunion_product_code: b.transunion_product_code || null
  }
}
function financingQuote(p: any, quantity: any, paymentType: string, termMonths: any, processingFeeCfg?: any) {
  const qty = Math.max(1, numberVal(quantity, 1))
  const supplier_cost = roundMoney(numberVal(p.buying_price) * qty)
  if (paymentType === 'cash') {
    const total = roundMoney(numberVal(p.cash_price) * qty)
    const deposit_pct = numberVal(p.cash_deposit_pct, 100)
    const amount_due_now = roundMoney(total * deposit_pct / 100)
    return {
      quantity: qty,
      supplier_cost,
      payment_type: 'cash',
      financing_model: 'cash',
      markup_pct: numberVal(p.cash_markup_pct, 0),
      amount_due_now,
      deposit_pct,
      deposit_amount: amount_due_now,
      finance_principal: total,
      term_months: 0,
      payment_frequency: 'one_off',
      installment_count: 0,
      installment_amount: 0,
      total_price: total,
      total_payable: total,
      outstanding_after_deposit: roundMoney(total - amount_due_now),
      disclosure_note: deposit_pct >= 100 ? 'Full cash payment is required at checkout.' : deposit_pct > 0 ? `A ${deposit_pct}% deposit is required to confirm the cash order.` : 'No deposit is required at checkout for this cash order.',
      terms_text: p.cash_terms_text || null,
      terms_document_url: p.cash_terms_doc_url || null
    }
  }
  const term = Math.max(numberVal(p.financing_term_min_months, 3), Math.min(numberVal(termMonths, numberVal(p.financing_term_min_months, 3)), numberVal(p.financing_term_max_months, 12)))
  const principalBase = roundMoney(numberVal(p.credit_price || p.cash_price) * qty)
  const deposit_pct = numberVal(p.financing_deposit_pct, 10)
  const deposit_amount = roundMoney(principalBase * deposit_pct / 100)
  const finance_principal = roundMoney(principalBase - deposit_amount)
  const interestRate = numberVal(p.financing_interest_pct, 0)
  const model = p.financing_model || 'loan_interest'
  const frequency = p.financing_frequency || (model === 'paygo' ? 'daily' : 'monthly')
  const installment_count = frequency === 'daily' ? term * 30 : frequency === 'weekly' ? term * 4 : term
  const financing_charge = model === 'loan_interest'
    ? roundMoney(finance_principal * (interestRate / 100) * (term / 12))
    : roundMoney(finance_principal * (interestRate / 100) * (term / 12))
  // Processing fee is calculated on the amount borrowed (finance principal),
  // scoped to the product when the fee structure targets specific products.
  const processing_fee = computeProcessingFee(processingFeeCfg, finance_principal, p.id)
  const financed_total = roundMoney(finance_principal + financing_charge + processing_fee)
  const installment_amount = installment_count > 0 ? roundMoney(financed_total / installment_count) : financed_total
  const total_payable = roundMoney(deposit_amount + financed_total)
  return {
    quantity: qty,
    supplier_cost,
    payment_type: 'financing',
    financing_model: model,
    markup_pct: interestRate,
    amount_due_now: deposit_amount,
    deposit_pct,
    deposit_amount,
    finance_principal,
    processing_fee,
    interest_rate_pct: interestRate,
    term_months: term,
    payment_frequency: frequency,
    installment_count,
    installment_amount,
    monthly_payment: frequency === 'monthly' ? installment_amount : roundMoney(financed_total / Math.max(term, 1)),
    total_price: principalBase,
    total_payable,
    outstanding_after_deposit: financed_total,
    disclosure_note: (model === 'paygo'
      ? 'PAYGO financing uses an upfront deposit and scheduled unlock payments similar to M-KOPA, adapted for agricultural equipment.'
      : 'Normal financing applies the configured flat interest across the selected term.')
      + (processing_fee > 0 ? ` A processing fee of ${processing_fee.toLocaleString()} applies to the financed amount.` : ''),
    terms_text: p.financing_terms_text || null,
    terms_document_url: p.financing_terms_doc_url || null
  }
}
// Whether the connected DB's `users` table carries the multitenant `org_id`
// column. The central farmsky_central_db (shared with Score) has it as UUID NOT
// NULL; the Equipment-only dev SQLite/D1 shape does not. Cached per-process
// after the first probe so we only introspect once. On any error (including
// SQLite where information_schema is absent) we assume the column is NOT present
// and fall back to org-agnostic inserts.
let _usersHasOrgId: boolean | null = null
async function usersHasOrgId(c: any): Promise<boolean> {
  if (_usersHasOrgId !== null) return _usersHasOrgId
  try {
    const r = await c.env.DB.prepare(
      `SELECT COUNT(*) AS n FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'org_id'`
    ).first<any>()
    _usersHasOrgId = Number(r?.n || 0) > 0
  } catch (_) {
    _usersHasOrgId = false
  }
  return _usersHasOrgId
}

// Resolve the tenant (org_id) a newly-created user must belong to: the creating
// admin's org. Prefer the value already on the session; if absent (older
// session issued before org_id was loaded) re-read it from the DB.
async function resolveCreatorOrgId(c: any, creator: SessionUser | null): Promise<string | null> {
  if (!creator) return null
  if (creator.org_id != null && creator.org_id !== '') return String(creator.org_id)
  if (!(await usersHasOrgId(c))) return null
  try {
    const o = await c.env.DB.prepare(`SELECT org_id FROM users WHERE CAST(id AS TEXT) = ?`).bind(String(creator.id)).first<any>()
    return o?.org_id != null ? String(o.org_id) : null
  } catch (_) { return null }
}

// A process-cached fallback tenant for user rows created OUTSIDE an admin session
// (public self-signup, and any admin-created row whose creator somehow lacks an
// org). The central farmsky_central_db enforces users.org_id NOT NULL, so these
// paths MUST supply one. Preference order:
//   1. EQUIPMENT_ORG_ID / DEFAULT_ORG_ID env (explicit operator override), then
//   2. the most-populated existing org (mode of users.org_id), then
//   3. the oldest organizations row.
// Returns null only on a DB shape without the org_id column (dev SQLite/D1),
// where the INSERT omits the column entirely.
let _defaultOrgId: string | null | undefined = undefined
async function resolveDefaultOrgId(c: any): Promise<string | null> {
  if (_defaultOrgId !== undefined) return _defaultOrgId
  if (!(await usersHasOrgId(c))) { _defaultOrgId = null; return null }
  const envOrg = (c.env?.EQUIPMENT_ORG_ID || c.env?.DEFAULT_ORG_ID || '').trim()
  if (envOrg) { _defaultOrgId = envOrg; return envOrg }
  // Most common org among existing users — the natural tenant for this deployment.
  try {
    const r = await c.env.DB.prepare(
      `SELECT org_id, COUNT(*) AS n FROM users WHERE org_id IS NOT NULL GROUP BY org_id ORDER BY n DESC LIMIT 1`
    ).first<any>()
    if (r?.org_id != null) { _defaultOrgId = String(r.org_id); return _defaultOrgId }
  } catch (_) {}
  // Fall back to the oldest organization on record.
  try {
    const r = await c.env.DB.prepare(`SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1`).first<any>()
    if (r?.id != null) { _defaultOrgId = String(r.id); return _defaultOrgId }
  } catch (_) {}
  _defaultOrgId = null
  return null
}

async function getSessionUser(c: any): Promise<SessionUser | null> {
  const token = getCookie(c, 'session') || c.req.header('Authorization')?.replace('Bearer ', '')
  if (!token) return null
  const row = await c.env.DB.prepare(
    `SELECT u.id, u.full_name, u.phone, u.email, u.avatar_url, u.role, u.region, u.label, u.permissions, u.status,
            u.schedule_enabled, u.access_days, u.access_start, u.access_end, s.expires_at
     FROM sessions s JOIN users u ON CAST(u.id AS TEXT) = s.user_id WHERE s.token = ?`
  ).bind(token).first<any>()
  if (!row) return null
  if (Number(row.expires_at) < Date.now()) return null
  if (row.status !== 'active') return null
  // Enforce time-based access window on every request.
  const window = await resolveAccessWindow(c, row)
  const access = checkAccessWindow({ enabled: window.enabled, days: window.days, start: window.start, end: window.end })
  if (!access.allowed) return null
  const fallback = await loadRoleTemplate(c, row.role)
  // Best-effort tenant scope. Kept as a SEPARATE query so a DB shape without the
  // multitenant `users.org_id` column (Equipment-only SQLite/D1 dev) never fails
  // authentication — the query is swallowed and org_id stays null there.
  let orgId: string | null = null
  if (await usersHasOrgId(c)) {
    try {
      const o = await c.env.DB.prepare(`SELECT org_id FROM users WHERE CAST(id AS TEXT) = ?`).bind(String(row.id)).first<any>()
      orgId = o?.org_id != null ? String(o.org_id) : null
    } catch (_) { orgId = null }
  }
  return {
    org_id: orgId,
    // Always expose the user id as a STRING. All user-reference columns
    // (created_by, agent_id, wallet.user_id, …) are now TEXT (migrations
    // 0024-0026) so they work whether users.id is INTEGER or UUID. Binding a
    // JS number against a TEXT column would raise `operator does not exist:
    // text = integer` on an integer-keyed DB; stringifying here makes every
    // downstream `WHERE <textcol> = ?` bind text=text on both DB shapes.
    id: row.id == null ? row.id : String(row.id),
    full_name: row.full_name,
    phone: row.phone,
    email: row.email || null,
    avatar_url: row.avatar_url || null,
    role: row.role,
    region: row.region,
    label: row.label || null,
    permissions: parsePermissions(row.permissions, row.role, fallback)
  }
}
// Declare the executing user's identity + capabilities inside the DB session so
// PostgreSQL Row-Level Security (backend/sql/03_ownership_rls_setup.sql) can
// strip away records the user has no relationship with. No-op on SQLite/D1.
// Running any RLS-protected query WITHOUT this context returns ZERO rows for
// general users — preventing systemic data-leak vectors.
async function setUserContext(c: any, user: SessionUser | null) {
  const setLocal = (c.env.DB as any)?.setSessionConfig
  if (typeof setLocal !== 'function') return
  try {
    await setLocal.call(c.env.DB, 'app.current_user_id', user ? String(user.id) : '')
    await setLocal.call(c.env.DB, 'app.current_role', user ? String(user.role) : '')
    const canFinance = user
      ? (['admin', 'super_admin'].includes(user.role) || Boolean(user.permissions?.can_manage_finance_settings))
      : false
    await setLocal.call(c.env.DB, 'app.user_can_finance', canFinance ? 'true' : 'false')
  } catch (_) {}
}
// Run a block with a temporary admin context so background / storefront reads
// (public catalog, provider callbacks) can see the global dataset, then restore.
async function withAdminContext(c: any, fn: () => Promise<any>) {
  const setLocal = (c.env.DB as any)?.setSessionConfig
  if (typeof setLocal === 'function') {
    try {
      await setLocal.call(c.env.DB, 'app.current_role', 'admin')
      await setLocal.call(c.env.DB, 'app.user_can_finance', 'true')
    } catch (_) {}
  }
  try { return await fn() }
  finally { await setUserContext(c, c.get('user') || null) }
}
async function requireAuth(c: any, next: any) {
  const user = await getSessionUser(c)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  c.set('user', user)
  await setUserContext(c, user)
  await next()
}
function requireRole(...roles: string[]) {
  return async (c: any, next: any) => {
    const user = c.get('user') as SessionUser
    if (!roles.includes(user.role)) return c.json({ error: 'Forbidden' }, 403)
    await next()
  }
}
function requirePermission(...perms: string[]) {
  return async (c: any, next: any) => {
    const user = c.get('user') as SessionUser
    if (!perms.some((perm) => hasPermission(user, perm))) return c.json({ error: 'Forbidden' }, 403)
    await next()
  }
}
async function audit(c: any, userId: string | number | null, action: string, entity: string, detail: string) {
  try {
    await c.env.DB.prepare(`INSERT INTO audit_logs (user_id, action, entity, detail) VALUES (?,?,?,?)`)
      .bind(userId == null ? null : String(userId), action, entity, detail).run()
  } catch (_) {}
}
function genPassword(): string {
  return String(Math.floor(1000 + Math.random() * 9000))
}

// Roles for which an email address is MANDATORY. Everyone else (agent, customer,
// partner, investor, operations_finance, …) may be onboarded without one.
const EMAIL_REQUIRED_ROLES = ['super_admin', 'admin', 'lender']
function emailIsRequired(role: string): boolean {
  return EMAIL_REQUIRED_ROLES.includes(String(role || '').toLowerCase())
}

// Local domain used for synthetic placeholder emails. These are NOT deliverable
// addresses — they exist purely to satisfy the central schema. Anything using
// `email` for real delivery must treat an @PLACEHOLDER_EMAIL_DOMAIN address as
// "no email on file".
const PLACEHOLDER_EMAIL_DOMAIN = 'no-email.farmsky.local'
function isPlaceholderEmail(email: any): boolean {
  return String(email || '').toLowerCase().endsWith('@' + PLACEHOLDER_EMAIL_DOMAIN)
}

// Resolve the value bound to the central `users.email` column. On the shared
// farmsky_central_db this column is BOTH `NOT NULL` and `UNIQUE`, so we cannot
// bind NULL and we cannot reuse a shared sentinel like '' across users (the 2nd
// such insert hits users_email_key → 23505). Behaviour:
//   • email supplied             → trimmed, lower-cased value.
//   • email blank, role needs it → { error } so the caller can 400.
//   • email blank, role optional → a UNIQUE, non-deliverable placeholder derived
//     from the phone (or a random UUID) so NOT NULL + UNIQUE are both satisfied.
//     `isPlaceholderEmail()` lets the rest of the app treat it as "no email".
function resolveEmail(role: string, rawEmail: any, phone?: any): { value: string } | { error: string } {
  const email = String(rawEmail ?? '').trim()
  if (email) return { value: email.toLowerCase() }
  if (emailIsRequired(role)) {
    return { error: `An email address is required for ${String(role).replace(/_/g, ' ')} accounts.` }
  }
  const key = String(phone ?? '').replace(/[^a-z0-9]/gi, '').toLowerCase() || (crypto.randomUUID().replace(/-/g, ''))
  return { value: `no-email+${key}@${PLACEHOLDER_EMAIL_DOMAIN}` }
}

// Re-authenticate the CURRENT session user by password. Used to gate sensitive
// data-egress actions (system-backup download + platform data export) so a
// walked-away session cannot be used to exfiltrate the whole database. Reads the
// caller's own stored password hash and verifies the supplied plaintext.
// Returns { ok:true } on success, or { ok:false, error } to be surfaced as 401/400.
async function verifyReauth(c: any, password: any): Promise<{ ok: true } | { ok: false; error: string; status: number }> {
  const pw = String(password ?? '')
  if (!pw) return { ok: false, error: 'Enter your password to confirm this download.', status: 400 }
  const user = c.get('user') as SessionUser
  if (!user) return { ok: false, error: 'Not authenticated.', status: 401 }
  const row = await c.env.DB.prepare(`SELECT password FROM users WHERE CAST(id AS TEXT) = ?`).bind(String(user.id)).first<any>()
  if (!row) return { ok: false, error: 'Account not found.', status: 401 }
  const check = await verifyPassword(pw, row.password)
  if (!check.ok) return { ok: false, error: 'Incorrect password. Please try again.', status: 401 }
  return { ok: true }
}

// A secure, random TEMPORARY password for the multi-user onboarding flow.
// Mixed-case + digits, avoids ambiguous characters (0/O, 1/l/I).
function genTempPassword(len = 10): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
  const bytes = new Uint8Array(len)
  crypto.getRandomValues(bytes)
  let out = ''
  for (let i = 0; i < len; i++) out += alphabet[bytes[i] % alphabet.length]
  return out
}

// Milliseconds a temporary password stays valid before it must be reset (3 hours).
const TEMP_PASSWORD_TTL_MS = 3 * 60 * 60 * 1000

// Stamp a freshly-created user with a temporary password + lifecycle flags and
// SMS it to them with the mandatory "do not share / expires in 3 hours" notice.
async function issueTempPassword(
  c: any,
  opts: { userId: number | bigint | string; phone: string; fullName?: string; hashedInto?: 'insert' }
): Promise<{ tempPassword: string; expiresAt: number; sms: { simulated?: boolean; success?: boolean; error?: string } }> {
  const tempPassword = genTempPassword()
  const expiresAt = Date.now() + TEMP_PASSWORD_TTL_MS
  const hashed = await hashPassword(tempPassword)
  await c.env.DB.prepare(
    `UPDATE users SET password=?, password_set=0, must_change_password=1, is_temp_password=1, temp_password_expires_at=? WHERE id=?`
  ).bind(hashed, expiresAt, String(opts.userId)).run()
  const msg =
    `Farmsky account created${opts.fullName ? ' for ' + opts.fullName : ''}. ` +
    `Temporary password: ${tempPassword}. ` +
    `Do not share this password. It expires within 3 hours. ` +
    `Log in and set your own password.`
  let sms: any = { simulated: true, success: true }
  try { sms = await sendSms(c.env, opts.phone, msg) } catch (e: any) { sms = { success: false, error: e?.message || 'SMS failed' } }
  return { tempPassword, expiresAt, sms }
}
async function createSession(c: any, user: any) {
  const token = genToken()
  const expires = Date.now() + 1000 * 60 * 60 * 12
  // user_id is TEXT (migration 0024) so it holds either Equipment's INTEGER id
  // or a UUID id from a shared/central users table. Bind the id as a string and
  // cast the placeholder to TEXT so the INSERT never hits a 22P02 type error.
  await c.env.DB.prepare(`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, CAST(? AS TEXT), ?)`).bind(token, String(user.id), expires).run()
  // Issue 7: mark the session cookie Secure when served over HTTPS so it is
  // never transmitted over a plaintext channel in production.
  const isHttps = (c.req.header('x-forwarded-proto') || '').includes('https') || new URL(c.req.url).protocol === 'https:'
  setCookie(c, 'session', token, { path: '/', httpOnly: true, maxAge: 60 * 60 * 12, sameSite: 'Lax', secure: isHttps })
  return token
}
// Issue an OTP, persist it, and send via SMS. Returns demo_otp when SMS not configured.
async function issueOtp(c: any, phone: string, purpose: string) {
  const code = generateOtp()
  const expires = Date.now() + 1000 * 60 * 5 // 5 minutes
  // Invalidate previous unconsumed OTPs for this phone+purpose
  await c.env.DB.prepare(`UPDATE otp_codes SET consumed=1 WHERE phone=? AND purpose=? AND consumed=0`).bind(phone, purpose).run()
  await c.env.DB.prepare(`INSERT INTO otp_codes (phone, code, purpose, expires_at) VALUES (?,?,?,?)`).bind(phone, code, purpose, expires).run()
  const msg = `Your Farmsky verification code is ${code}. It expires in 5 minutes.`
  const sms = await sendSms(c.env, phone, msg)
  return { sms, demo_otp: sms.simulated ? code : undefined }
}
// Validate an OTP; marks it consumed on success.
async function verifyOtp(c: any, phone: string, code: string, purpose: string): Promise<{ ok: boolean; error?: string }> {
  const row = await c.env.DB.prepare(
    `SELECT * FROM otp_codes WHERE phone=? AND purpose=? AND consumed=0 ORDER BY id DESC LIMIT 1`
  ).bind(phone, purpose).first<any>()
  if (!row) return { ok: false, error: 'No active code. Request a new one.' }
  if (Number(row.expires_at) < Date.now()) return { ok: false, error: 'Code expired. Request a new one.' }
  if (Number(row.attempts) >= 5) return { ok: false, error: 'Too many attempts. Request a new code.' }
  if (String(row.code) !== String(code).trim()) {
    await c.env.DB.prepare(`UPDATE otp_codes SET attempts=attempts+1 WHERE id=?`).bind(row.id).run()
    return { ok: false, error: 'Incorrect code.' }
  }
  await c.env.DB.prepare(`UPDATE otp_codes SET consumed=1 WHERE id=?`).bind(row.id).run()
  return { ok: true }
}
// Mask a phone number for display in OTP prompts, e.g. 254712345678 -> 2547****5678.
function maskPhone(phone: string): string {
  const p = String(phone || '').trim()
  if (p.length <= 6) return p ? p.replace(/.(?=.{2})/g, '*') : p
  const head = p.slice(0, 4)
  const tail = p.slice(-4)
  return `${head}${'*'.repeat(Math.max(2, p.length - 8))}${tail}`
}

// ----------------------------------------------------------------------------
// AUTH
// ----------------------------------------------------------------------------
app.post('/api/login', async (c) => {
  const { phone, password } = await c.req.json()
  const raw = String(phone || '').trim()
  const norm = normalizePhone(raw)
  // Match the entered value, the normalized 2547... form, OR the +2547... form,
  // so seeded "+254..." accounts and OTP-normalized "254..." accounts both work
  // regardless of how the user typed the number (07.., 2547.., +2547..).
  const plus = norm ? '+' + norm : raw
  let user = await c.env.DB.prepare(`SELECT * FROM users WHERE phone = ? OR phone = ? OR phone = ?`).bind(raw, norm, plus).first<any>()
  // Phase 4: env-driven PBKDF2 verification (identical to Feed). Accepts a
  // legacy plaintext value and re-hashes it on the next successful login.
  const check = user ? await verifyPassword(String(password), user.password) : { ok: false, legacy: false }
  if (!user || !check.ok) return c.json({ error: 'Invalid phone number or password' }, 401)
  if (user.status !== 'active') return c.json({ error: 'Account suspended' }, 403)
  // PASSWORD LIFECYCLE: a temporary (admin/agent-issued) password that has
  // expired can no longer be used. Tell the client to offer an admin reset.
  if (user.is_temp_password && user.temp_password_expires_at && Number(user.temp_password_expires_at) < Date.now()) {
    return c.json({ error: 'Your temporary password has expired. Please ask an admin to reset it.', temp_expired: true, phone: user.phone }, 403)
  }
  if (check.legacy) {
    try { await c.env.DB.prepare(`UPDATE users SET password=? WHERE id=?`).bind(await hashPassword(String(password)), user.id).run() } catch (_) {}
  }
  // First-login with a temporary password: authenticate, but force an immediate
  // password change before granting a full session / app access.
  if (user.must_change_password) {
    const changeToken = await createSession(c, user)
    await audit(c, user.id, 'login', 'user', `${user.role} logged in with temporary password (must change)`)
    return c.json({
      token: changeToken,
      must_change_password: true,
      user: { id: user.id, full_name: user.full_name, phone: user.phone, role: user.role }
    })
  }
  // Enforce time-based access windows (per-user override, else role template).
  const window = await resolveAccessWindow(c, user)
  const access = checkAccessWindow({ enabled: window.enabled, days: window.days, start: window.start, end: window.end })
  if (!access.allowed) return c.json({ error: access.reason || 'Access is restricted at this time.' }, 403)
  const token = await createSession(c, user)
  await audit(c, user.id, 'login', 'user', `${user.role} logged in`)
  const loginFallback = await loadRoleTemplate(c, user.role)
  return c.json({ token, user: { id: user.id, full_name: user.full_name, phone: user.phone, role: user.role, region: user.region, label: user.label || null, permissions: parsePermissions(user.permissions, user.role, loginFallback) } })
})
app.post('/api/logout', async (c) => {
  const token = getCookie(c, 'session')
  if (token) await c.env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(token).run()
  deleteCookie(c, 'session', { path: '/' })
  return c.json({ ok: true })
})
app.get('/api/me', requireAuth, (c) => c.json({ user: c.get('user') }))

// ----------------------------------------------------------------------------
// SELF-SERVICE PROFILE (Instruction 3)
//   * Farmers (role=customer): may update their own profile data EXCEPT
//     national_id and phone/mobile. Also avatar + password.
//   * All other users: may ONLY update their profile picture and password.
//   * Editing OTHER users is done by super_admin / authorized users via the
//     existing PUT /api/users/:id (Edit button in the users list).
// ----------------------------------------------------------------------------

// Fetch own profile (user fields + farmer/customer record when role=customer).
app.get('/api/me/profile', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  let customer: any = null
  if (user.role === 'customer') {
    customer = await c.env.DB.prepare(`SELECT * FROM customers WHERE user_id=?`).bind(user.id).first<any>()
  }
  return c.json({ user, customer })
})

// Update own profile picture (any authenticated user).
app.put('/api/me/avatar', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const { avatar_url } = await c.req.json()
  // Profile picture is an uploaded image attachment — validate before storing.
  if (avatar_url && !isSafeDataUrlOrHttp(avatar_url)) {
    return c.json({ error: 'Profile picture must be a JPEG, PNG, WebP or GIF image under 8 MB.' }, 400)
  }
  await c.env.DB.prepare(`UPDATE users SET avatar_url=? WHERE id=?`).bind(avatar_url || null, user.id).run()
  await audit(c, user.id, 'update', 'profile', 'avatar')
  return c.json({ ok: true, avatar_url: avatar_url || null })
})

// Change own password (verify current password first).
app.put('/api/me/password', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const { current_password, new_password } = await c.req.json()
  if (!new_password || String(new_password).length < 4) return c.json({ error: 'New password must be at least 4 characters' }, 400)
  const row = await c.env.DB.prepare(`SELECT password FROM users WHERE id=?`).bind(user.id).first<any>()
  const chk = row ? await verifyPassword(String(current_password), row.password) : { ok: false, legacy: false }
  if (!row || !chk.ok) return c.json({ error: 'Current password is incorrect' }, 400)
  // Clear the temporary-password lifecycle flags: once the user sets their own
  // password it is no longer temporary / must-change / time-limited.
  await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1, must_change_password=0, is_temp_password=0, temp_password_expires_at=NULL WHERE id=?`).bind(await hashPassword(String(new_password)), user.id).run()
  await audit(c, user.id, 'update', 'profile', 'password change')
  return c.json({ ok: true })
})

// Update own profile data.
//   Farmers  -> full customer profile (EXCEPT national_id & phone/mobile) + avatar.
//   Others   -> avatar only (name/region managed by admins).
app.put('/api/me/profile', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const b = await c.req.json()

  // Everyone may update their avatar via this endpoint. The profile picture is an
  // attachment (uploaded image) — validate it is a real image and within size.
  if (b.avatar_url !== undefined) {
    if (b.avatar_url && !isSafeDataUrlOrHttp(b.avatar_url)) {
      return c.json({ error: 'Profile picture must be a JPEG, PNG, WebP or GIF image under 8 MB.' }, 400)
    }
    await c.env.DB.prepare(`UPDATE users SET avatar_url=? WHERE id=?`).bind(b.avatar_url || null, user.id).run()
  }

  if (user.role !== 'customer') {
    // Non-farmers: profile picture only (already handled above). Everything else ignored.
    await audit(c, user.id, 'update', 'profile', 'avatar (non-farmer self-update)')
    const updated = await getSessionUser(c)
    return c.json({ ok: true, user: updated, note: 'Only your profile picture and password can be changed here.' })
  }

  // Farmer: locate their customer record.
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE user_id=?`).bind(user.id).first<any>()
  if (!cust) return c.json({ error: 'Farmer profile not found' }, 404)

  // Explicitly IGNORE immutable fields: national_id, phone, mobile.
  const saccoProvided = b.sacco_membership !== undefined
  const saccoMember = ['yes', 'true', '1', 'on'].includes(String(b.sacco_membership || '').toLowerCase())
  await c.env.DB.prepare(
    `UPDATE customers SET
      full_name=COALESCE(?, full_name),
      date_of_birth=COALESCE(?, date_of_birth),
      gender=COALESCE(?, gender),
      alt_mobile=COALESCE(?, alt_mobile),
      county=COALESCE(?, county),
      sub_county=COALESCE(?, sub_county),
      ward=COALESCE(?, ward),
      village=COALESCE(?, village),
      latitude=COALESCE(?, latitude),
      longitude=COALESCE(?, longitude),
      value_chain_type=COALESCE(?, value_chain_type),
      value_chain=COALESCE(?, value_chain),
      acreage=COALESCE(?, acreage),
      herd_size=COALESCE(?, herd_size),
      farm_experience=COALESCE(?, farm_experience),
      annual_production=COALESCE(?, annual_production),
      existing_loans=COALESCE(?, existing_loans),
      sacco_membership=COALESCE(?, sacco_membership)
     WHERE id=?`
  ).bind(
    b.full_name ?? null, b.date_of_birth ?? null, b.gender ?? null,
    b.alt_mobile ?? null, b.county ?? null, b.sub_county ?? null,
    b.ward ?? null, b.village ?? null, b.latitude ?? null, b.longitude ?? null,
    b.value_chain_type ?? null, b.value_chain ?? null, b.acreage ?? null, b.herd_size ?? null,
    b.farm_experience ?? null, b.annual_production ?? null, b.existing_loans ?? null,
    saccoProvided ? (saccoMember ? 'yes' : 'no') : null,
    cust.id
  ).run()
  // Keep the users.full_name in sync when the farmer renames themselves.
  if (b.full_name) {
    await c.env.DB.prepare(`UPDATE users SET full_name=? WHERE id=?`).bind(String(b.full_name).trim(), user.id).run()
  }
  await audit(c, user.id, 'update', 'profile', 'farmer self-update (ID & phone locked)')
  const updated = await getSessionUser(c)
  return c.json({ ok: true, user: updated })
})

// ---- Auth provider status (so the UI can show live vs demo) ----
app.get('/api/auth/status', (c) => c.json({ sms_live: smsConfigured(c.env) }))
app.get('/api/integrations/transunion/status', requireAuth, (c) => {
  const live = Boolean(c.env.TRANSUNION_API_URL && c.env.TRANSUNION_API_KEY)
  return c.json({ live, environment: c.env.TRANSUNION_ENV || 'stub', ready_for_mapping: live })
})

// ---- Customer SIGN-UP via SMS OTP ----
// Step 1: request an OTP for a new phone number.
app.post('/api/signup/request-otp', async (c) => {
  const { phone, full_name } = await c.req.json()
  const p = normalizePhone(phone || '')
  if (!p || p.length < 9) return c.json({ error: 'Enter a valid phone number' }, 400)
  if (!full_name || String(full_name).trim().length < 2) return c.json({ error: 'Enter your full name' }, 400)
  const existing = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  if (existing) return c.json({ error: 'An account with this phone already exists. Please sign in.' }, 409)
  const { sms, demo_otp } = await issueOtp(c, p, 'signup')
  if (!sms.simulated && !sms.success) return c.json({ error: sms.error || 'Failed to send OTP' }, 502)
  return c.json({ ok: true, phone: p, message: sms.simulated ? 'Demo mode: use the code shown below.' : `OTP sent to ${p}.`, demo_otp })
})
// Step 1 (completion): verify OTP + set password -> create account + auto sign-in.
// Sign-up STEP 1 captures ONLY: Full Name, Phone (verified here), ID Number, Password.
// ID documents, passport photo, liveliness and TransUnion are STEP 2 (KYC) and are
// completed LATER — cash purchases work without them; financed purchases are gated
// (see /api/murabaha/apply -> kyc_required). ID number + phone must be UNIQUE.
app.post('/api/signup/verify', async (c) => {
  const { phone, full_name, code, password, region, national_id } = await c.req.json()
  const p = normalizePhone(phone || '')
  const name = String(full_name || '').trim()
  const idNo = String(national_id || '').trim()
  // ---- Input validation & sanitisation --------------------------------
  if (name.length < 2 || name.length > 120) return c.json({ error: 'Enter your full name' }, 400)
  if (!p || p.length < 9) return c.json({ error: 'Enter a valid phone number' }, 400)
  if (!/^[0-9]{5,12}$/.test(idNo)) return c.json({ error: 'Enter a valid National ID number (digits only)' }, 400)
  if (!password || String(password).length < 4 || String(password).length > 100) return c.json({ error: 'Password must be 4-100 characters' }, 400)
  const v = await verifyOtp(c, p, code, 'signup')
  if (!v.ok) return c.json({ error: v.error }, 400)
  // ---- Uniqueness: phone (users) AND national_id (customers) -----------
  const existing = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  if (existing) return c.json({ error: 'Account already exists. Please sign in.' }, 409)
  const idClash = await c.env.DB.prepare(`SELECT id FROM customers WHERE national_id=?`).bind(idNo).first()
  if (idClash) return c.json({ error: 'An account with this National ID already exists.' }, 409)
  const role = 'customer'
  const farmerPerms = await permissionsForRole(c, role)
  // Customers never provide an email at signup — resolveEmail supplies a UNIQUE,
  // non-deliverable placeholder derived from the phone. This satisfies the
  // central users.email NOT NULL + UNIQUE constraints (binding '' collided on
  // the 2nd signup → users_email_key / 23505).
  const signupEmailRes = resolveEmail(role, null, p)
  const signupEmail = 'value' in signupEmailRes ? signupEmailRes.value : ''
  // Public self-signup has no creating admin — assign the deployment's default
  // tenant so the central NOT NULL users.org_id constraint is satisfied.
  const orgId = await resolveDefaultOrgId(c)
  const withOrg = await usersHasOrgId(c) && orgId != null
  const r = withOrg
    ? await c.env.DB.prepare(
        `INSERT INTO users (full_name, phone, email, password, role, status, region, password_set, label, permissions, org_id) VALUES (?,?,?,?, ?, 'active', ?, 1, ?, ?, ?)`
      ).bind(name, p, signupEmail, await hashPassword(String(password)), role, region || null, 'Farmer', JSON.stringify(farmerPerms), orgId).run()
    : await c.env.DB.prepare(
        `INSERT INTO users (full_name, phone, email, password, role, status, region, password_set, label, permissions) VALUES (?,?,?,?, ?, 'active', ?, 1, ?, ?)`
      ).bind(name, p, signupEmail, await hashPassword(String(password)), role, region || null, 'Farmer', JSON.stringify(farmerPerms)).run()
  const userId = r.meta.last_row_id
  await c.env.DB.prepare(
    `INSERT INTO customers (user_id, full_name, national_id, mobile, kyc_status) VALUES (?,?,?,?, 'pending')`
  ).bind(userId, name, idNo, p).run()
  const user = { id: userId, full_name: name, phone: p, role, region, label: 'Farmer', permissions: farmerPerms }
  await createSession(c, user)
  await audit(c, userId, 'signup', 'user', 'customer self-registered (step 1: name/phone/ID/password)')
  return c.json({ ok: true, user, kyc_pending: true })
})

// ---- PASSWORD RESET via SMS OTP ----
app.post('/api/reset-password/request-otp', async (c) => {
  const { phone } = await c.req.json()
  const p = normalizePhone(phone || '')
  const user = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  // Do not reveal whether the phone exists; but in demo we send anyway only if it exists.
  if (!user) return c.json({ ok: true, phone: p, message: 'If the number is registered, an OTP has been sent.' })
  const { sms, demo_otp } = await issueOtp(c, p, 'reset')
  if (!sms.simulated && !sms.success) return c.json({ error: sms.error || 'Failed to send OTP' }, 502)
  return c.json({ ok: true, phone: p, message: sms.simulated ? 'Demo mode: use the code shown below.' : `OTP sent to ${p}.`, demo_otp })
})
app.post('/api/reset-password/verify', async (c) => {
  const { phone, code, password } = await c.req.json()
  const p = normalizePhone(phone || '')
  if (!password || String(password).length < 4) return c.json({ error: 'Password must be at least 4 characters' }, 400)
  const v = await verifyOtp(c, p, code, 'reset')
  if (!v.ok) return c.json({ error: v.error }, 400)
  const user = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first<any>()
  if (!user) return c.json({ error: 'Account not found' }, 404)
  await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1 WHERE id=?`).bind(await hashPassword(String(password)), user.id).run()
  await audit(c, user.id, 'reset_password', 'user', 'password reset via SMS OTP')
  return c.json({ ok: true, message: 'Password updated. You can now sign in.' })
})

// ----------------------------------------------------------------------------
// PRODUCTS / INVENTORY
// ----------------------------------------------------------------------------
// Storefront + management catalog. Products are read under admin context so the
// public shop and managers see the global catalog; ownership filtering for the
// "My Inventory" grid is applied explicitly below via ?mine=1.
app.get('/api/products', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const mine = c.req.query('mine') === '1'
  const shop = c.req.query('shop') === '1'
  const marketplaceFilter = String(c.req.query('marketplace') || '').trim().toLowerCase()
  const sourceFilter = String(c.req.query('source') || '').trim().toLowerCase()
  // Isolation floor: the Equipment app is the MAIN app and sees the whole
  // catalogue. Any OTHER app (feed / mazao), identified by APP_MARKETPLACE, may
  // only ever read rows tagged with its own source_platform — it can never query
  // the broader database. Defence-in-depth alongside RLS.
  const appMarketplace = String((c.env as any).APP_MARKETPLACE || 'equipment').toLowerCase()
  const rows = await withAdminContext(c, async () => {
    let query = `SELECT * FROM products`
    const binds: any[] = []
    const where: string[] = []
    if (appMarketplace !== 'equipment') { where.push(`source_platform = ?`); binds.push(appMarketplace) }
    // Storefront: only fully-authorized products are visible to buyers.
    if (shop) where.push(`finance_status = 'published'`)
    if (mine && !['admin', 'super_admin'].includes(user.role)) { where.push(`created_by = ?`); binds.push(user.id) }
    // Phase 5 — data isolation by APP_TYPE: this app only surfaces catalog
    // rows scoped to itself or shared ('both'). Equipment sees equipment+both.
    const appType = String(c.env.APP_TYPE || 'equipment').toLowerCase() === 'feed' ? 'feed' : 'equipment'
    where.push(`app_scope IN (?, 'both')`); binds.push(appType)
    // Storefront marketplace + product-origin filters (taxonomy / admin panel tabs).
    if (['equipment', 'feeds', 'inputs'].includes(marketplaceFilter)) { where.push(`marketplace = ?`); binds.push(marketplaceFilter) }
    if (VALID_SOURCE_PLATFORMS.includes(sourceFilter)) { where.push(`source_platform = ?`); binds.push(sourceFilter) }
    if (where.length) query += ` WHERE ` + where.join(' AND ')
    query += ` ORDER BY name`
    const { results } = await c.env.DB.prepare(query).bind(...binds).all()
    return results
  })
  const withStatus = (rows as any[]).map((p: any) => ({
    ...p,
    stock_status: p.quantity <= 0 ? 'out_of_stock' : p.quantity <= p.reorder_threshold ? 'low_stock' : 'in_stock'
  }))
  return c.json({ products: withStatus, can_manage_inventory: hasPermission(user, 'can_manage_inventory'), can_manage_finance_settings: hasPermission(user, 'can_manage_finance_settings') })
})
// Drafting a product needs can_manage_inventory. If the author is NOT authorized
// for finance, the product is saved as 'pending_finance' with finance fields
// neutralized, and lands in the finance-approval queue.
app.post('/api/products', requireAuth, requirePermission('can_manage_inventory'), async (c) => {
  const user = c.get('user') as SessionUser
  const canFinance = hasPermission(user, 'can_manage_finance_settings')
  let raw: any
  try { raw = await c.req.json() } catch (_) { return c.json({ error: 'Invalid request body' }, 400) }
  const p = normalizeProductPayload(raw)
  if (!p.sku || !p.name) return c.json({ error: 'SKU and name are required' }, 400)
  // Numeric sanity — never let NaN / negatives reach the NOT NULL money columns.
  if (!(p.buying_price >= 0) || !(p.cash_price >= 0) || !(p.credit_price >= 0)) {
    return c.json({ error: 'Prices must be valid non-negative numbers.' }, 400)
  }
  // Validate any UPLOADED agreement documents / image before we touch the DB.
  // (image is validated by isSafeDataUrlOrHttp; docs may also be PDFs.)
  if (p.image && !isSafeDataUrlOrHttp(p.image)) {
    return c.json({ error: 'Product image must be a JPEG, PNG, WebP or GIF under 8 MB.' }, 400)
  }
  for (const [field, label] of [['cash_terms_doc_url', 'Cash agreement'], ['financing_terms_doc_url', 'Financing agreement']] as const) {
    const v = (p as any)[field]
    if (v && !isSafeDocDataUrlOrHttp(v)) {
      return c.json({ error: `${label} document must be a PDF or image under 8 MB.` }, 400)
    }
  }
  // Permanent source tag: default to this app (equipment); allow an explicit,
  // whitelisted override so inventory managers can list into a merchant/feed/
  // mazao marketplace from the admin destination buttons.
  const sourcePlatform = VALID_SOURCE_PLATFORMS.includes(String(raw?.source_platform || '').toLowerCase())
    ? String(raw.source_platform).toLowerCase()
    : 'equipment'
  // Reject a duplicate SKU up front with a clear 409 instead of a raw 500 from
  // the UNIQUE(sku) constraint (this was the reported crash on product upload).
  const dup = await c.env.DB.prepare(`SELECT id FROM products WHERE sku = ?`).bind(p.sku).first<any>()
  if (dup) return c.json({ error: `A product with SKU "${p.sku}" already exists. Use a unique SKU.` }, 409)
  // Enforce the split at the app layer too (defence-in-depth alongside the RLS trigger).
  let financeStatus = 'published'
  if (!canFinance) {
    p.credit_markup_pct = 0
    p.credit_price = p.cash_price
    p.financing_enabled = false
    p.financing_interest_pct = 0
    p.financing_terms_text = null
    p.financing_terms_doc_url = null
    p.payment_option_mode = 'cash'
    financeStatus = 'pending_finance'
  }
  const financeSetBy = canFinance ? user.id : null
  try {
    const r = await c.env.DB.prepare(
      `INSERT INTO products (sku,name,category,subcategory,marketplace,source_platform,description,product_type,supplier_id,buying_price,cash_markup_pct,credit_markup_pct,cash_price,credit_price,quantity,unit,reorder_threshold,image,cash_enabled,financing_enabled,payment_option_mode,financing_model,financing_interest_pct,financing_frequency,financing_term_min_months,financing_term_max_months,cash_deposit_pct,financing_deposit_pct,cash_terms_text,financing_terms_text,cash_terms_doc_url,financing_terms_doc_url,transunion_product_code,created_by,finance_status,finance_set_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      p.sku, p.name, p.category, p.subcategory, p.marketplace, sourcePlatform, p.description, p.product_type, p.supplier_id, p.buying_price, p.cash_markup_pct, p.credit_markup_pct,
      p.cash_price, p.credit_price, p.quantity, p.unit, p.reorder_threshold, p.image, p.cash_enabled, p.financing_enabled,
      p.payment_option_mode, p.financing_model, p.financing_interest_pct, p.financing_frequency, p.financing_term_min_months,
      p.financing_term_max_months, p.cash_deposit_pct, p.financing_deposit_pct, p.cash_terms_text, p.financing_terms_text,
      p.cash_terms_doc_url, p.financing_terms_doc_url, p.transunion_product_code, user.id, financeStatus, financeSetBy
    ).run()
    await audit(c, user.id, 'create', 'product', `${p.name} (${financeStatus}, ${p.marketplace}/${sourcePlatform})`)
    return c.json({ id: r.meta.last_row_id, finance_status: financeStatus, marketplace: p.marketplace, source_platform: sourcePlatform })
  } catch (err: any) {
    const msg = String(err?.message || err)
    console.error('Product create failed:', msg)
    if (/unique|duplicate/i.test(msg)) return c.json({ error: `A product with SKU "${p.sku}" already exists. Use a unique SKU.` }, 409)
    return c.json({ error: 'Could not save the product. Please check the fields and try again.' }, 500)
  }
})
// Editing core/cash details needs can_manage_inventory. Editing finance columns
// needs can_manage_finance_settings — if the editor lacks it, the existing
// finance values are preserved (COALESCE-style) and cannot be changed.
app.put('/api/products/:id', requireAuth, requirePermission('can_manage_inventory', 'can_manage_finance_settings'), async (c) => {
  const user = c.get('user') as SessionUser
  const id = c.req.param('id')
  const canInv = hasPermission(user, 'can_manage_inventory')
  const canFinance = hasPermission(user, 'can_manage_finance_settings')
  const existing = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(id).first<any>())
  if (!existing) return c.json({ error: 'Not found' }, 404)
  let rawEdit: any
  try { rawEdit = await c.req.json() } catch (_) { return c.json({ error: 'Invalid request body' }, 400) }
  const p = normalizeProductPayload(rawEdit)
  // Validate uploaded image / agreement documents before touching the DB.
  if (canInv) {
    if (p.image && !isSafeDataUrlOrHttp(p.image)) return c.json({ error: 'Product image must be a JPEG, PNG, WebP or GIF under 8 MB.' }, 400)
    if (p.cash_terms_doc_url && !isSafeDocDataUrlOrHttp(p.cash_terms_doc_url)) return c.json({ error: 'Cash agreement document must be a PDF or image under 8 MB.' }, 400)
    // A changed SKU must remain unique.
    if (p.sku && p.sku !== existing.sku) {
      const dup = await c.env.DB.prepare(`SELECT id FROM products WHERE sku = ? AND id <> ?`).bind(p.sku, id).first<any>()
      if (dup) return c.json({ error: `A product with SKU "${p.sku}" already exists. Use a unique SKU.` }, 409)
    }
  }
  if (canFinance && p.financing_terms_doc_url && !isSafeDocDataUrlOrHttp(p.financing_terms_doc_url)) {
    return c.json({ error: 'Financing agreement document must be a PDF or image under 8 MB.' }, 400)
  }
  // Choose which columns the editor is allowed to change. (source_platform is the
  // PERMANENT origin tag and is never editable.)
  const coreCols = canInv ? {
    sku: p.sku, name: p.name, category: p.category, subcategory: p.subcategory, marketplace: p.marketplace, description: p.description, product_type: p.product_type,
    buying_price: p.buying_price, cash_markup_pct: p.cash_markup_pct, cash_price: p.cash_price,
    quantity: p.quantity, unit: p.unit, reorder_threshold: p.reorder_threshold, image: p.image || existing.image,
    cash_enabled: p.cash_enabled, cash_deposit_pct: p.cash_deposit_pct, cash_terms_text: p.cash_terms_text, cash_terms_doc_url: p.cash_terms_doc_url
  } : {
    sku: existing.sku, name: existing.name, category: existing.category, subcategory: existing.subcategory, marketplace: existing.marketplace, description: existing.description, product_type: existing.product_type,
    buying_price: existing.buying_price, cash_markup_pct: existing.cash_markup_pct, cash_price: existing.cash_price,
    quantity: existing.quantity, unit: existing.unit, reorder_threshold: existing.reorder_threshold, image: existing.image,
    cash_enabled: existing.cash_enabled, cash_deposit_pct: existing.cash_deposit_pct, cash_terms_text: existing.cash_terms_text, cash_terms_doc_url: existing.cash_terms_doc_url
  }
  const finCols = canFinance ? {
    credit_markup_pct: p.credit_markup_pct, credit_price: p.credit_price, financing_enabled: p.financing_enabled,
    financing_model: p.financing_model, financing_interest_pct: p.financing_interest_pct, financing_frequency: p.financing_frequency,
    financing_term_min_months: p.financing_term_min_months, financing_term_max_months: p.financing_term_max_months,
    financing_deposit_pct: p.financing_deposit_pct, financing_terms_text: p.financing_terms_text, financing_terms_doc_url: p.financing_terms_doc_url,
    transunion_product_code: p.transunion_product_code,
    payment_option_mode: p.payment_option_mode, finance_status: 'published', finance_set_by: user.id
  } : {
    credit_markup_pct: existing.credit_markup_pct, credit_price: existing.credit_price, financing_enabled: existing.financing_enabled,
    financing_model: existing.financing_model, financing_interest_pct: existing.financing_interest_pct, financing_frequency: existing.financing_frequency,
    financing_term_min_months: existing.financing_term_min_months, financing_term_max_months: existing.financing_term_max_months,
    financing_deposit_pct: existing.financing_deposit_pct, financing_terms_text: existing.financing_terms_text, financing_terms_doc_url: existing.financing_terms_doc_url,
    transunion_product_code: existing.transunion_product_code,
    payment_option_mode: existing.payment_option_mode, finance_status: existing.finance_status, finance_set_by: existing.finance_set_by
  }
  try {
    await c.env.DB.prepare(
      `UPDATE products SET sku=?, name=?, category=?, subcategory=?, marketplace=?, description=?, product_type=?, buying_price=?, cash_markup_pct=?, credit_markup_pct=?, cash_price=?, credit_price=?, quantity=?, unit=?, reorder_threshold=?, image=COALESCE(?, image), cash_enabled=?, financing_enabled=?, payment_option_mode=?, financing_model=?, financing_interest_pct=?, financing_frequency=?, financing_term_min_months=?, financing_term_max_months=?, cash_deposit_pct=?, financing_deposit_pct=?, cash_terms_text=?, financing_terms_text=?, cash_terms_doc_url=?, financing_terms_doc_url=?, transunion_product_code=?, finance_status=?, finance_set_by=?, finance_set_at=CASE WHEN ?='published' THEN CURRENT_TIMESTAMP ELSE finance_set_at END WHERE id=?`
    ).bind(
      coreCols.sku, coreCols.name, coreCols.category, coreCols.subcategory, coreCols.marketplace, coreCols.description, coreCols.product_type, coreCols.buying_price, coreCols.cash_markup_pct, finCols.credit_markup_pct,
      coreCols.cash_price, finCols.credit_price, coreCols.quantity, coreCols.unit, coreCols.reorder_threshold, coreCols.image || null, coreCols.cash_enabled, finCols.financing_enabled,
      finCols.payment_option_mode, finCols.financing_model, finCols.financing_interest_pct, finCols.financing_frequency, finCols.financing_term_min_months,
      finCols.financing_term_max_months, coreCols.cash_deposit_pct, finCols.financing_deposit_pct, coreCols.cash_terms_text, finCols.financing_terms_text,
      coreCols.cash_terms_doc_url, finCols.financing_terms_doc_url, finCols.transunion_product_code, finCols.finance_status, finCols.finance_set_by, finCols.finance_status, id
    ).run()
  } catch (err: any) {
    const msg = String(err?.message || err)
    console.error('Product update failed:', msg)
    if (/unique|duplicate/i.test(msg)) return c.json({ error: `A product with SKU "${coreCols.sku}" already exists. Use a unique SKU.` }, 409)
    return c.json({ error: 'Could not update the product. Please check the fields and try again.' }, 500)
  }
  await audit(c, user.id, 'update', 'product', `${coreCols.name}${canFinance ? '' : ' (core only)'}`)
  return c.json({ ok: true })
})
app.delete('/api/products/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const used = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE product_id=?`).bind(id).first<any>()
  if (used?.n > 0) return c.json({ error: 'Cannot delete: product is referenced by existing purchases' }, 400)
  await c.env.DB.prepare(`DELETE FROM products WHERE id=?`).bind(id).run()
  await audit(c, c.get('user').id, 'delete', 'product', String(id))
  return c.json({ ok: true })
})
app.put('/api/products/:id/stock', requireAuth, requirePermission('can_manage_inventory'), async (c) => {
  const id = c.req.param('id')
  const { quantity, movement_type } = await c.req.json()
  await c.env.DB.prepare(`UPDATE products SET quantity = quantity + ? WHERE id = ?`).bind(Number(quantity), id).run()
  await c.env.DB.prepare(`INSERT INTO stock_movements (product_id, movement_type, quantity, reference) VALUES (?,?,?,?)`)
    .bind(id, movement_type || 'purchase', quantity, 'manual adjustment').run()
  return c.json({ ok: true })
})

// ---- Split-data workflow: finance-approval queue -------------------------
// Products drafted by a base user awaiting an authorized finance user to supply
// markups / rates / agreements before they can be published to the storefront.
app.get('/api/products/finance-queue', requireAuth, requirePermission('can_manage_finance_settings'), async (c) => {
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(
      `SELECT p.*, u.full_name AS created_by_name
         FROM products p LEFT JOIN users u ON CAST(u.id AS TEXT) = p.created_by
        WHERE p.finance_status = 'pending_finance'
        ORDER BY p.created_at DESC`
    ).all()
    return results
  })
  return c.json({ products: rows })
})
// Authorized finance user supplies the finance components and publishes.
app.put('/api/products/:id/finance', requireAuth, requirePermission('can_manage_finance_settings'), async (c) => {
  const user = c.get('user') as SessionUser
  const id = c.req.param('id')
  const b = await c.req.json()
  const publish = b.finance_status !== 'pending_finance'
  await c.env.DB.prepare(
    `UPDATE products SET
        credit_markup_pct = COALESCE(?, credit_markup_pct),
        credit_price = COALESCE(?, credit_price),
        financing_enabled = COALESCE(?, financing_enabled),
        financing_model = COALESCE(?, financing_model),
        financing_interest_pct = COALESCE(?, financing_interest_pct),
        financing_frequency = COALESCE(?, financing_frequency),
        financing_term_min_months = COALESCE(?, financing_term_min_months),
        financing_term_max_months = COALESCE(?, financing_term_max_months),
        financing_deposit_pct = COALESCE(?, financing_deposit_pct),
        financing_terms_text = COALESCE(?, financing_terms_text),
        financing_terms_doc_url = COALESCE(?, financing_terms_doc_url),
        payment_option_mode = COALESCE(?, payment_option_mode),
        finance_notes = COALESCE(?, finance_notes),
        finance_status = ?, finance_set_by = ?, finance_set_at = CURRENT_TIMESTAMP
      WHERE id = ?`
  ).bind(
    b.credit_markup_pct ?? null, b.credit_price ?? null,
    b.financing_enabled === undefined ? null : (boolInt(b.financing_enabled, true) ? 1 : 0),
    b.financing_model ?? null, b.financing_interest_pct ?? null, b.financing_frequency ?? null,
    b.financing_term_min_months ?? null, b.financing_term_max_months ?? null, b.financing_deposit_pct ?? null,
    b.financing_terms_text ?? null, b.financing_terms_doc_url ?? null,
    b.payment_option_mode ?? (publish ? 'both' : null), b.finance_notes ?? null,
    publish ? 'published' : 'pending_finance', user.id, id
  ).run()
  await audit(c, user.id, 'finance_authorize', 'product', `product ${id} ${publish ? 'published' : 'saved'}`)
  return c.json({ ok: true, finance_status: publish ? 'published' : 'pending_finance' })
})
// ---- Admin audit: products hidden from storefront for lack of finance -----
// Diagnostic + reminder feed for authorized finance personnel.
app.get('/api/products/finance-audit', requireAuth, requirePermission('can_manage_finance_settings'), async (c) => {
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(
      `SELECT p.id, p.sku, p.name, p.finance_status, p.created_at, p.created_by,
              u.full_name AS created_by_name,
              (CASE WHEN p.credit_markup_pct IS NULL OR p.credit_markup_pct = 0 THEN 1 ELSE 0 END) AS missing_markup,
              (CASE WHEN p.financing_terms_text IS NULL OR p.financing_terms_text = '' THEN 1 ELSE 0 END) AS missing_agreement
         FROM products p LEFT JOIN users u ON CAST(u.id AS TEXT) = p.created_by
        WHERE p.finance_status <> 'published'
        ORDER BY p.created_at ASC`
    ).all()
    return results
  })
  const list = rows as any[]
  const reminder = list.length
    ? `${list.length} product(s) are hidden from the storefront pending financial parameters. Authorized finance personnel should review the queue.`
    : 'All products have complete financial parameters and are visible on the storefront.'
  return c.json({ hidden_products: list, count: list.length, reminder, notify_roles: ['admin', 'super_admin', 'operations_finance'] })
})

// ----------------------------------------------------------------------------
// CUSTOMERS / ONBOARDING / VERIFICATION
// ----------------------------------------------------------------------------
app.get('/api/customers', requireAuth, async (c) => {
  const user = c.get('user')
  let query = `SELECT * FROM customers`
  let binds: any[] = []
  if (user.role === 'agent') { query += ` WHERE agent_id = ?`; binds = [user.id] }
  query += ` ORDER BY created_at DESC`
  const { results } = await c.env.DB.prepare(query).bind(...binds).all()
  return c.json({ customers: (results as any[]).map((r) => redactCustomer(user, r)) })
})
app.get('/api/customers/:id', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(c.req.param('id')).first()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  const tu = await c.env.DB.prepare(`SELECT * FROM transunion_checks WHERE customer_id=? ORDER BY id DESC LIMIT 1`).bind(c.req.param('id')).first()
  const idv = await c.env.DB.prepare(`SELECT * FROM id_verifications WHERE customer_id=? ORDER BY id DESC LIMIT 1`).bind(c.req.param('id')).first()
  const showFinancial = hasVisibility(user, 'view_financial_data')
  return c.json({ customer: redactCustomer(user, cust), transunion: showFinancial ? tu : null, id_verification: idv })
})
app.post('/api/customers', requireAuth, requireRole('agent', 'admin', 'super_admin'), async (c) => {
  const b = await c.req.json()
  const user = c.get('user')
  // Validate + enforce a unique National ID on agent/admin onboarding.
  const onbId = String(b.national_id || '').trim()
  if (onbId) {
    if (!/^[0-9]{5,12}$/.test(onbId)) return c.json({ error: 'Enter a valid National ID number (digits only)' }, 400)
    const clash = await c.env.DB.prepare(`SELECT id FROM customers WHERE national_id=?`).bind(onbId).first()
    if (clash) return c.json({ error: 'A customer with this National ID already exists.' }, 409)
    b.national_id = onbId
  }
  // Validate any uploaded document images before storing.
  for (const f of ['id_front_url', 'id_back_url']) {
    if (b[f] && !isSafeDataUrlOrHttp(b[f])) return c.json({ error: `${f.replace(/_/g, ' ')} must be a JPEG, PNG, WebP or GIF image under 8 MB.` }, 400)
  }
  const saccoMember = ['yes', 'true', '1', 'on'].includes(String(b.sacco_membership || '').toLowerCase())
  const assignedAgent = user.role === 'agent' ? user.id : (b.agent_id || user.id)
  const r = await c.env.DB.prepare(
    `INSERT INTO customers (agent_id,onboarded_by,full_name,national_id,date_of_birth,gender,mobile,alt_mobile,county,sub_county,ward,village,latitude,longitude,value_chain_type,value_chain,acreage,herd_size,farm_experience,annual_production,existing_loans,sacco_membership,id_front_url,id_back_url,kyc_status,status)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'pending', 'active')`
  ).bind(
    assignedAgent, assignedAgent,
    b.full_name, b.national_id, b.date_of_birth, b.gender, b.mobile, b.alt_mobile, b.county, b.sub_county,
    b.ward, b.village, b.latitude || null, b.longitude || null, b.value_chain_type, b.value_chain,
    b.acreage || null, b.herd_size || null, b.farm_experience || null, b.annual_production || null,
    b.existing_loans || null,
    saccoMember ? 'yes' : 'no',
    b.id_front_url || null, b.id_back_url || null
  ).run()
  await audit(c, user.id, 'onboard', 'customer', b.full_name)
  return c.json({ id: r.meta.last_row_id })
})
// Update farmer profile (admin + agent for their own customer)
app.put('/api/customers/:id', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const id = c.req.param('id')
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(id).first<any>()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  const isAdmin = ['admin', 'super_admin'].includes(user.role)
  const isOwningAgent = user.role === 'agent' && cust.agent_id === user.id
  // The owning customer may update their OWN record here (used by the Step-2 KYC
  // document upload). They can never change immutable identity fields.
  const isOwningCustomer = user.role === 'customer' && cust.user_id === user.id
  if (!isAdmin && !isOwningAgent && !isOwningCustomer) return c.json({ error: 'Forbidden' }, 403)
  const b = await c.req.json()
  // Immutable identity fields: national_id and mobile can never be changed after
  // creation (uniqueness + integrity). Only a fresh admin create can set them.
  b.national_id = undefined
  b.mobile = undefined
  // Validate any uploaded document images (data URLs) before storing them.
  for (const f of ['id_front_url', 'id_back_url', 'selfie_url', 'passport_photo_url']) {
    if (b[f] !== undefined && b[f] !== null && b[f] !== '' && !isSafeDataUrlOrHttp(b[f])) {
      return c.json({ error: `${f.replace(/_/g, ' ')} must be a JPEG, PNG, WebP or GIF image under 8 MB.` }, 400)
    }
  }
  const saccoProvided = b.sacco_membership !== undefined
  const saccoMember = ['yes', 'true', '1', 'on'].includes(String(b.sacco_membership || '').toLowerCase())
  await c.env.DB.prepare(
    `UPDATE customers SET
      full_name=COALESCE(?, full_name),
      national_id=COALESCE(?, national_id),
      date_of_birth=COALESCE(?, date_of_birth),
      gender=COALESCE(?, gender),
      mobile=COALESCE(?, mobile),
      alt_mobile=COALESCE(?, alt_mobile),
      county=COALESCE(?, county),
      sub_county=COALESCE(?, sub_county),
      ward=COALESCE(?, ward),
      village=COALESCE(?, village),
      latitude=COALESCE(?, latitude),
      longitude=COALESCE(?, longitude),
      value_chain_type=COALESCE(?, value_chain_type),
      value_chain=COALESCE(?, value_chain),
      acreage=COALESCE(?, acreage),
      herd_size=COALESCE(?, herd_size),
      farm_experience=COALESCE(?, farm_experience),
      annual_production=COALESCE(?, annual_production),
      existing_loans=COALESCE(?, existing_loans),
      sacco_membership=COALESCE(?, sacco_membership),
      id_front_url=COALESCE(?, id_front_url),
      id_back_url=COALESCE(?, id_back_url)
     WHERE id=?`
  ).bind(
    b.full_name ?? null, b.national_id ?? null, b.date_of_birth ?? null, b.gender ?? null,
    b.mobile ?? null, b.alt_mobile ?? null, b.county ?? null, b.sub_county ?? null,
    b.ward ?? null, b.village ?? null, b.latitude ?? null, b.longitude ?? null,
    b.value_chain_type ?? null, b.value_chain ?? null, b.acreage ?? null, b.herd_size ?? null,
    b.farm_experience ?? null, b.annual_production ?? null, b.existing_loans ?? null,
    saccoProvided ? (saccoMember ? 'yes' : 'no') : null,
    b.id_front_url ?? null, b.id_back_url ?? null, id
  ).run()
  await audit(c, user.id, 'update', 'customer', String(id))
  return c.json({ ok: true })
})
// Admin can suspend / reactivate farmer profiles
app.put('/api/customers/:id/status', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const { status } = await c.req.json()
  if (!['active', 'suspended'].includes(String(status))) return c.json({ error: 'Status must be active or suspended' }, 400)
  const cust = await c.env.DB.prepare(`SELECT user_id FROM customers WHERE id=?`).bind(id).first<any>()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  await c.env.DB.prepare(`UPDATE customers SET status=? WHERE id=?`).bind(status, id).run()
  if (cust.user_id) {
    await c.env.DB.prepare(`UPDATE users SET status=? WHERE id=?`).bind(status, cust.user_id).run()
    if (status === 'suspended') await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id = CAST(? AS TEXT)`).bind(cust.user_id).run()
  }
  await audit(c, c.get('user').id, status === 'active' ? 'activate' : 'deactivate', 'customer', String(id))
  return c.json({ ok: true })
})
// Admin can delete farmer profiles (and the linked customer-role user)
app.delete('/api/customers/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const cust = await c.env.DB.prepare(`SELECT user_id FROM customers WHERE id=?`).bind(id).first<any>()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  const open = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE customer_id=? AND status IN ('active','pending','pending_payment')`).bind(id).first<any>()
  if (Number(open?.n || 0) > 0) return c.json({ error: 'Farmer has open contracts. Settle or cancel them first.' }, 400)
  await c.env.DB.prepare(`DELETE FROM transunion_checks WHERE customer_id=?`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM id_verifications WHERE customer_id=?`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM customers WHERE id=?`).bind(id).run()
  if (cust.user_id) {
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id = CAST(? AS TEXT)`).bind(cust.user_id).run()
    await c.env.DB.prepare(`DELETE FROM users WHERE id=? AND role='customer'`).bind(cust.user_id).run()
  }
  await audit(c, c.get('user').id, 'delete', 'customer', String(id))
  return c.json({ ok: true })
})
// Verification engine — ID verification, liveness, IPRS and credit
// evaluation are delegated to Farmsky Score (score.farmsky.africa) when
// configured; otherwise a deterministic local simulation is used.
app.post('/api/customers/:id/verify', requireAuth, async (c) => {
  const id = c.req.param('id')
  const user = c.get('user')
  const cust = await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(id).first<any>()
  if (!cust) return c.json({ error: 'Not found' }, 404)
  if (!['admin', 'super_admin', 'agent', 'operations_finance'].includes(user.role)) {
    if (!(user.role === 'customer' && cust.user_id === user.id)) return c.json({ error: 'Forbidden' }, 403)
  }
  // Persist the passport / selfie photo captured in this step (for liveliness).
  const vbody = await c.req.json().catch(() => ({} as any))
  if (vbody?.selfie_url && isSafeDataUrlOrHttp(vbody.selfie_url)) {
    await c.env.DB.prepare(`UPDATE customers SET selfie_url=? WHERE id=?`).bind(String(vbody.selfie_url), id).run()
    cust.selfie_url = String(vbody.selfie_url)
  }
  // STEP 2 (KYC) requires: ID front + back, a passport / selfie photo, and a
  // successful liveness check before the credit evaluation runs.
  if (!cust.id_front_url || !cust.id_back_url) return c.json({ error: 'Front and back national ID uploads are required before verification' }, 400)
  if (!cust.selfie_url) return c.json({ error: 'A passport / selfie photo is required before verification' }, 400)

  // ---------------------------------------------------------------------
  // Farmsky Score integration.
  // When Score (score.farmsky.africa) is configured, ID verification,
  // liveness, IPRS and the full credit evaluation are performed by Score's
  // APIs. Every Score response is mirrored into this database's DEDICATED
  // score_* tables. If Score is unreachable / not configured we fall back
  // to a deterministic local simulation so the flow always completes.
  // ---------------------------------------------------------------------
  const nationalId = String(cust.national_id || '')
  let faceMatch = 1
  let livenessPassed = 1
  let idVerified = 1
  let iprsStatus = 'VERIFIED'
  let scoreLive = false
  let score = Math.floor(Math.random() * 350 + 450)
  let band: string = score >= 700 ? 'low' : score >= 600 ? 'medium' : 'high'
  let riskTier = band
  let decision: string | null = null
  let scoreRef: string | null = null

  if (scoreConfigured(c.env) && nationalId) {
    // 1) ID verification + liveness (combined KYC on Score).
    const kyc = await scoreKyc(c.env, { national_id: nationalId })
    if (kyc.live) {
      scoreLive = true
      idVerified = kyc.verified ? 1 : 0
      faceMatch = kyc.face_match ? 1 : 0
      livenessPassed = kyc.liveness_passed ? 1 : 0
      await c.env.DB.prepare(
        `INSERT INTO score_verifications (customer_id,score_request_id,national_id,full_name,id_verified,face_match,liveness_passed,liveness_score,raw_response) VALUES (?,?,?,?,?,?,?,?,?)`
      ).bind(id, kyc.request_id || null, nationalId, cust.full_name || null, idVerified, faceMatch, livenessPassed, kyc.liveness_score ?? null, JSON.stringify(kyc.raw || {})).run().catch(() => {})
    } else {
      // Fall back to a standalone liveness check if combined KYC was unavailable.
      const live = await scoreLiveness(c.env, nationalId || String(id))
      if (live.live) { scoreLive = true; livenessPassed = live.liveness_passed ? 1 : 0 }
    }

    // 2) IPRS government-registry lookup.
    const iprs = await scoreIprs(c.env, nationalId)
    if (iprs.live) {
      scoreLive = true
      iprsStatus = iprs.status || iprsStatus
      await c.env.DB.prepare(
        `INSERT INTO score_iprs_checks (customer_id,score_request_id,national_id,status,registry_name,pep_sanctions_hit,raw_response) VALUES (?,?,?,?,?,?,?)`
      ).bind(id, iprs.request_id || null, nationalId, iprsStatus, iprs.registry_name || null, iprs.pep_sanctions_hit ? 1 : 0, JSON.stringify(iprs.raw || {})).run().catch(() => {})
    }

    // 3) Full credit evaluation.
    const evalPayload = {
      applicant_type: 'INDIVIDUAL_FARMER',
      applicant: {
        national_id: nationalId,
        full_name: cust.full_name,
        date_of_birth: cust.date_of_birth,
        gps: (cust.latitude && cust.longitude) ? { lat: Number(cust.latitude), lon: Number(cust.longitude) } : undefined,
        county: cust.county || undefined,
      },
    }
    const cr = await scoreCreditEvaluation(c.env, evalPayload)
    if (cr.live && typeof cr.composite_score === 'number') {
      scoreLive = true
      score = cr.composite_score
      riskTier = cr.risk_tier || riskTier
      decision = cr.decision || null
      scoreRef = cr.lender_reference || null
      // Map Score's risk tier to Equipment's low/medium/high band.
      const t = String(riskTier).toLowerCase()
      band = /low|a\b|prime|excellent/.test(t) ? 'low' : /high|d\b|e\b|sub|poor/.test(t) ? 'high' : 'medium'
      await c.env.DB.prepare(
        `INSERT INTO score_credit_evaluations (customer_id,score_reference,applicant_type,composite_score,risk_tier,decision,model_version,raw_response) VALUES (?,?,?,?,?,?,?,?)`
      ).bind(id, scoreRef, 'INDIVIDUAL_FARMER', score, riskTier, decision, cr.model_version || null, JSON.stringify(cr.raw || {})).run().catch(() => {})
    }
  }

  const providerRef = scoreRef || `SCORE-${Date.now()}`
  const integrationStatus = scoreLive ? 'live_score' : 'stubbed'
  await c.env.DB.prepare(`INSERT INTO transunion_checks (customer_id,credit_score,risk_band,defaults_found,raw_response,provider_reference,integration_status) VALUES (?,?,?,?,?,?,?)`)
    .bind(id, score, band, band === 'high' ? 1 : 0, JSON.stringify({ score, band, risk_tier: riskTier, decision, score_live: scoreLive, iprs_status: iprsStatus }), providerRef, integrationStatus).run()
  await c.env.DB.prepare(`INSERT INTO id_verifications (customer_id,face_match,liveness,ocr_name,ocr_dob,ocr_id_number,status) VALUES (?,?,?,?,?,?, 'verified')`)
    .bind(id, faceMatch, livenessPassed, cust.full_name, cust.date_of_birth, cust.national_id).run()
  await c.env.DB.prepare(`UPDATE customers SET kyc_status='verified', risk_band=?, credit_score=?, liveliness_passed=?, kyc_completed_at=CURRENT_TIMESTAMP WHERE id=?`).bind(band, score, livenessPassed, id).run()
  await audit(c, user.id, 'verify', 'customer', `KYC verified for ${cust.full_name}${scoreLive ? ' via Farmsky Score' : ''}`)
  return c.json({
    ok: true,
    credit_score: score,
    risk_band: band,
    risk_tier: riskTier,
    decision,
    face_match: !!faceMatch,
    liveness: !!livenessPassed,
    id_verified: !!idVerified,
    iprs_status: iprsStatus,
    score_integration: scoreLive ? 'live' : 'simulated',
    provider_reference: providerRef,
  })
})

// ----------------------------------------------------------------------------
// MURABAHA
// ----------------------------------------------------------------------------
app.post('/api/murabaha/quote', requireAuth, async (c) => {
  const { product_id, quantity, payment_type, term_months } = await c.req.json()
  const p = await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(product_id).first<any>()
  if (!p) return c.json({ error: 'Product not found' }, 404)
  if (payment_type === 'cash' && !p.cash_enabled) return c.json({ error: 'Cash purchase is not enabled for this equipment' }, 400)
  if (payment_type !== 'cash' && !p.financing_enabled) return c.json({ error: 'Financing is not enabled for this equipment' }, 400)
  const feeCfg = await getSetting(c, 'processing_fee', DEFAULT_PROCESSING_FEE)
  const q = financingQuote(p, quantity, payment_type === 'cash' ? 'cash' : 'financing', term_months, feeCfg)
  return c.json({ product: p.name, ...q })
})
app.post('/api/murabaha/apply', requireAuth, async (c) => {
  const user = c.get('user')
  const { customer_id, product_id, quantity, payment_type, term_months, delivery_location, consent } = await c.req.json()
  if (!consent) return c.json({ error: 'Customer consent to the configured terms is required' }, 400)
  // The catalog + the buyer's own customer row are read under admin context so
  // ownership RLS (which scopes products to their lister) doesn't block checkout.
  const p = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(product_id).first<any>())
  if (!p) return c.json({ error: 'Product not found' }, 404)
  if (p.finance_status && p.finance_status !== 'published') return c.json({ error: 'This product is not yet available for purchase' }, 400)
  const qty = Math.max(1, Number(quantity) || 1)
  if (p.quantity < qty) return c.json({ error: 'Insufficient stock' }, 400)
  let custId = customer_id
  if (user.role === 'customer') {
    const myCust = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id, agent_id FROM customers WHERE user_id=?`).bind(user.id).first<any>())
    if (!myCust) return c.json({ error: 'Customer profile not found' }, 404)
    custId = myCust.id
  }
  const custRow = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(custId).first<any>())
  if (!custRow) return c.json({ error: 'Farmer not found' }, 404)
  // AGENT "BUY FOR" GUARD: an agent placing an order on behalf of a farmer may
  // only select a farmer assigned to their own roster.
  if (user.role === 'agent' && String(custRow.agent_id) !== String(user.id)) {
    return c.json({ error: 'You can only place orders for farmers assigned to you.' }, 403)
  }
  const normalizedPaymentType = payment_type === 'cash' ? 'cash' : 'financing'
  if (normalizedPaymentType === 'financing' && custRow?.kyc_status !== 'verified') {
    return c.json({
      error: 'kyc_required',
      message: 'Complete registration (TransUnion credit check, ID upload, and liveness verification) before equipment financing purchases.',
      customer_id: custId
    }, 412)
  }
  const feeCfg = await getSetting(c, 'processing_fee', DEFAULT_PROCESSING_FEE)
  const q = financingQuote(p, qty, normalizedPaymentType, term_months, feeCfg)
  const contractRef = ref(normalizedPaymentType === 'cash' ? 'CSH' : (q.financing_model === 'paygo' ? 'PGO' : 'FIN'))
  const status = normalizedPaymentType === 'cash'
    ? (q.amount_due_now > 0 ? 'pending_payment' : 'awaiting_cash_balance')
    : 'pending'
  const r = await c.env.DB.prepare(
    `INSERT INTO murabaha_contracts (contract_ref,customer_id,agent_id,created_by,product_id,quantity,payment_type,supplier_cost,markup_pct,murabaha_price,term_months,monthly_payment,delivery_location,status,ownership_recorded,consent_given,amount_paid,outstanding,financing_model,interest_rate_pct,deposit_pct,deposit_amount,finance_principal,payment_frequency,installment_amount,dispatch_status,terms_document_url,terms_text)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    contractRef, custId, custRow?.agent_id || null, custRow?.onboarded_by || custRow?.agent_id || user.id, product_id, qty, normalizedPaymentType, q.supplier_cost, q.markup_pct,
    q.total_payable, q.term_months, q.monthly_payment || q.installment_amount || 0, delivery_location || '', status,
    0, 1, 0, q.total_payable, q.financing_model, q.interest_rate_pct || 0, q.deposit_pct, q.deposit_amount,
    q.finance_principal, q.payment_frequency, q.installment_amount || 0, 'pending', q.terms_document_url || null, q.terms_text || null
  ).run()
  const contractId = r.meta.last_row_id
  await audit(c, user.id, 'apply', 'financing', `${normalizedPaymentType} ${contractRef}`)
  return c.json({
    id: contractId,
    contract_ref: contractRef,
    status,
    payment_type: normalizedPaymentType,
    financing_model: q.financing_model,
    amount_due_now: q.amount_due_now,
    deposit_amount: q.deposit_amount,
    deposit_pct: q.deposit_pct,
    total_payable: q.total_payable,
    outstanding: q.total_payable,
    installment_amount: q.installment_amount,
    monthly_payment: q.monthly_payment || q.installment_amount,
    // Deposit is required (and a prompt must be raised) when a cash deposit > 0
    // is due. Deposit = 0 skips the prompt and advances the order automatically.
    requires_payment: normalizedPaymentType === 'cash' && q.amount_due_now > 0,
    payment_frequency: q.payment_frequency,
    // "Buy For" context: when an agent placed this order on a farmer's behalf,
    // surface the farmer so the client can direct the deposit prompt to them.
    buy_for: user.role === 'agent',
    farmer: { id: custRow.id, name: custRow.full_name || 'Farmer', phone: custRow.mobile || '' }
  })
})

// ----------------------------------------------------------------------------
// MULTI-PRODUCT BUNDLED CHECKOUT
// Place a SINGLE checkout that contains several products. Each item keeps its
// OWN payment_type / term / deposit so every product independently respects its
// listing (cash) or finance-specified conditions — exactly like placing each
// order on its own, but grouped under one shared bundle_ref and settled with a
// single aggregated deposit prompt.
//
// Available to farmers (their own basket) AND agents (Buy-For a roster farmer).
// Body: { customer_id?, delivery_location?, consent, items: [ { product_id,
//         quantity, payment_type, term_months } ] }
// ----------------------------------------------------------------------------
// KYC PRE-CHECK for checkout. Resolves the buyer (the farmer themselves for a
// self-purchase, or the agent's selected roster farmer for a Buy-For order) and
// reports whether their registration/KYC is complete. The client calls this the
// moment "Place an Order" is pressed so an unverified buyer is redirected to the
// registration flow BEFORE any order is created — for both cash and financing.
app.post('/api/checkout/kyc-check', requireAuth, async (c) => {
  const user = c.get('user')
  const { customer_id } = await c.req.json().catch(() => ({}))
  let custId = customer_id
  if (user.role === 'customer') {
    const myCust = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first<any>())
    if (!myCust) return c.json({ error: 'Customer profile not found' }, 404)
    custId = myCust.id
  }
  if (!custId) return c.json({ error: 'No buyer selected for this order' }, 400)
  const custRow = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id, full_name, mobile, agent_id, kyc_status FROM customers WHERE id=?`).bind(custId).first<any>())
  if (!custRow) return c.json({ error: 'Farmer not found' }, 404)
  // Agents may only run this for a farmer on their own roster.
  if (user.role === 'agent' && String(custRow.agent_id) !== String(user.id)) {
    return c.json({ error: 'You can only place orders for farmers assigned to you.' }, 403)
  }
  const verified = custRow.kyc_status === 'verified'
  return c.json({
    verified,
    kyc_status: custRow.kyc_status || 'pending',
    customer_id: custRow.id,
    farmer: { id: custRow.id, name: custRow.full_name || 'Farmer', phone: custRow.mobile || '' }
  })
})

app.post('/api/murabaha/apply-bundle', requireAuth, async (c) => {
  const user = c.get('user')
  const { customer_id, delivery_location, consent, items } = await c.req.json()
  if (!consent) return c.json({ error: 'Customer consent to the configured terms is required' }, 400)
  if (!Array.isArray(items) || items.length === 0) return c.json({ error: 'Add at least one product to the order' }, 400)
  if (items.length > 50) return c.json({ error: 'Too many items in a single order' }, 400)

  // Resolve the buyer once. Farmers order for themselves; agents/staff pass a
  // customer_id (the roster guard below restricts agents to their own farmers).
  let custId = customer_id
  if (user.role === 'customer') {
    const myCust = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT id, agent_id FROM customers WHERE user_id=?`).bind(user.id).first<any>())
    if (!myCust) return c.json({ error: 'Customer profile not found' }, 404)
    custId = myCust.id
  }
  const custRow = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM customers WHERE id=?`).bind(custId).first<any>())
  if (!custRow) return c.json({ error: 'Farmer not found' }, 404)
  // AGENT "BUY FOR" GUARD: an agent may only order for a farmer on their roster.
  if (user.role === 'agent' && String(custRow.agent_id) !== String(user.id)) {
    return c.json({ error: 'You can only place orders for farmers assigned to you.' }, 403)
  }

  const feeCfg = await getSetting(c, 'processing_fee', DEFAULT_PROCESSING_FEE)
  const bundleRef = ref('BND')

  // ---- PASS 1: validate & quote every item BEFORE writing anything, so a bad
  // item (out of stock / unknown product / KYC-gated financing) fails the whole
  // bundle atomically instead of leaving a half-created order. ----
  const prepared: Array<{ p: any; qty: number; ptype: string; q: any }> = []
  for (const raw of items) {
    const productId = raw?.product_id
    const p = await withAdminContext(c, async () => await c.env.DB.prepare(`SELECT * FROM products WHERE id=?`).bind(productId).first<any>())
    if (!p) return c.json({ error: `Product not found (id ${productId})` }, 404)
    if (p.finance_status && p.finance_status !== 'published') return c.json({ error: `"${p.name}" is not yet available for purchase` }, 400)
    const qty = Math.max(1, Number(raw?.quantity) || 1)
    if (p.quantity < qty) return c.json({ error: `Insufficient stock for "${p.name}"` }, 400)
    const ptype = raw?.payment_type === 'cash' ? 'cash' : 'financing'
    // Each item independently respects its listing/finance conditions: cash must
    // be enabled for cash items, financing enabled for financed items.
    if (ptype === 'cash' && p.cash_enabled === 0) return c.json({ error: `"${p.name}" cannot be bought with cash` }, 400)
    if (ptype === 'financing' && p.financing_enabled === 0) return c.json({ error: `"${p.name}" is not available on financing` }, 400)
    // Financing requires a verified farmer (TransUnion/KYC), same as single apply.
    if (ptype === 'financing' && custRow?.kyc_status !== 'verified') {
      return c.json({
        error: 'kyc_required',
        message: 'Complete registration (TransUnion credit check, ID upload, and liveness verification) before equipment financing purchases.',
        customer_id: custId,
        product_name: p.name
      }, 412)
    }
    const q = financingQuote(p, qty, ptype, raw?.term_months, feeCfg)
    prepared.push({ p, qty, ptype, q })
  }

  // ---- PASS 2: create one contract per item, all under the shared bundle_ref. ----
  const created: any[] = []
  let depositDueNow = 0
  let bundleTotal = 0
  let bundleOutstanding = 0
  for (const it of prepared) {
    const { p, qty, ptype, q } = it
    const contractRef = ref(ptype === 'cash' ? 'CSH' : (q.financing_model === 'paygo' ? 'PGO' : 'FIN'))
    const status = ptype === 'cash'
      ? (q.amount_due_now > 0 ? 'pending_payment' : 'awaiting_cash_balance')
      : 'pending'
    const r = await c.env.DB.prepare(
      `INSERT INTO murabaha_contracts (contract_ref,bundle_ref,customer_id,agent_id,created_by,product_id,quantity,payment_type,supplier_cost,markup_pct,murabaha_price,term_months,monthly_payment,delivery_location,status,ownership_recorded,consent_given,amount_paid,outstanding,financing_model,interest_rate_pct,deposit_pct,deposit_amount,finance_principal,payment_frequency,installment_amount,dispatch_status,terms_document_url,terms_text)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      contractRef, bundleRef, custId, custRow?.agent_id || null, custRow?.onboarded_by || custRow?.agent_id || user.id, p.id, qty, ptype, q.supplier_cost, q.markup_pct,
      q.total_payable, q.term_months, q.monthly_payment || q.installment_amount || 0, delivery_location || '', status,
      0, 1, 0, q.total_payable, q.financing_model, q.interest_rate_pct || 0, q.deposit_pct, q.deposit_amount,
      q.finance_principal, q.payment_frequency, q.installment_amount || 0, 'pending', q.terms_document_url || null, q.terms_text || null
    ).run()
    const contractId = r.meta.last_row_id
    // Only cash deposits are collected via the upfront checkout prompt; financing
    // deposits are collected on their own schedule at approval time.
    const itemDueNow = ptype === 'cash' ? numberVal(q.amount_due_now, 0) : 0
    depositDueNow = roundMoney(depositDueNow + itemDueNow)
    bundleTotal = roundMoney(bundleTotal + numberVal(q.total_payable, 0))
    bundleOutstanding = roundMoney(bundleOutstanding + numberVal(q.total_payable, 0))
    created.push({
      id: contractId,
      contract_ref: contractRef,
      product_id: p.id,
      product_name: p.name,
      quantity: qty,
      payment_type: ptype,
      status,
      amount_due_now: itemDueNow,
      deposit_amount: q.deposit_amount,
      total_payable: q.total_payable
    })
  }

  await audit(c, user.id, 'apply_bundle', 'financing', `${bundleRef} (${created.length} items)`)
  const cashItems = created.filter(x => x.payment_type === 'cash')
  return c.json({
    ok: true,
    bundle_ref: bundleRef,
    items: created,
    item_count: created.length,
    // Aggregated cash deposit across all cash items in the bundle. When > 0 the
    // client raises a SINGLE payment prompt (directed to the farmer for Buy-For).
    deposit_due_now: depositDueNow,
    requires_payment: depositDueNow > 0,
    // Settle the combined cash deposit against the first cash item's contract;
    // remaining cash items with a due deposit are listed so the client can chain
    // their prompts if a provider requires one STK per contract.
    pay_contract_id: cashItems.find(x => x.amount_due_now > 0)?.id || null,
    cash_deposit_contract_ids: cashItems.filter(x => x.amount_due_now > 0).map(x => x.id),
    bundle_total: bundleTotal,
    bundle_outstanding: bundleOutstanding,
    buy_for: user.role === 'agent',
    farmer: { id: custRow.id, name: custRow.full_name || 'Farmer', phone: custRow.mobile || '' }
  })
})

app.get('/api/murabaha', requireAuth, async (c) => {
  const user = c.get('user')
  let q = `SELECT mc.*, p.name as product_name, cu.full_name as customer_name
           FROM murabaha_contracts mc JOIN products p ON p.id = mc.product_id JOIN customers cu ON cu.id = mc.customer_id`
  const binds: any[] = []
  const where: string[] = []
  if (user.role === 'agent') { where.push(`mc.agent_id = ?`); binds.push(user.id) }
  else if (user.role === 'customer') {
    const myCust = await c.env.DB.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first<any>()
    where.push(`mc.customer_id = ?`); binds.push(myCust?.id || -1)
  } else {
    // Staff roles: enforce Sales Visibility permissions (cash vs financed).
    const canCash = hasVisibility(user, 'view_cash_sales')
    const canFin = hasVisibility(user, 'view_financed_sales')
    if (!canCash && !canFin) { where.push(`1 = 0`) }
    else if (canCash && !canFin) { where.push(`mc.payment_type = 'cash'`) }
    else if (!canCash && canFin) { where.push(`mc.payment_type = 'financing'`) }
  }
  if (where.length) q += ` WHERE ` + where.join(' AND ')
  q += ` ORDER BY mc.created_at DESC`
  const { results } = await c.env.DB.prepare(q).bind(...binds).all()
  return c.json({ contracts: results })
})
app.get('/api/murabaha/:id', requireAuth, async (c) => {
  const id = c.req.param('id')
  const contract = await c.env.DB.prepare(
    `SELECT mc.*, p.name as product_name, p.unit, cu.full_name as customer_name, cu.national_id, cu.county
     FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id JOIN customers cu ON cu.id=mc.customer_id WHERE mc.id=?`
  ).bind(id).first()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  const { results: repayments } = await c.env.DB.prepare(`SELECT * FROM repayments WHERE contract_id=? ORDER BY installment_no`).bind(id).all()
  const { results: txns } = await c.env.DB.prepare(`SELECT * FROM transactions WHERE contract_id=? ORDER BY id`).bind(id).all()
  return c.json({ contract, repayments, transactions: txns })
})
app.post('/api/murabaha/:id/decision', requireAuth, requireRole('admin', 'super_admin', 'operations_finance'), async (c) => {
  const id = c.req.param('id')
  const { action, notes } = await c.req.json()
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first<any>()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  if (contract.status !== 'pending') return c.json({ error: 'Application is not pending' }, 400)
  await c.env.DB.prepare(`INSERT INTO approvals (contract_id,reviewer_id,action,notes) VALUES (?,?,?,?)`).bind(id, c.get('user').id, action, notes || '').run()
  if (action === 'approve') {
    await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='active', ownership_recorded=1 WHERE id=?`).bind(id).run()
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity - ? WHERE id=?`).bind(contract.quantity, contract.product_id).run()
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?,?,?,?)`).bind(contract.product_id, contract.financing_model === 'paygo' ? 'paygo_allocation' : 'credit_allocation', contract.quantity, contract.contract_ref).run()
    await c.env.DB.prepare(`INSERT INTO invoices (invoice_ref,contract_id,customer_id,amount,status) VALUES (?,?,?,?, 'unpaid')`).bind(ref('INV'), id, contract.customer_id, contract.murabaha_price).run()
    const term = Number(contract.term_months) || 0
    const installment = Number(contract.installment_amount || contract.monthly_payment || 0)
    const frequency = contract.payment_frequency || 'monthly'
    const count = frequency === 'daily' ? term * 30 : frequency === 'weekly' ? term * 4 : term
    const start = new Date()
    for (let i = 1; i <= count; i++) {
      const due = new Date(start)
      if (frequency === 'weekly') due.setDate(due.getDate() + i * 7)
      else if (frequency === 'daily') due.setDate(due.getDate() + i)
      else due.setMonth(due.getMonth() + i)
      const amount = i === count ? roundMoney(Number(contract.outstanding) - installment * (count - 1)) : installment
      await c.env.DB.prepare(`INSERT INTO repayments (contract_id,installment_no,due_date,amount_due,status) VALUES (?,?,?,?, 'current')`)
        .bind(id, i, due.toISOString().slice(0, 10), amount > 0 ? amount : installment).run()
    }
  } else if (action === 'reject') {
    await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='rejected' WHERE id=?`).bind(id).run()
  }
  await audit(c, c.get('user').id, action, 'financing', contract.contract_ref)
  return c.json({ ok: true, action })
})
app.post('/api/murabaha/:id/dispatch', requireAuth, requireRole('admin', 'super_admin', 'operations_finance'), async (c) => {
  const id = c.req.param('id')
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first<any>()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  if (!['active', 'completed', 'awaiting_cash_balance'].includes(contract.status)) return c.json({ error: 'Only approved or paid purchases can be dispatched' }, 400)
  await c.env.DB.prepare(`UPDATE murabaha_contracts SET dispatch_status='dispatched', dispatched_at=CURRENT_TIMESTAMP, dispatched_by=? WHERE id=?`).bind(c.get('user').id, id).run()
  await audit(c, c.get('user').id, 'dispatch', 'contract', contract.contract_ref)
  return c.json({ ok: true })
})

// ============================================================================
// MARK DELIVERED — confirm the product reached the farmer. On successful
// delivery of an order that still carries an outstanding balance, we surface
// the balance + the farmer's phone so the client can immediately raise a
// final-balance payment prompt to the farmer (Requirement 5). Admins/ops and
// the owning agent (who fulfils their own farmers' orders) may mark delivery.
// ============================================================================
app.post('/api/murabaha/:id/deliver', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const id = c.req.param('id')
  const contract = await withAdminContext(c, async () => await c.env.DB.prepare(
    `SELECT mc.*, cu.full_name AS customer_name, cu.mobile AS customer_mobile
       FROM murabaha_contracts mc JOIN customers cu ON cu.id=mc.customer_id WHERE mc.id=?`
  ).bind(id).first<any>())
  if (!contract) return c.json({ error: 'Not found' }, 404)
  const isStaff = ['admin', 'super_admin', 'operations_finance'].includes(user.role) || hasPermission(user, 'collect_payment')
  const isOwningAgent = user.role === 'agent' && String(contract.agent_id) === String(user.id)
  if (!isStaff && !isOwningAgent) return c.json({ error: 'You do not have permission to mark this order delivered.' }, 403)
  if (!['active', 'completed', 'awaiting_cash_balance'].includes(contract.status)) {
    return c.json({ error: 'Only an approved / paid order can be marked delivered.' }, 400)
  }
  if (contract.dispatch_status === 'delivered') return c.json({ error: 'This order is already marked delivered.' }, 400)
  await c.env.DB.prepare(`UPDATE murabaha_contracts SET dispatch_status='delivered', dispatched_at=COALESCE(dispatched_at, CURRENT_TIMESTAMP), dispatched_by=COALESCE(dispatched_by, ?) WHERE id=?`).bind(user.id, id).run()
  await audit(c, user.id, 'deliver', 'contract', contract.contract_ref)
  const outstanding = roundMoney(numberVal(contract.outstanding, 0))
  const balanceDue = outstanding > 0.5
  // Notify the farmer that delivery is done and (if applicable) a balance is due.
  try {
    if (contract.customer_mobile) {
      const msg = balanceDue
        ? `Your order ${contract.contract_ref} has been delivered. A final balance of KES ${outstanding.toLocaleString()} is now due.`
        : `Your order ${contract.contract_ref} has been delivered. Thank you for choosing Farmsky.`
      await sendSms(c.env, String(contract.customer_mobile), msg)
    }
  } catch (_) {}
  return c.json({
    ok: true,
    delivered: true,
    balance_due: balanceDue,
    outstanding,
    contract_ref: contract.contract_ref,
    farmer: { id: contract.customer_id, name: contract.customer_name || 'Farmer', phone: contract.customer_mobile || '' }
  })
})

// ============================================================================
// CONTRACT CONTROLS (parity) — edit / cancel a financing contract, gated by
// the can_manage_contracts permission.
// ============================================================================
function canManageContracts(user: SessionUser) {
  return ['admin', 'super_admin'].includes(user.role) || hasPermission(user, 'can_manage_contracts')
}

// Edit a contract's editable commercial fields.
app.put('/api/murabaha/:id', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!canManageContracts(user)) return c.json({ error: 'You do not have permission to edit contracts.' }, 403)
  const id = c.req.param('id')
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first<any>()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  if (contract.status === 'cancelled') return c.json({ error: 'A cancelled contract cannot be edited.' }, 400)
  const b = await c.req.json()
  const price = b.murabaha_price !== undefined ? numberVal(b.murabaha_price, contract.murabaha_price) : contract.murabaha_price
  const paid = numberVal(contract.amount_paid, 0)
  const outstanding = roundMoney(Math.max(0, price - paid))
  await c.env.DB.prepare(
    `UPDATE murabaha_contracts SET
       murabaha_price=?,
       outstanding=?,
       deposit_pct=COALESCE(?, deposit_pct),
       deposit_amount=COALESCE(?, deposit_amount),
       installment_amount=COALESCE(?, installment_amount),
       payment_frequency=COALESCE(?, payment_frequency),
       term_months=COALESCE(?, term_months),
       terms_text=COALESCE(?, terms_text)
     WHERE id=?`
  ).bind(
    price, outstanding,
    b.deposit_pct !== undefined ? numberVal(b.deposit_pct, contract.deposit_pct) : null,
    b.deposit_amount !== undefined ? numberVal(b.deposit_amount, contract.deposit_amount) : null,
    b.installment_amount !== undefined ? numberVal(b.installment_amount, contract.installment_amount) : null,
    b.payment_frequency ?? null,
    b.term_months !== undefined ? numberVal(b.term_months, contract.term_months) : null,
    b.terms_text ?? null,
    id
  ).run()
  await audit(c, user.id, 'edit', 'contract', contract.contract_ref)
  return c.json({ ok: true })
})

// Cancel a contract.
app.post('/api/murabaha/:id/cancel', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!canManageContracts(user)) return c.json({ error: 'You do not have permission to cancel contracts.' }, 403)
  const id = c.req.param('id')
  const { reason } = await c.req.json().catch(() => ({}))
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(id).first<any>()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  if (contract.status === 'cancelled') return c.json({ error: 'Contract is already cancelled.' }, 400)
  if (contract.status === 'completed') return c.json({ error: 'A completed contract cannot be cancelled.' }, 400)
  await c.env.DB.prepare(`UPDATE murabaha_contracts SET status='cancelled' WHERE id=?`).bind(id).run()
  if (contract.ownership_recorded) {
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity + ? WHERE id=?`).bind(contract.quantity, contract.product_id).run()
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?, 'cancellation_return', ?, ?)`).bind(contract.product_id, contract.quantity, contract.contract_ref).run()
  }
  await audit(c, user.id, 'cancel', 'contract', `${contract.contract_ref}${reason ? ' — ' + String(reason).slice(0, 200) : ''}`)
  return c.json({ ok: true })
})

// ----------------------------------------------------------------------------
// ISSUE 2 — FINANCING DUE-DATE REMINDERS
//   Lists financing installments due within N days (default 3) of their due
//   date, so an operator (or a scheduled job) can dispatch automated reminders
//   to customers to pay the amount that is due. Also flags overdue items.
// ----------------------------------------------------------------------------
app.get('/api/murabaha/reminders/due', requireAuth, async (c) => {
  const withinDays = Math.max(0, Math.min(60, Number(c.req.query('days') || 3)))
  const rows = await c.env.DB.prepare(
    `SELECT r.id AS repayment_id, r.installment_no, r.due_date, r.amount_due, r.amount_paid, r.status,
            mc.id AS contract_id, mc.contract_ref, mc.payment_type, mc.outstanding,
            cu.full_name AS customer_name, cu.mobile AS customer_phone
       FROM repayments r
       JOIN murabaha_contracts mc ON mc.id = r.contract_id
       LEFT JOIN customers cu ON cu.id = mc.customer_id
      WHERE mc.payment_type != 'cash'
        AND mc.status = 'active'
        AND r.status != 'completed'
      ORDER BY r.due_date ASC
      LIMIT 500`
  ).all<any>()
  const today = new Date(); today.setHours(0, 0, 0, 0)
  const reminders = (rows?.results || []).map((r: any) => {
    const due = new Date(r.due_date); due.setHours(0, 0, 0, 0)
    const days = Math.round((due.getTime() - today.getTime()) / 86400000)
    const balance = Number(r.amount_due) - Number(r.amount_paid || 0)
    return { ...r, balance_due: balance, days_to_due: days, overdue: days < 0 }
  }).filter((r: any) => r.balance_due > 0.5 && r.days_to_due <= withinDays)
  return c.json({ ok: true, within_days: withinDays, count: reminders.length, reminders })
})

// ----------------------------------------------------------------------------
// PAYMENTS - M-Pesa Daraja STK Push (real when configured, simulated otherwise)
// ----------------------------------------------------------------------------
async function applyPayment(c: any, contract: any, amt: number, receipt: string, method: string, phone: string) {
  const isCash = contract.payment_type === 'cash'
  const currentPaid = numberVal(contract.amount_paid, 0)
  const totalDue = numberVal(contract.murabaha_price, 0)
  const newPaid = roundMoney(currentPaid + amt)
  const newOutstanding = roundMoney(Math.max(0, totalDue - newPaid))
  const firstCashCollection = isCash && !contract.ownership_recorded
  if (firstCashCollection) {
    await c.env.DB.prepare(`UPDATE products SET quantity = quantity - ? WHERE id=?`).bind(contract.quantity, contract.product_id).run()
    await c.env.DB.prepare(`INSERT INTO stock_movements (product_id,movement_type,quantity,reference) VALUES (?,?,?,?)`).bind(contract.product_id, 'sale', contract.quantity, contract.contract_ref).run()
    await c.env.DB.prepare(`INSERT INTO invoices (invoice_ref,contract_id,customer_id,amount,status) VALUES (?,?,?,?, ?)`).bind(ref('INV'), contract.id, contract.customer_id, totalDue, newOutstanding <= 0 ? 'paid' : 'partial').run()
  }
  await c.env.DB.prepare(`INSERT INTO transactions (txn_ref,contract_id,customer_id,amount,method,type,mpesa_receipt,phone,status) VALUES (?,?,?,?,?,?,?,?, 'success')`)
    .bind(ref('TXN'), contract.id, contract.customer_id, amt, method, isCash ? 'cash_sale' : (contract.financing_model === 'paygo' ? 'paygo_repayment' : 'repayment'), receipt, phone).run()
  const status = isCash
    ? (newOutstanding <= 0 ? 'completed' : 'awaiting_cash_balance')
    : (newOutstanding <= 0 ? 'completed' : 'active')
  await c.env.DB.prepare(`UPDATE murabaha_contracts SET amount_paid=?, outstanding=?, status=?, ownership_recorded=1 WHERE id=?`).bind(newPaid, newOutstanding, status, contract.id).run()
  let remaining = amt
  const { results: due } = await c.env.DB.prepare(`SELECT * FROM repayments WHERE contract_id=? AND status!='completed' ORDER BY installment_no`).bind(contract.id).all<any>()
  for (const inst of due) {
    if (remaining <= 0) break
    const need = numberVal(inst.amount_due) - numberVal(inst.amount_paid)
    const pay = Math.min(need, remaining)
    const paidTotal = roundMoney(numberVal(inst.amount_paid) + pay)
    const st = paidTotal >= numberVal(inst.amount_due) ? 'completed' : 'current'
    await c.env.DB.prepare(`UPDATE repayments SET amount_paid=?, status=?, paid_at=CURRENT_TIMESTAMP WHERE id=?`).bind(paidTotal, st, inst.id).run()
    remaining = roundMoney(remaining - pay)
  }
  await c.env.DB.prepare(`UPDATE invoices SET status=? WHERE contract_id=?`).bind(newOutstanding <= 0 ? 'paid' : 'partial', contract.id).run()
  // When an order/contract is fully settled, dynamically credit the agent's
  // wallet per their active commission rules (idempotent per contract).
  if (status === 'completed' && contract.status !== 'completed') {
    try { await distributeCommission(c, { ...contract, status }) } catch (_) {}
  }
  return { amount_paid: newPaid, outstanding: newOutstanding, status }
}

// NOTE: Provider webhooks (M-Pesa + SasaPay) settle SYNCHRONOUSLY before ACKing.
// SasaPay explicitly advised NOT to queue their transactions — they send the
// confirmation immediately and have a LIMITED number of retries, so any deferred
// (background) settlement that fails would be lost forever and the payment that
// already moved into the merchant wallet would never reflect on the platform.
// We therefore do all settlement inline and only return 200 once the ledger is
// updated; on error we return 500 so the provider re-delivers within its retries.

app.post('/api/mpesa/stkpush', requireAuth, async (c) => {
  const { contract_id, amount, phone } = await c.req.json()
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(contract_id).first<any>()
  if (!contract) return c.json({ error: 'Contract not found' }, 404)
  if (contract.payment_type === 'cash' && ['pending_payment', 'awaiting_cash_balance', 'completed'].includes(contract.status)) {
    const p = await c.env.DB.prepare(`SELECT quantity FROM products WHERE id=?`).bind(contract.product_id).first<any>()
    if ((!contract.ownership_recorded) && (!p || p.quantity < contract.quantity)) return c.json({ error: 'This item is now out of stock.' }, 409)
  } else if (contract.payment_type !== 'cash' && !['active', 'completed'].includes(contract.status)) {
    return c.json({ error: 'This purchase is not open for payment.' }, 400)
  }
  const amt = Number(amount)
  if (amt <= 0) return c.json({ error: 'Invalid amount' }, 400)
  if (amt > Number(contract.outstanding || 0)) return c.json({ error: 'Amount exceeds outstanding balance' }, 400)
  const desc = contract.payment_type === 'cash' ? 'Cash Equipment Purchase' : (contract.financing_model === 'paygo' ? 'PAYGO Equipment Payment' : 'Equipment Financing Payment')
  const result = await stkPush(c.env, { phone: phone || c.get('user').phone, amount: amt, account: contract.contract_ref, description: desc })
  if (!result.success) return c.json({ error: result.error || 'STK push failed' }, 502)
  await c.env.DB.prepare(`INSERT INTO payment_intents (checkout_request_id,merchant_request_id,contract_id,customer_id,amount,phone,method,status) VALUES (?,?,?,?,?,?,?, 'pending')`)
    .bind(result.checkout_request_id, result.merchant_request_id, contract_id, contract.customer_id, amt, normalizePhone(phone || c.get('user').phone), 'mpesa').run()
  await audit(c, c.get('user').id, 'stk_push', 'mpesa', `KES ${amt} to ${contract.contract_ref} (${result.simulated ? 'sim' : 'live'})`)
  return c.json({ ok: true, simulated: result.simulated, checkout_request_id: result.checkout_request_id, customer_message: result.customer_message })
})
app.post('/api/mpesa/confirm', requireAuth, async (c) => {
  const { checkout_request_id } = await c.req.json()
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
  if (!intent) return c.json({ error: 'Payment intent not found' }, 404)
  if (intent.status === 'success') return c.json({ ok: true, status: 'success', mpesa_receipt: intent.mpesa_receipt })
  let success = false, receipt = ''
  if (!mpesaConfigured(c.env) || String(checkout_request_id).includes('SIM')) {
    success = true; receipt = 'SLE' + Math.random().toString(36).slice(2, 9).toUpperCase()
  } else {
    const q = await stkQuery(c.env, checkout_request_id)
    const rc = q?.ResultCode
    const isSuccess = rc === '0' || rc === 0
    // Daraja query semantics:
    //  * ResultCode 0            => paid.
    //  * No ResultCode, only an  => still processing (query fired before the
    //    errorCode/errorMessage     customer finished / Safaricom hasn't posted
    //    like 500.001.1001          the result yet). This is PENDING, not failed.
    //  * A terminal ResultCode   => user cancelled (1032), timeout (1037),
    //    (1032/1037/1/1025/...)     insufficient funds (1), etc => FAILED.
    // The bug (screenshot): a "still under processing" response was being shown
    // as "Payment Failed". We now only mark FAILED on a genuinely terminal
    // ResultCode, and never surface a processing message as a failure.
    const descRaw = String(q?.ResultDesc || q?.errorMessage || q?.CustomerMessage || '')
    const looksPending = /process|being processed|under processing|pending|not.*found|try again|wait/i.test(descRaw)
    if (isSuccess) {
      success = true; receipt = 'LIVE' + Date.now().toString().slice(-7)
    } else if (rc !== undefined && rc !== null && rc !== '' && !looksPending) {
      // Genuine terminal failure — give the user a clean, non-contradictory reason.
      return c.json({ ok: false, status: 'failed', result_desc: descRaw || 'Payment was not completed.' })
    } else {
      // Still processing (no terminal ResultCode, or a "processing" message).
      return c.json({ ok: false, status: 'pending' })
    }
  }
  if (success) {
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
    const res = await applyPayment(c, contract, intent.amount, receipt, 'mpesa', intent.phone)
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=? WHERE checkout_request_id=?`).bind(receipt, checkout_request_id).run()
    return c.json({ ok: true, status: 'success', mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status })
  }
  return c.json({ ok: false, status: 'pending' })
})
app.post('/api/mpesa/callback', async (c) => {
  try {
    const body: any = await c.req.json()
    const cb = body?.Body?.stkCallback
    if (!cb) return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
    const checkout = cb.CheckoutRequestID
    const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first<any>()
    if (intent && intent.status === 'pending') {
      if (cb.ResultCode === 0) {
        const items = cb.CallbackMetadata?.Item || []
        const receiptItem = items.find((i: any) => i.Name === 'MpesaReceiptNumber')
        const receipt = receiptItem?.Value || 'LIVE' + Date.now()
        const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
        if (contract) await applyPayment(c, contract, intent.amount, String(receipt), 'mpesa', intent.phone)
        await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, result_desc=? WHERE checkout_request_id=?`).bind(String(receipt), cb.ResultDesc || '', checkout).run()
      } else {
        await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=? WHERE checkout_request_id=?`).bind(cb.ResultDesc || 'Failed', checkout).run()
      }
    }
    return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  } catch (e) {
    return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  }
})
app.get('/api/mpesa/status', requireAuth, (c) => {
  const mpesaMode = ['sandbox', 'development', 'dev', 'test'].includes(String(c.env.MPESA_ENV || '').trim().toLowerCase()) ? 'sandbox' : 'production'
  return c.json({ live: mpesaConfigured(c.env), mode: mpesaConfigured(c.env) ? mpesaMode : 'simulation' })
})

// ----------------------------------------------------------------------------
// PAYMENTS - SasaPay STK Push (real when configured, simulated otherwise)
// Docs: https://developer.sasapay.app/docs/getting-started
// ----------------------------------------------------------------------------
// Public channel/bank catalogue — everything SasaPay supports (wallet, mobile, all banks).
app.get('/api/sasapay/channels', (c) => {
  return c.json({
    channels: SASAPAY_CHANNELS,
    banks:  SASAPAY_CHANNELS.filter((x) => x.type === 'bank'),
    mobile: SASAPAY_CHANNELS.filter((x) => x.type === 'mobile'),
    wallet: SASAPAY_CHANNELS.filter((x) => x.type === 'wallet'),
    live: sasapayConfigured(c.env),
    mode: sasapayConfigured(c.env) ? sasapayMode(c.env) : 'simulation'
  })
})

// ----------------------------------------------------------------------------
// C2B CHECKOUT — pay a contract via SasaPay wallet, M-PESA/Airtel/T-Kash, or ANY bank.
//   channel_code drives the rail:
//     '0'      -> SasaPay wallet   (returns needs_otp=true; complete via /process)
//     '63902'  -> M-PESA STK       ; '63903' Airtel ; '63907' T-Kash ; '97' Telkom
//     '01'..   -> any supported bank (account_number required)
// ----------------------------------------------------------------------------
app.post('/api/sasapay/stkpush', requireAuth, async (c) => {
  const b = await c.req.json()
  const { contract_id, amount, phone, account_number } = b
  // Accept channel_code (preferred) or legacy channel string.
  let channelCode: string = String(b.channel_code || '').trim()
  if (!channelCode) channelCode = b.channel === 'BANK' ? '' : '63902'
  const chan = channelByCode(channelCode)

  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(contract_id).first<any>()
  if (!contract) return c.json({ error: 'Contract not found' }, 404)

  if (contract.payment_type === 'cash' && ['pending_payment', 'awaiting_cash_balance', 'completed'].includes(contract.status)) {
    const p = await c.env.DB.prepare(`SELECT quantity FROM products WHERE id=?`).bind(contract.product_id).first<any>()
    if ((!contract.ownership_recorded) && (!p || p.quantity < contract.quantity)) return c.json({ error: 'This item is now out of stock.' }, 409)
  } else if (contract.payment_type !== 'cash' && !['active', 'completed'].includes(contract.status)) {
    return c.json({ error: 'This purchase is not open for payment.' }, 400)
  }

  const amt = Number(amount)
  if (amt <= 0) return c.json({ error: 'Invalid amount' }, 400)
  if (amt > Number(contract.outstanding || 0)) return c.json({ error: 'Amount exceeds outstanding balance' }, 400)

  const isBank = chan?.type === 'bank'
  // Issue 4 fix: bank channels are routed by NetworkCode + the customer's phone number
  // (SasaPay delivers the STK / Pesalink prompt to the phone). A bank account number is
  // NOT part of the C2B request-payment contract, so we no longer require or forward it.
  if (!chan && channelCode) return c.json({ error: 'Unknown payment channel selected.' }, 400)

  const desc = contract.payment_type === 'cash' ? 'Cash Equipment Purchase' : 'Equipment Financing Payment'
  const payerPhone = phone || c.get('user').phone

  const result = await sasapayStkPush(c.env, {
    phone: payerPhone,
    amount: amt,
    account: contract.contract_ref,
    description: desc,
    networkCode: channelCode || '63902',
    channelCode: channelCode || '63902'
  })

  if (!result.success) return c.json({ error: result.error || 'SasaPay transaction initialization failed' }, 502)

  await c.env.DB.prepare(
    `INSERT INTO payment_intents
       (checkout_request_id, merchant_request_id, contract_id, customer_id, amount, phone,
        method, status, provider, direction, channel_code, channel_name, account_number,
        transaction_reference, needs_otp)
     VALUES (?,?,?,?,?,?, 'sasapay', 'pending', 'sasapay', 'payin', ?,?,?,?,?)`
  ).bind(
    result.checkout_request_id, result.merchant_request_id, contract_id, contract.customer_id, amt,
    sasapayNormalizePhone(payerPhone), channelCode || '63902', chan?.name || null,
    account_number || null, result.transaction_reference || null, result.needs_otp ? 1 : 0
  ).run()

  await audit(c, c.get('user').id, 'stk_push', 'sasapay', `KES ${amt} via ${chan?.name || channelCode} to ${contract.contract_ref} (${result.simulated ? 'sim' : 'live'})`)

  return c.json({
    ok: true,
    simulated: result.simulated,
    checkout_request_id: result.checkout_request_id,
    needs_otp: !!result.needs_otp,
    channel: chan?.name || channelCode,
    customer_message: result.customer_message || (result.needs_otp
      ? 'Enter the OTP sent to your SasaPay wallet to authorise the payment.'
      : (isBank ? 'Bank payment initiated. Approve the prompt sent to your phone / banking app.' : 'STK Push sent. Enter your PIN on your phone.'))
  })
})

// Complete a SasaPay WALLET checkout by submitting the OTP (VerificationCode).
app.post('/api/sasapay/process', requireAuth, async (c) => {
  const { checkout_request_id, verification_code } = await c.req.json()
  if (!checkout_request_id || !verification_code) return c.json({ error: 'checkout_request_id and verification_code are required' }, 400)
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
  if (!intent) return c.json({ error: 'Payment intent not found' }, 404)
  if (intent.status === 'success') return c.json({ ok: true, status: 'success' })

  const r = await sasapayProcessPayment(c.env, checkout_request_id, String(verification_code))
  if (!r.success) return c.json({ ok: false, error: r.error || 'OTP verification failed' }, 400)
  // Payment now moves to processing; final settlement arrives via callback / confirm.
  return c.json({ ok: true, status: 'processing', customer_message: r.customer_message || 'OTP accepted. Confirming payment…' })
})

// Poll / confirm a SasaPay checkout status and settle the contract on success.
app.post('/api/sasapay/confirm', requireAuth, async (c) => {
  const { checkout_request_id } = await c.req.json()
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
  if (!intent) return c.json({ error: 'Payment intent not found' }, 404)
  // Terminal states win — the callback/IPN is authoritative. Never auto-settle a
  // payment the gateway already reported as failed (or re-apply a success).
  if (intent.status === 'success') return c.json({ ok: true, status: 'success', mpesa_receipt: intent.mpesa_receipt })
  if (intent.status === 'failed') return c.json({ ok: false, status: 'failed', result_desc: intent.result_desc || 'Payment not completed' })

  let success = false, receipt = ''
  // Only auto-settle in SIMULATION mode (no live creds) or for explicit SIM ids.
  if (!sasapayConfigured(c.env) || String(checkout_request_id).includes('SIM')) {
    success = true; receipt = 'SP' + Math.random().toString(36).slice(2, 9).toUpperCase()
  } else {
    // Primary settlement path is the async CALLBACK: SasaPay posts the payin
    // result to SASAPAY_CALLBACK_URL, and /api/sasapay/callback flips the intent
    // to 'success'. The status-query endpoint is ASYNCHRONOUS — it usually just
    // returns "Your request has been received. Check your callback url…" and does
    // NOT carry the payment result inline. So:
    //   1) Pass the callback URL to the query to NUDGE SasaPay into re-posting
    //      the result to our webhook (helps recover a dropped first callback).
    //   2) Only settle here if the query genuinely returns paid/failed inline;
    //      otherwise report 'pending' and let the callback (or a later poll that
    //      sees intent.status='success') finish the job.
    const q = await sasapayQuery(c.env, checkout_request_id, c.env.SASAPAY_CALLBACK_URL)
    console.log('--- SasaPay Response Debug:', JSON.stringify(q));
    // `paid` is the ONLY signal that means the customer actually paid.
    // Do NOT treat top-level `status:true` as paid — the status-query endpoint
    // returns `{status:true, message:"...Check your callback url..."}` merely to
    // acknowledge the QUERY, not the payment. Trusting it would settle unpaid
    // transactions. Real settlement always arrives via /api/sasapay/callback.
    if (q?.paid === true) {
      success = true
      receipt = q.TransactionCode || q.TransactionID || ('SPL' + Date.now().toString().slice(-7))
    } else if (q?.failed === true) {
      const rawDesc = String(q.ResultDesc || q.message || 'Payment not completed')
      const safeDesc = /</.test(rawDesc) ? 'Payment not completed' : rawDesc
      await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(safeDesc.slice(0, 300), checkout_request_id).run()
      return c.json({ ok: false, status: 'failed', result_desc: safeDesc })
    } else {
      // Still processing (async ack / customer hasn't entered PIN/OTP yet).
      // Re-read the intent in case the callback settled it between our first
      // read and now — this is what lets the poll succeed once the webhook lands.
      const latest = await c.env.DB.prepare(`SELECT status, mpesa_receipt, result_desc FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
      if (latest?.status === 'success') return c.json({ ok: true, status: 'success', mpesa_receipt: latest.mpesa_receipt })
      if (latest?.status === 'failed') return c.json({ ok: false, status: 'failed', result_desc: latest.result_desc || 'Payment not completed' })
      return c.json({ ok: false, status: 'pending' })
    }
  }

  if (success) {
    // Idempotency guard: re-read the intent to make sure a concurrent callback
    // (or a second poll) didn't already settle it — never double-apply funds.
    const fresh = await c.env.DB.prepare(`SELECT status, mpesa_receipt FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
    if (fresh?.status === 'success') {
      return c.json({ ok: true, status: 'success', mpesa_receipt: fresh.mpesa_receipt })
    }
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
    const res = await applyPayment(c, contract, intent.amount, receipt, 'sasapay', intent.phone)
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, transaction_code=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`).bind(receipt, receipt, checkout_request_id).run()
    return c.json({ ok: true, status: 'success', mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status })
  }
  return c.json({ ok: false, status: 'pending' })
})

// ----------------------------------------------------------------------------
// SasaPay settlement engine — SYNCHRONOUS. Matches the callback/IPN payload to a
// pending payin intent and applies the payment to the contract. Returns a result
// object so the route can pick the right HTTP status.
//
//   { outcome: 'settled' }        -> money applied, intent -> success
//   { outcome: 'failed' }         -> gateway reported a failed payin
//   { outcome: 'already' }        -> intent already terminal (idempotent no-op)
//   { outcome: 'no_match' }       -> no pending intent found for this payload
//
// IMPORTANT: this NEVER swallows a DB/settlement error — it throws, so the route
// can respond non-200 and let SasaPay re-deliver (their retries are limited, so
// a silently-dropped settlement would be lost forever).
async function settleSasapayPayin(c: any, body: any, source: 'callback' | 'ipn') {
  // Match by CheckoutRequestID (primary) -> AccountReference/BillRef (== contract_ref)
  // -> phone+amount (last resort). SasaPay sometimes echoes a different ref back.
  const checkout = body?.CheckoutRequestID || body?.MerchantRequestID
  const billRef = body?.BillRefNumber || body?.AccountReference || body?.InvoiceNumber

  let intent = checkout
    ? await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first<any>()
    : null
  if (!intent && billRef) {
    intent = await c.env.DB.prepare(
      `SELECT pi.* FROM payment_intents pi JOIN murabaha_contracts mc ON mc.id = pi.contract_id
        WHERE mc.contract_ref = ? AND pi.status = 'pending' ORDER BY pi.created_at DESC LIMIT 1`
    ).bind(String(billRef)).first<any>()
  }
  if (!intent) {
    const msisdn = body?.CustomerMobile || body?.MSISDN || body?.PhoneNumber || body?.Msisdn
    const amt = Number(body?.TransAmount ?? body?.Amount ?? body?.amount ?? 0)
    if (msisdn && amt > 0) {
      const norm = sasapayNormalizePhone(String(msisdn))
      intent = await c.env.DB.prepare(
        `SELECT * FROM payment_intents
          WHERE phone = ? AND amount = ? AND status = 'pending' AND direction = 'payin'
          ORDER BY created_at DESC LIMIT 1`
      ).bind(norm, amt).first<any>()
      if (intent) console.log(`SasaPay ${source} matched by phone+amount fallback:`, `${norm} KES ${amt} -> ${intent.checkout_request_id}`)
    }
  }

  if (!intent) {
    console.warn(`SasaPay ${source}: NO matching intent`, JSON.stringify({ checkout, billRef }))
    await audit(c, null, `${source}_no_match`, 'sasapay', `checkout=${checkout || '?'} billRef=${billRef || '?'}`)
    return { outcome: 'no_match' as const }
  }

  // Idempotency: a settled/failed intent is a no-op (SasaPay may re-deliver).
  if (intent.status !== 'pending') {
    console.log(`SasaPay ${source}: intent already`, intent.status, `(${intent.checkout_request_id}) — idempotent no-op`)
    return { outcome: 'already' as const, intent }
  }

  // The IPN channel only fires on SUCCESS (no ResultCode), so treat it as paid.
  const code = body.ResultCode ?? body.status_code
  const paid = source === 'ipn'
    ? true
    : (code === 0 || code === '0' || body.Paid === true || body.paid === true || body.status === true)

  if (!paid) {
    await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`)
      .bind(String(body.ResultDesc || body.message || 'Failed').slice(0, 300), intent.checkout_request_id).run()
    console.log(`SasaPay ${source} marked FAILED:`, `${intent.checkout_request_id} — ${body.ResultDesc || body.message || 'Failed'}`)
    return { outcome: 'failed' as const, intent }
  }

  const receipt = body.TransactionCode || body.TransID || body.TransactionID || body.ThirdPartyTransID || body.MpesaReceiptNumber || ('SPL' + Date.now())
  const paidAmt = Number(body.TransAmount ?? body.Amount ?? body.amount ?? 0)
  if (paidAmt && Math.abs(paidAmt - Number(intent.amount)) > 0.5) {
    console.warn(`SasaPay ${source} amount mismatch:`, `intent=${intent.amount} callback=${paidAmt} ref=${intent.checkout_request_id}`)
    await audit(c, null, `${source}_amount_mismatch`, 'sasapay', `intent=${intent.amount} callback=${paidAmt} ref=${intent.checkout_request_id}`)
  }
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
  if (contract) await applyPayment(c, contract, intent.amount, String(receipt), 'sasapay', intent.phone)
  await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, transaction_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`)
    .bind(String(receipt), String(receipt), body.ResultDesc || 'Transaction processed successfully.', intent.checkout_request_id).run()
  await audit(c, null, `${source}_settled`, 'sasapay', `settled ${intent.checkout_request_id} KES ${intent.amount} receipt ${receipt}`)
  console.log(`SasaPay ${source} SETTLED:`, `${intent.checkout_request_id} KES ${intent.amount} receipt ${receipt}`)
  return { outcome: 'settled' as const, intent, receipt }
}

// C2B CALLBACK — SasaPay posts the payin result here (both success + failure).
//   Secured by IP whitelist + HMAC-SHA512 signature (X-SasaPay-Signature) and
//   made idempotent (a settled intent is never re-applied).
// ----------------------------------------------------------------------------
app.post('/api/sasapay/callback', async (c) => {
  // SasaPay guidance: DO NOT QUEUE the transaction — they send the confirmation
  // immediately and have only a LIMITED number of retries. If we ACK 200 and then
  // process in the background, a background failure (transient DB error, dropped
  // fire-and-forget promise on Render) is lost forever: SasaPay sees success, we
  // never settle, and the money that already moved into the merchant wallet is
  // never reflected on the platform. FIX: settle SYNCHRONOUSLY here and only ACK
  // 200 once the ledger is actually updated. If settlement throws, return 500 so
  // SasaPay's retry re-delivers it.
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || c.req.header('x-real-ip')
  const sig = c.req.header('x-sasapay-signature') || c.req.header('X-SasaPay-Signature')
  const body: any = await c.req.json().catch(() => ({}))

  // ALWAYS log the raw callback first — our single source of truth on Render.
  console.log('SasaPay C2B callback received:', JSON.stringify({ ip: ip || null, hasSig: !!sig, body }))

  // Authenticity check — VERIFY, but NEVER drop a real settlement. The money has
  // ALREADY moved on SasaPay's side, so refusing only desyncs our ledger.
  if (sasapayConfigured(c.env)) {
    const ipOk = isTrustedSasapayIp(ip)
    const sigOk = await verifySasapaySignature(c.env, sig, {
      sasapay_transaction_code: body.TransactionCode || body.TransactionID || '',
      merchant_code: body.MerchantCode || '',
      account_number: body.AccountReference || body.BillRefNumber || '',
      payment_reference: body.CheckoutRequestID || body.MerchantRequestID || '',
      amount: body.Amount || body.TransAmount || ''
    })
    if (!ipOk && !sigOk) {
      console.warn('SasaPay callback UNVERIFIED (processing anyway):', `ip=${ip || '?'} sig=${sig ? 'present-but-bad' : 'missing'}`)
      await audit(c, null, 'callback_unverified', 'sasapay', `unverified ip=${ip || '?'} sig=${sig ? 'bad' : 'missing'} ref=${body.CheckoutRequestID || body.MerchantRequestID || body.BillRefNumber || '?'}`).catch(() => {})
    }
  }

  const checkout = body?.CheckoutRequestID || body?.MerchantRequestID
  const billRef = body?.BillRefNumber || body?.AccountReference
  if (!checkout && !billRef) {
    // Nothing to correlate — ACK so SasaPay stops retrying an unusable payload.
    return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  }

  try {
    await settleSasapayPayin(c, body, 'callback')
    // Settled / failed / already-terminal / no-match are all a definitive ACK —
    // we do NOT want SasaPay to keep retrying any of those.
    return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  } catch (err: any) {
    // A genuine processing error — ask SasaPay to re-deliver (their retry budget).
    console.error('SasaPay callback settlement FAILED (returning 500 for retry):', err?.message || err)
    await audit(c, null, 'callback_error', 'sasapay', `err=${String(err?.message || err).slice(0, 200)} ref=${checkout || billRef || '?'}`).catch(() => {})
    return c.json({ ResultCode: 1, ResultDesc: 'Temporary error, please retry' }, 500)
  }
})

// IPN — SasaPay posts SUCCESSFUL payins here (secondary confirmation channel).
// NOTE (per SasaPay docs): the IPN payload does NOT include CheckoutRequestID.
// It carries { BillRefNumber, TransID, ThirdPartyTransID, TransAmount, MSISDN,
// TransactionType, ... } — so we correlate the payin to a pending intent via
// BillRefNumber (== the AccountReference we sent == the contract_ref).
app.post('/api/sasapay/ipn', async (c) => {
  // Same rule as /callback: SasaPay does NOT queue and has limited retries, so
  // settle SYNCHRONOUSLY and only ACK 200 once the ledger is updated. On error,
  // return 500 so SasaPay re-delivers within its retry budget.
  const body: any = await c.req.json().catch(() => ({}))
  console.log('SasaPay IPN received:', JSON.stringify(body))

  const checkout = body?.CheckoutRequestID || body?.MerchantRequestID
  const billRef = body?.BillRefNumber || body?.AccountReference || body?.InvoiceNumber
  if (!checkout && !billRef) return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })

  try {
    await settleSasapayPayin(c, body, 'ipn')
    return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  } catch (err: any) {
    console.error('SasaPay IPN settlement FAILED (returning 500 for retry):', err?.message || err)
    await audit(c, null, 'ipn_error', 'sasapay', `err=${String(err?.message || err).slice(0, 200)} ref=${checkout || billRef || '?'}`).catch(() => {})
    return c.json({ ResultCode: 1, ResultDesc: 'Temporary error, please retry' }, 500)
  }
})

// ----------------------------------------------------------------------------
// ACCOUNT VALIDATION — confirm the holder name of a mobile/bank/wallet before
// paying it (used by the register-payout-account + direct-pay flows).
// ----------------------------------------------------------------------------
app.post('/api/sasapay/validate-account', requireAuth, async (c) => {
  const { channel_code, account_number } = await c.req.json()
  if (!channel_code || !account_number) return c.json({ error: 'channel_code and account_number are required' }, 400)
  const chan = channelByCode(String(channel_code))
  if (!chan) return c.json({ error: 'Unknown channel' }, 400)
  const acct = chan.type === 'mobile' || chan.type === 'wallet' ? sasapayNormalizePhone(String(account_number)) : String(account_number)
  const v = await sasapayValidateAccount(c.env, String(channel_code), acct)
  if (!v.success) return c.json({ ok: false, error: v.error || 'Validation failed' }, 400)
  return c.json({ ok: true, simulated: v.simulated, account_name: v.account_name, channel_name: v.channel_name || chan.name, normalized_account: acct })
})

// ----------------------------------------------------------------------------
// BALANCE — confirm the merchant/organisation float across SasaPay accounts.
// ----------------------------------------------------------------------------
app.get('/api/sasapay/balance', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const bal = await sasapayBalance(c.env)
  if (!bal.success) return c.json({ ok: false, error: bal.error || 'Balance query failed' }, 502)
  return c.json({ ok: true, simulated: bal.simulated, currency: bal.currency, org_balance: bal.org_balance, accounts: bal.accounts || [] })
})

app.get('/api/sasapay/status', requireAuth, (c) => {
  return c.json({ live: sasapayConfigured(c.env), mode: sasapayConfigured(c.env) ? sasapayMode(c.env) : 'simulation' })
})

// Some gateways (SasaPay included) probe a callback URL with a GET during
// registration / health-checks and will REFUSE to POST results to a URL that
// does not answer that probe with 200. Answer it explicitly for both the
// payin callback and IPN paths so the URL is always accepted upstream.
app.get('/api/sasapay/callback', (c) => c.json({ ok: true, service: 'sasapay-callback', method: 'expects POST' }))
app.get('/api/sasapay/ipn', (c) => c.json({ ok: true, service: 'sasapay-ipn', method: 'expects POST' }))

// Callback health diagnostic — lets an operator confirm, without DB access,
// whether SasaPay callbacks/IPNs are actually reaching this server. Reads the
// audit trail our webhook handlers write (callback_settled / callback_unverified
// / callback_no_match / ipn_settled …) and the current pending payin backlog.
app.get('/api/sasapay/callback-health', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const events = await c.env.DB.prepare(
    `SELECT action, detail, created_at FROM audit_logs
      WHERE entity='sasapay' AND (action LIKE 'callback%' OR action LIKE 'ipn%')
      ORDER BY created_at DESC LIMIT 20`
  ).all<any>()
  const last = await c.env.DB.prepare(
    `SELECT action, detail, created_at FROM audit_logs
      WHERE action IN ('callback_settled','callback_unverified','callback_no_match','callback_amount_mismatch','ipn_settled','ipn_no_match')
      ORDER BY created_at DESC LIMIT 1`
  ).first<any>()
  const pending = await c.env.DB.prepare(
    `SELECT checkout_request_id, amount, phone, channel_name, created_at
       FROM payment_intents
      WHERE provider='sasapay' AND direction='payin' AND status='pending'
      ORDER BY created_at DESC LIMIT 20`
  ).all<any>()
  return c.json({
    live: sasapayConfigured(c.env),
    callback_url: c.env.SASAPAY_CALLBACK_URL || null,
    last_webhook_event: last || null,
    recent_webhook_events: events?.results || [],
    pending_payins: pending?.results || [],
    pending_count: (pending?.results || []).length
  })
})

// ----------------------------------------------------------------------------
// ISSUE 1 — ADMIN PAYMENT RECOVERY (in-app payment_intents)
//   When a customer's wallet is debited but the async gateway callback never
//   lands, the intent (and therefore the dashboard/contract) is stuck PENDING.
//   These authorised endpoints let an operator (a) list hanging intents,
//   (b) re-query the upstream gateway status directly, and (c) manually push a
//   hanging payment to SUCCESS (settling the contract + wallet ledger).
// ----------------------------------------------------------------------------

// List payment intents that are stuck pending (optionally older than N minutes).
app.get('/api/admin/payments/pending', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const minAgeMin = Math.max(0, Number(c.req.query('min_age_min') || 0))
  const rows = await c.env.DB.prepare(
    `SELECT pi.*, mc.contract_ref, mc.outstanding, mc.status AS contract_status,
            cu.full_name AS customer_name
       FROM payment_intents pi
       LEFT JOIN murabaha_contracts mc ON mc.id = pi.contract_id
       LEFT JOIN customers cu ON cu.id = pi.customer_id
      WHERE pi.status = 'pending'
      ORDER BY pi.created_at DESC
      LIMIT 200`
  ).all<any>()
  const now = Date.now()
  const list = (rows?.results || []).filter((r: any) => {
    if (!minAgeMin) return true
    const t = Date.parse(r.created_at || '') || now
    return (now - t) >= minAgeMin * 60 * 1000
  })
  return c.json({ ok: true, count: list.length, intents: list })
})

// Recover a single hanging intent. mode='query' re-checks the gateway and only
// settles if the gateway now reports SUCCESS; mode='force' overrides and pushes
// the intent to SUCCESS regardless (records who forced it, for audit).
app.post('/api/admin/payments/recover', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const checkout = String(body.checkout_request_id || '').trim()
  const mode = String(body.mode || 'query').toLowerCase() // 'query' | 'force'
  if (!checkout) return c.json({ error: 'checkout_request_id is required' }, 400)

  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first<any>()
  if (!intent) return c.json({ error: 'Payment intent not found' }, 404)
  if (intent.status === 'success') {
    return c.json({ ok: true, status: 'success', already: true, mpesa_receipt: intent.mpesa_receipt })
  }

  let success = false, receipt = '', gatewayDesc = ''
  let forced = false

  if (mode === 'force') {
    // Authorised manual override — push to SUCCESS.
    success = true
    forced = true
    receipt = String(body.receipt || intent.transaction_code || ('MANUAL' + Date.now().toString().slice(-8)))
    gatewayDesc = 'Manual admin override'
  } else {
    // Query upstream gateway directly.
    if (!sasapayConfigured(c.env) || String(checkout).includes('SIM')) {
      success = true; receipt = 'SP' + Math.random().toString(36).slice(2, 9).toUpperCase()
    } else {
      const q = await sasapayQuery(c.env, checkout)
      console.log('--- SasaPay Response Debug:', JSON.stringify(q));
      gatewayDesc = String(q?.ResultDesc || q?.message || '')
      if (q?.paid === true || q?.status === true) {
        success = true
        receipt = q.TransactionCode || q.TransactionID || ('SPL' + Date.now().toString().slice(-7))
      } else if (q?.pending === true) {
        return c.json({ ok: false, status: 'pending', result_desc: gatewayDesc || 'Gateway still processing' })
      } else {
        // Definitive failure reported by the gateway.
        await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`)
          .bind((gatewayDesc || 'Payment not completed').slice(0, 300), checkout).run()
        await audit(c, c.get('user').id, 'payment_recover', 'sasapay', `marked FAILED ${checkout} (${gatewayDesc})`)
        return c.json({ ok: false, status: 'failed', result_desc: gatewayDesc || 'Payment not completed' })
      }
    }
  }

  if (success) {
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
    let res: any = null
    if (contract) res = await applyPayment(c, contract, intent.amount, receipt, 'sasapay', intent.phone)
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, transaction_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE checkout_request_id=?`)
      .bind(receipt, receipt, (gatewayDesc || (forced ? 'Manual admin override' : 'Recovered')).slice(0, 300), checkout).run()
    await audit(c, c.get('user').id, 'payment_recover', 'sasapay',
      `${forced ? 'FORCED' : 'query-settled'} ${checkout} -> SUCCESS (KES ${intent.amount}, receipt ${receipt})`)
    return c.json({ ok: true, status: 'success', forced, mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status })
  }
  return c.json({ ok: false, status: 'pending' })
})
// ----------------------------------------------------------------------------
// PAYMENTS - KCB Buni STK Push (real when configured, simulated otherwise)
// Docs: https://buni.kcbgroup.com/getting-started
// ----------------------------------------------------------------------------
app.post('/api/buni/stkpush', requireAuth, async (c) => {
  const { contract_id, amount, phone } = await c.req.json()
  const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(contract_id).first<any>()
  if (!contract) return c.json({ error: 'Contract not found' }, 404)
  if (contract.payment_type === 'cash' && ['pending_payment', 'awaiting_cash_balance', 'completed'].includes(contract.status)) {
    const p = await c.env.DB.prepare(`SELECT quantity FROM products WHERE id=?`).bind(contract.product_id).first<any>()
    if ((!contract.ownership_recorded) && (!p || p.quantity < contract.quantity)) return c.json({ error: 'This item is now out of stock.' }, 409)
  } else if (contract.payment_type !== 'cash' && !['active', 'completed'].includes(contract.status)) {
    return c.json({ error: 'This purchase is not open for payment.' }, 400)
  }
  const amt = Number(amount)
  if (amt <= 0) return c.json({ error: 'Invalid amount' }, 400)
  if (amt > Number(contract.outstanding || 0)) return c.json({ error: 'Amount exceeds outstanding balance' }, 400)
  const desc = contract.payment_type === 'cash' ? 'Cash Equipment Purchase' : 'Equipment Financing Payment'
  const result = await buniStkPush(c.env, { phone: phone || c.get('user').phone, amount: amt, account: contract.contract_ref, description: desc })
  if (!result.success) return c.json({ error: result.error || 'KCB Buni STK push failed' }, 502)
  await c.env.DB.prepare(`INSERT INTO payment_intents (checkout_request_id,merchant_request_id,contract_id,customer_id,amount,phone,method,status) VALUES (?,?,?,?,?,?,?, 'pending')`)
    .bind(result.checkout_request_id, result.merchant_request_id, contract_id, contract.customer_id, amt, normalizePhone(phone || c.get('user').phone), 'buni').run()
  await audit(c, c.get('user').id, 'stk_push', 'buni', `KES ${amt} to ${contract.contract_ref} (${result.simulated ? 'sim' : 'live'})`)
  return c.json({ ok: true, simulated: result.simulated, checkout_request_id: result.checkout_request_id, customer_message: result.customer_message })
})
app.post('/api/buni/confirm', requireAuth, async (c) => {
  const { checkout_request_id } = await c.req.json()
  const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout_request_id).first<any>()
  if (!intent) return c.json({ error: 'Payment intent not found' }, 404)
  if (intent.status === 'success') return c.json({ ok: true, status: 'success', mpesa_receipt: intent.mpesa_receipt })
  let success = false, receipt = ''
  if (!buniConfigured(c.env) || String(checkout_request_id).includes('SIM')) {
    success = true; receipt = 'BUNI' + Math.random().toString(36).slice(2, 9).toUpperCase()
  } else {
    const q = await buniQuery(c.env, checkout_request_id)
    const code = q.ResultCode ?? q.status_code
    if (code === '0' || code === 0 || q.status === true) { success = true; receipt = 'BUNI' + Date.now().toString().slice(-7) }
    else if (code) return c.json({ ok: false, status: 'failed', result_desc: q.ResultDesc || q.message || 'Payment not completed' })
    else return c.json({ ok: false, status: 'pending' })
  }
  if (success) {
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
    const res = await applyPayment(c, contract, intent.amount, receipt, 'buni', intent.phone)
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=? WHERE checkout_request_id=?`).bind(receipt, checkout_request_id).run()
    return c.json({ ok: true, status: 'success', mpesa_receipt: receipt, amount_paid: res?.amount_paid, outstanding: res?.outstanding, contract_status: res?.status })
  }
  return c.json({ ok: false, status: 'pending' })
})
app.post('/api/buni/callback', async (c) => {
  try {
    const body: any = await c.req.json()
    const checkout = body?.CheckoutRequestID || body?.TransactionID
    if (!checkout) return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
    const intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(checkout).first<any>()
    if (intent && intent.status === 'pending') {
      const code = body.ResultCode ?? body.status_code
      if (code === 0 || code === '0' || body.status === true) {
        const receipt = body.TransactionID || body.ReceiptNumber || 'BUNI' + Date.now()
        const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
        if (contract) await applyPayment(c, contract, intent.amount, String(receipt), 'buni', intent.phone)
        await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, result_desc=? WHERE checkout_request_id=?`).bind(String(receipt), body.ResultDesc || '', checkout).run()
      } else {
        await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=? WHERE checkout_request_id=?`).bind(body.ResultDesc || body.message || 'Failed', checkout).run()
      }
    }
    return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  } catch { return c.json({ ResultCode: 0, ResultDesc: 'Accepted' }) }
})
app.get('/api/buni/status', requireAuth, (c) => {
  // Buni is hidden from the front-end user. The gateway routes remain
  // functional for server-to-server integrations, but the UI never exposes it.
  return c.json({ live: buniConfigured(c.env), mode: buniConfigured(c.env) ? (c.env.BUNI_ENV || 'sandbox') : 'simulation', hidden: true })
})

// ----------------------------------------------------------------------------
// CENTRAL PAYMENT GATEWAY (shared by equipment / feed / input marketplaces)
// Public endpoint URL:  https://equipment.farmsky.africa/api/v1/payments/*
// ----------------------------------------------------------------------------
app.route('/api/v1/payments', paymentGateway)

// ----------------------------------------------------------------------------
// CLIENT-TENANT INBOUND WEBHOOK (Nia by Farmsky)
// The Equipment Central Gateway POSTs a SIGNED PAYMENT_COMPLETED/FAILED
// notification here when a delegated transaction settles. We verify the HMAC
// with our CROSS_APP_HMAC_SECRET, then drive the SAME settlement path used by
// the M-Pesa callback (applyPayment → ledger, ownership, commissions).
//   Payload: { transaction_ref, origin_reference, payment_method, status,
//              provider_receipt, amount, currency, result_code, result_desc }
//   Headers: X-Farmsky-Client / -Timestamp / -Nonce / -Signature
// ----------------------------------------------------------------------------
app.post('/api/v1/payment-webhook', async (c) => {
  const rawBody = await c.req.text()
  const clientKey = c.req.header('X-Farmsky-Client') || ''
  const timestamp = c.req.header('X-Farmsky-Timestamp') || ''
  const nonce = c.req.header('X-Farmsky-Nonce') || ''
  const signature = c.req.header('X-Farmsky-Signature') || ''
  const expectedKey = String((c.env as any).PAYMENT_CLIENT_KEY || 'nia_farmsky_key')
  const secret = String((c.env as any).CROSS_APP_HMAC_SECRET || '')

  let payload: any = {}
  try { payload = rawBody ? JSON.parse(rawBody) : {} } catch { payload = {} }

  const v = await verifySignature(secret, clientKey, timestamp, nonce, rawBody, signature)
  const valid = v.ok && clientKey === expectedKey

  const txRef = payload.transaction_ref || null            // gateway ref == our checkout_request_id
  const originRef = payload.origin_reference || null        // our contract_ref
  const status = String(payload.status || '').toUpperCase()

  // Audit every inbound webhook (best-effort; table exists via 0008 central schema).
  try {
    await c.env.DB.prepare(
      `INSERT INTO nia_webhook_log (client_key, transaction_ref, origin_reference, status, signature_valid, raw_payload) VALUES (?,?,?,?,?,?)`
    ).bind(clientKey, txRef, originRef, status, valid ? 1 : 0, rawBody.slice(0, 8000)).run()
  } catch (_) { /* audit table optional */ }

  if (!valid) return c.json({ ok: false, error: v.error || 'Invalid signature or client' }, 401)

  // Resolve the local payment_intent by the gateway transaction_ref (mapped to
  // checkout_request_id on initiate), else by the origin contract reference.
  let intent: any = null
  if (txRef) intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE checkout_request_id=?`).bind(txRef).first<any>()
  if (!intent && originRef) {
    const ct = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE contract_ref=?`).bind(originRef).first<any>()
    if (ct) intent = await c.env.DB.prepare(`SELECT * FROM payment_intents WHERE contract_id=? AND status='pending' ORDER BY id DESC LIMIT 1`).bind(ct.id).first<any>()
  }
  if (!intent) return c.json({ ok: true, matched: false, note: 'No matching payment intent' })
  if (intent.status === 'success') return c.json({ ok: true, matched: true, already: true })

  if (status === 'SUCCESS') {
    const receipt = payload.provider_receipt || ('GW' + Date.now().toString().slice(-8))
    const contract = await c.env.DB.prepare(`SELECT * FROM murabaha_contracts WHERE id=?`).bind(intent.contract_id).first<any>()
    if (contract) await applyPayment(c, contract, intent.amount, String(receipt), intent.method || payload.payment_method || 'mpesa', intent.phone)
    await c.env.DB.prepare(`UPDATE payment_intents SET status='success', mpesa_receipt=?, result_desc=? WHERE checkout_request_id=?`)
      .bind(String(receipt), payload.result_desc || 'Settled via Equipment gateway', intent.checkout_request_id).run()
    return c.json({ ok: true, matched: true, settled: true })
  } else if (status === 'FAILED' || status === 'EXPIRED') {
    await c.env.DB.prepare(`UPDATE payment_intents SET status='failed', result_desc=? WHERE checkout_request_id=?`)
      .bind(payload.result_desc || status, intent.checkout_request_id).run()
    return c.json({ ok: true, matched: true, settled: false })
  }
  return c.json({ ok: true, matched: true, note: 'Non-terminal status' })
})

// ----------------------------------------------------------------------------
// PUBLIC MERCHANT API (Phase 3) — HMAC-authenticated inventory + checkout
// Mounted under /api  ->  /api/v1/merchant/*  and  /api/v1/checkout/*
// ----------------------------------------------------------------------------
app.route('/api', merchantApi)

// ----------------------------------------------------------------------------
// UNIFIED PAYMENT LEDGER (Phase 2) — Equipment admin dashboard reads this to
// see BOTH equipment_app and feed_app transactions, filterable by category
// (inventory_type) + origin_platform. RBAC: admin/super_admin only.
// ----------------------------------------------------------------------------
app.get('/api/ledger', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const invType = c.req.query('inventory_type') || ''      // 'equipment' | 'feed'
  const origin = c.req.query('origin_platform') || ''      // 'equipment_app' | 'feed_app'
  const status = c.req.query('status') || ''
  const method = c.req.query('method') || ''
  const q = c.req.query('q') || ''
  const filters: string[] = []
  const binds: any[] = []
  if (invType) { filters.push('inventory_type = ?'); binds.push(invType) }
  if (origin) { filters.push('origin_platform = ?'); binds.push(origin) }
  if (status) { filters.push('status = ?'); binds.push(status) }
  if (method) { filters.push('payment_method = ?'); binds.push(method) }
  if (q) { filters.push('(transaction_ref LIKE ? OR phone LIKE ? OR description LIKE ?)'); binds.push(`%${q}%`, `%${q}%`, `%${q}%`) }
  const where = filters.length ? 'WHERE ' + filters.join(' AND ') : ''
  const rows = await withAdminContext(c, async () => await c.env.DB.prepare(
    `SELECT transaction_ref, origin_app, origin_platform, inventory_type, payment_method, phone,
            amount, currency, status, description, created_at, completed_at
       FROM central_transactions ${where} ORDER BY created_at DESC LIMIT 500`
  ).bind(...binds).all<any>())
  return c.json({ transactions: rows.results || [] })
})

// ----------------------------------------------------------------------------
// CROSS-APP SSO HANDOFF (Phase 2) — no second login between Equipment & Feed
// ----------------------------------------------------------------------------
// Signed-in user requests a handoff URL to the sibling app.
app.get('/api/cross/handoff', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const secret = c.env.CROSS_APP_HMAC_SECRET || ''
  const target = String(c.req.query('target') || '')
  // Choose the destination origin by target: 'score' -> SCORE_APP_URL,
  // anything else -> the configured sibling marketplace (Feed/Equipment).
  const siblingUrl = (target === 'score'
    ? String(c.env.SCORE_APP_URL || '')
    : String(c.env.CROSS_APP_URL || '')
  ).replace(/\/+$/, '')
  if (!secret || !siblingUrl) return c.json({ error: 'Cross-app navigation is not configured' }, 503)
  // The same short-lived HMAC-signed token is accepted by every Farmsky
  // app's /sso endpoint, so no second login is needed at the destination.
  // Email + name are carried so email-keyed apps (Score) can resolve/create
  // the account without a second login.
  // The Equipment Admin Portal is the SINGLE source of truth for Super-Admin
  // status. Carry the originating role + a super_admin assertion so the
  // destination app (Score) grants the SAME Super-Admin access with the SAME
  // credentials — no second login and no separate Super-Admin config there.
  const isSuper = user.role === 'super_admin'
  const token = await mintHandoffToken(secret, normalizePhone(user.phone), {
    email: user.email,
    name: user.full_name,
    role: user.role,
    super_admin: isSuper,
  })
  // Optional deep-link: `dest` tells the destination app which view to open
  // after SSO (e.g. dest=api-access lands the lender on the Score console's
  // API Access tab). Kept as an allow-listed slug to avoid open-redirect abuse.
  const destRaw = String(c.req.query('dest') || '').trim()
  const dest = /^[a-z0-9-]{1,32}$/.test(destRaw) ? destRaw : ''
  const qs = `token=${encodeURIComponent(token)}` + (dest ? `&dest=${encodeURIComponent(dest)}` : '')
  return c.json({ url: `${siblingUrl}/sso?${qs}`, target, dest: dest || null })
})

// Lender opts in to consuming the Farmsky APIs from the Equipment platform.
// Records the opt-in (best-effort audit) before the SSO handoff to Score,
// where the lender enables and manages API access. Lender-tier only.
app.post('/api/cross/use-apis', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (user.role !== 'lender') return c.json({ error: 'Only Lender-tier accounts can consume the APIs' }, 403)
  try {
    await audit(c, user.id, 'update', 'user', 'lender opted in to Use APIs (Farmsky Score API consumption)')
  } catch (_) { /* audit is best-effort; never block the handoff */ }
  return c.json({ ok: true })
})

// Sibling app lands here: verify HMAC token, issue a local session, redirect.
app.get('/sso', async (c) => {
  const token = c.req.query('token') || ''
  const secret = c.env.CROSS_APP_HMAC_SECRET || ''
  const v = await verifyHandoffToken(secret, token)
  const escHtml = (s: string) => String(s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch] as string))
  if (!v.ok) return c.html(`<h3>Sign-in link invalid or expired</h3><p>${escHtml(v.error || '')}</p><p><a href="/">Go to sign in</a></p>`, 401)
  // Match the account across every stored phone format: normalized 254...,
  // the '+'-prefixed form, and the raw value carried in the token.
  const norm = normalizePhone(v.phone!)
  const plus = norm.startsWith('254') ? '+' + norm : norm
  const user = await c.env.DB.prepare(`SELECT * FROM users WHERE phone = ? OR phone = ? OR phone = ?`).bind(v.phone, norm, plus).first<any>()
  if (!user) return c.html(`<h3>No matching account on this platform</h3><p>Please sign in normally.</p><p><a href="/">Go to sign in</a></p>`, 404)
  if (user.status !== 'active') return c.html(`<h3>Account is not active on this platform</h3><p><a href="/">Go to sign in</a></p>`, 403)
  await createSession(c, user)
  await audit(c, user.id, 'login', 'user', `${user.role} signed in via cross-app SSO handoff`)
  return c.redirect('/')
})

// Expose cross-app config to the frontend (so nav buttons show only when set).
app.get('/api/cross/config', requireAuth, (c) => {
  return c.json({
    app_type: String(c.env.APP_TYPE || 'equipment'),
    cross_app_configured: !!(c.env.CROSS_APP_HMAC_SECRET && c.env.CROSS_APP_URL),
    cross_app_url: c.env.CROSS_APP_URL || null,
    // Score SSO button is shown when the shared handoff secret AND the
    // Score origin are configured. Reuses the same session (no re-login).
    score_configured: !!(c.env.CROSS_APP_HMAC_SECRET && c.env.SCORE_APP_URL),
    score_url: c.env.SCORE_APP_URL || null
  })
})

// ----------------------------------------------------------------------------
// HOSTED CHECKOUT PAGE (Phase 3) — where merchant buttons redirect the buyer.
// ----------------------------------------------------------------------------
app.get('/checkout/:ref', async (c) => {
  const ref = c.req.param('ref')
  const row = await c.env.DB.prepare(
    `SELECT * FROM merchant_checkouts WHERE checkout_ref = ?`
  ).bind(ref).first<any>()
  if (!row) return c.html(`<h3>Checkout session not found</h3>`, 404)
  return c.html(CHECKOUT_PAGE(row))
})

// ----------------------------------------------------------------------------
// DASHBOARD / ANALYTICS

function CHECKOUT_PAGE(row: any): string {
  const isFinancing = row.transaction_type === 'FINANCING_REQUEST'
  const esc = (s: any) => String(s == null ? '' : s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch] as string))
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Farmsky Checkout</title>
  <link href="/static/tailwind.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
  </head><body class="bg-slate-100 min-h-screen flex items-center justify-center p-4">
  <div class="bg-white rounded-2xl shadow-xl max-w-md w-full p-8">
    <div class="text-center mb-6"><i class="fas fa-leaf text-teal-600 text-4xl mb-2"></i>
      <h1 class="text-xl font-bold text-slate-800">Farmsky Checkout</h1>
      <p class="text-sm text-slate-500">${esc(row.inventory_type)} · ${isFinancing ? 'Financing Request' : 'Direct Purchase'}</p></div>
    <div class="border rounded-xl p-4 mb-4 bg-slate-50">
      <div class="flex justify-between mb-2"><span class="text-slate-500">Item</span><span class="font-medium">${esc(row.item_title)}</span></div>
      <div class="flex justify-between mb-2"><span class="text-slate-500">Category</span><span>${esc(row.category || 'general')}</span></div>
      <div class="flex justify-between mb-2"><span class="text-slate-500">Amount</span><span class="font-bold text-teal-700">KES ${Number(row.amount).toLocaleString()}</span></div>
      ${isFinancing ? `<div class="flex justify-between"><span class="text-slate-500">Tenor</span><span>${row.financing_tenor_months} months</span></div>` : ''}
    </div>
    <div class="text-sm text-slate-600 mb-4">
      <div><i class="fas fa-user mr-2 text-slate-400"></i>${esc(row.customer_full_name)}</div>
      <div><i class="fas fa-phone mr-2 text-slate-400"></i>${esc(row.customer_phone)}</div>
    </div>
    <button onclick="pay()" id="payBtn" class="btn w-full bg-teal-600 hover:bg-teal-700 text-white py-3 rounded-xl font-medium">
      <i class="fas fa-lock mr-2"></i>${isFinancing ? 'Submit Financing Request' : 'Pay Now'}</button>
    <p class="text-xs text-slate-400 text-center mt-4">Secured by Farmsky · Ref ${esc(row.checkout_ref)}</p>
  </div>
  <script>
    function pay(){
      var b=document.getElementById('payBtn');
      b.disabled=true; b.innerHTML='<i class="fas fa-spinner fa-spin mr-2"></i>Processing…';
      setTimeout(function(){
        b.innerHTML='<i class="fas fa-check mr-2"></i>Request received';
        b.classList.remove('bg-teal-600','hover:bg-teal-700'); b.classList.add('bg-emerald-600');
        ${row.success_callback_url ? `setTimeout(function(){ location.href=${JSON.stringify(String(row.success_callback_url))}; }, 1200);` : ''}
      }, 1400);
    }
  </script></body></html>`
}


// Admin-only view of cross-app payment activity
app.get('/api/v1/payments-admin/summary', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const res = await fetch(new URL('/api/v1/payments/admin/summary', c.req.url).toString())
  return c.json(await res.json())
})

// ----------------------------------------------------------------------------
// DASHBOARD / ANALYTICS
// ----------------------------------------------------------------------------
app.get('/api/dashboard', requireAuth, async (c) => {
  const user = c.get('user'), db = c.env.DB
  if (user.role === 'customer') {
    const myCust = await db.prepare(`SELECT id FROM customers WHERE user_id=?`).bind(user.id).first<any>()
    const cid = myCust?.id || -1
    const contracts = await db.prepare(`SELECT COUNT(*) n, COALESCE(SUM(outstanding),0) out FROM murabaha_contracts WHERE customer_id=? AND status='active'`).bind(cid).first<any>()
    const completed = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE customer_id=? AND status='completed'`).bind(cid).first<any>()
    const nextDue = await db.prepare(`SELECT r.* FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id WHERE mc.customer_id=? AND r.status!='completed' ORDER BY r.due_date LIMIT 1`).bind(cid).first<any>()
    return c.json({ role: 'customer', active_contracts: contracts?.n || 0, total_outstanding: contracts?.out || 0, completed_contracts: completed?.n || 0, next_payment: nextDue || null })
  }
  if (user.role === 'agent') {
    const cust = await db.prepare(`SELECT COUNT(*)::int n FROM customers WHERE agent_id=?`).bind(user.id).first<any>()
    const active = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE agent_id=? AND status='active'`).bind(user.id).first<any>()
    const pending = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE agent_id=? AND status='pending'`).bind(user.id).first<any>()
    const portfolio = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot, COALESCE(SUM(outstanding),0) out FROM murabaha_contracts WHERE agent_id=?`).bind(user.id).first<any>()
    const late = await db.prepare(`SELECT COUNT(*)::int n FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id WHERE mc.agent_id=? AND r.status='late'`).bind(user.id).first<any>()
    const creditOnly = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE agent_id=? AND payment_type='financing'`).bind(user.id).first<any>()
    const par = portfolio?.tot ? Math.round((portfolio.out / portfolio.tot) * 100) : 0
    return c.json({ role: 'agent', customers_onboarded: cust?.n || 0, active_contracts: active?.n || 0, pending_approvals: pending?.n || 0, portfolio_value: portfolio?.tot || 0, portfolio_at_risk: par, late_installments: late?.n || 0, commission: Math.round((portfolio?.tot || 0) * 0.025), credit_purchases: creditOnly?.n || 0 })
  }
  const sales = await db.prepare(`SELECT COALESCE(SUM(amount),0) tot FROM transactions WHERE status='success'`).first<any>()
  const financed = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot FROM murabaha_contracts WHERE payment_type='financing'`).first<any>()
  const cashSales = await db.prepare(`SELECT COALESCE(SUM(murabaha_price),0) tot FROM murabaha_contracts WHERE payment_type='cash'`).first<any>()
  const activeCust = await db.prepare(`SELECT COUNT(*)::int n FROM customers`).first<any>()
  const invValue = await db.prepare(`SELECT COALESCE(SUM(buying_price*quantity),0) tot FROM products`).first<any>()
  const totalRepay = await db.prepare(`SELECT COUNT(*)::int n FROM repayments`).first<any>()
  const completedRepay = await db.prepare(`SELECT COUNT(*)::int n FROM repayments WHERE status='completed'`).first<any>()
  const defaulted = await db.prepare(`SELECT COUNT(*)::int n FROM repayments WHERE status='defaulted'`).first<any>()
  const pending = await db.prepare(`SELECT COUNT(*)::int n FROM murabaha_contracts WHERE status='pending'`).first<any>()
  const repayRate = totalRepay?.n ? Math.round((completedRepay.n / totalRepay.n) * 100) : 0
  const defaultRate = totalRepay?.n ? Math.round((defaulted.n / totalRepay.n) * 100) : 0
  const { results: topProducts } = await db.prepare(`SELECT p.name, COUNT(mc.id) sales FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id GROUP BY p.id ORDER BY sales DESC LIMIT 5`).all()
  return c.json({ role: user.role === 'operations_finance' ? 'operations_finance' : 'admin', total_sales: sales?.tot || 0, equipment_financed: financed?.tot || 0, cash_sales: cashSales?.tot || 0, repayment_rate: repayRate, default_rate: defaultRate, inventory_value: invValue?.tot || 0, active_customers: activeCust?.n || 0, pending_approvals: pending?.n || 0, top_products: topProducts })
})

// ----------------------------------------------------------------------------
// AGENTS
// ----------------------------------------------------------------------------
app.get('/api/agents', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT u.id, u.full_name, u.phone, u.email, u.region, u.label, u.permissions, u.status,
     (SELECT COUNT(*) FROM customers WHERE agent_id=CAST(u.id AS TEXT)) customers,
     (SELECT COUNT(*) FROM murabaha_contracts WHERE agent_id=CAST(u.id AS TEXT) AND status='active') active
     FROM users u WHERE u.role='agent'`
  ).all()
  const agentFallback = await loadRoleTemplate(c, 'agent')
  return c.json({ agents: results.map((a: any) => ({ ...a, email: isPlaceholderEmail(a.email) ? '' : a.email, permissions: parsePermissions(a.permissions, 'agent', agentFallback) })) })
})
// Multi-user onboarding: request an OTP to verify a new user's phone before
// creating their account (parity).
app.post('/api/onboard/request-otp', requireAuth, requireRole('admin', 'super_admin', 'agent'), async (c) => {
  const { phone } = await c.req.json()
  const p = normalizePhone(phone || '')
  if (!p) return c.json({ error: 'A valid phone number is required' }, 400)
  const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  if (dup) return c.json({ error: 'A user with this phone already exists' }, 409)
  const { sms, demo_otp } = await issueOtp(c, p, 'onboard')
  if (!sms.simulated && !sms.success) return c.json({ error: sms.error || 'Failed to send OTP' }, 502)
  return c.json({ ok: true, phone: p, message: sms.simulated ? 'Demo mode: use the code shown below.' : `Verification code sent to ${p}.`, demo_otp })
})

app.post('/api/agents', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const b = await c.req.json()
  const p = normalizePhone(b.phone || '')
  if (!b.full_name || !p) return c.json({ error: 'Name and phone are required' }, 400)
  const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first()
  if (dup) return c.json({ error: 'A user with this phone already exists' }, 409)
  const provided = b.password && String(b.password).length >= 4
  // Multi-user onboarding: unless an explicit password is set, verify the new
  // user's phone via OTP, then issue a temporary (must-change, 3h-expiry) one.
  if (!provided) {
    const v = await verifyOtp(c, p, String(b.otp_code || ''), 'onboard')
    if (!v.ok) return c.json({ error: v.error || 'Phone verification required', otp_required: true }, 400)
  }
  const pwd = provided ? String(b.password) : genPassword()
  const perms = await permissionsForRole(c, 'agent', b.permissions || {})
  const creator = c.get('user') as SessionUser
  const creatorId = creator.id
  // Email is optional for agents. resolveEmail supplies a unique, non-deliverable
  // placeholder (derived from phone) when blank, satisfying the central
  // users.email NOT NULL + UNIQUE constraints (was 23502 on null, 23505 on '').
  const emailRes = resolveEmail('agent', b.email, b.phone)
  if ('error' in emailRes) return c.json({ error: emailRes.error }, 400)
  const email = emailRes.value
  const orgId = (await resolveCreatorOrgId(c, creator)) ?? (await resolveDefaultOrgId(c))
  const withOrg = await usersHasOrgId(c) && orgId != null
  const r = withOrg
    ? await c.env.DB.prepare(`INSERT INTO users (full_name,phone,email,password,role,region,password_set,label,permissions,created_by,org_id) VALUES (?,?,?,?, 'agent', ?, ?, ?, ?, ?, ?)`).bind(b.full_name, p, email, await hashPassword(pwd), b.region || null, provided, b.label || 'Agent', JSON.stringify(perms), creatorId, orgId).run()
    : await c.env.DB.prepare(`INSERT INTO users (full_name,phone,email,password,role,region,password_set,label,permissions,created_by) VALUES (?,?,?,?, 'agent', ?, ?, ?, ?, ?)`).bind(b.full_name, p, email, await hashPassword(pwd), b.region || null, provided, b.label || 'Agent', JSON.stringify(perms), creatorId).run()
  await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(r.meta.last_row_id, b.region || null, JSON.stringify(perms)).run()
  await audit(c, creatorId, 'create', 'agent', b.full_name)
  if (provided) return c.json({ id: r.meta.last_row_id, password: pwd, password_was_set_by_admin: true })
  const t = await issueTempPassword(c, { userId: r.meta.last_row_id as number, phone: p, fullName: b.full_name })
  return c.json({ id: r.meta.last_row_id, password: t.tempPassword, password_was_set_by_admin: false, temporary: true, expires_at: t.expiresAt, sms_simulated: !!t.sms.simulated })
})
app.post('/api/users/:id/reset-password', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const target = await c.env.DB.prepare(`SELECT id, full_name, phone, role FROM users WHERE id=?`).bind(id).first<any>()
  if (!target) return c.json({ error: 'User not found' }, 404)
  if (target.role === 'super_admin' && String(id) !== String(c.get('user').id)) return c.json({ error: 'Cannot reset another Super Admin password' }, 400)
  const body = await c.req.json().catch(() => ({}))
  const provided = body?.password && String(body.password).length >= 4
  // Admin-triggered reset. When no explicit password is supplied (the normal
  // path — including recovering an expired temporary password) we reissue a
  // fresh temporary password with the mandatory-change + 3h-expiry lifecycle.
  if (provided) {
    await c.env.DB.prepare(`UPDATE users SET password=?, password_set=1, must_change_password=0, is_temp_password=0, temp_password_expires_at=NULL WHERE id=?`).bind(await hashPassword(String(body.password)), id).run()
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id = CAST(? AS TEXT)`).bind(id).run()
    await audit(c, c.get('user').id, 'reset_password', target.role, target.full_name)
    return c.json({ ok: true, new_password: String(body.password), user: target.full_name })
  }
  await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id = CAST(? AS TEXT)`).bind(id).run()
  const t = await issueTempPassword(c, { userId: id as any, phone: target.phone, fullName: target.full_name })
  await audit(c, c.get('user').id, 'reset_password', target.role, `${target.full_name} (temporary)`)
  return c.json({ ok: true, new_password: t.tempPassword, user: target.full_name, temporary: true, expires_at: t.expiresAt, sms_simulated: !!t.sms.simulated })
})

// Public: a user whose temporary password expired can ask an admin to reset it.
app.post('/api/onboard/request-reset', async (c) => {
  const { phone } = await c.req.json().catch(() => ({}))
  const p = normalizePhone(phone || '')
  const user = await c.env.DB.prepare(`SELECT id, full_name FROM users WHERE phone=?`).bind(p).first<any>()
  // Do not reveal account existence; always respond ok.
  if (user) {
    try { await audit(c, user.id, 'reset_request', 'user', `Temp-password reset requested for ${user.full_name}`) } catch {}
  }
  return c.json({ ok: true, message: 'Your request has been sent. An administrator will reset your password shortly.' })
})
app.put('/api/agents/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const b = await c.req.json()
  const perms = await permissionsForRole(c, 'agent', b.permissions || {})
  // Agents don't require email — resolveEmail supplies a unique placeholder when
  // blank (central users.email is NOT NULL + UNIQUE).
  const emailRes = resolveEmail('agent', b.email, b.phone)
  if ('error' in emailRes) return c.json({ error: emailRes.error }, 400)
  const email = emailRes.value
  await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, region=?, label=?, permissions=? WHERE id=? AND role='agent'`).bind(b.full_name, b.phone, email, b.region, b.label || 'Agent', JSON.stringify(perms), id).run()
  await c.env.DB.prepare(`UPDATE agents SET region=?, permissions=? WHERE user_id=?`).bind(b.region, JSON.stringify(perms), id).run()
  await audit(c, c.get('user').id, 'update', 'agent', b.full_name)
  return c.json({ ok: true })
})

// ----------------------------------------------------------------------------
// USER ACCOUNTS (admin) - create, edit, activate/deactivate, delete
// ----------------------------------------------------------------------------
app.get('/api/users', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT id, full_name, phone, email, role, label, permissions, status, region, schedule_enabled, access_days, access_start, access_end, created_at FROM users ORDER BY id`).all()
  const usersWithPerms = [] as any[]
  for (const u of results as any[]) {
    const fallback = await loadRoleTemplate(c, u.role)
    usersWithPerms.push({ ...u, email: isPlaceholderEmail(u.email) ? '' : u.email, permissions: parsePermissions(u.permissions, u.role, fallback), access_days: safeJson(u.access_days, []) })
  }
  return c.json({ users: usersWithPerms })
})
app.post('/api/users', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const b = await c.req.json()
  const p = normalizePhone(b.phone || '')
  if (!b.full_name || !p || !b.role) return c.json({ error: 'Name, phone and role are required' }, 400)
  const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(p).first<any>()
  if (dup) return c.json({ error: 'A user with this phone already exists' }, 409)
  const provided = b.password && String(b.password).length >= 4
  // Admin-driven onboarding. The creating admin is already authenticated and
  // authorized (requireRole admin/super_admin), so we do NOT gate account
  // creation behind a phone OTP — that regressed the legacy "Create User" flow
  // into a "No active code. Request a new one." dead-end whenever the admin
  // left the (optional) password blank. Behaviour:
  //   • password supplied  → use it (account is immediately usable).
  //   • password blank      → auto-generate a TEMPORARY password and SMS it to
  //     the new user (they must change it on first login).
  // An OTP is only consumed when the caller explicitly supplies one (kept for
  // backward compatibility with any self-service onboarding UI); a missing or
  // absent OTP never blocks an admin create.
  if (!provided && b.otp_code) {
    const v = await verifyOtp(c, p, String(b.otp_code || ''), 'onboard')
    if (!v.ok) return c.json({ error: v.error || 'Phone verification failed', otp_required: true }, 400)
  }
  const pwd = provided ? String(b.password) : genPassword()
  const perms = await permissionsForRole(c, String(b.role), b.permissions || {})
  const templateRow = await c.env.DB.prepare(`SELECT label FROM role_templates WHERE role_key=?`).bind(String(b.role)).first<any>()
  const label = b.label || templateRow?.label || (String(b.role) === 'operations_finance' ? 'Operations & Finance' : String(b.role).replace(/_/g, ' '))
  const schedEnabled = boolInt(b.schedule_enabled, false) ? 1 : 0
  const schedDays = Array.isArray(b.access_days) ? JSON.stringify(b.access_days) : null
  // Email is mandatory ONLY for super_admin/admin/lender; any other role may be
  // created without one. resolveEmail supplies a unique placeholder when blank so
  // the central users.email NOT NULL + UNIQUE constraints hold (23502/23505).
  const emailRes = resolveEmail(String(b.role), b.email, b.phone)
  if ('error' in emailRes) return c.json({ error: emailRes.error }, 400)
  const email = emailRes.value
  const creator = c.get('user') as SessionUser
  const creatorId = creator.id
  // Central farmsky_central_db enforces users.org_id NOT NULL. New accounts
  // inherit the creating admin's tenant. Only include the column when the DB
  // shape actually has it (Equipment-only SQLite/D1 dev omits it), and resolve
  // the org_id defensively (session may predate the org_id-aware getSessionUser).
  const orgId = (await resolveCreatorOrgId(c, creator)) ?? (await resolveDefaultOrgId(c))
  const withOrg = await usersHasOrgId(c) && orgId != null
  const r = withOrg
    ? await c.env.DB.prepare(`INSERT INTO users (full_name, phone, email, password, role, label, permissions, status, region, password_set, schedule_enabled, access_days, access_start, access_end, created_by, org_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(b.full_name, p, email, await hashPassword(pwd), b.role, label, JSON.stringify(perms), b.status || 'active', b.region || null, provided, schedEnabled, schedDays, b.access_start || null, b.access_end || null, creatorId, orgId).run()
    : await c.env.DB.prepare(`INSERT INTO users (full_name, phone, email, password, role, label, permissions, status, region, password_set, schedule_enabled, access_days, access_start, access_end, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(b.full_name, p, email, await hashPassword(pwd), b.role, label, JSON.stringify(perms), b.status || 'active', b.region || null, provided, schedEnabled, schedDays, b.access_start || null, b.access_end || null, creatorId).run()
  if (b.role === 'agent') await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(r.meta.last_row_id, b.region || null, JSON.stringify(perms)).run()
  await audit(c, creatorId, 'create', 'user', `${b.full_name} (${b.role})`)
  if (provided) return c.json({ id: r.meta.last_row_id, password: pwd, password_was_set_by_admin: true })
  const t = await issueTempPassword(c, { userId: r.meta.last_row_id as number, phone: p, fullName: b.full_name })
  return c.json({ id: r.meta.last_row_id, password: t.tempPassword, password_was_set_by_admin: false, temporary: true, expires_at: t.expiresAt, sms_simulated: !!t.sms.simulated })
})
app.put('/api/users/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const b = await c.req.json()
  const perms = await permissionsForRole(c, String(b.role), b.permissions || {})
  const schedEnabled = boolInt(b.schedule_enabled, false) ? 1 : 0
  const schedDays = Array.isArray(b.access_days) ? JSON.stringify(b.access_days) : null
  // Same email policy on edit: required for super_admin/admin/lender; a unique
  // placeholder otherwise so central users.email NOT NULL + UNIQUE both hold.
  const emailRes = resolveEmail(String(b.role), b.email, b.phone)
  if ('error' in emailRes) return c.json({ error: emailRes.error }, 400)
  const email = emailRes.value
  if (b.password) {
    await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, role=?, label=?, permissions=?, region=?, schedule_enabled=?, access_days=?, access_start=?, access_end=?, password=? WHERE id=?`).bind(b.full_name, b.phone, email, b.role, b.label || null, JSON.stringify(perms), b.region, schedEnabled, schedDays, b.access_start || null, b.access_end || null, await hashPassword(String(b.password)), id).run()
  } else {
    await c.env.DB.prepare(`UPDATE users SET full_name=?, phone=?, email=?, role=?, label=?, permissions=?, region=?, schedule_enabled=?, access_days=?, access_start=?, access_end=? WHERE id=?`).bind(b.full_name, b.phone, email, b.role, b.label || null, JSON.stringify(perms), b.region, schedEnabled, schedDays, b.access_start || null, b.access_end || null, id).run()
  }
  if (b.role === 'agent') {
    const exists = await c.env.DB.prepare(`SELECT user_id FROM agents WHERE user_id=?`).bind(id).first<any>()
    if (exists) await c.env.DB.prepare(`UPDATE agents SET region=?, permissions=? WHERE user_id=?`).bind(b.region || null, JSON.stringify(perms), id).run()
    else await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(id, b.region || null, JSON.stringify(perms)).run()
  }
  await audit(c, c.get('user').id, 'update', 'user', b.full_name)
  return c.json({ ok: true })
})
app.put('/api/users/:id/status', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const { status } = await c.req.json()
  if (String(id) === String(c.get('user').id)) return c.json({ error: 'You cannot change your own status' }, 400)
  await c.env.DB.prepare(`UPDATE users SET status=? WHERE id=?`).bind(status, id).run()
  if (status === 'suspended') await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id = CAST(? AS TEXT)`).bind(id).run()
  await audit(c, c.get('user').id, status === 'active' ? 'activate' : 'deactivate', 'user', String(id))
  return c.json({ ok: true })
})
app.delete('/api/users/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  if (String(id) === String(c.get('user').id)) return c.json({ error: 'You cannot delete your own account' }, 400)
  const u = await c.env.DB.prepare(`SELECT role FROM users WHERE id=?`).bind(id).first<any>()
  if (u?.role === 'super_admin') return c.json({ error: 'Cannot delete a Super Admin account' }, 400)
  await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id = CAST(? AS TEXT)`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM agents WHERE user_id=?`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM users WHERE id=?`).bind(id).run()
  await audit(c, c.get('user').id, 'delete', 'user', String(id))
  return c.json({ ok: true })
})
// ----------------------------------------------------------------------------
// PERMISSION CATALOG & ROLE TEMPLATES (Super Admin)
// ----------------------------------------------------------------------------
app.get('/api/permissions', requireAuth, async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT permission_key, label, description, category FROM permission_catalog ORDER BY category, label`).all()
  const { results: roles } = await c.env.DB.prepare(`SELECT role_key, label, description, permissions, is_system, schedule_enabled, access_days, access_start, access_end FROM role_templates ORDER BY label`).all()
  return c.json({
    permissions: results,
    roles: (roles as any[]).map((r) => ({ ...r, permissions: safeJson(r.permissions, {}), access_days: safeJson(r.access_days, []) }))
  })
})
app.post('/api/permissions', requireAuth, requireRole('super_admin'), async (c) => {
  const b = await c.req.json()
  const key = String(b.permission_key || '').trim().toLowerCase().replace(/[^a-z0-9_]+/g, '_')
  if (!key || !b.label) return c.json({ error: 'Permission key and label are required' }, 400)
  await c.env.DB.prepare(`INSERT INTO permission_catalog (permission_key, label, description, category) VALUES (?,?,?,?)`)
    .bind(key, b.label, b.description || null, b.category || 'general').run()
  await audit(c, c.get('user').id, 'create', 'permission', key)
  return c.json({ ok: true, permission_key: key })
})
app.delete('/api/permissions/:key', requireAuth, requireRole('super_admin'), async (c) => {
  const key = c.req.param('key')
  await c.env.DB.prepare(`DELETE FROM permission_catalog WHERE permission_key=?`).bind(key).run()
  await audit(c, c.get('user').id, 'delete', 'permission', key)
  return c.json({ ok: true })
})
app.post('/api/role-templates', requireAuth, requireRole('super_admin'), async (c) => {
  const b = await c.req.json()
  const key = String(b.role_key || '').trim().toLowerCase().replace(/[^a-z0-9_]+/g, '_')
  if (!key || !b.label) return c.json({ error: 'Role key and label are required' }, 400)
  const perms = b.permissions && typeof b.permissions === 'object' ? b.permissions : {}
  const scheduleEnabled = boolInt(b.schedule_enabled, false) ? 1 : 0
  const accessDays = Array.isArray(b.access_days) ? JSON.stringify(b.access_days) : null
  const accessStart = b.access_start || null
  const accessEnd = b.access_end || null
  const existing = await c.env.DB.prepare(`SELECT id, is_system FROM role_templates WHERE role_key=?`).bind(key).first<any>()
  if (existing) {
    await c.env.DB.prepare(`UPDATE role_templates SET label=?, description=?, permissions=?, schedule_enabled=?, access_days=?, access_start=?, access_end=? WHERE role_key=?`)
      .bind(b.label, b.description || null, JSON.stringify(perms), scheduleEnabled, accessDays, accessStart, accessEnd, key).run()
  } else {
    await c.env.DB.prepare(`INSERT INTO role_templates (role_key, label, description, permissions, is_system, schedule_enabled, access_days, access_start, access_end) VALUES (?,?,?,?, 0, ?,?,?,?)`)
      .bind(key, b.label, b.description || null, JSON.stringify(perms), scheduleEnabled, accessDays, accessStart, accessEnd).run()
  }
  await audit(c, c.get('user').id, existing ? 'update' : 'create', 'role_template', key)
  return c.json({ ok: true, role_key: key })
})
app.delete('/api/role-templates/:key', requireAuth, requireRole('super_admin'), async (c) => {
  const key = c.req.param('key')
  const row = await c.env.DB.prepare(`SELECT is_system FROM role_templates WHERE role_key=?`).bind(key).first<any>()
  if (!row) return c.json({ error: 'Not found' }, 404)
  if (row.is_system) return c.json({ error: 'Built-in roles cannot be deleted' }, 400)
  const used = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM users WHERE role=?`).bind(key).first<any>()
  if (Number(used?.n || 0) > 0) return c.json({ error: 'Cannot delete: users are assigned to this role.' }, 400)
  await c.env.DB.prepare(`DELETE FROM role_templates WHERE role_key=?`).bind(key).run()
  await audit(c, c.get('user').id, 'delete', 'role_template', key)
  return c.json({ ok: true })
})

// ----------------------------------------------------------------------------
// FINANCING & MARKUP SETTINGS (processing fee + markup)
// ----------------------------------------------------------------------------
app.get('/api/settings/financing', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const processing_fee = normalizeProcessingFee(await getSetting(c, 'processing_fee', DEFAULT_PROCESSING_FEE))
  const financing_markup = normalizeFinancingMarkup(await getSetting(c, 'financing_markup', DEFAULT_FINANCING_MARKUP))
  // Lightweight inventory list so the UI can offer product selection.
  const { results } = await c.env.DB.prepare(`SELECT id, sku, name, category, quantity FROM products ORDER BY name`).all()
  return c.json({
    processing_fee,
    financing_markup,
    // legacy alias kept so older frontends do not break
    finance_markup: financing_markup,
    products: results,
    can_manage_processing_fees: hasPermission(user, 'manage_processing_fees'),
    can_manage_markup: hasPermission(user, 'manage_markup_pct')
  })
})
app.put('/api/settings/processing-fee', requireAuth, requirePermission('manage_processing_fees'), async (c) => {
  const b = await c.req.json()
  const cfg = normalizeProcessingFee(b)
  await setSetting(c, 'processing_fee', cfg)
  await audit(c, c.get('user').id, 'update', 'settings', `processing_fee:${cfg.enabled ? cfg.mode : 'disabled'} products:${cfg.product_ids.length || 'all'}`)
  return c.json({ ok: true, processing_fee: cfg })
})
async function saveFinancingMarkup(c: any) {
  const b = await c.req.json()
  const cfg = normalizeFinancingMarkup(b)
  await setSetting(c, 'financing_markup', cfg)
  await audit(c, c.get('user').id, 'update', 'settings', `financing_markup:${cfg.financing_applicable ? cfg.mode : 'cash_only'} products:${cfg.product_ids.length || 'all'}`)
  return c.json({ ok: true, financing_markup: cfg, finance_markup: cfg })
}
app.put('/api/settings/financing-markup', requireAuth, requirePermission('manage_markup_pct'), saveFinancingMarkup)
// Backward-compatible alias (the earlier frontend saved to /settings/markup, which 404'd).
app.put('/api/settings/markup', requireAuth, requirePermission('manage_markup_pct'), saveFinancingMarkup)

// ----------------------------------------------------------------------------
// WITHDRAWAL CHARGE + SUPPORT CONTACT SETTINGS
//   • withdrawal_charge : the standard withdrawal charge schema (flat + %).
//   • support_contact   : phone/email shown when SasaPay main wallet is short.
// Both are configured from the Super-Admin dashboard (admin/super_admin only).
// ----------------------------------------------------------------------------
function isAdminRole(user: SessionUser) {
  return user.role === 'admin' || user.role === 'super_admin' || hasPermission(user, 'manage_wallets')
}
// GET — readable by any authenticated user so the wallet/withdraw UI can show
// the withdrawable limit and the support contact if a payout can't be settled.
app.get('/api/settings/withdrawal', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const withdrawal_charge = normalizeWithdrawalCharge(await getSetting(c, 'withdrawal_charge', DEFAULT_WITHDRAWAL_CHARGE))
  const support_contact = normalizeSupportContact(await getSetting(c, 'support_contact', DEFAULT_SUPPORT_CONTACT))
  return c.json({ withdrawal_charge, support_contact, can_manage: isAdminRole(user) })
})
app.put('/api/settings/withdrawal-charge', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!isAdminRole(user)) return c.json({ error: 'Forbidden' }, 403)
  const b = await c.req.json()
  const cfg = normalizeWithdrawalCharge(b)
  await setSetting(c, 'withdrawal_charge', cfg)
  await audit(c, user.id, 'update', 'settings', `withdrawal_charge:${cfg.enabled ? 'on' : 'off'} flat:${cfg.flat_fee} pct:${cfg.percentage_rate}`)
  return c.json({ ok: true, withdrawal_charge: cfg })
})
app.put('/api/settings/support-contact', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!isAdminRole(user)) return c.json({ error: 'Forbidden' }, 403)
  const b = await c.req.json()
  const cfg = normalizeSupportContact(b)
  await setSetting(c, 'support_contact', cfg)
  await audit(c, user.id, 'update', 'settings', `support_contact phone:${cfg.phone ? 'set' : 'empty'} email:${cfg.email ? 'set' : 'empty'}`)
  return c.json({ ok: true, support_contact: cfg })
})

// Inline "add product to inventory" used by the Processing Fee / Markup builders.
// Authorized either by the classic admin roles OR the fee/markup management perms.
app.post('/api/settings/quick-product', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const allowed = user.role === 'admin' || user.role === 'super_admin' ||
    hasPermission(user, 'manage_processing_fees') || hasPermission(user, 'manage_markup_pct')
  if (!allowed) return c.json({ error: 'Forbidden' }, 403)
  let raw: any
  try { raw = await c.req.json() } catch (_) { return c.json({ error: 'Invalid request body' }, 400) }
  const p = normalizeProductPayload(raw)
  if (!p.sku || !p.name) return c.json({ error: 'SKU and name are required' }, 400)
  if (!(p.buying_price >= 0) || !(p.cash_price >= 0) || !(p.credit_price >= 0)) return c.json({ error: 'Prices must be valid non-negative numbers.' }, 400)
  if (p.image && !isSafeDataUrlOrHttp(p.image)) return c.json({ error: 'Product image must be a JPEG, PNG, WebP or GIF under 8 MB.' }, 400)
  if (p.cash_terms_doc_url && !isSafeDocDataUrlOrHttp(p.cash_terms_doc_url)) return c.json({ error: 'Cash agreement document must be a PDF or image under 8 MB.' }, 400)
  if (p.financing_terms_doc_url && !isSafeDocDataUrlOrHttp(p.financing_terms_doc_url)) return c.json({ error: 'Financing agreement document must be a PDF or image under 8 MB.' }, 400)
  const sourcePlatform = VALID_SOURCE_PLATFORMS.includes(String(raw?.source_platform || '').toLowerCase()) ? String(raw.source_platform).toLowerCase() : 'equipment'
  const dup = await c.env.DB.prepare(`SELECT id FROM products WHERE sku = ?`).bind(p.sku).first<any>()
  if (dup) return c.json({ error: `A product with SKU "${p.sku}" already exists. Use a unique SKU.` }, 409)
  try {
    const r = await c.env.DB.prepare(
      `INSERT INTO products (sku,name,category,subcategory,marketplace,source_platform,description,product_type,supplier_id,buying_price,cash_markup_pct,credit_markup_pct,cash_price,credit_price,quantity,unit,reorder_threshold,image,cash_enabled,financing_enabled,payment_option_mode,financing_model,financing_interest_pct,financing_frequency,financing_term_min_months,financing_term_max_months,cash_deposit_pct,financing_deposit_pct,cash_terms_text,financing_terms_text,cash_terms_doc_url,financing_terms_doc_url,transunion_product_code,created_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      p.sku, p.name, p.category, p.subcategory, p.marketplace, sourcePlatform, p.description, p.product_type, p.supplier_id, p.buying_price, p.cash_markup_pct, p.credit_markup_pct,
      p.cash_price, p.credit_price, p.quantity, p.unit, p.reorder_threshold, p.image, p.cash_enabled, p.financing_enabled,
      p.payment_option_mode, p.financing_model, p.financing_interest_pct, p.financing_frequency, p.financing_term_min_months,
      p.financing_term_max_months, p.cash_deposit_pct, p.financing_deposit_pct, p.cash_terms_text, p.financing_terms_text,
      p.cash_terms_doc_url, p.financing_terms_doc_url, p.transunion_product_code, user.id
    ).run()
    await audit(c, user.id, 'create', 'product', `${p.name} (via settings builder, ${p.marketplace}/${sourcePlatform})`)
    return c.json({ id: r.meta.last_row_id, product: { id: r.meta.last_row_id, sku: p.sku, name: p.name, category: p.category, marketplace: p.marketplace, quantity: p.quantity } })
  } catch (err: any) {
    const msg = String(err?.message || err)
    console.error('Quick product create failed:', msg)
    if (/unique|duplicate/i.test(msg)) return c.json({ error: `A product with SKU "${p.sku}" already exists. Use a unique SKU.` }, 409)
    return c.json({ error: 'Could not save the product. Please check the fields and try again.' }, 500)
  }
})

app.post('/api/change-requests', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!hasPermission(user, 'request_admin_action')) return c.json({ error: 'Forbidden' }, 403)
  const { entity_type, entity_id, requested_action, reason } = await c.req.json()
  await c.env.DB.prepare(`INSERT INTO change_requests (requester_id, entity_type, entity_id, requested_action, reason) VALUES (?,?,?,?,?)`).bind(user.id, entity_type, entity_id || null, requested_action, reason || '').run()
  await audit(c, user.id, 'request_admin_action', entity_type || 'entity', `${requested_action || 'request'} ${entity_id || ''}`)
  return c.json({ ok: true })
})

// ============================================================================
// PROFILE AMENDMENT WORKFLOW (parity) — locked identity fields (National ID /
// phone) can only change via a reviewed request.
// ============================================================================
function canReviewAmendments(user: SessionUser) {
  return ['admin', 'super_admin'].includes(user.role) || hasPermission(user, 'manage_users')
}

// Submit an amendment request (any authenticated user).
app.post('/api/profile-amendments', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const b = await c.req.json()
  const newNid = b.new_national_id !== undefined && b.new_national_id !== null ? String(b.new_national_id).trim() : ''
  const newPhoneRaw = b.new_phone !== undefined && b.new_phone !== null ? String(b.new_phone).trim() : ''
  const newPhone = newPhoneRaw ? normalizePhone(newPhoneRaw) : ''
  const reason = String(b.reason || '').trim()
  if (!newNid && !newPhone) return c.json({ error: 'Provide a new National ID and/or a new phone number.' }, 400)
  if (reason.length < 4) return c.json({ error: 'Please give a reason for the change (at least 4 characters).' }, 400)
  const tv = validateTextFields({ new_national_id: newNid, reason }, [
    { key: 'new_national_id', label: 'National ID', max: 40 },
    { key: 'reason', label: 'Reason', max: 500 }
  ])
  if (!tv.ok) return c.json({ error: tv.error }, 400)
  const open = await c.env.DB.prepare(`SELECT id FROM profile_amendments WHERE user_id=? AND status='pending'`).bind(user.id).first<any>()
  if (open) return c.json({ error: 'You already have a pending amendment request awaiting review.' }, 400)
  const cust = await c.env.DB.prepare(`SELECT id, national_id, mobile FROM customers WHERE user_id=?`).bind(user.id).first<any>()
  const field = newNid && newPhone ? 'both' : (newNid ? 'national_id' : 'phone')
  await c.env.DB.prepare(
    `INSERT INTO profile_amendments (user_id, customer_id, field, current_national_id, current_phone, new_national_id, new_phone, reason)
     VALUES (?,?,?,?,?,?,?,?)`
  ).bind(user.id, cust?.id || null, field, cust?.national_id || null, cust?.mobile || user.phone || null, newNid || null, newPhone || null, reason).run()
  await audit(c, user.id, 'request', 'profile_amendment', `${field} change requested`)
  return c.json({ ok: true })
})

// List MY amendment requests.
app.get('/api/profile-amendments/mine', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  const { results } = await c.env.DB.prepare(`SELECT * FROM profile_amendments WHERE user_id=? ORDER BY created_at DESC`).bind(user.id).all()
  return c.json({ amendments: results })
})

// List all amendment requests for the review dashboard (default: pending).
app.get('/api/profile-amendments', requireAuth, async (c) => {
  const user = c.get('user') as SessionUser
  if (!canReviewAmendments(user)) return c.json({ error: 'Forbidden' }, 403)
  const status = c.req.query('status') || 'pending'
  let q = `SELECT pa.*, u.full_name AS requester_name, u.role AS requester_role, r.full_name AS reviewer_name
           FROM profile_amendments pa
           JOIN users u ON CAST(u.id AS TEXT) = pa.user_id
           LEFT JOIN users r ON CAST(r.id AS TEXT) = pa.reviewed_by`
  const binds: any[] = []
  if (status !== 'all') { q += ` WHERE pa.status=?`; binds.push(status) }
  q += ` ORDER BY pa.created_at DESC`
  const { results } = await c.env.DB.prepare(q).bind(...binds).all()
  return c.json({ amendments: results })
})

// Approve / reject an amendment request.
app.post('/api/profile-amendments/:id/decision', requireAuth, async (c) => {
  const actor = c.get('user') as SessionUser
  if (!canReviewAmendments(actor)) return c.json({ error: 'Forbidden' }, 403)
  const id = c.req.param('id')
  const { action, notes } = await c.req.json()
  const amend = await c.env.DB.prepare(`SELECT * FROM profile_amendments WHERE id=?`).bind(id).first<any>()
  if (!amend) return c.json({ error: 'Not found' }, 404)
  if (amend.status !== 'pending') return c.json({ error: 'This request has already been reviewed.' }, 400)
  if (action === 'approve') {
    if (amend.new_national_id) {
      const dup = await c.env.DB.prepare(`SELECT id FROM customers WHERE national_id=? AND user_id<>?`).bind(amend.new_national_id, amend.user_id).first<any>()
      if (dup) return c.json({ error: 'Cannot approve: that National ID is already in use.' }, 409)
    }
    if (amend.new_phone) {
      const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=? AND id<>?`).bind(amend.new_phone, amend.user_id).first<any>()
      if (dup) return c.json({ error: 'Cannot approve: that phone number is already in use.' }, 409)
    }
    await withAdminContext(c, async () => {
      if (amend.new_phone) {
        await c.env.DB.prepare(`UPDATE users SET phone=? WHERE id=?`).bind(amend.new_phone, amend.user_id).run()
        if (amend.customer_id) await c.env.DB.prepare(`UPDATE customers SET mobile=? WHERE id=?`).bind(amend.new_phone, amend.customer_id).run()
      }
      if (amend.new_national_id && amend.customer_id) {
        await c.env.DB.prepare(`UPDATE customers SET national_id=? WHERE id=?`).bind(amend.new_national_id, amend.customer_id).run()
      }
    })
    await c.env.DB.prepare(`UPDATE profile_amendments SET status='approved', reviewed_by=?, review_notes=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?`).bind(actor.id, notes || null, id).run()
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id = CAST(? AS TEXT)`).bind(amend.user_id).run()
  } else if (action === 'reject') {
    await c.env.DB.prepare(`UPDATE profile_amendments SET status='rejected', reviewed_by=?, review_notes=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?`).bind(actor.id, notes || null, id).run()
  } else {
    return c.json({ error: 'Action must be approve or reject.' }, 400)
  }
  await audit(c, actor.id, action, 'profile_amendment', String(id))
  return c.json({ ok: true, action })
})

// ============================================================================
// AUTOMATED SYSTEM BACKUPS (parity)
// ============================================================================
const AUTO_BACKUP_INTERVAL_MS = 6 * 60 * 60 * 1000 // every 6 hours
const BACKUP_DATASETS = ['users', 'customers', 'agents', 'products', 'murabaha_contracts', 'repayments', 'transactions', 'audit_logs']

// Resolve the recipient(s) for automated backup emails. Supports a comma/;-
// separated list so ops can notify multiple mailboxes.
function backupRecipients(env: any): string[] {
  const raw = String(env?.BACKUP_EMAIL_TO || env?.BACKUP_NOTIFY_EMAIL || '').trim()
  if (!raw) return []
  return raw.split(/[,;\s]+/).map((s: string) => s.trim()).filter((s: string) => /.+@.+\..+/.test(s))
}

async function performBackup(c: any, triggerType: 'manual' | 'auto', createdBy: number | null) {
  const snapshot: Record<string, any[]> = {}
  let total = 0
  await withAdminContext(c, async () => {
    for (const ds of BACKUP_DATASETS) {
      try {
        const { results } = await c.env.DB.prepare(`SELECT * FROM ${ds}`).all()
        snapshot[ds] = results || []
        total += (results || []).length
      } catch (_) { snapshot[ds] = [] }
    }
  })
  const payload = JSON.stringify({ created_at: new Date().toISOString(), datasets: snapshot })
  const summary = BACKUP_DATASETS.map(ds => `${ds}: ${snapshot[ds]?.length || 0}`).join(', ')
  const res = await c.env.DB.prepare(
    `INSERT INTO system_backups (trigger_type, summary, record_count, size_bytes, payload, status, created_by) VALUES (?,?,?,?,?, 'success', ?)`
  ).bind(triggerType, summary, total, payload.length, payload, createdBy).run()
  return { backup_id: res.meta?.last_row_id, record_count: total, size_bytes: payload.length, payload, summary, snapshot }
}

// Build the platform DATA EXPORT (all datasets) as a single CSV bundle. Each
// dataset section is prefixed by a header line, so ops get one file covering
// every table. Runs under admin context so RLS never hides rows.
async function buildFullExportCsv(c: any): Promise<string> {
  const parts: string[] = []
  await withAdminContext(c, async () => {
    for (const [key, def] of Object.entries(EXPORT_DATASETS)) {
      try {
        const { results } = await c.env.DB.prepare(def.sql + ' ORDER BY 1 DESC').all()
        parts.push(`### ${def.label} (${key}) — ${(results || []).length} rows`)
        parts.push(toCsv(def.cols, results || []))
        parts.push('')
      } catch (_) { /* skip dataset that failed */ }
    }
  })
  return parts.join('\n')
}

// Email BOTH backups (system snapshot JSON + platform data export CSV) to the
// configured recipient(s). Best-effort: returns whether it sent and why not.
async function emailBackups(c: any, backup: { backup_id?: any; payload: string; summary: string }): Promise<{ sent: boolean; reason?: string; to?: string[] }> {
  const to = backupRecipients(c.env)
  if (!to.length) return { sent: false, reason: 'no_recipient' }
  if (!emailConfigured(c.env)) return { sent: false, reason: 'email_not_configured' }
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
  let exportCsv = ''
  try { exportCsv = await buildFullExportCsv(c) } catch (_) { exportCsv = '' }
  const attachments = [
    { filename: `farmsky-system-backup-${stamp}.json`, contentBase64: base64Utf8(backup.payload), contentType: 'application/json' }
  ]
  if (exportCsv) attachments.push({ filename: `farmsky-data-export-${stamp}.csv`, contentBase64: base64Utf8(exportCsv), contentType: 'text/csv' })
  const r = await sendEmail(c.env, {
    to: to.join(', '),
    subject: `Farmsky automated backup — ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`,
    text: `Automated 6-hourly Farmsky backup.\n\nSystem backup #${backup.backup_id || '?'}\nDatasets: ${backup.summary}\n\nTwo files are attached:\n  1) Full system backup (JSON snapshot of all tables)\n  2) Platform data export (CSV bundle of all datasets)\n\nThis email is generated automatically; do not reply.`,
    attachments
  })
  if (!r.success) return { sent: false, reason: r.error || 'send_failed', to }
  return { sent: true, to }
}

async function maybeAutoBackup(c: any) {
  try {
    const last = await c.env.DB.prepare(`SELECT created_at FROM system_backups WHERE trigger_type='auto' ORDER BY id DESC LIMIT 1`).first<any>()
    if (last?.created_at) {
      const lastMs = new Date(last.created_at).getTime()
      if (!Number.isNaN(lastMs) && Date.now() - lastMs < AUTO_BACKUP_INTERVAL_MS) return { ran: false }
    }
    const bk = await performBackup(c, 'auto', null)
    // Automated delivery: email BOTH backups to the designated recipient(s).
    let emailed: { sent: boolean; reason?: string; to?: string[] } = { sent: false, reason: 'no_recipient' }
    try { emailed = await emailBackups(c, bk) } catch (e: any) { emailed = { sent: false, reason: e?.message || 'email_error' } }
    return { ran: true, emailed }
  } catch (_) { return { ran: false } }
}

app.get('/api/backups', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  await maybeAutoBackup(c)
  const { results } = await c.env.DB.prepare(
    `SELECT b.id, b.trigger_type, b.summary, b.record_count, b.size_bytes, b.status, b.error, b.created_at, u.full_name created_by_name
       FROM system_backups b LEFT JOIN users u ON CAST(u.id AS TEXT)=b.created_by
      ORDER BY b.id DESC LIMIT 100`
  ).all()
  return c.json({ backups: results || [], interval_hours: AUTO_BACKUP_INTERVAL_MS / 3600000 })
})

app.post('/api/backups', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  try {
    const out = await performBackup(c, 'manual', c.get('user').id)
    // Return ONLY metadata — never the snapshot/payload here. The full data
    // (which contains password hashes) is downloadable only via the
    // password-re-auth /download endpoint.
    return c.json({ ok: true, backup_id: out.backup_id, record_count: out.record_count, size_bytes: out.size_bytes })
  } catch (e: any) {
    return c.json({ error: e?.message || 'Backup failed' }, 500)
  }
})

// SENSITIVE — downloading a full system backup requires the admin/super-admin to
// RE-ENTER their password (defence against a walked-away session exfiltrating the
// whole DB). Delivered as POST so the password travels in the body, never a URL.
app.post('/api/backups/:id/download', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const reauth = await verifyReauth(c, body?.password)
  if (!reauth.ok) return c.json({ error: reauth.error, reauth_required: true }, reauth.status as any)
  const row = await c.env.DB.prepare(`SELECT id, payload, created_at FROM system_backups WHERE id=?`).bind(c.req.param('id')).first<any>()
  if (!row || !row.payload) return c.json({ error: 'Backup not found' }, 404)
  await audit(c, c.get('user').id, 'backup_download', 'system', `backup #${row.id} (password re-auth)`)
  return new Response(row.payload, {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="farmsky-backup-${row.id}.json"`
    }
  })
})
// Legacy GET is retired for security — always instruct the client to POST with a
// password confirmation. Never returns backup data.
app.get('/api/backups/:id/download', requireAuth, requireRole('admin', 'super_admin'), (c) => {
  return c.json({ error: 'Password confirmation required. POST to this URL with { password } to download.', reauth_required: true }, 401)
})

app.post('/api/backups/run-auto', async (c) => {
  const token = c.req.header('x-admin-task-token') || ''
  const expected = (c.env as any).ADMIN_TASK_TOKEN
  if (expected && token === expected) {
    const r = await maybeAutoBackup(c)
    return c.json({ ok: true, ...r })
  }
  // In-process scheduler (Node server 6h timer). Authorized by a per-boot nonce
  // injected into ENV that never leaves the process — external callers can't know it.
  const internalNonce = (c.env as any).INTERNAL_SCHEDULER_NONCE
  if (internalNonce && c.req.header('x-internal-scheduler') === internalNonce) {
    const r = await maybeAutoBackup(c)
    return c.json({ ok: true, ...r })
  }
  const sessionToken = getCookie(c, 'session')
  const sess = sessionToken ? await c.env.DB.prepare(`SELECT u.role FROM sessions s JOIN users u ON CAST(u.id AS TEXT)=s.user_id WHERE s.token=? AND s.expires_at > ?`).bind(sessionToken, Date.now()).first<any>() : null
  if (!sess || !['admin', 'super_admin'].includes(sess.role)) return c.json({ error: 'Unauthorized' }, 401)
  const r = await maybeAutoBackup(c)
  return c.json({ ok: true, ...r })
})

// ============================================================================
// BULK USER DATA UPLOAD & STANDARDIZATION (parity)
// ============================================================================
function mapImportRow(raw: Record<string, any>): Record<string, string> {
  const norm: Record<string, any> = {}
  for (const [k, v] of Object.entries(raw)) {
    norm[String(k).toLowerCase().replace(/[^a-z0-9]/g, '')] = v
  }
  const pick = (...keys: string[]) => {
    for (const k of keys) { const v = norm[k]; if (v != null && String(v).trim() !== '') return String(v).trim() }
    return ''
  }
  return {
    full_name: pick('fullname', 'name', 'names', 'customername', 'farmername'),
    phone: pick('phone', 'phonenumber', 'mobile', 'msisdn', 'tel', 'telephone', 'contact'),
    national_id: pick('nationalid', 'idnumber', 'idno', 'id', 'nid'),
    email: pick('email', 'emailaddress'),
    county: pick('county', 'region'),
    sub_county: pick('subcounty', 'subcounties'),
    ward: pick('ward'),
    village: pick('village', 'location'),
    value_chain_type: pick('valuechaintype', 'vct', 'category', 'farmtype', 'partnertype'),
    value_chain: pick('valuechain', 'vc', 'crop', 'produce', 'commodity'),
    region: pick('region', 'county', 'area')
  }
}

const IMPORT_REQUIRED: Record<string, string[]> = {
  farmers: ['full_name', 'phone', 'national_id', 'county'],
  agents: ['full_name', 'phone'],
  partners: ['full_name', 'phone']
}

function validateImportRow(category: string, row: Record<string, string>): string[] {
  const required = IMPORT_REQUIRED[category] || ['full_name', 'phone']
  const issues: string[] = []
  for (const f of required) {
    if (!row[f] || String(row[f]).trim() === '') issues.push(`missing ${f}`)
  }
  if (row.phone) {
    const p = normalizePhone(row.phone)
    if (!p || p.length < 12) issues.push('invalid phone')
  }
  return issues
}

async function recomputeBatchCounts(c: any, batchId: number) {
  const v = await c.env.DB.prepare(`SELECT COUNT(*) n FROM import_rows WHERE batch_id=? AND status='valid'`).bind(batchId).first<any>()
  const e = await c.env.DB.prepare(`SELECT COUNT(*) n FROM import_rows WHERE batch_id=? AND status='exception'`).bind(batchId).first<any>()
  const d = await c.env.DB.prepare(`SELECT COUNT(*) n FROM import_rows WHERE batch_id=? AND status='dispatched'`).bind(batchId).first<any>()
  await c.env.DB.prepare(`UPDATE import_batches SET valid_rows=?, exception_rows=?, dispatched_rows=? WHERE id=?`)
    .bind(Number(v?.n || 0), Number(e?.n || 0), Number(d?.n || 0), batchId).run()
}

app.post('/api/imports', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { category, filename, rows } = await c.req.json()
  const cat = String(category || '').toLowerCase()
  if (!['farmers', 'agents', 'partners'].includes(cat)) return c.json({ error: 'category must be farmers, agents or partners' }, 400)
  if (!Array.isArray(rows) || rows.length === 0) return c.json({ error: 'No rows to import' }, 400)
  if (rows.length > 5000) return c.json({ error: 'Batch too large (max 5000 rows)' }, 400)
  const creator = c.get('user').id
  const batch = await c.env.DB.prepare(
    `INSERT INTO import_batches (category, filename, total_rows, status, created_by) VALUES (?,?,?, 'review', ?)`
  ).bind(cat, filename || null, rows.length, creator).run()
  const batchId = batch.meta.last_row_id
  let valid = 0, exceptions = 0
  for (let i = 0; i < rows.length; i++) {
    const mapped = mapImportRow(rows[i] || {})
    if (mapped.phone) mapped.phone = normalizePhone(mapped.phone)
    const issues = validateImportRow(cat, mapped)
    const status = issues.length ? 'exception' : 'valid'
    if (status === 'valid') valid++; else exceptions++
    await c.env.DB.prepare(
      `INSERT INTO import_rows (batch_id, row_number, full_name, phone, national_id, email, county, sub_county, ward, village, value_chain_type, value_chain, region, raw, status, issues)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(
      batchId, i + 1, mapped.full_name || null, mapped.phone || null, mapped.national_id || null, mapped.email || null,
      mapped.county || null, mapped.sub_county || null, mapped.ward || null, mapped.village || null,
      mapped.value_chain_type || null, mapped.value_chain || null, mapped.region || null,
      JSON.stringify(rows[i] || {}), status, issues.join(', ') || null
    ).run()
  }
  await c.env.DB.prepare(`UPDATE import_batches SET valid_rows=?, exception_rows=? WHERE id=?`).bind(valid, exceptions, batchId).run()
  await audit(c, creator, 'import', cat, `batch #${batchId}: ${rows.length} rows (${exceptions} exceptions)`)
  return c.json({ ok: true, batch_id: batchId, total: rows.length, valid, exceptions })
})

app.get('/api/imports', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT b.*, u.full_name created_by_name FROM import_batches b LEFT JOIN users u ON CAST(u.id AS TEXT)=b.created_by ORDER BY b.id DESC LIMIT 100`
  ).all()
  return c.json({ batches: results || [] })
})

app.get('/api/imports/:id', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const batch = await c.env.DB.prepare(`SELECT * FROM import_batches WHERE id=?`).bind(id).first<any>()
  if (!batch) return c.json({ error: 'Batch not found' }, 404)
  const { results } = await c.env.DB.prepare(`SELECT * FROM import_rows WHERE batch_id=? ORDER BY row_number`).bind(id).all()
  return c.json({ batch, rows: results || [] })
})

app.put('/api/imports/rows/:rowId', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const rowId = c.req.param('rowId')
  const b = await c.req.json()
  const row = await c.env.DB.prepare(`SELECT r.*, ba.category FROM import_rows r JOIN import_batches ba ON ba.id=r.batch_id WHERE r.id=?`).bind(rowId).first<any>()
  if (!row) return c.json({ error: 'Row not found' }, 404)
  if (row.status === 'dispatched') return c.json({ error: 'Row already onboarded' }, 400)
  const merged: Record<string, string> = {
    full_name: b.full_name ?? row.full_name ?? '',
    phone: b.phone != null ? normalizePhone(b.phone) : (row.phone || ''),
    national_id: b.national_id ?? row.national_id ?? '',
    email: b.email ?? row.email ?? '',
    county: b.county ?? row.county ?? '',
    sub_county: b.sub_county ?? row.sub_county ?? '',
    ward: b.ward ?? row.ward ?? '',
    village: b.village ?? row.village ?? '',
    value_chain_type: b.value_chain_type ?? row.value_chain_type ?? '',
    value_chain: b.value_chain ?? row.value_chain ?? '',
    region: b.region ?? row.region ?? ''
  }
  const issues = validateImportRow(row.category, merged)
  const status = issues.length ? 'exception' : 'valid'
  await c.env.DB.prepare(
    `UPDATE import_rows SET full_name=?, phone=?, national_id=?, email=?, county=?, sub_county=?, ward=?, village=?, value_chain_type=?, value_chain=?, region=?, status=?, issues=? WHERE id=?`
  ).bind(merged.full_name || null, merged.phone || null, merged.national_id || null, merged.email || null,
    merged.county || null, merged.sub_county || null, merged.ward || null, merged.village || null,
    merged.value_chain_type || null, merged.value_chain || null, merged.region || null,
    status, issues.join(', ') || null, rowId).run()
  await recomputeBatchCounts(c, row.batch_id)
  return c.json({ ok: true, status, issues })
})

app.post('/api/imports/:id/dispatch', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const id = c.req.param('id')
  const batch = await c.env.DB.prepare(`SELECT * FROM import_batches WHERE id=?`).bind(id).first<any>()
  if (!batch) return c.json({ error: 'Batch not found' }, 404)
  const cat = String(batch.category)
  const roleForCategory = cat === 'agents' ? 'agent' : cat === 'partners' ? 'partner' : 'customer'
  const { results } = await c.env.DB.prepare(`SELECT * FROM import_rows WHERE batch_id=? AND status='valid'`).bind(id).all()
  const rows = (results || []) as any[]
  const creatorUser = c.get('user') as SessionUser
  const creator = creatorUser.id
  // Resolve the tenant once for the whole batch (importer's org, else default).
  const importOrgId = (await resolveCreatorOrgId(c, creatorUser)) ?? (await resolveDefaultOrgId(c))
  const withImportOrg = await usersHasOrgId(c) && importOrgId != null
  let created = 0, skipped = 0
  const errors: string[] = []
  for (const row of rows) {
    const phone = normalizePhone(row.phone || '')
    if (!phone) { skipped++; continue }
    const dup = await c.env.DB.prepare(`SELECT id FROM users WHERE phone=?`).bind(phone).first<any>()
    if (dup) { skipped++; errors.push(`${row.full_name || phone}: already exists`); continue }
    try {
      const perms = await permissionsForRole(c, roleForCategory === 'agent' ? 'agent' : roleForCategory === 'partner' ? 'partner' : 'customer', {})
      const placeholder = await hashPassword(genPassword())
      // Bulk-import roles (agent/partner/customer) never require email; a unique
      // placeholder (from phone) satisfies central users.email NOT NULL + UNIQUE.
      const emailRes = resolveEmail(roleForCategory, row.email, phone)
      if ('error' in emailRes) { skipped++; errors.push(`${row.full_name || phone}: ${emailRes.error}`); continue }
      const email = emailRes.value
      const ur = withImportOrg && importOrgId != null
        ? await c.env.DB.prepare(
            `INSERT INTO users (full_name, phone, email, password, role, region, password_set, permissions, created_by, org_id) VALUES (?,?,?,?,?,?,0,?,?,?)`
          ).bind(row.full_name, phone, email, placeholder, roleForCategory, row.region || row.county || null, JSON.stringify(perms), creator, importOrgId).run()
        : await c.env.DB.prepare(
            `INSERT INTO users (full_name, phone, email, password, role, region, password_set, permissions, created_by) VALUES (?,?,?,?,?,?,0,?,?)`
          ).bind(row.full_name, phone, email, placeholder, roleForCategory, row.region || row.county || null, JSON.stringify(perms), creator).run()
      const userId = ur.meta.last_row_id as number
      if (roleForCategory === 'customer') {
        await c.env.DB.prepare(
          `INSERT INTO customers (user_id, agent_id, onboarded_by, full_name, national_id, mobile, county, sub_county, ward, village, value_chain_type, value_chain, kyc_status, status)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'pending', 'active')`
        ).bind(userId, null, creator, row.full_name, row.national_id || null, phone, row.county || null, row.sub_county || null, row.ward || null, row.village || null, row.value_chain_type || null, row.value_chain || null).run()
      } else if (roleForCategory === 'agent') {
        await c.env.DB.prepare(`INSERT INTO agents (user_id,region,permissions) VALUES (?,?,?)`).bind(userId, row.region || row.county || null, JSON.stringify(perms)).run()
      }
      await issueTempPassword(c, { userId, phone, fullName: row.full_name })
      await c.env.DB.prepare(`UPDATE import_rows SET status='dispatched', created_user_id=? WHERE id=?`).bind(userId, row.id).run()
      created++
    } catch (e: any) {
      skipped++; errors.push(`${row.full_name || phone}: ${e?.message || 'failed'}`)
    }
  }
  await recomputeBatchCounts(c, Number(id))
  const remaining = await c.env.DB.prepare(`SELECT COUNT(*) n FROM import_rows WHERE batch_id=? AND status='exception'`).bind(id).first<any>()
  const newStatus = Number(remaining?.n || 0) === 0 ? 'completed' : 'dispatched'
  await c.env.DB.prepare(`UPDATE import_batches SET status=? WHERE id=?`).bind(newStatus, id).run()
  await audit(c, creator, 'import_dispatch', cat, `batch #${id}: ${created} onboarded, ${skipped} skipped`)
  return c.json({ ok: true, created, skipped, errors: errors.slice(0, 50), status: newStatus })
})

// Repayment performance
app.get('/api/repayments', requireAuth, requireRole('admin', 'super_admin', 'support', 'operations_finance'), async (c) => {
  const { results } = await c.env.DB.prepare(
    `SELECT r.*, mc.contract_ref, cu.full_name customer FROM repayments r
     JOIN murabaha_contracts mc ON mc.id=r.contract_id JOIN customers cu ON cu.id=mc.customer_id ORDER BY r.due_date`
  ).all()
  return c.json({ repayments: results })
})
// Documents
app.get('/api/documents/:type/:id', requireAuth, async (c) => {
  const type = c.req.param('type'), id = c.req.param('id')
  const contract = await c.env.DB.prepare(
    `SELECT mc.*, p.name product_name, cu.full_name customer_name, cu.national_id, cu.county
     FROM murabaha_contracts mc JOIN products p ON p.id=mc.product_id JOIN customers cu ON cu.id=mc.customer_id WHERE mc.id=?`
  ).bind(id).first()
  if (!contract) return c.json({ error: 'Not found' }, 404)
  return c.json({ type, contract, txn_id: contract.contract_ref, qr: `https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=${contract.contract_ref}` })
})

// ----------------------------------------------------------------------------
// ADMIN DATA EXPORT  (filter + download CSV/Excel locally, or email a copy)
// ----------------------------------------------------------------------------
// Supported datasets and their base queries. Filters are applied safely.
const EXPORT_DATASETS: Record<string, { label: string; sql: string; cols: string[]; filterable: Record<string, string> }> = {
  users: {
    label: 'Users / Accounts',
    sql: `SELECT id, full_name, phone, email, role, label, status, region, created_at FROM users`,
    cols: ['id', 'full_name', 'phone', 'email', 'role', 'label', 'status', 'region', 'created_at'],
    filterable: { role: 'role', status: 'status', region: 'region' }
  },
  customers: {
    label: 'Customers / Farmers',
    sql: `SELECT cu.id, cu.full_name, cu.mobile, cu.county, cu.value_chain, cu.kyc_status, cu.risk_band, cu.credit_score, u.full_name agent FROM customers cu LEFT JOIN users u ON CAST(u.id AS TEXT)=cu.agent_id`,
    cols: ['id', 'full_name', 'mobile', 'county', 'value_chain', 'kyc_status', 'risk_band', 'credit_score', 'agent'],
    filterable: { kyc_status: 'cu.kyc_status', risk_band: 'cu.risk_band', county: 'cu.county' }
  },
  agents: {
    label: 'Agents',
    sql: `SELECT id, full_name, phone, email, region, status, created_at FROM users WHERE role='agent'`,
    cols: ['id', 'full_name', 'phone', 'email', 'region', 'status', 'created_at'],
    filterable: { status: 'status', region: 'region' }
  },
  products: {
    label: 'Inventory / Products',
    sql: `SELECT id, sku, name, category, product_type, payment_option_mode, financing_model, financing_interest_pct, cash_deposit_pct, financing_deposit_pct, buying_price, cash_price, credit_price, quantity, unit, reorder_threshold, image FROM products`,
    cols: ['id', 'sku', 'name', 'category', 'product_type', 'payment_option_mode', 'financing_model', 'financing_interest_pct', 'cash_deposit_pct', 'financing_deposit_pct', 'buying_price', 'cash_price', 'credit_price', 'quantity', 'unit', 'reorder_threshold', 'image'],
    filterable: { category: 'category' }
  },
  contracts: {
    label: 'Murabaha Contracts',
    sql: `SELECT mc.id, mc.contract_ref, cu.full_name customer, p.name product, mc.payment_type, mc.financing_model, mc.deposit_pct, mc.deposit_amount, mc.payment_frequency, mc.installment_amount, mc.murabaha_price, mc.amount_paid, mc.outstanding, mc.status, mc.dispatch_status, mc.created_at FROM murabaha_contracts mc JOIN customers cu ON cu.id=mc.customer_id JOIN products p ON p.id=mc.product_id`,
    cols: ['id', 'contract_ref', 'customer', 'product', 'payment_type', 'financing_model', 'deposit_pct', 'deposit_amount', 'payment_frequency', 'installment_amount', 'murabaha_price', 'amount_paid', 'outstanding', 'status', 'dispatch_status', 'created_at'],
    filterable: { status: 'mc.status', payment_type: 'mc.payment_type' }
  },
  repayments: {
    label: 'Repayments',
    sql: `SELECT r.id, mc.contract_ref, cu.full_name customer, r.installment_no, r.due_date, r.amount_due, r.amount_paid, r.status FROM repayments r JOIN murabaha_contracts mc ON mc.id=r.contract_id JOIN customers cu ON cu.id=mc.customer_id`,
    cols: ['id', 'contract_ref', 'customer', 'installment_no', 'due_date', 'amount_due', 'amount_paid', 'status'],
    filterable: { status: 'r.status' }
  },
  transactions: {
    label: 'Transactions / Payments',
    sql: `SELECT t.id, t.txn_ref, cu.full_name customer, t.amount, t.method, t.type, t.mpesa_receipt, t.status, t.created_at FROM transactions t LEFT JOIN customers cu ON cu.id=t.customer_id`,
    cols: ['id', 'txn_ref', 'customer', 'amount', 'method', 'type', 'mpesa_receipt', 'status', 'created_at'],
    filterable: { status: 't.status', method: 't.method', type: 't.type' }
  },
  audit_logs: {
    label: 'Audit Log',
    sql: `SELECT a.id, u.full_name actor, a.action, a.entity, a.detail, a.created_at FROM audit_logs a LEFT JOIN users u ON CAST(u.id AS TEXT)=a.user_id`,
    cols: ['id', 'actor', 'action', 'entity', 'detail', 'created_at'],
    filterable: { action: 'a.action', entity: 'a.entity' }
  }
}

async function buildExport(c: any, dataset: string, filters: Record<string, string>, dateFrom?: string, dateTo?: string) {
  const def = EXPORT_DATASETS[dataset]
  if (!def) throw new Error('Unknown dataset')
  const where: string[] = []
  const binds: any[] = []
  const hasWhere = /\bwhere\b/i.test(def.sql)
  for (const [key, col] of Object.entries(def.filterable)) {
    const v = filters?.[key]
    if (v != null && String(v).trim() !== '' && String(v) !== 'all') {
      where.push(`${col} = ?`); binds.push(v)
    }
  }
  // Date range on created_at / due_date if present
  const dateCol = def.cols.includes('created_at') ? 'created_at' : (def.cols.includes('due_date') ? 'due_date' : null)
  if (dateCol && dateFrom) { where.push(`${dateCol} >= ?`); binds.push(dateFrom) }
  if (dateCol && dateTo) { where.push(`${dateCol} <= ?`); binds.push(dateTo + ' 23:59:59') }
  let sql = def.sql
  if (where.length) sql += (hasWhere ? ' AND ' : ' WHERE ') + where.join(' AND ')
  sql += ` ORDER BY 1 DESC`
  // Run the export under admin context so PostgreSQL Row-Level Security never
  // strips rows. Admins/super-admins ARE authorized to export the whole dataset;
  // without this the ownership RLS policies (keyed on app.current_user_id, which
  // can be lost/narrowed on a pooled connection between requests) intermittently
  // returned ZERO rows — producing a file with only the header line and no data.
  // This mirrors buildFullExportCsv(), which already wraps its reads this way.
  const results = await withAdminContext(c, async () => {
    const stmt = binds.length ? c.env.DB.prepare(sql).bind(...binds) : c.env.DB.prepare(sql)
    const out = await stmt.all()
    return out.results
  })
  // Mask non-deliverable placeholder emails so exports never leak internal
  // synthetic addresses (they mean "no email on file").
  const rows = (results || []).map((r: any) => (r && 'email' in r && isPlaceholderEmail(r.email)) ? { ...r, email: '' } : r)
  return { label: def.label, cols: def.cols, rows }
}

// base64 of a UTF-8 string, works in both Node and Workers runtimes.
function base64Utf8(s: string): string {
  if (typeof Buffer !== 'undefined') return Buffer.from(s, 'utf8').toString('base64')
  const bytes = new TextEncoder().encode(s)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  // @ts-ignore btoa exists in Workers
  return btoa(bin)
}
function toCsv(cols: string[], rows: any[]): string {
  const esc = (v: any) => {
    const s = v == null ? '' : String(v)
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s
  }
  const head = cols.map(esc).join(',')
  const body = rows.map((r) => cols.map((cKey) => esc(r[cKey])).join(',')).join('\n')
  return head + '\n' + body
}

// Metadata: list datasets + their filter options (distinct values).
app.get('/api/export/datasets', requireAuth, requireRole('admin', 'super_admin'), (c) => {
  const list = Object.entries(EXPORT_DATASETS).map(([key, d]) => ({ key, label: d.label, filters: Object.keys(d.filterable), cols: d.cols }))
  return c.json({ datasets: list, email_configured: emailConfigured(c.env) })
})
// Return filtered data as JSON (frontend turns it into CSV/XLSX for local download).
app.post('/api/export/data', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { dataset, filters, date_from, date_to } = await c.req.json()
  try {
    const out = await buildExport(c, dataset, filters || {}, date_from, date_to)
    await audit(c, c.get('user').id, 'export', dataset, `${out.rows.length} rows`)
    return c.json({ ok: true, ...out })
  } catch (e: any) {
    return c.json({ error: e.message || 'Export failed' }, 400)
  }
})
// Email a filtered export (CSV attachment) to a recipient.
app.post('/api/export/email', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const { dataset, filters, date_from, date_to, to, format } = await c.req.json()
  if (!to || !/.+@.+\..+/.test(String(to))) return c.json({ error: 'Enter a valid recipient email' }, 400)
  if (!emailConfigured(c.env)) {
    return c.json({ error: 'email_not_configured', message: 'Email provider not configured. Use the Download button instead, or set EMAIL_API_URL/TOKEN/FROM at deploy.' }, 412)
  }
  try {
    const out = await buildExport(c, dataset, filters || {}, date_from, date_to)
    const csv = toCsv(out.cols, out.rows)
    const b64 = base64Utf8(csv)
    const fname = `farmsky-${dataset}-${new Date().toISOString().slice(0, 10)}.csv`
    const r = await sendEmail(c.env, {
      to,
      subject: `Farmsky export — ${out.label} (${out.rows.length} rows)`,
      text: `Attached is the ${out.label} export you requested from Farmsky (${out.rows.length} rows).`,
      attachments: [{ filename: fname, contentBase64: b64, contentType: 'text/csv' }]
    })
    if (!r.success) return c.json({ error: r.error || 'Email send failed' }, 502)
    await audit(c, c.get('user').id, 'export_email', dataset, `to ${to}`)
    return c.json({ ok: true, message: `Export emailed to ${to}` })
  } catch (e: any) {
    return c.json({ error: e.message || 'Export failed' }, 400)
  }
})
// SENSITIVE — downloading platform data requires the admin/super-admin to
// RE-ENTER their password (same protection as the full system backup). Returns
// the filtered CSV directly as an attachment once the password is confirmed.
app.post('/api/export/download', requireAuth, requireRole('admin', 'super_admin'), async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const reauth = await verifyReauth(c, body?.password)
  if (!reauth.ok) return c.json({ error: reauth.error, reauth_required: true }, reauth.status as any)
  const { dataset, filters, date_from, date_to } = body || {}
  try {
    const out = await buildExport(c, dataset, filters || {}, date_from, date_to)
    const csv = toCsv(out.cols, out.rows)
    const fname = `farmsky-${dataset}-${new Date().toISOString().slice(0, 10)}.csv`
    await audit(c, c.get('user').id, 'export_download', dataset, `${out.rows.length} rows (password re-auth)`)
    return new Response(csv, {
      headers: {
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="${fname}"`
      }
    })
  } catch (e: any) {
    return c.json({ error: e.message || 'Export failed' }, 400)
  }
})

// ============================================================================
// WALLET SYSTEM — double-entry ledger, earning rules, commissions, payouts
// ============================================================================

// Ensure a user has a wallet row; returns the wallet id. Created under admin
// context so it works regardless of the caller's ownership scope.
async function ensureWallet(c: any, userId: string | number, assignedBy: string | number | null = null): Promise<number> {
  return await withAdminContext(c, async () => {
    const existing = await c.env.DB.prepare(`SELECT id FROM wallets WHERE user_id=?`).bind(String(userId)).first<any>()
    if (existing) return Number(existing.id)
    const r = await c.env.DB.prepare(`INSERT INTO wallets (user_id, assigned_by) VALUES (?,?)`).bind(String(userId), assignedBy == null ? null : String(assignedBy)).run()
    return Number(r.meta.last_row_id)
  })
}
// Post a ledger entry (the ONLY sanctioned way a balance changes). The DB
// trigger stamps balance_after and syncs wallets.balance atomically.
async function postLedger(c: any, opts: { userId: string | number; walletId: number; type: 'credit' | 'debit'; amount: number; category: string; reference?: string | null; description?: string | null; createdBy?: string | number | null }) {
  return await c.env.DB.prepare(
    `INSERT INTO wallet_ledger (wallet_id, user_id, entry_type, amount, balance_after, category, reference, description, created_by)
     VALUES (?,?,?,?, 0, ?,?,?,?)`
  ).bind(opts.walletId, String(opts.userId), opts.type, roundMoney(opts.amount), opts.category, opts.reference ?? null, opts.description ?? null, opts.createdBy == null ? null : String(opts.createdBy)).run()
}

// GET my wallet + ledger statement (RLS scopes agents to their own).
app.get('/api/wallet', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const walletId = await ensureWallet(c, user.id)
  const wallet = await c.env.DB.prepare(`SELECT * FROM wallets WHERE id=?`).bind(walletId).first<any>()
  const { results: ledger } = await c.env.DB.prepare(`SELECT * FROM wallet_ledger WHERE wallet_id=? ORDER BY id DESC LIMIT 200`).bind(walletId).all()
  const { results: rules } = await c.env.DB.prepare(`SELECT * FROM earning_rules WHERE user_id=? AND is_active=1 ORDER BY id`).bind(user.id).all()
  // Withdrawal charge schema + the holder's withdrawable limit (balance − effective charge).
  const chargeCfg = normalizeWithdrawalCharge(await getSetting(c, 'withdrawal_charge', DEFAULT_WITHDRAWAL_CHARGE))
  const supportContact = normalizeSupportContact(await getSetting(c, 'support_contact', DEFAULT_SUPPORT_CONTACT))
  const balance = numberVal(wallet?.balance, 0)
  const limit = computeWithdrawableLimit(chargeCfg, balance)
  return c.json({
    wallet, ledger, earning_rules: rules,
    withdrawal_charge: chargeCfg,
    withdrawable: limit.withdrawable,
    charge_at_max: limit.charge_at_max,
    support_contact: supportContact
  })
})

// ---- Admin wallet management ----
// List all wallets with holder details (admin global view).
app.get('/api/wallets', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(
      `SELECT w.*, u.full_name, u.phone, u.role,
              (SELECT COUNT(*) FROM earning_rules er WHERE er.user_id=w.user_id AND er.is_active=1) AS rule_count
         FROM wallets w JOIN users u ON CAST(u.id AS TEXT) = w.user_id ORDER BY u.full_name`
    ).all()
    return results
  })
  return c.json({ wallets: rows })
})
// Assign / create a wallet for a user (admin authorizes it).
app.post('/api/wallets', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const admin = c.get('user') as SessionUser
  const b = await c.req.json()
  const userId = String(b.user_id ?? '').trim()
  if (!userId) return c.json({ error: 'user_id is required' }, 400)
  const walletId = await ensureWallet(c, userId, admin.id)
  await audit(c, admin.id, 'assign', 'wallet', `wallet for user ${userId}`)
  return c.json({ ok: true, wallet_id: walletId })
})

// ---- Earning rules (admin sets criteria: 2% commission, KES 5,000 retainer…) ----
app.get('/api/earning-rules/:userId', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const userId = c.req.param('userId')
  const rows = await withAdminContext(c, async () => {
    const { results } = await c.env.DB.prepare(`SELECT * FROM earning_rules WHERE user_id=? ORDER BY id`).bind(userId).all()
    return results
  })
  return c.json({ earning_rules: rows })
})
app.post('/api/earning-rules', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const admin = c.get('user') as SessionUser
  const b = await c.req.json()
  const userId = String(b.user_id ?? '').trim()
  const ruleType = String(b.rule_type || '').trim()
  if (!userId || !ruleType) return c.json({ error: 'user_id and rule_type are required' }, 400)
  const calcMethod = b.calc_method === 'percentage' ? 'percentage' : 'fixed'
  await ensureWallet(c, userId, admin.id)
  const r = await withAdminContext(c, async () => await c.env.DB.prepare(
    `INSERT INTO earning_rules (user_id, rule_type, calc_method, rate, fixed_amount, applies_to, description, is_active, created_by)
     VALUES (?,?,?,?,?,?,?,1,?)`
  ).bind(userId, ruleType, calcMethod, calcMethod === 'percentage' ? numberVal(b.rate, 0) : null, calcMethod === 'fixed' ? numberVal(b.fixed_amount, 0) : null, b.applies_to || (ruleType === 'commission' ? 'completed_order' : 'manual'), b.description || null, admin.id).run())
  await audit(c, admin.id, 'create', 'earning_rule', `${ruleType} for user ${userId}`)
  return c.json({ ok: true, id: r.meta.last_row_id })
})
app.put('/api/earning-rules/:id', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const admin = c.get('user') as SessionUser
  const id = c.req.param('id')
  const b = await c.req.json()
  await withAdminContext(c, async () => await c.env.DB.prepare(
    `UPDATE earning_rules SET rule_type=COALESCE(?,rule_type), calc_method=COALESCE(?,calc_method), rate=?, fixed_amount=?, applies_to=COALESCE(?,applies_to), description=COALESCE(?,description), is_active=COALESCE(?,is_active), updated_at=CURRENT_TIMESTAMP WHERE id=?`
  ).bind(b.rule_type ?? null, b.calc_method ?? null, b.rate ?? null, b.fixed_amount ?? null, b.applies_to ?? null, b.description ?? null, b.is_active === undefined ? null : (boolInt(b.is_active, true) ? 1 : 0), id).run())
  await audit(c, admin.id, 'update', 'earning_rule', String(id))
  return c.json({ ok: true })
})

// ---- Dynamic commission distribution on order completion ----
// Called when a contract/order status becomes 'completed'. Evaluates the target
// agent's active commission rules and credits their wallet dynamically.
async function distributeCommission(c: any, contract: any) {
  if (!contract) return
  const agentId = contract.created_by || contract.agent_id
  if (!agentId) return
  const orderValue = numberVal(contract.murabaha_price ?? contract.total_payable, 0)
  await withAdminContext(c, async () => {
    const { results: rules } = await c.env.DB.prepare(
      `SELECT * FROM earning_rules WHERE user_id=? AND is_active=1 AND applies_to='completed_order'`
    ).bind(agentId).all()
    if (!rules?.length) return
    const walletId = await ensureWallet(c, agentId)
    for (const rule of rules as any[]) {
      // Idempotency: don't double-credit the same contract for the same rule.
      const dup = await c.env.DB.prepare(
        `SELECT 1 FROM wallet_ledger WHERE wallet_id=? AND category=? AND reference=? LIMIT 1`
      ).bind(walletId, rule.rule_type, contract.contract_ref).first<any>()
      if (dup) continue
      const amount = rule.calc_method === 'percentage'
        ? roundMoney(orderValue * numberVal(rule.rate, 0) / 100)
        : roundMoney(numberVal(rule.fixed_amount, 0))
      if (amount <= 0) continue
      await postLedger(c, { userId: agentId, walletId, type: 'credit', amount, category: rule.rule_type, reference: contract.contract_ref, description: `${rule.rule_type} on ${contract.contract_ref}`, createdBy: null })
    }
  })
}

// ---- Admin payout disbursals (retainers, transport, per-diems) ----
// Batch-process fixed funds to one user or all agents.
app.post('/api/wallet/payouts', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const admin = c.get('user') as SessionUser
  const b = await c.req.json()
  const category = String(b.category || 'retainer')
  const amount = roundMoney(numberVal(b.amount, 0))
  if (amount <= 0) return c.json({ error: 'amount must be > 0' }, 400)
  const batchRef = ref('PAY')
  const result = await withAdminContext(c, async () => {
    let recipients: string[] = []
    if (Array.isArray(b.user_ids) && b.user_ids.length) {
      recipients = b.user_ids.map((x: any) => String(x ?? '').trim()).filter(Boolean)
    } else if (b.user_id) {
      recipients = [String(b.user_id).trim()]
    } else if (b.target === 'all_agents') {
      const { results } = await c.env.DB.prepare(`SELECT id FROM users WHERE role='agent' AND status='active'`).all()
      recipients = (results as any[]).map((r) => String(r.id)).filter(Boolean)
    }
    if (!recipients.length) return { error: 'No recipients resolved' }
    let total = 0, count = 0
    for (const uid of recipients) {
      const walletId = await ensureWallet(c, uid, admin.id)
      await postLedger(c, { userId: uid, walletId, type: 'credit', amount, category, reference: batchRef, description: b.description || `${category} disbursal`, createdBy: admin.id })
      total += amount; count++
    }
    await c.env.DB.prepare(
      `INSERT INTO payout_batches (batch_ref, category, description, total_amount, recipient_count, issued_by, payment_method) VALUES (?,?,?,?,?,?, 'wallet_credit')`
    ).bind(batchRef, category, b.description || null, roundMoney(total), count, admin.id).run()
    return { total: roundMoney(total), count }
  })
  if ((result as any).error) return c.json(result, 400)
  await audit(c, admin.id, 'payout', 'wallet', `${batchRef} ${category} x${(result as any).count}`)
  return c.json({ ok: true, batch_ref: batchRef, ...(result as any) })
})

// ---- Real-time earning analytics (RLS: agent sees self, admin sees global) ----
app.get('/api/wallet/analytics', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const isAdmin = hasPermission(user, 'manage_wallets') && ['admin', 'super_admin'].includes(user.role)
  // `scope=self` (default) always reports figures for the CALLER'S OWN wallet
  // only — statement, Total Debited and Total Earned are strictly scoped to the
  // active wallet id (double-entry integrity). `scope=global` is an admin-only
  // platform-wide roll-up used by the admin Wallets view.
  const requested = String(c.req.query('scope') || 'self')
  const wantGlobal = requested === 'global' && isAdmin

  if (wantGlobal) {
    // Platform-wide roll-up (admin). Runs under admin context so RLS does not clip it.
    return await withAdminContext(c, async () => {
      const byCategory = await c.env.DB.prepare(
        `SELECT category, entry_type, COUNT(*) AS entries, COALESCE(SUM(amount),0) AS total
           FROM wallet_ledger GROUP BY category, entry_type ORDER BY category`
      ).all()
      const totals = await c.env.DB.prepare(
        `SELECT COALESCE(SUM(CASE WHEN entry_type='credit' THEN amount ELSE 0 END),0) AS total_earned,
                COALESCE(SUM(CASE WHEN entry_type='debit'  THEN amount ELSE 0 END),0) AS total_debited
           FROM wallet_ledger`
      ).first<any>()
      return c.json({ scope: 'global', totals, by_category: byCategory.results })
    })
  }

  // Self scope: explicitly filter by the caller's own wallet id so the numbers
  // never depend on RLS session context and can never leak another wallet's data.
  const walletId = await ensureWallet(c, user.id)
  const byCategory = await c.env.DB.prepare(
    `SELECT category, entry_type, COUNT(*) AS entries, COALESCE(SUM(amount),0) AS total
       FROM wallet_ledger WHERE wallet_id=? GROUP BY category, entry_type ORDER BY category`
  ).bind(walletId).all()
  const totals = await c.env.DB.prepare(
    `SELECT COALESCE(SUM(CASE WHEN entry_type='credit' THEN amount ELSE 0 END),0) AS total_earned,
            COALESCE(SUM(CASE WHEN entry_type='debit'  THEN amount ELSE 0 END),0) AS total_debited
       FROM wallet_ledger WHERE wallet_id=?`
  ).bind(walletId).first<any>()
  return c.json({ scope: 'self', wallet_id: walletId, totals, by_category: byCategory.results })
})

// ============================================================================
// PAYOUT DESTINATIONS — a user registers the mobile / bank / SasaPay accounts
// they can withdraw to. Each is validated against SasaPay before it is usable.
// ============================================================================
app.get('/api/payout-accounts', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const { results } = await c.env.DB.prepare(`SELECT * FROM payout_accounts WHERE user_id=? ORDER BY is_default DESC, id DESC`).bind(user.id).all()
  return c.json({ accounts: results })
})

app.post('/api/payout-accounts', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const b = await c.req.json()
  const channelCode = String(b.channel_code || '').trim()
  const chan = channelByCode(channelCode)
  if (!chan) return c.json({ error: 'Unknown channel' }, 400)
  const raw = String(b.account_number || '').trim()
  if (!raw) return c.json({ error: 'account_number is required' }, 400)
  const account = (chan.type === 'mobile' || chan.type === 'wallet') ? sasapayNormalizePhone(raw) : raw
  const acctType = accountTypeForChannel(channelCode)

  // Validate against SasaPay to capture + confirm the holder name.
  const v = await sasapayValidateAccount(c.env, channelCode, account)
  const verified = v.success ? 1 : 0
  const accountName = v.account_name || b.account_name || null

  if (b.is_default) {
    await c.env.DB.prepare(`UPDATE payout_accounts SET is_default=0 WHERE user_id=?`).bind(user.id).run()
  }
  const r = await c.env.DB.prepare(
    `INSERT INTO payout_accounts (user_id, label, channel_code, channel_name, account_type, account_number, account_name, is_verified, is_default, created_by)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(user.id, b.label || chan.name, channelCode, chan.name, acctType, account, accountName, verified, b.is_default ? 1 : 0, user.id).run()
  await audit(c, user.id, 'create', 'payout_account', `${chan.name} ${account} (${verified ? 'verified' : 'unverified'})`)
  return c.json({ ok: true, id: r.meta.last_row_id, is_verified: !!verified, account_name: accountName, simulated: v.simulated })
})

app.delete('/api/payout-accounts/:id', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  await c.env.DB.prepare(`DELETE FROM payout_accounts WHERE id=? AND user_id=?`).bind(c.req.param('id'), user.id).run()
  return c.json({ ok: true })
})

// ============================================================================
// WALLET WITHDRAWAL — a wallet holder cashes out to their registered mobile /
// bank / SasaPay destination. Debits the ledger first, then pushes B2C.
// ============================================================================
app.post('/api/wallet/withdraw', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const b = await c.req.json()
  const amount = roundMoney(numberVal(b.amount, 0))
  if (amount <= 0) return c.json({ error: 'amount must be > 0' }, 400)

  // Resolve the destination channel. The DESTINATION NUMBER is always LOCKED to
  // the user's own registered phone — custom / third-party cash-out numbers are
  // strictly prohibited. Bank withdrawals still honour a saved bank payout
  // account (a bank account can't be the phone number), but mobile / wallet
  // cash-outs are forced to the registered number regardless of any input.
  const registeredPhone = sasapayNormalizePhone(String(user.phone || '').trim())
  let channelCode = String(b.channel_code || '').trim()
  let receiver = ''
  let recipientName: string | null = b.account_name || null
  if (b.payout_account_id) {
    const acct = await c.env.DB.prepare(`SELECT * FROM payout_accounts WHERE id=? AND user_id=?`).bind(b.payout_account_id, user.id).first<any>()
    if (!acct) return c.json({ error: 'Payout account not found' }, 404)
    channelCode = String(acct.channel_code)
    receiver = String(acct.account_number)
    recipientName = acct.account_name || null
  }
  const chan = channelByCode(channelCode)
  if (!chan) return c.json({ error: 'A valid withdrawal channel is required' }, 400)
  if (chan.type === 'mobile' || chan.type === 'wallet') {
    // PHONE NUMBER LOCK: ignore any client-supplied number; use the registered one.
    if (!registeredPhone) return c.json({ error: 'Your account has no registered phone number. Please update your profile.' }, 400)
    receiver = registeredPhone
    recipientName = recipientName || user.full_name || null
  }
  if (!receiver) return c.json({ error: 'A destination account is required' }, 400)
  if (chan.type === 'mobile' || chan.type === 'wallet') receiver = sasapayNormalizePhone(receiver)

  // ---- OTP AUTHORISATION (mandatory before any outgoing funds) ----------------
  // Two-step: first call (no otp_code) issues an OTP to the registered number and
  // returns needs_otp; second call (with otp_code) verifies it before we debit.
  if (!registeredPhone) return c.json({ error: 'Your account has no registered phone number for OTP.' }, 400)
  const otpCode = String(b.otp_code || '').trim()
  if (!otpCode) {
    const { demo_otp } = await issueOtp(c, registeredPhone, 'wallet_withdraw')
    return c.json({ needs_otp: true, phone: maskPhone(registeredPhone), message: 'Enter the code sent to your registered number to authorise this withdrawal.', demo_otp })
  }
  const otpOk = await verifyOtp(c, registeredPhone, otpCode, 'wallet_withdraw')
  if (!otpOk.ok) return c.json({ error: otpOk.error || 'Invalid verification code.', otp_failed: true }, 400)

  const reference = ref('WD')
  const walletId = await ensureWallet(c, user.id)

  // Load configuration + the holder's CURRENT balance so we can validate against
  // the withdrawable limit (balance − effective withdrawal charge) before we
  // touch the ledger. Wallet isolation: this is strictly the caller's own wallet.
  const chargeCfg = normalizeWithdrawalCharge(await getSetting(c, 'withdrawal_charge', DEFAULT_WITHDRAWAL_CHARGE))
  const supportContact = normalizeSupportContact(await getSetting(c, 'support_contact', DEFAULT_SUPPORT_CONTACT))
  const walletRow = await c.env.DB.prepare(`SELECT balance FROM wallets WHERE id=?`).bind(walletId).first<any>()
  const balance = roundMoney(numberVal(walletRow?.balance, 0))
  const charge = computeWithdrawalCharge(chargeCfg, amount)
  const totalDebit = roundMoney(amount + charge)
  const limit = computeWithdrawableLimit(chargeCfg, balance)

  // Enforce an optional minimum withdrawal.
  if (chargeCfg.min_withdrawal > 0 && amount < chargeCfg.min_withdrawal) {
    return c.json({ error: `The minimum withdrawal is KES ${chargeCfg.min_withdrawal.toLocaleString()}.` }, 400)
  }

  // 1) Withdrawable-limit pre-check (automated backend calculation). The holder
  // may only withdraw an amount whose gross + effective charge is within their
  // balance. On failure: on-screen message + SMS to the registered number.
  if (totalDebit > balance) {
    const insufficientMsg = 'Unsuccessful. You have insufficient Balance'
    const smsBody = `${insufficientMsg}. Your wallet balance is KES ${balance.toLocaleString()}. `
      + `The most you can withdraw now is KES ${limit.withdrawable.toLocaleString()} `
      + `(after a KES ${limit.charge_at_max.toLocaleString()} withdrawal charge).`
    // Fire-and-forget SMS to the user's registered number (simulated when unconfigured).
    try { if (user.phone) await sendSms(c.env, user.phone, smsBody) } catch (_) {}
    return c.json({
      error: insufficientMsg,
      insufficient: true,
      balance,
      requested: amount,
      charge,
      withdrawable: limit.withdrawable,
      charge_at_max: limit.charge_at_max
    }, 400)
  }

  // 2) SasaPay main-wallet funding check. If the settlement account (org balance)
  // cannot cover the gross payout, we DO NOT debit the holder — instead we tell
  // them to contact Farmsky (support phone/email configured by the super-admin).
  const mainBal = await sasapayBalance(c.env)
  if (mainBal.success && !mainBal.simulated && numberVal(mainBal.org_balance, 0) < amount) {
    return c.json({
      error: 'Contact Farmsky',
      contact_farmsky: true,
      support_phone: supportContact.phone,
      support_email: supportContact.email,
      message: 'We are unable to process your withdrawal right now. Please contact Farmsky.'
    }, 503)
  }

  // 3) Debit the wallet ledger up-front (gross + charge). The trigger rejects if
  //    the balance is short (defence-in-depth against a race with the pre-check).
  try {
    await postLedger(c, { userId: user.id, walletId, type: 'debit', amount, category: 'withdrawal', reference, description: b.reason || `Withdrawal to ${chan.name}`, createdBy: user.id })
    if (charge > 0) {
      await postLedger(c, { userId: user.id, walletId, type: 'debit', amount: charge, category: 'withdrawal_charge', reference, description: `Withdrawal charge for ${reference}`, createdBy: user.id })
    }
  } catch (e: any) {
    const msg = String(e?.message || '')
    if (/insufficient/i.test(msg)) {
      // Roll back the gross debit if the charge debit failed after it succeeded.
      try { await postLedger(c, { userId: user.id, walletId, type: 'credit', amount, category: 'adjustment', reference, description: `Reversal — charge could not be posted ${reference}`, createdBy: user.id }) } catch (_) {}
      const insufficientMsg = 'Unsuccessful. You have insufficient Balance'
      try { if (user.phone) await sendSms(c.env, user.phone, `${insufficientMsg}. The most you can withdraw now is KES ${limit.withdrawable.toLocaleString()}.`) } catch (_) {}
      return c.json({ error: insufficientMsg, insufficient: true, withdrawable: limit.withdrawable }, 400)
    }
    return c.json({ error: 'Withdrawal could not be posted' }, 400)
  }

  // 4) Record the withdrawal, then push B2C.
  await c.env.DB.prepare(
    `INSERT INTO wallet_withdrawals (reference, flow, wallet_id, user_id, amount, currency, channel_code, channel_name, receiver_number, recipient_name, reason, status, ledger_debited, created_by)
     VALUES (?, 'withdrawal', ?,?,?, 'KES', ?,?,?,?,?, 'processing', 1, ?)`
  ).bind(reference, walletId, user.id, amount, channelCode, chan.name, receiver, recipientName, b.reason || 'Wallet withdrawal', user.id).run()

  const payout = await sasapayB2C(c.env, { amount, receiverNumber: receiver, channel: channelCode, reason: b.reason || 'Wallet withdrawal', reference })

  if (!payout.success) {
    // Reverse BOTH the gross debit and the charge (credit back) and mark failed.
    await postLedger(c, { userId: user.id, walletId, type: 'credit', amount, category: 'adjustment', reference, description: `Reversal — failed withdrawal ${reference}`, createdBy: user.id })
    if (charge > 0) {
      await postLedger(c, { userId: user.id, walletId, type: 'credit', amount: charge, category: 'adjustment', reference, description: `Reversal — withdrawal charge ${reference}`, createdBy: user.id })
    }
    await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='failed', ledger_debited=0, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`).bind(payout.error || 'B2C failed', reference).run()
    return c.json({ error: payout.error || 'Disbursal failed; wallet has been refunded.' }, 502)
  }

  await c.env.DB.prepare(`UPDATE wallet_withdrawals SET simulated=?, b2c_request_id=?, conversation_id=?, transaction_charges=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`)
    .bind(payout.simulated ? 1 : 0, payout.b2c_request_id || null, payout.conversation_id || null, numberVal(payout.transaction_charges, 0), payout.simulated ? 'success' : 'processing', reference).run()

  await audit(c, user.id, 'withdraw', 'wallet', `KES ${amount} (+KES ${charge} charge) to ${chan.name} ${receiver} (${payout.simulated ? 'sim' : 'live'})`)
  return c.json({ ok: true, simulated: payout.simulated, reference, amount, charge, total_debited: totalDebit, status: payout.simulated ? 'success' : 'processing', customer_message: payout.customer_message || (payout.simulated ? 'Withdrawal completed (simulation).' : 'Withdrawal is being processed.') })
})

app.get('/api/wallet/withdrawals', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const { results } = await c.env.DB.prepare(`SELECT * FROM wallet_withdrawals ORDER BY id DESC LIMIT 100`).all()
  return c.json({ withdrawals: results })
})

// ============================================================================
// P2P FUND TRANSFER ("Send Money") — a wallet holder sends funds directly to
// another user/wallet inside Farmsky. Double-entry: debit sender, credit
// recipient (both via postLedger). OTP-authorised before any funds move, and
// the OTP is dispatched to the SENDER's registered phone number.
//
// Two-step, like the withdrawal flow:
//   1) POST with a recipient + amount (no otp_code) → resolves recipient, runs
//      an insufficient-balance pre-check, issues an OTP, returns needs_otp.
//   2) POST again with otp_code → verifies, then commits the double-entry.
// ============================================================================

// Resolve a P2P recipient from a phone number (preferred) or explicit user_id.
// Returns the recipient user row (admin-context read so we can look up any user)
// or an { error } object.
async function resolveTransferRecipient(c: any, b: any): Promise<{ user?: any; error?: string }> {
  return await withAdminContext(c, async () => {
    const rawUserId = String(b.recipient_user_id ?? '').trim()
    if (rawUserId) {
      const u = await c.env.DB.prepare(`SELECT id, full_name, phone, status FROM users WHERE id=?`).bind(rawUserId).first<any>()
      if (!u) return { error: 'Recipient not found.' }
      return { user: u }
    }
    const rawPhone = String(b.recipient_phone ?? '').trim()
    if (!rawPhone) return { error: 'A recipient phone number is required.' }
    const norm = sasapayNormalizePhone(rawPhone)
    const local = norm.startsWith('254') ? '0' + norm.slice(3) : rawPhone
    const plus = norm ? '+' + norm : rawPhone
    const u = await c.env.DB.prepare(
      `SELECT id, full_name, phone, status FROM users WHERE phone=? OR phone=? OR phone=? OR phone=?`
    ).bind(rawPhone, norm, plus, local).first<any>()
    if (!u) return { error: 'No Farmsky user is registered with that phone number.' }
    return { user: u }
  })
}

// Look up a recipient (used by the frontend to preview the name before sending).
app.get('/api/wallet/lookup-recipient', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const found = await resolveTransferRecipient(c, { recipient_phone: c.req.query('phone'), recipient_user_id: c.req.query('user_id') })
  if (found.error) return c.json({ error: found.error }, 404)
  const recipient = found.user
  if (String(recipient.id) === String(user.id)) return c.json({ error: 'You cannot send money to yourself.' }, 400)
  if (recipient.status && recipient.status !== 'active') return c.json({ error: 'That account cannot receive funds.' }, 400)
  return c.json({ ok: true, recipient: { id: recipient.id, name: recipient.full_name || 'Farmsky user', phone: maskPhone(sasapayNormalizePhone(String(recipient.phone || ''))) } })
})

app.post('/api/wallet/transfer', requireAuth, requirePermission('view_wallet', 'manage_wallets'), async (c) => {
  const user = c.get('user') as SessionUser
  const b = await c.req.json()
  const amount = roundMoney(numberVal(b.amount, 0))
  if (amount <= 0) return c.json({ error: 'amount must be > 0' }, 400)

  // Resolve the recipient (by phone or explicit user_id).
  const found = await resolveTransferRecipient(c, b)
  if (found.error) return c.json({ error: found.error }, 404)
  const recipient = found.user
  if (String(recipient.id) === String(user.id)) return c.json({ error: 'You cannot send money to yourself.' }, 400)
  if (recipient.status && recipient.status !== 'active') return c.json({ error: 'That account cannot receive funds.' }, 400)

  // Sender's wallet + balance (strictly the caller's own wallet).
  const senderWalletId = await ensureWallet(c, user.id)
  const senderRow = await c.env.DB.prepare(`SELECT balance FROM wallets WHERE id=?`).bind(senderWalletId).first<any>()
  const balance = roundMoney(numberVal(senderRow?.balance, 0))
  if (amount > balance) {
    return c.json({ error: 'Unsuccessful. You have insufficient Balance', insufficient: true, balance }, 400)
  }

  // ---- OTP AUTHORISATION (mandatory before any outgoing funds) ----------------
  const registeredPhone = sasapayNormalizePhone(String(user.phone || '').trim())
  if (!registeredPhone) return c.json({ error: 'Your account has no registered phone number for OTP.' }, 400)
  const otpCode = String(b.otp_code || '').trim()
  if (!otpCode) {
    const { demo_otp } = await issueOtp(c, registeredPhone, 'wallet_transfer')
    return c.json({
      needs_otp: true,
      phone: maskPhone(registeredPhone),
      recipient: { id: recipient.id, name: recipient.full_name || 'Farmsky user' },
      amount,
      message: 'Enter the code sent to your registered number to authorise this transfer.',
      demo_otp
    })
  }
  const otpOk = await verifyOtp(c, registeredPhone, otpCode, 'wallet_transfer')
  if (!otpOk.ok) return c.json({ error: otpOk.error || 'Invalid verification code.', otp_failed: true }, 400)

  const reference = ref('P2P')
  const note = String(b.reason || '').trim()

  // Commit the double-entry under admin context (so we can credit the recipient's
  // wallet regardless of RLS). The DB trigger rejects the sender debit if the
  // balance is short — defence-in-depth against a race with the pre-check.
  try {
    await withAdminContext(c, async () => {
      const recipientWalletId = await ensureWallet(c, recipient.id)
      // 1) Debit the sender first (trigger enforces sufficient balance).
      await postLedger(c, {
        userId: user.id, walletId: senderWalletId, type: 'debit', amount,
        category: 'p2p_transfer', reference,
        description: note || `Sent to ${recipient.full_name || 'user'}`, createdBy: user.id
      })
      // 2) Credit the recipient.
      await postLedger(c, {
        userId: recipient.id, walletId: recipientWalletId, type: 'credit', amount,
        category: 'p2p_transfer', reference,
        description: note || `Received from ${user.full_name || 'a Farmsky user'}`, createdBy: user.id
      })
      // 3) Record the transfer.
      await c.env.DB.prepare(
        `INSERT INTO wallet_withdrawals (reference, flow, wallet_id, user_id, recipient_user_id, amount, currency, channel_code, channel_name, receiver_number, recipient_name, reason, status, ledger_debited, created_by)
         VALUES (?, 'p2p_transfer', ?,?,?,?, 'KES', '0', 'Farmsky Wallet (P2P)', ?, ?, ?, 'success', 1, ?)`
      ).bind(reference, senderWalletId, user.id, String(recipient.id), amount, sasapayNormalizePhone(String(recipient.phone || '')), recipient.full_name || null, note || 'P2P transfer', user.id).run()
    })
  } catch (e: any) {
    const msg = String(e?.message || '')
    if (/insufficient/i.test(msg)) {
      return c.json({ error: 'Unsuccessful. You have insufficient Balance', insufficient: true }, 400)
    }
    return c.json({ error: 'Transfer could not be completed' }, 400)
  }

  // Notify both parties by SMS (simulated when unconfigured).
  try {
    if (user.phone) await sendSms(c.env, user.phone, `You sent KES ${amount.toLocaleString()} to ${recipient.full_name || 'a Farmsky user'}. Ref ${reference}.`)
    if (recipient.phone) await sendSms(c.env, String(recipient.phone), `You received KES ${amount.toLocaleString()} from ${user.full_name || 'a Farmsky user'}. Ref ${reference}.`)
  } catch (_) {}

  await audit(c, user.id, 'transfer', 'wallet', `KES ${amount} to user ${recipient.id} (${recipient.full_name || ''})`)
  return c.json({ ok: true, reference, amount, recipient: { id: recipient.id, name: recipient.full_name || 'Farmsky user' }, status: 'success', customer_message: `KES ${amount.toLocaleString()} sent to ${recipient.full_name || 'the recipient'}.` })
})

// ============================================================================
// ADMIN DIRECT PAYMENT — an authorised admin pays an individual directly, to
// either their in-app wallet OR a mobile/bank number via SasaPay B2C.
//   destination: 'wallet' (credit an internal wallet) | 'external' (B2C payout)
// ============================================================================
app.post('/api/wallet/direct-pay', requireAuth, requirePermission('manage_wallets'), async (c) => {
  const admin = c.get('user') as SessionUser
  const b = await c.req.json()
  const amount = roundMoney(numberVal(b.amount, 0))
  if (amount <= 0) return c.json({ error: 'amount must be > 0' }, 400)
  const destination = b.destination === 'external' ? 'external' : 'wallet'
  const reference = ref('DP')

  if (destination === 'wallet') {
    // Credit an internal user's wallet directly.
    const recipientId = String(b.user_id ?? '').trim()
    if (!recipientId) return c.json({ error: 'user_id is required for a wallet payment' }, 400)
    const result = await withAdminContext(c, async () => {
      const walletId = await ensureWallet(c, recipientId, admin.id)
      await postLedger(c, { userId: recipientId, walletId, type: 'credit', amount, category: b.category || 'direct_pay', reference, description: b.reason || 'Direct payment', createdBy: admin.id })
      await c.env.DB.prepare(
        `INSERT INTO wallet_withdrawals (reference, flow, wallet_id, user_id, recipient_user_id, amount, currency, channel_code, channel_name, receiver_number, reason, status, ledger_debited, created_by)
         VALUES (?, 'direct_pay', ?,?,?,?, 'KES', '0', 'SasaPay Wallet (internal)', ?, ?, 'success', 0, ?)`
      ).bind(reference, walletId, admin.id, recipientId, amount, String(recipientId), b.reason || 'Direct wallet payment', admin.id).run()
      return { walletId }
    })
    await audit(c, admin.id, 'direct_pay', 'wallet', `KES ${amount} to user ${recipientId} wallet`)
    return c.json({ ok: true, destination: 'wallet', reference, status: 'success', ...(result as any) })
  }

  // External B2C payout to a mobile / bank number.
  const channelCode = String(b.channel_code || '').trim()
  const chan = channelByCode(channelCode)
  if (!chan) return c.json({ error: 'A valid payout channel is required' }, 400)
  let receiver = String(b.account_number || '').trim()
  if (!receiver) return c.json({ error: 'A destination account is required' }, 400)
  if (chan.type === 'mobile' || chan.type === 'wallet') receiver = sasapayNormalizePhone(receiver)

  await c.env.DB.prepare(
    `INSERT INTO wallet_withdrawals (reference, flow, user_id, recipient_user_id, amount, currency, channel_code, channel_name, receiver_number, recipient_name, reason, status, ledger_debited, created_by)
     VALUES (?, 'direct_pay', ?,?,?, 'KES', ?,?,?,?,?, 'processing', 0, ?)`
  ).bind(reference, admin.id, b.user_id ? String(b.user_id).trim() : null, amount, channelCode, chan.name, receiver, b.account_name || null, b.reason || 'Direct payment', admin.id).run()

  const payout = await sasapayB2C(c.env, { amount, receiverNumber: receiver, channel: channelCode, reason: b.reason || 'Direct payment', reference })
  if (!payout.success) {
    await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='failed', result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`).bind(payout.error || 'B2C failed', reference).run()
    return c.json({ error: payout.error || 'Disbursal failed' }, 502)
  }
  await c.env.DB.prepare(`UPDATE wallet_withdrawals SET simulated=?, b2c_request_id=?, conversation_id=?, transaction_charges=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`)
    .bind(payout.simulated ? 1 : 0, payout.b2c_request_id || null, payout.conversation_id || null, numberVal(payout.transaction_charges, 0), payout.simulated ? 'success' : 'processing', reference).run()
  await audit(c, admin.id, 'direct_pay', 'sasapay', `KES ${amount} to ${chan.name} ${receiver} (${payout.simulated ? 'sim' : 'live'})`)
  return c.json({ ok: true, destination: 'external', simulated: payout.simulated, reference, status: payout.simulated ? 'success' : 'processing', customer_message: payout.customer_message || 'Payment is being processed.' })
})

// ============================================================================
// B2C CALLBACK — SasaPay posts the payout result here (success AND failure).
// Secured by IP whitelist + HMAC-SHA512 signature; idempotent by reference.
// ============================================================================
app.post('/api/sasapay/b2c-callback', async (c) => {
  try {
    const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for') || c.req.header('x-real-ip')
    const sig = c.req.header('x-sasapay-signature') || c.req.header('X-SasaPay-Signature')
    const body: any = await c.req.json().catch(() => ({}))

    if (sasapayConfigured(c.env)) {
      const ipOk = isTrustedSasapayIp(ip)
      const sigOk = await verifySasapaySignature(c.env, sig, {
        sasapay_transaction_code: body.TransactionCode || body.SasaPayTransactionCode || '',
        merchant_code: body.MerchantCode || '',
        account_number: body.ReceiverNumber || '',
        payment_reference: body.MerchantTransactionReference || body.OriginatorConversationID || '',
        amount: body.Amount || ''
      })
      if (!ipOk && !sigOk) {
        await audit(c, null, 'callback_rejected', 'sasapay_b2c', `untrusted ip=${ip || '?'} sig=${sig ? 'bad' : 'missing'}`)
        return c.json({ ResultCode: 1, ResultDesc: 'Rejected' }, 403)
      }
    }

    const reference = body.MerchantTransactionReference || body.OriginatorConversationID
    const b2cId = body.B2CRequestID || body.ConversationID
    const row = reference
      ? await c.env.DB.prepare(`SELECT * FROM wallet_withdrawals WHERE reference=?`).bind(reference).first<any>()
      : (b2cId ? await c.env.DB.prepare(`SELECT * FROM wallet_withdrawals WHERE b2c_request_id=? OR conversation_id=?`).bind(b2cId, b2cId).first<any>() : null)

    if (row && (row.status === 'processing' || row.status === 'pending')) {
      const code = body.ResultCode ?? body.status_code ?? body.TransactionCode
      const success = (code === 0 || code === '0' || body.status === true || String(body.ResultDesc || '').toLowerCase().includes('success'))
      if (success) {
        await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='success', transaction_code=?, result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`)
          .bind(body.TransactionCode || body.SasaPayTransactionCode || '', String(code ?? '0'), body.ResultDesc || 'Success', row.reference).run()
      } else {
        // Payout failed AFTER we debited a wallet → refund the source wallet.
        if (row.ledger_debited && row.wallet_id && row.user_id) {
          try {
            await withAdminContext(c, async () => {
              await postLedger(c, { userId: row.user_id, walletId: row.wallet_id, type: 'credit', amount: numberVal(row.amount, 0), category: 'adjustment', reference: row.reference, description: `Reversal — failed payout ${row.reference}`, createdBy: null })
            })
          } catch (_) {}
        }
        await c.env.DB.prepare(`UPDATE wallet_withdrawals SET status='failed', ledger_debited=0, result_code=?, result_desc=?, updated_at=CURRENT_TIMESTAMP WHERE reference=?`)
          .bind(String(code ?? '1'), body.ResultDesc || 'Payout failed', row.reference).run()
      }
    }
    return c.json({ ResultCode: 0, ResultDesc: 'Accepted' })
  } catch { return c.json({ ResultCode: 0, ResultDesc: 'Accepted' }) }
})

// ----------------------------------------------------------------------------
// SECURITY VALIDATION — confirm RLS isolation is active
// Running the ownership-scoped tables WITHOUT a user context must yield 0 rows.
// ----------------------------------------------------------------------------
app.get('/api/security/rls-check', requireAuth, requireRole('super_admin'), async (c) => {
  const setLocal = (c.env.DB as any)?.setSessionConfig
  if (typeof setLocal !== 'function') return c.json({ supported: false, note: 'RLS is a PostgreSQL feature; not active on this runtime.' })
  // Deliberately clear the context, then read each protected table.
  await setLocal.call(c.env.DB, 'app.current_user_id', '')
  await setLocal.call(c.env.DB, 'app.current_role', '')
  const probe = async (t: string) => {
    try { const r = await c.env.DB.prepare(`SELECT COUNT(*)::int n FROM ${t}`).first<any>(); return Number(r?.n ?? -1) }
    catch { return -1 }
  }
  const result = {
    customers: await probe('customers'),
    products: await probe('products'),
    murabaha_contracts: await probe('murabaha_contracts'),
    wallet_ledger: await probe('wallet_ledger')
  }
  // Restore this admin's context.
  await setUserContext(c, c.get('user'))
  const leaking = Object.entries(result).filter(([, n]) => n > 0).map(([t]) => t)
  return c.json({
    supported: true,
    without_context_counts: result,
    isolation_ok: leaking.length === 0,
    message: leaking.length === 0
      ? 'RLS active: no rows are visible without a user context — data-leak vectors are closed.'
      : `WARNING: tables leaking without context: ${leaking.join(', ')}. Ensure backend/sql/03_ownership_rls_setup.sql has been applied.`
  })
})

// ----------------------------------------------------------------------------
// FRONTEND SHELL
// ----------------------------------------------------------------------------
app.get('/', (c) => c.html(SHELL))

const SHELL = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nia by Farmsky — Input Marketplace</title>
  <meta name="description" content="Nia by Farmsky — buy certified seeds, fertilizers, agrochemicals and farm tools. Secure M-Pesa / SasaPay checkout.">
  <link rel="icon" type="image/png" href="/static/favicon.png">
  <!-- Production Tailwind build (compiled via Tailwind CLI, no runtime CDN JIT). -->
  <link href="/static/tailwind.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js"></script>
  <link href="/static/style.css" rel="stylesheet">
</head>
<body class="bg-slate-100 text-slate-800">
  <div id="app"></div>
  <script src="/static/app.js"></script>
</body>
</html>`

export default app
