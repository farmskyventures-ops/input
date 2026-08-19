-- =====================================================================
-- 0030_nia_client_webhook_log.sql
-- Nia (client tenant) audit log for INBOUND signed payment webhooks received
-- from the Equipment Central Gateway at POST /api/v1/payment-webhook.
-- Kept separate from the gateway's own `central_callbacks` (which logs
-- OUTBOUND provider callbacks on the host side).
-- =====================================================================
CREATE TABLE IF NOT EXISTS nia_webhook_log (
  id BIGSERIAL PRIMARY KEY,
  client_key TEXT,
  transaction_ref TEXT,
  origin_reference TEXT,
  status TEXT,
  signature_valid INTEGER,
  raw_payload TEXT,
  received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_nia_webhook_txref ON nia_webhook_log(transaction_ref);
