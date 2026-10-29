-- =====================================================================
-- 0041 — Loan/Financing Products consolidation + explicit product states
--
-- Resolves the TRIPLE-REDUNDANCY of financing configuration (inventory form,
-- finance settings, approval queue) by making `financing_types` the SOLE
-- authoring tool for financing rules. The inventory form becomes a MAPPING step
-- (link a product to pre-configured loan products) and the approval queue
-- approves/rejects LINK requests only.
--
-- Nia (crop inputs / horticulture) did not previously carry the financing_types
-- table, so this migration CREATES it (matching Equipment/Feed), seeds the
-- built-in types, extends it into full Loan/Financing Products, and adds the
-- explicit product finance-state columns.
--
-- STRICTLY ADDITIVE / NON-BREAKING. Idempotent. Mirrored across all 3 apps.
-- =====================================================================

-- 0. Base table (created here for Nia; IF NOT EXISTS keeps it idempotent).
CREATE TABLE IF NOT EXISTS financing_types (
  id           SERIAL PRIMARY KEY,
  type_key     TEXT UNIQUE NOT NULL,
  label        TEXT NOT NULL,
  description  TEXT,
  charge_mode  TEXT DEFAULT 'percentage',
  is_system    INTEGER DEFAULT 0,
  active       INTEGER DEFAULT 1,
  sort_order   INTEGER DEFAULT 100,
  created_by   TEXT,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed the built-in financing types (idempotent).
INSERT INTO financing_types (type_key, label, description, charge_mode, is_system, sort_order)
VALUES
  ('loan_interest', 'Financing (with interest)', 'Standard installment financing with an interest / finance charge.', 'percentage', 1, 10),
  ('paygo',         'PAYGO',                     'Pay-as-you-go financing billed per cycle until fully settled.',       'percentage', 1, 20),
  ('murabaha',      'Murabaha',                  'Sharia-compliant cost-plus-markup financing (no interest, no penalties).', 'percentage', 1, 30)
ON CONFLICT (type_key) DO NOTHING;

-- Agreement templates (Nia port — created here so new loan products can seed one).
CREATE TABLE IF NOT EXISTS agreement_templates (
  id           SERIAL PRIMARY KEY,
  path_key     TEXT UNIQUE NOT NULL,
  title        TEXT,
  overview_html TEXT,
  body_html    TEXT,
  updated_by   TEXT,
  created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 1. Promote financing_types to full loan products (additive columns).
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS interest_pct REAL;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS markup_pct REAL;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS deposit_pct REAL;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS term_min_months INTEGER;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS term_max_months INTEGER;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS tenure_unit TEXT;           -- monthly | yearly | custom
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS rate_per_cycle REAL;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS amount_per_cycle REAL;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS cycle_count INTEGER;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS cycle_length_days INTEGER;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS frequency TEXT;             -- daily | weekly | monthly
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS processing_fee_json TEXT;   -- per-loan-product processing fee config
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS terms_text TEXT;
ALTER TABLE financing_types ADD COLUMN IF NOT EXISTS terms_doc_url TEXT;

-- 2. Explicit product finance-state machine (additive; legacy finance_status kept).
ALTER TABLE products ADD COLUMN IF NOT EXISTS finance_state TEXT;
ALTER TABLE products ADD COLUMN IF NOT EXISTS finance_pending_type_key TEXT;
-- Nia products may also lack the financing_type_key mapping column — add it.
ALTER TABLE products ADD COLUMN IF NOT EXISTS financing_type_key TEXT;

-- 3. Backfill finance_state from the legacy columns (one-time, idempotent).
UPDATE products
   SET finance_state = CASE
     WHEN finance_status = 'pending_finance' THEN 'FINANCE_PENDING_APPROVAL'
     WHEN financing_enabled = 1 AND finance_status = 'published' THEN 'FINANCE_APPROVED'
     ELSE 'CASH_ONLY_ACTIVE'
   END
 WHERE finance_state IS NULL;
