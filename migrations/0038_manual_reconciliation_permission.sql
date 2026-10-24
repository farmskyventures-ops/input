-- =====================================================================
-- 0038 — Sales Manual Reconciliation permission (ported from Equipment 0042)
--
-- Nia forked before the manual-reconciliation capability existed. This adds the
-- delegable `sales_manual_reconciliation` permission so a Super-Admin (or a user
-- explicitly granted it) can manually settle a cash sale / whole bundle paid
-- directly to the bank, through the same applyPayment / settleBundlePayment
-- engine used by the automated gateway.
--
-- Idempotent + auto-applied by db-init on boot.
-- =====================================================================
INSERT OR IGNORE INTO permission_catalog (permission_key, label, description, category) VALUES
  ('sales_manual_reconciliation', 'Sales Manual Reconciliation', 'Manually settle cash sale dues/installments (single item or whole bundle) paid directly to the bank using a unique transaction reference, and generate the official receipt.', 'payments');

-- Super-Admin holds it by default (role template + existing super-admin users).
UPDATE role_templates
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"sales_manual_reconciliation":true}'::jsonb)::text
 WHERE role_key = 'super_admin';
UPDATE users
   SET permissions = (COALESCE(NULLIF(permissions, ''), '{}')::jsonb || '{"sales_manual_reconciliation":true}'::jsonb)::text
 WHERE role = 'super_admin';
