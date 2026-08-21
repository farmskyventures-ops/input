-- =====================================================================
-- FIX: Ownership RLS policies silently failed to create, causing admin
--      data EXPORTS (and admin list views) to return HEADERS ONLY with
--      ZERO data rows for customers / contracts / repayments / wallets.
--
-- Root cause
-- ----------
-- The userref columns (agent_id, onboarded_by, created_by, user_id,
-- recipient_user_id) were migrated to TEXT in schema revisions 0024-0026,
-- but the ownership policies in backend/sql/03_ownership_rls_setup.sql
-- compared them against current_app_user_id(), which returns INTEGER:
--
--     ERROR: operator does not exist: text = integer
--
-- That error made the CREATE POLICY statements FAIL. A table left with
-- ROW LEVEL SECURITY ENABLED + FORCED but NO surviving policy denies EVERY
-- row -- even to admins/super-admins. So exporting those datasets produced
-- a file containing only the column header line and no rows.
--
-- This migration re-creates the ownership policies with TEXT-safe
-- comparisons (::TEXT on both sides) so they create successfully AND admins
-- still bypass via current_app_is_admin(). It is idempotent and auto-applied
-- by db-init on every boot, so the live sites self-heal on the next deploy
-- (no manual superuser step required). backend/sql/03_ownership_rls_setup.sql
-- has been corrected to match for fresh installs.
--
-- NOTE: RLS statements are PostgreSQL-only. On SQLite/D1 the runner skips
-- unsupported syntax, so this migration is a no-op there.
-- =====================================================================

-- Session-context helpers (idempotent). The TEXT variant is the important
-- addition: it compares userref columns regardless of their SQL type.
CREATE OR REPLACE FUNCTION current_app_user_id() RETURNS INTEGER AS $$
  SELECT NULLIF(current_setting('app.current_user_id', true), '')::INTEGER;
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION current_app_user_id_text() RETURNS TEXT AS $$
  SELECT NULLIF(current_setting('app.current_user_id', true), '');
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION current_app_is_admin() RETURNS BOOLEAN AS $$
  SELECT COALESCE(current_setting('app.current_role', true), '') IN ('admin', 'super_admin');
$$ LANGUAGE sql STABLE;

-- Repair every ownership policy with TEXT-safe comparisons. Each table is
-- guarded so a schema without a given table never aborts the migration.
DO $mig$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='customers') THEN
    EXECUTE 'ALTER TABLE customers ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE customers FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS ownership_customers ON customers';
    EXECUTE 'CREATE POLICY ownership_customers ON customers
               USING (current_app_is_admin() OR onboarded_by::TEXT = current_app_user_id_text() OR agent_id::TEXT = current_app_user_id_text())
               WITH CHECK (current_app_is_admin() OR onboarded_by::TEXT = current_app_user_id_text() OR agent_id::TEXT = current_app_user_id_text())';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='murabaha_contracts') THEN
    EXECUTE 'ALTER TABLE murabaha_contracts ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE murabaha_contracts FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS ownership_contracts ON murabaha_contracts';
    EXECUTE 'CREATE POLICY ownership_contracts ON murabaha_contracts
               USING (
                 current_app_is_admin()
                 OR created_by::TEXT = current_app_user_id_text()
                 OR agent_id::TEXT   = current_app_user_id_text()
                 OR customer_id IN (SELECT id FROM customers WHERE onboarded_by::TEXT = current_app_user_id_text() OR agent_id::TEXT = current_app_user_id_text())
               )
               WITH CHECK (
                 current_app_is_admin()
                 OR created_by::TEXT = current_app_user_id_text()
                 OR agent_id::TEXT   = current_app_user_id_text()
                 OR customer_id IN (SELECT id FROM customers WHERE onboarded_by::TEXT = current_app_user_id_text() OR agent_id::TEXT = current_app_user_id_text())
               )';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='products') THEN
    EXECUTE 'ALTER TABLE products ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE products FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS ownership_products ON products';
    EXECUTE 'CREATE POLICY ownership_products ON products
               USING (current_app_is_admin() OR created_by::TEXT = current_app_user_id_text())
               WITH CHECK (current_app_is_admin() OR created_by::TEXT = current_app_user_id_text())';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='wallets') THEN
    EXECUTE 'ALTER TABLE wallets ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE wallets FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS ownership_wallets ON wallets';
    EXECUTE 'CREATE POLICY ownership_wallets ON wallets
               USING (current_app_is_admin() OR user_id::TEXT = current_app_user_id_text())
               WITH CHECK (current_app_is_admin() OR user_id::TEXT = current_app_user_id_text())';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='wallet_ledger') THEN
    EXECUTE 'ALTER TABLE wallet_ledger ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE wallet_ledger FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS ownership_wallet_ledger ON wallet_ledger';
    EXECUTE 'CREATE POLICY ownership_wallet_ledger ON wallet_ledger
               USING (current_app_is_admin() OR user_id::TEXT = current_app_user_id_text())
               WITH CHECK (current_app_is_admin() OR user_id::TEXT = current_app_user_id_text())';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='earning_rules') THEN
    EXECUTE 'ALTER TABLE earning_rules ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE earning_rules FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS ownership_earning_rules ON earning_rules';
    EXECUTE 'CREATE POLICY ownership_earning_rules ON earning_rules
               USING (current_app_is_admin() OR user_id::TEXT = current_app_user_id_text())
               WITH CHECK (current_app_is_admin() OR user_id::TEXT = current_app_user_id_text())';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='payout_accounts') THEN
    EXECUTE 'ALTER TABLE payout_accounts ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE payout_accounts FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS ownership_payout_accounts ON payout_accounts';
    EXECUTE 'CREATE POLICY ownership_payout_accounts ON payout_accounts
               USING (current_app_is_admin() OR user_id::TEXT = current_app_user_id_text())
               WITH CHECK (current_app_is_admin() OR user_id::TEXT = current_app_user_id_text())';
  END IF;

  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='wallet_withdrawals') THEN
    EXECUTE 'ALTER TABLE wallet_withdrawals ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE wallet_withdrawals FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS ownership_wallet_withdrawals ON wallet_withdrawals';
    EXECUTE 'CREATE POLICY ownership_wallet_withdrawals ON wallet_withdrawals
               USING (current_app_is_admin() OR user_id::TEXT = current_app_user_id_text() OR recipient_user_id::TEXT = current_app_user_id_text())
               WITH CHECK (current_app_is_admin() OR user_id::TEXT = current_app_user_id_text() OR recipient_user_id::TEXT = current_app_user_id_text())';
  END IF;
END
$mig$;
