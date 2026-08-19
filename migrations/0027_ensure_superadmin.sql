-- =====================================================================
-- 0027 — guarantee the Equipment Super-Admin account exists with the
--        designated phone number 0702875711 (normalized 254702875711),
--        regardless of whether the shared central `users` table is integer-
--        or UUID-keyed, and regardless of whether the demo seed ever ran.
--
-- WHY THIS EXISTS
-- ---------------------------------------------------------------------
--   * The demo seed (seed.sql) only runs when Equipment CREATES the users
--     table. On the shared central DB, Score created `public.users` first, so
--     the seed never ran and NO super_admin account exists for Equipment.
--   * 0014 tried to fix the phone with `UPDATE users ... WHERE id = 1`, but on
--     a UUID users table `id = 1` throws `operator does not exist: uuid = integer`
--     and is skipped — so the phone was never set on the shared DB.
--
-- This migration is id-type-agnostic: it never references `id`, matches on the
-- role/phone instead, and lets the table's own id default (BIGSERIAL or UUID
-- default) generate the primary key on INSERT. Idempotent & re-runnable.
--
-- Requested Super-Admin login: phone 0702875711  (== +254702875711 == 254702875711)
-- Default password: 1224 (legacy plaintext; verifyPassword accepts it and will
-- re-hash on first login). Change it after first sign-in.
-- =====================================================================

-- 1. Normalize any EXISTING super_admin that already uses one of the accepted
--    phone spellings to the canonical normalized form the app matches on.
UPDATE users
   SET phone = '254702875711', role = 'super_admin', status = 'active'
 WHERE role = 'super_admin'
   AND phone IN ('0702875711', '+254702875711', '254702875711', '0702875711 ');

-- 2. If an account already exists on ANY of the accepted phone spellings,
--    make sure it is an ACTIVE super_admin on the canonical phone.
UPDATE users
   SET role = 'super_admin', status = 'active', phone = '254702875711'
 WHERE phone IN ('0702875711', '+254702875711', '254702875711');

-- 3. Create the Super-Admin only if no account holds the canonical phone yet.
--    Column list is explicit so the id default (serial/uuid) fills the PK.
--    Super-Admin capability comes from role (hasPermission() short-circuits to
--    true for super_admin/admin), so permissions is just '{}' (role defaults).
--
--    org_id HANDLING: on the shared central DB, `public.users` carries a
--    `org_id UUID NOT NULL` column (created by the Score platform). Omitting it
--    throws 23502 and the whole INSERT is skipped, so the Super-Admin was never
--    created there. This DO-block detects the column and, when present, supplies
--    a tenant (the most-populated existing org, else the oldest organizations
--    row). On the Equipment-only shape (no org_id column) it runs the plain
--    INSERT. Idempotent & id-type-agnostic.
DO $$
DECLARE
  has_org  BOOLEAN;
  v_org    UUID;
BEGIN
  IF EXISTS (SELECT 1 FROM users WHERE phone = '254702875711') THEN
    RETURN;
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_name = 'users' AND column_name = 'org_id'
  ) INTO has_org;

  IF has_org THEN
    -- Prefer the most-populated existing tenant, else the oldest organization.
    SELECT org_id INTO v_org
      FROM users WHERE org_id IS NOT NULL
      GROUP BY org_id ORDER BY COUNT(*) DESC LIMIT 1;
    IF v_org IS NULL THEN
      SELECT id INTO v_org FROM organizations ORDER BY created_at ASC LIMIT 1;
    END IF;

    -- Only insert when we actually have a tenant to attach (NOT NULL constraint).
    IF v_org IS NOT NULL THEN
      INSERT INTO users (full_name, phone, email, password, role, status, region, password_set, label, permissions, org_id)
      VALUES ('System Administrator', '254702875711', 'admin@farmsky.africa', '1224',
              'super_admin', 'active', 'HQ - Nairobi', 1, 'Super Admin', '{}', v_org);
    END IF;
  ELSE
    INSERT INTO users (full_name, phone, email, password, role, status, region, password_set, label, permissions)
    VALUES ('System Administrator', '254702875711', 'admin@farmsky.africa', '1224',
            'super_admin', 'active', 'HQ - Nairobi', 1, 'Super Admin', '{}');
  END IF;
END $$;
