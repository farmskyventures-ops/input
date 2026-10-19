-- =====================================================================
-- 0034 — Crop/Horticultural input specification fields.
--
-- Nia is an agricultural & horticultural INPUT marketplace. Inputs (certified
-- seeds, fertilizers, crop-protection chemicals, soil conditioners) carry
-- regulatory and agronomic specifications that farm equipment does not. Add
-- dedicated, nullable columns so the catalog, product detail, checkout copy and
-- invoices can surface input-specific metrics. All nullable + idempotent DDL
-- (db-init swallows 42701 duplicate-column), safe to re-run on every boot.
-- =====================================================================

ALTER TABLE products ADD COLUMN active_ingredient TEXT;      -- e.g. "Glyphosate 360 g/L"
ALTER TABLE products ADD COLUMN application_rate TEXT;       -- e.g. "2–3 L/acre"
ALTER TABLE products ADD COLUMN acreage_coverage TEXT;      -- e.g. "Covers 1 acre"
ALTER TABLE products ADD COLUMN pack_size TEXT;             -- e.g. "50 kg bag", "1 L bottle"
ALTER TABLE products ADD COLUMN registration_number TEXT;  -- PCPB / KEPHIS reg. no.

-- Populate the demo Nia input catalog (0031) with representative, well-formed
-- agronomic / regulatory specifications so product detail, checkout copy and the
-- consolidated invoice showcase the input-specific metrics. Idempotent per-SKU.
UPDATE products SET active_ingredient='Hybrid maize (certified)', application_rate='25,000–26,000 plants/acre', acreage_coverage='Plants ~1 acre', pack_size='2 kg pack', registration_number='KEPHIS-SEED-DK777' WHERE sku='NIA-SEED-DK777';
UPDATE products SET active_ingredient='Bean seed KK8 (certified)', application_rate='25–30 kg/acre', acreage_coverage='Plants ~1 acre', pack_size='1 kg pack', registration_number='KEPHIS-SEED-KK8' WHERE sku='NIA-SEED-KK8';
UPDATE products SET active_ingredient='Tomato F1 hybrid (Anna)', application_rate='40–60 g/acre nursery', acreage_coverage='Transplants ~1 acre', pack_size='10 g tin', registration_number='KEPHIS-SEED-ANNAF1' WHERE sku='NIA-SEED-TOMANNA';
UPDATE products SET active_ingredient='N:P:K 17-17-17', application_rate='50–100 kg/acre at planting', acreage_coverage='1–2 bags/acre', pack_size='50 kg bag', registration_number='KEBS-FERT-NPK17' WHERE sku='NIA-FERT-NPK17';
UPDATE products SET active_ingredient='Calcium Ammonium Nitrate 26% N', application_rate='50 kg/acre top-dress', acreage_coverage='1 bag/acre', pack_size='50 kg bag', registration_number='KEBS-FERT-CAN' WHERE sku='NIA-FERT-CAN';
UPDATE products SET active_ingredient='Di-Ammonium Phosphate 18-46-0', application_rate='50 kg/acre at planting', acreage_coverage='1 bag/acre', pack_size='50 kg bag', registration_number='KEBS-FERT-DAP' WHERE sku='NIA-FERT-DAP';
UPDATE products SET active_ingredient='Glyphosate 360 g/L', application_rate='2–3 L/acre', acreage_coverage='Covers ~1 acre', pack_size='1 L bottle', registration_number='PCPB(CR)-GLYPHO-0360' WHERE sku='NIA-CP-GLYPHO';
UPDATE products SET active_ingredient='Lambda-cyhalothrin 17.5 g/L', application_rate='20–40 ml/20 L water', acreage_coverage='Covers ~1 acre', pack_size='250 ml bottle', registration_number='PCPB(CR)-LAMBDA-0175' WHERE sku='NIA-CP-LAMBDA';
UPDATE products SET active_ingredient='Metalaxyl-M 40 g/kg + Mancozeb 640 g/kg', application_rate='50 g/20 L water', acreage_coverage='Covers ~1 acre', pack_size='1 kg pack', registration_number='PCPB(CR)-RIDOMIL-GOLD' WHERE sku='NIA-CP-RIDOMIL';
UPDATE products SET active_ingredient='Calcium carbonate (agricultural lime)', application_rate='1–2 bags/acre per soil test', acreage_coverage='1–2 bags/acre', pack_size='50 kg bag', registration_number='KEBS-SOIL-LIME' WHERE sku='NIA-SOIL-LIME';
UPDATE products SET active_ingredient='Composted organic manure', application_rate='4–8 bags/acre', acreage_coverage='Enriches ~1 acre', pack_size='50 kg bag', registration_number='N/A (organic)' WHERE sku='NIA-SOIL-MANURE';
