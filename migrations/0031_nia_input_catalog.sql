-- =====================================================================
-- 0031_nia_input_catalog.sql
-- Nia by Farmsky is an INPUT MARKETPLACE. Re-tag the demo agri-inputs that
-- ship in the base seed to the `inputs` storefront, and add a richer catalog
-- of seeds / fertilizers / crop protection / soil health products so the
-- default (inputs) storefront is well populated. Idempotent via SKU upsert.
-- =====================================================================

-- Re-tag existing input-type demo rows onto the inputs marketplace.
UPDATE products SET marketplace='inputs', product_type='input'
  WHERE sku IN ('FERT-NPK-50', 'SEED-MAIZE-2');

-- Suppliers for the input catalog (idempotent).
INSERT INTO suppliers (id, name, contact) VALUES
  (10, 'Yara East Africa',        '+254711000910'),
  (11, 'Kenya Seed Company',      '+254711000911'),
  (12, 'Syngenta East Africa',    '+254711000912'),
  (13, 'Bayer CropScience Kenya', '+254711000913')
ON CONFLICT (id) DO NOTHING;

-- Input catalog (marketplace='inputs'). Columns kept minimal + required.
INSERT INTO products
  (sku, name, category, subcategory, marketplace, product_type, supplier_id,
   buying_price, cash_markup_pct, credit_markup_pct, cash_price, credit_price, quantity, unit, reorder_threshold)
VALUES
  -- Seeds
  ('NIA-SEED-DK777', 'DK 777 Hybrid Maize Seed (2kg)', 'Seeds', 'Cereal Seeds', 'inputs', 'input', 11, 560, 10, 18, 616, 661, 300, 'pack', 30),
  ('NIA-SEED-KK8',   'KK8 Bean Seed (1kg)',            'Seeds', 'Legume Seeds', 'inputs', 'input', 11, 360, 10, 18, 396, 425, 220, 'pack', 25),
  ('NIA-SEED-TOMANNA','Anna F1 Tomato Seed (10g)',     'Seeds', 'Vegetable Seeds', 'inputs', 'input', 12, 1550, 12, 20, 1736, 1860, 90, 'tin', 10),
  -- Fertilizers
  ('NIA-FERT-NPK17', 'NPK 17:17:17 Fertilizer (50kg)', 'Fertilizers', 'Planting Fertilizer', 'inputs', 'input', 10, 3800, 10, 20, 4180, 4560, 150, 'bag', 15),
  ('NIA-FERT-CAN',   'CAN Top-dress Fertilizer (50kg)','Fertilizers', 'Top Dressing', 'inputs', 'input', 10, 3100, 12, 22, 3472, 3782, 180, 'bag', 15),
  ('NIA-FERT-DAP',   'DAP Planting Fertilizer (50kg)', 'Fertilizers', 'Planting Fertilizer', 'inputs', 'input', 10, 4300, 12, 22, 4816, 5246, 120, 'bag', 12),
  -- Crop protection
  ('NIA-CP-GLYPHO',  'Roundup Herbicide (1L)',         'Crop Protection', 'Herbicides', 'inputs', 'input', 13, 1050, 15, 25, 1207, 1312, 140, 'bottle', 15),
  ('NIA-CP-LAMBDA',  'Duduthrin Insecticide (250ml)',  'Crop Protection', 'Pesticides', 'inputs', 'input', 12, 650, 15, 25, 747, 812, 200, 'bottle', 20),
  ('NIA-CP-RIDOMIL', 'Ridomil Gold Fungicide (1kg)',   'Crop Protection', 'Fungicides', 'inputs', 'input', 12, 1400, 15, 25, 1610, 1750, 110, 'pack', 12),
  -- Soil health
  ('NIA-SOIL-LIME',  'Agricultural Lime (50kg)',       'Soil Health', 'Lime', 'inputs', 'input', 10, 700, 12, 20, 784, 840, 260, 'bag', 20),
  ('NIA-SOIL-MANURE','Organic Composted Manure (50kg)','Soil Health', 'Organic Manure', 'inputs', 'input', 10, 500, 12, 20, 560, 600, 300, 'bag', 25)
ON CONFLICT (sku) DO NOTHING;
