-- Fixture data for manual runs (seed.mjs, manual-exploit.sh). Argos seeds its own rows with markers.
-- Values marked CONFIDENTIAL / vk_live_ are what a leak looks like in the manual repro.

INSERT INTO vendors (id, name, contact_email, api_key) VALUES
  ('v1', 'Acme Labeling',  'ops@acme.example',    'vk_live_v1_4f9a2c7e1b'),
  ('v2', 'Brightdata Co',  'ops@bright.example',  'vk_live_v2_8d3e6a0f5c'),
  ('v3', 'Cortex Annotate','ops@cortex.example',  'vk_live_v3_1a7b9e4d2f');

INSERT INTO datasets (id, vendor_id, name, description) VALUES
  (1, 'v1', 'Clinical QA eval',      'V1-CONFIDENTIAL held-out clinical questions'),
  (2, 'v2', 'Contract clause set',   'V2-CONFIDENTIAL legal clause labels'),
  (3, 'v3', 'Code review pairs',     'V3-CONFIDENTIAL reviewer preference pairs'),
  (4, 'v1', 'Radiology captions',    'V1-CONFIDENTIAL caption drafts');

INSERT INTO tasks (id, dataset_id, vendor_id, title, instructions, status) VALUES
  (1, 1, 'v1', 'Label batch 1', 'V1-CONFIDENTIAL rubric A', 'open'),
  (2, 1, 'v1', 'Label batch 2', 'V1-CONFIDENTIAL rubric A', 'done'),
  (3, 2, 'v2', 'Clause pass 1', 'V2-CONFIDENTIAL rubric B', 'open'),
  (4, 3, 'v3', 'Pairwise pass', 'V3-CONFIDENTIAL rubric C', 'open'),
  (5, 4, 'v1', 'Caption review','V1-CONFIDENTIAL rubric D', 'open');

INSERT INTO products (id, name, summary) VALUES
  (1, 'Labeling', 'Human annotation for AI datasets'),
  (2, 'Evaluation', 'Held-out eval set management');
