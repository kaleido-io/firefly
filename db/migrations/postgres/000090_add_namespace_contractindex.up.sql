BEGIN;
ALTER TABLE namespaces ADD COLUMN contract_index INTEGER DEFAULT 0;
COMMIT;
