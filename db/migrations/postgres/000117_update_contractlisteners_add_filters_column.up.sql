BEGIN;
ALTER TABLE contractlisteners ADD COLUMN filters TEXT;
COMMIT;