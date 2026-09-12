-- verdant R03 migration 0002_receipts; predecessor: 0001_init (unchanged).
-- Fresh: apply 0001 + its ledger note, then this file in ONE transaction in
-- an unpublished private database. Publish only the validated, closed file.
-- Upgrade: validate the complete 0001 schema/ledger in the owning writer
-- transaction, then apply this file. No existing rows or dirty flags change.
-- Backfill: one legacy receipt per outbox row, including duplicates. These
-- attest only that the row predates receipts, NOT any historical transition.
-- Receipts are NOT outbox events. New attempts use a separate identity from
-- the business operation, preserving additive business-operation duplicates.
-- Compatibility: user_version remains 1 (unchanged row/consumer contract).
-- The ledger and application_id identify the storage protocol revision;
-- unknown revisions and downgraded/incomplete combinations are refused.
-- Generation-1 access/binding consumers accept this additive upgraded store.
-- WAL/FULL, one writer, extra space for receipts; no down migration. A process
-- crash rolls back the entire upgrade, not evidence of power-loss durability.
CREATE TABLE storage_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    identity TEXT NOT NULL
);
INSERT INTO storage_identity VALUES (1, lower(hex(randomblob(32))));
CREATE TABLE storage_receipts (
    operation TEXT PRIMARY KEY,
    request TEXT NOT NULL,
    response TEXT NOT NULL
);
INSERT INTO storage_receipts(operation, request, response)
    SELECT 'legacy:' || id, 'legacy-outbox-row-only', CAST(id AS TEXT)
    FROM outbox;
INSERT INTO schema_migrations VALUES (2, 'R03 0002_receipts: admission and reconciliation');
PRAGMA application_id = 1447383636;
