-- verdant M02 Slice B migration 0006_action_lifecycle; predecessor: 0005_action_identity.
-- Fresh: apply 0001 + its ledger note, then 0002, then 0003, then 0004, then
-- 0005, then this file in ONE private transaction in an unpublished private database
-- (writer-gated; fresh SqliteStore::open stays at 0003 until the writer
-- ensures apply 0004 then 0005 then 0006; 0003, 0004, 0005 and 0006 are valid currents).
-- Publish only the validated, closed file.
-- Upgrade: validate the complete 0005 schema/ledger in the owning writer
-- transaction, then apply this file. No existing rows or dirty flags change.
-- No backfill: action_journal/action_targets rows keep their values; the new
-- lifecycle table starts empty. Missing lifecycle rows read conservatively as
-- admitted (never invented dispatched/terminal); legacy 0004/0005 stale-payload
-- rules preserved (no silent rewrite, no backfill, no v1 conversion).
-- Compatibility: user_version remains 1 (unchanged row/consumer contract).
-- The ledger and application_id identify the storage protocol revision;
-- unknown revisions and downgraded/incomplete combinations are refused.
-- Generation-1 access/binding/observation consumers accept this additive
-- upgraded store. WAL/FULL, one writer, extra space for lifecycle; no down
-- migration. A process crash rolls back the entire upgrade, not evidence of
-- power-loss durability.
-- Exactly one new table plus two indexes. No outbox, receipt, observation or
-- accepted/sealed payload backfill. No v1 descriptor conversion, no legacy
-- preview backfill, no migration-rewrite helpers, no deprecated aliases
-- (greenfield forward-only; applied migrations are never rewritten).
-- Lifecycle (Slice B): durable attempt progression admitted->dispatched->
-- terminal/unresolved with wall anchor and predecessor obligation link.
-- Rate 6/hour and 5s deadline anchor to durable created wall time; constrained
-- admitted-null-release/cancel-unattempted stay exempt so SET quota cannot
-- starve cleanup. Outstanding is state-filtered, scope-filtered, bounded page.
CREATE TABLE action_lifecycle (
    operation TEXT PRIMARY KEY REFERENCES action_journal(operation) ON DELETE CASCADE,
    attempt TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('admitted', 'dispatched', 'terminal', 'unresolved')),
    updated INTEGER NOT NULL CHECK (updated >= 0),
    predecessor TEXT REFERENCES action_journal(operation) ON DELETE SET NULL
);
CREATE INDEX action_lifecycle_state ON action_lifecycle(state);
CREATE INDEX action_lifecycle_predecessor ON action_lifecycle(predecessor);
INSERT INTO schema_migrations VALUES (6, 'M02-SliceB 0006_action_lifecycle: durable lifecycle, rate anchor, custody link');
