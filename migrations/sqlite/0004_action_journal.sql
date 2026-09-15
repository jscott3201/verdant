-- verdant M02-PR06 migration 0004_action_journal; predecessor: 0003_observations.
-- Fresh: apply 0001 + its ledger note, then 0002, then 0003, then this file in
-- ONE private transaction in an unpublished private database (writer-gated;
-- fresh SqliteStore::open stays at 0003 until the writer ensure applies this
-- file; both 0003 and 0004 are valid currents). Publish only the validated,
-- closed file.
-- Upgrade: validate the complete 0003 schema/ledger in the owning writer
-- transaction, then apply this file. No existing rows or dirty flags change.
-- No backfill: action_journal/action_targets start empty; per-target
-- generations start at 0 (no row) and advance only through guarded admission.
-- Compatibility: user_version remains 1 (unchanged row/consumer contract).
-- The ledger and application_id identify the storage protocol revision;
-- unknown revisions and downgraded/incomplete combinations are refused.
-- Generation-1 access/binding/observation consumers accept this additive
-- upgraded store. WAL/FULL, one writer, extra space for journal; no down
-- migration. A process crash rolls back the entire upgrade, not evidence of
-- power-loss durability.
-- Exactly two new tables plus one index. No outbox, receipt, observation or
-- accepted/sealed payload backfill. No v1 descriptor conversion, no legacy
-- preview backfill, no migration-rewrite helpers, no deprecated aliases
-- (greenfield forward-only; applied migrations are never rewritten).
CREATE TABLE action_journal (
    operation TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    equipment TEXT NOT NULL,
    binding_revision INTEGER NOT NULL CHECK (binding_revision >= 0),
    accepted_revision INTEGER NOT NULL CHECK (accepted_revision >= 0),
    expected_generation INTEGER NOT NULL CHECK (expected_generation >= 0),
    target_generation INTEGER NOT NULL CHECK (target_generation > expected_generation),
    payload TEXT NOT NULL,
    deadline_secs INTEGER NOT NULL CHECK (deadline_secs = 5),
    ceiling INTEGER NOT NULL CHECK (ceiling >= 0),
    actor TEXT NOT NULL,
    attempt TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('admitted')),
    created INTEGER NOT NULL
);
CREATE TABLE action_targets (
    scope TEXT NOT NULL,
    equipment TEXT NOT NULL,
    current_generation INTEGER NOT NULL CHECK (current_generation >= 0),
    PRIMARY KEY (scope, equipment)
);
CREATE INDEX action_journal_target ON action_journal(scope, equipment, target_generation);
INSERT INTO schema_migrations VALUES (4, 'M02-PR06 0004_action_journal: durable admission and per-target state');
