-- verdant M02 Slice A migration 0005_action_identity; predecessor: 0004_action_journal.
-- Fresh: apply 0001 + its ledger note, then 0002, then 0003, then 0004, then
-- this file in ONE private transaction in an unpublished private database
-- (writer-gated; fresh SqliteStore::open stays at 0003 until the writer
-- ensures apply 0004 then 0005; 0003, 0004 and 0005 are valid currents).
-- Publish only the validated, closed file.
-- Upgrade: validate the complete 0004 schema/ledger in the owning writer
-- transaction, then apply this file. No existing rows or dirty flags change.
-- No backfill: action_journal/action_targets rows keep their values; the four
-- new identity columns stay NULL on existing 'admitted' rows. Those rows
-- remain readable via reconcile but refuse for new handoffs as stale-payload
-- (no silent rewrite, no backfill, no v1 conversion).
-- Compatibility: user_version remains 1 (unchanged row/consumer contract).
-- The ledger and application_id identify the storage protocol revision;
-- unknown revisions and downgraded/incomplete combinations are refused.
-- Generation-1 access/binding/observation consumers accept this additive
-- upgraded store. WAL/FULL, one writer, extra space for identity; no down
-- migration. A process crash rolls back the entire upgrade, not evidence of
-- power-loss durability.
-- Exactly four new nullable columns plus one index. No outbox, receipt,
-- observation or accepted/sealed payload backfill. No v1 descriptor
-- conversion, no legacy preview backfill, no migration-rewrite helpers, no
-- deprecated aliases (greenfield forward-only; applied migrations are never
-- rewritten).
-- Lossless identity (Slice A): exact binary32 wire_bits (u32 bits, not
-- {:.4} text), explicit action kind ('set' vs 'release'), authorized release
-- admission flag plus release target/obligation reference. The {:.4} payload
-- text stays presentation-only; handoffs compare wire_bits/kind/target, not
-- rounded text. Slice B delivered: lifecycle in action_journal/lifecycle.rs
-- (0006), owned 6/hour in action_journal/rate.rs, custody predecessor link in
-- admission_body_v2 -- see action_journal/identity.rs header.
ALTER TABLE action_journal ADD COLUMN wire_bits INTEGER CHECK (wire_bits IS NULL OR (wire_bits >= 0 AND wire_bits <= 4294967295));
ALTER TABLE action_journal ADD COLUMN action_kind TEXT CHECK (action_kind IS NULL OR action_kind IN ('set', 'release'));
ALTER TABLE action_journal ADD COLUMN release_admitted INTEGER CHECK (release_admitted IS NULL OR release_admitted IN (0, 1));
ALTER TABLE action_journal ADD COLUMN release_target TEXT;
CREATE INDEX IF NOT EXISTS action_journal_identity ON action_journal(scope, equipment, action_kind, wire_bits);
INSERT INTO schema_migrations VALUES (5, 'M02-SliceA 0005_action_identity: lossless wire identity and kind');
