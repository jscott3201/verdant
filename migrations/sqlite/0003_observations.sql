-- M02-PR03B 0003_observations; predecessor: validated 0002_receipts.
-- Fresh: 0001 + 0002 + 0003 in the private bootstrap transaction.
-- Upgrade: additive, one admitted BEGIN IMMEDIATE transaction, WAL/FULL.
-- user_version stays 1; no outbox, receipt or accepted/sealed payload backfill.
-- Exactly three new tables. current is a derived view, not editable meaning.
-- The bounded window owner reserves obw:state and obw:ticket:* receipt keys:
-- one scoped producer journal per store, finite ticket replay, durable fencing
-- state. Existing owners' receipts/outbox rows are never pruned by this owner.
-- No down migration. Interrupted upgrades roll back; reopen validates the full
-- ledger and schema. No power-loss, live WAL quota or real disk-full claim.
CREATE TABLE observations (
    scope TEXT NOT NULL,
    producer TEXT NOT NULL,
    generation TEXT NOT NULL,
    seq INTEGER NOT NULL CHECK (seq >= 0),
    binding_key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    unit TEXT NOT NULL,
    source_ms INTEGER,
    receipt_ms INTEGER NOT NULL,
    ingestion_ms INTEGER NOT NULL,
    receipt_mark TEXT NOT NULL,
    incarnation TEXT NOT NULL,
    suitability TEXT NOT NULL CHECK (suitability IN ('synthetic-value-only', 'refused')),
    created INTEGER NOT NULL,
    PRIMARY KEY (scope, producer, generation, seq),
    UNIQUE (scope, producer, seq)
);
CREATE INDEX observations_binding ON observations(scope, producer, binding_key, seq);
CREATE TABLE pins (
    pin_id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    producer TEXT NOT NULL,
    generation TEXT NOT NULL,
    seq INTEGER NOT NULL,
    expiry_ms INTEGER NOT NULL,
    admit_seq INTEGER NOT NULL,
    FOREIGN KEY (scope, producer, generation, seq)
        REFERENCES observations(scope, producer, generation, seq)
);
CREATE TABLE gaps (
    scope TEXT NOT NULL,
    producer TEXT NOT NULL,
    from_seq INTEGER NOT NULL CHECK (from_seq >= 0),
    to_seq INTEGER NOT NULL CHECK (to_seq >= from_seq),
    reason TEXT NOT NULL CHECK (reason = 'window-evicted'),
    PRIMARY KEY (scope, producer, from_seq)
);
CREATE VIEW current AS
    SELECT o.* FROM observations o, storage_receipts s,
        json_each(s.response, '$.current') c
    WHERE s.operation = 'obw:state' AND s.request = 'obw-state-v1'
        AND o.scope = json_extract(s.response, '$.scope')
        AND o.producer = json_extract(s.response, '$.producer')
        AND o.seq = c.value;
INSERT INTO schema_migrations VALUES
    (3, 'M02-PR03B 0003_observations: finite window and custody');
