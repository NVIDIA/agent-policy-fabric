# APF Audit Event Schema

The wire contract for APF audit records: `apf.audit.event.v1.schema.json`.

Every audit record emitted by any APF component validates against this schema
before it is written. It is the single source of truth for the record shape —
event types, decision/verdict vocabulary, findings, effects, and the redaction
and sanitization bounds.

Unlike the authoring schemas in `../jsonschema/` (which describe policy
documents an operator writes by hand), this is an **output/wire** contract:
it describes what APF *emits*, not what anyone authors.

The `apf-audit` crate embeds this file at build time
(`crates/apf-audit/src/lib.rs`, exported as `AUDIT_EVENT_SCHEMA_JSON`) and
validates every event against it. Producers and downstream consumers
(collectors, SIEM queries) should treat this file as authoritative.

For a human-readable guide to the event types, when each fires, and how
findings are populated, see `crates/apf-audit/README.md`.
