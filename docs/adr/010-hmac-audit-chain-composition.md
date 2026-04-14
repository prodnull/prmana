# ADR-010: HMAC Audit Chain Composition

## Status

Accepted

## Context

prmana emits audit events that are enriched into OCSF before being written to the
final audit sink. The integrity chain must be verifiable against what operators
actually consume.

Two compositions were considered:

- Compute the HMAC chain over the raw internal event, then enrich to OCSF
- Enrich to OCSF first, then compute the HMAC chain over the final payload

If the HMAC covers only the raw event, any later enrichment, normalization, or field
reordering can make downstream verification diverge from the stored output.

## Decision

The audit pipeline is:

`bare event -> OCSF enrichment -> HMAC chain`

The HMAC chain covers the OCSF-enriched payload that is actually emitted, not the raw
pre-enrichment event.

## Consequences

### Positive

- Integrity verification matches the final stored audit record
- Operators can verify the chain against the exact output format they ingest
- Avoids false verification failures caused by enrichment steps

### Negative

- Any change to OCSF enrichment semantics changes the HMAC input format
- Raw internal events are not independently chained unless explicitly stored
- Enrichment bugs affect both presentation and chained payload content
