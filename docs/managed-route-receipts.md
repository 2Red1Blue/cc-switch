# Managed route receipts

The owner-only Unix control socket exposes route evidence for Fabric correlations. `POST /managed/v1/route-events/seal` closes ingress and establishes a durable high watermark. `GET /managed/v1/route-events/receipt?correlationId=<id>&after=<global-sequence>&limit=<page-size>` reads an already complete seal and its events. The GET does not seal a correlation, wait for calls, reconcile state, create files, change permissions, or repair the sequence pointer.

The receipt GET returns `404` when there is no durable correlation record and `409` when a record exists but ingress, active calls, pending hops, reserved hops, or its high watermark do not yet describe a complete seal. Both handled errors use JSON with `schemaVersion: 1`, `producerSchemaGeneration: 1`, `correlationId`, and `error` set to `receipt_missing` or `receipt_unsealed`, respectively. A router-level `404` for an unsupported path does not carry this envelope. Invalid correlation IDs return `400`; inconsistent persisted state returns `500`. A successful response contains `schemaVersion: 1`, `producerSchemaGeneration: 1`, `state: "sealed"`, `correlationId`, the seal's `eventCount` and `highWatermark`, and the existing page fields `events`, `nextAfter`, `latestSequence`, `cursorAhead`, `hasMore`, `cursorGap`, and `scanTruncated`. There is no `timedOut` field on this durable read.

The handled error body is exactly these four fields, with `Content-Type: application/json`:

```json
{"schemaVersion":1,"producerSchemaGeneration":1,"correlationId":"attempt-1","error":"receipt_missing"}
```

For `409`, `error` is `"receipt_unsealed"`. An older producer without the receipt route returns a generic router-level `404` without this envelope; consumers can distinguish that response from `receipt_missing`.

`after` and `nextAfter` are global sequence cursors. The producer always scans through the seal's persisted high watermark, independently of later events or caller input. `eventCount` and `highWatermark` repeat unchanged across pages; `latestSequence` is the current persisted global pointer and can advance when other correlations append events. A missing or invalid event file appears as `cursorGap`; a bounded scan that stops before the watermark appears as `scanTruncated`. Consumers must check those fields and the correlation event count before treating the receipt as complete evidence.
