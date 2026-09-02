# Sluice library surface (`v0.1.0`)

Sluice is importable as a Go library. Every package under `pkg/` is public.
`v0.x` means "public API, not yet stable": a minor bump may break it, and the
`CHANGELOG.md` says how. `cmd/sluice` is the reference caller.

The shape: `pipeline.Run` collects documents from configured receivers, parses
them with GUAC, assembles each into a `varve.Stream`, lets your `Decorator`s
extend that stream, and writes it to a `Sink`. You supply the sink (usually
`*varve.Client`) and the decorators.

## `pkg/pipeline`

| Identifier | Role |
|---|---|
| `Run(ctx, config.Config, Deps) (Receipt, error)` | The one entry point. One-shot when no receiver polls; daemon otherwise. |
| `Deps{Sink, Observer, Now, Logger, Decorators}` | Injected I/O, clock, metrics, log, hooks. Only `Sink` is required. |
| `Sink` | `Ingest(ctx, varve.Stream) (varve.Receipt, error)`. `*varve.Client` satisfies it. |
| `Decorator` | `Decorate(ctx, DecorateInput) (varve.Stream, error)`. Runs after assemble, before the sink, once per document. Returned records merge into the document's stream. Must not modify `in.Records`. Must be safe for concurrent use. |
| `DecorateInput` | `Raw`, `Digest` (lower-case hex sha256 of `Raw`), `Source`, `Origin`, `Doc`, `Preds`, `Records`, `ValidFrom`, `Fallback`, `Now`. |
| `DecorateError{Source, Digest, Err}` | One rejected document. Implements `error` and `Unwrap`. |
| `Receipt` | Run outcome: `Documents`, `Nodes`, `Edges`, `Transactions`, `Basis`, `Skipped`, `Fallbacks`, `Expanded`, `ExpansionBudget`, `ExpansionExhausted`, `Decorated`, `DecorateFailed`. `String()` renders it. |
| `Observer` | Metrics seam: `DocumentIngested`, `DocumentSkipped`, `DocumentFailed`, `RecordsEmitted`, `FallbacksCounted`, `ExpansionDocuments`, `DocumentDecorated`, `DocumentDecorateFailed`. `*metrics.Metrics` satisfies it. |

Decorators run in `Deps.Decorators` order. Each sees the stream the previous
ones extended. An error skips that document only, records a `DecorateError`,
and the run continues. In one-shot mode every document's stream is merged with
`varve.Merge` and sent in one `POST`, so a decorator's records land in the same
transaction as the document's Sluice records.

## `pkg/varve`

| Identifier | Role |
|---|---|
| `NewClient(ClientConfig) (*Client, error)` | Builds the `/v1/ingest` client. Errors on a bad `Addr`, an empty token pair, or a `Graph` starting with `__`. |
| `ClientConfig{Addr, Token, TokenProvider, Graph, HTTP, MaxAttempts, OnRetry}` | `TokenProvider` wins over `Token`. `Graph` becomes `?graph=<name>`; empty means the Varve default graph. |
| `TokenProvider` | `func(ctx) (string, error)`. Called once per HTTP attempt. Must be safe for concurrent use. |
| `StaticToken(string) TokenProvider` | Wraps a constant token. |
| `(*Client).Ingest(ctx, Stream) (Receipt, error)` | Posts the stream. Retries 408/429/503 and transport errors with capped backoff. Follows one 421. Any terminal non-2xx is `*IngestError`. |
| `IngestError{Status, Message, Committed}` | A non-2xx answer. `Committed` is the chunk progress that survived. 404 `unknown_graph` arrives here. |
| `Receipt` | What `/v1/ingest` returns: `Nodes`, `Edges`, `Transactions`, `Basis`, `SystemTime`. |
| `Stream{Nodes, Edges}` | The record unit. Nodes first, then edges. |
| `Merge(...Stream) Stream` | The one dedup rule: by id, first record wins, earliest non-zero `ValidFrom` wins, first-seen order. |
| `NodeRecord`, `EdgeRecord`, `Prop` | One record each. `ValidFrom` zero means "omitted on the wire". |
| `NodeID`, `EdgeID`, `NodeLabel`, `EdgeLabel` | String types for ids and labels. |
| `Value`, `Str`, `Int`, `Float`, `Bool` | The closed set of property values the wire accepts. |
| `WriteNDJSON(io.Writer, Stream) error` | Renders a stream as bulk-ingest NDJSON. |

## `pkg/guacseam`

The only package that calls GUAC behaviour.

| Identifier | Role |
|---|---|
| `Collect(ctx, Sources, DocumentFunc) (Outcome, error)` | Runs every configured receiver once (or polls) and hands each parsed document to `fn` in arrival order. |
| `DocumentFunc` | `func(ctx, Parsed) error`. An error aborts the pass. |
| `Parsed{Source, Origin, Doc, Preds, Purls}` | One collected and parsed document. `Doc.Blob` holds the raw bytes. |
| `Origin`, `OriginReceiver`, `OriginExpansion` | Where the document came from. |
| `Sources{Files, OCI, S3, GCS, Scan, OnSkip}` | The receiver set for one pass. |
| `FilesReceiver`, `OCIReceiver`, `S3Receiver`, `GCSReceiver` | Receiver settings. |
| `ScanFlags{Vulns, Licenses, EOL, DepsDev}` | The parse-time enrichment scanners. |
| `Outcome{Documents, Failed}`, `FailedDocument{Source, Err}` | One pass's counts and skips. |
| `ExpandDepsDev(ctx, purls, limit, DocumentFunc) (Expansion, error)` | Budget-bounded deps.dev expansion. Documents arrive with `OriginExpansion`. |
| `Expansion{Collected, Limit, Exhausted}` | One expansion pass. |

## `pkg/assemble`

| Identifier | Role |
|---|---|
| `Assemble(ctx, []assembler.IngestPredicates, validtime.Guard, now) AssembleResult` | Predicates to one deduped, id-sorted `varve.Stream`. |
| `AssembleResult{Stream, Fallbacks, ValidFrom, Fallback}` | The stream, the fallback count, and the document-level valid time. |
| `Label*` constants (`varve.NodeLabel`) | The node vocabulary: `PkgVersion`, `PkgName`, `SrcName`, `Artifact`, `Vulnerability`, `Builder`, `License`, and one label per evidence kind. |
| `Edge*` constants (`varve.EdgeLabel`) | The edge vocabulary: `PkgHasVersion` plus one subject/object label per evidence kind. |
| `PkgVersionID`, `PkgNameID`, `SrcNameID`, `ArtifactID`, `VulnID`, `BuilderID`, `LicenseID`, `EvidenceID`, `EdgeIDFor` | Deterministic id derivation. Silt depends on these; a change is a breaking release. |
| `CanonQualifiers`, `KVPair` | Purl qualifier canonicalisation. |

## `pkg/config`

| Identifier | Role |
|---|---|
| `Load(io.Reader) (Config, error)`, `LoadFile(path)` | Parse and validate `pipeline.yaml`. Unknown keys fail. |
| `Config{Receivers, Processors, Sink}` | The validated pipeline definition. A library caller may build it directly. |
| `Receivers{Files, OCI, S3, GCS}` and the four receiver structs | Absent receiver is `nil`. `Poll == 0` means one pass. |
| `Processors{ValidTime, Enrich, Expand}` | Guard bounds, scanner flags, expansion budget. |
| `Sink{Varve}`, `VarveSink{Addr, TokenEnv, Graph}` | The writer declaration. `pipeline.Run` never reads it; the caller builds the client. |

## `pkg/validtime`

| Identifier | Role |
|---|---|
| `Guard{Floor, Skew}`, `Default()` | The valid-time guard. |
| `(Guard).Resolve(*time.Time, now) (time.Time, bool)` | Native timestamp to valid time, or fall back to `now`. |

## `pkg/metrics`

| Identifier | Role |
|---|---|
| `New() *Metrics`, `(*Metrics).Handler()` | A Prometheus registry with Sluice's counters. Satisfies `pipeline.Observer`. Also `SinkRetry()` for `ClientConfig.OnRetry`. |

## What stays unexported

These are implementation details. Do not depend on them.

- `assemble.builder` and the seventeen `map*` methods. Use `Assemble`.
- `guacseam.collectWith`, `parseWorkers`, `processAndParse`, `drainExpansion`, `expansionHandler`, and the collector builders.
- `varve` retry internals: `backoff`, `parseRetryAfter`, `sleepUntil`, `ingestErrorBody`.
- `pipeline.sourcesFromConfig`, `anyPolling`, `noopObserver`, `fold`.
- `config.wire*` structs. The YAML shape is documented in the README, not in Go.
