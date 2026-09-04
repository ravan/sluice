# Sluice library surface (`v0.4.0`)

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
| `Deps{Sink, Observer, Now, Logger, Decorators, Enrichers}` | Injected I/O, clock, metrics, log, hooks, enrichers. Only `Sink` is required. |
| `Sink` | `Ingest(ctx, varve.Stream) (varve.Receipt, error)`. `*varve.Client` satisfies it. |
| `Decorator` | `Decorate(ctx, DecorateInput) (varve.Stream, error)`. Runs after assemble, before the sink, once per document. Returned records merge into the document's stream. Must not modify `in.Records`. Must be safe for concurrent use. |
| `DecorateInput` | `Raw`, `Digest` (lower-case hex sha256 of `Raw`), `Source`, `Origin`, `Doc`, `Preds`, `Records`, `ValidFrom`, `Fallback`, `Now`. |
| `DecorateError{Source, Digest, Err}` | One rejected document. Implements `error` and `Unwrap`. |
| `EnrichError{Source, Digest, Err}` | One failed enrichment call. Implements `error` and `Unwrap`. The document is still ingested. |
| `ErrNoEnricher` | The `Err` of the `EnrichError` recorded when the policy names a source `Deps.Enrichers` has none for. |
| `Receipt` | Run outcome: `Documents`, `Nodes`, `Edges`, `Transactions`, `Basis`, `Skipped`, `Fallbacks`, `Expanded`, `ExpansionBudget`, `ExpansionExhausted`, `Decorated`, `DecorateFailed`, `Claims`, `EnrichFailed`. `String()` renders it. |
| `Observer` | Metrics seam: `DocumentIngested`, `DocumentSkipped`, `DocumentFailed`, `RecordsEmitted`, `FallbacksCounted`, `ExpansionDocuments`, `DocumentDecorated`, `DocumentDecorateFailed`, `ClaimsEmitted`, `EnrichFailed(enrich.Source)`. `*metrics.Metrics` satisfies it. |

Decorators run in `Deps.Decorators` order. Each sees the stream the previous
ones extended. An error skips that document only, records a `DecorateError`,
and the run continues. In one-shot mode every document's stream is merged with
`varve.Merge` and sent in one `POST`, so a decorator's records land in the same
transaction as the document's Sluice records.

Enrichers run after assemble and before the decorators, in the order
`config.Processors.Enrich.Policy.Sources` names — not `Deps.Enrichers` order. A
policy naming a source no enricher was built for is skipped silently. Each
enricher sees the claims the previous ones added. An enricher returns a `Claim`,
which names no jurisdiction; `Policy.Stamp` turns it into the `StampedClaim` the
fold sites take, so an enricher cannot state where its own host sits.

## `pkg/enrich`

| Identifier | Role |
|---|---|
| `Source`, `Jurisdiction` | String types. The seven `Source*` names match Silt's `rules.Enricher`; `EU`, `US`, `Other`. |
| `Sources`, `Jurisdictions` | The closed source set, and each fixed-host source's jurisdiction. `vulnerablecode` has no entry: its host is a deployment choice, so `Policy.Hosted` supplies it. |
| `AllJurisdictions` | The closed jurisdiction set: `EU`, `US`, `Other`. |
| `SourceRunner`, `(Source).Runner()` | What produces a source's claims: `RunByEnricher` (the pipeline calls an `Enricher`, per document), `RunByScanner` (GUAC runs it in the parser, gated by `ScanFlags`), `RunByReplay` (a host job replays it). A source no table names is `RunByEnricher`, so a missing enricher is still reported. |
| `ParsePolicy([]string, bool, map[Source]Jurisdiction) (Policy, error)` | Validates source names and hosted jurisdictions. `ErrUnknownSource` (wrapped), a duplicate error, or `ErrUnknownJurisdiction` (wrapped). |
| `ParseJurisdiction(string) (Jurisdiction, error)` | Validates a jurisdiction name read out of config. `ErrUnknownJurisdiction` (wrapped). |
| `Policy{Sources, EUOnly, Hosted}` | The org's rules. `Sources` is priority order. `Hosted` is the per-install jurisdiction of a source whose host is a deployment choice; it wins over `Jurisdictions`. |
| `(Policy).JurisdictionOf(Source) Jurisdiction` | `Hosted`, else `Jurisdictions`, else `Other`. A source no table names is `Other`, which `eu_only` refuses: the cap fails closed. |
| `(Policy).Stamp([]Claim) []StampedClaim` | Places every claim in the jurisdiction `JurisdictionOf` gives its source. The only constructor of `StampedClaim`. |
| `(Policy).Allows(Source) bool` | Listed, and under `EUOnly` sitting in the EU by `JurisdictionOf`. |
| `(Policy).ScanFlags() guacseam.ScanFlags` | The same policy, gating GUAC's four in-parser scanners. |
| `Claim{Source, Subject, Also, Fact, Value, Ref, ValidFrom, FetchedAt}` | One fact from one source about one subject. `Fact` is a `Fact`, not a string. There is no jurisdiction field: only the policy can supply one. |
| `StampedClaim` | A `Claim` the policy has placed in a jurisdiction. `Jurisdiction()` reads it; `Records()` renders the node and its `ABOUT` edges. Only `Policy.Stamp` builds one. |
| `Fact`, `Facts` | The closed set of fact names, including `advisory_id` and `fixed_by`. `Fact` is part of a claim's identity, so an unlisted name would mint a second node instead of replaying onto the first. |
| `ParseFact(string) (Fact, error)` | Validates a name read off the wire or out of config. `ErrUnknownFact` (wrapped). |
| `FactValue{Fact, Value}` | One fact paired with the value a source states for it. An enricher builds these before it knows the subject. |
| `Prop*` constants | The property-key vocabulary of a `Claim` node: `source`, `source_jurisdiction`, `fetched_at`, `fact`, `value`, `ref`, `subject_id`. |
| `(Claim).ID()`, `(StampedClaim).Records()` | Identity is source, subject, fact, value, so a re-fetch replays onto the same node. `Records` renders one `Claim` node plus one `ABOUT` edge per subject. It sits on `StampedClaim`, so an unstamped claim cannot reach the graph. |
| `LabelClaim`, `EdgeAbout` | The graph vocabulary enrichment adds. |
| `Input{Digest, Records, Now}` | One document as an enricher sees it. `Records` holds earlier enrichers' claims too. |
| `Enricher` | `Source() Source`; `Enrich(ctx, Input) ([]Claim, error)`. Must not modify `in.Records`. |
| `VulnNames(varve.Stream) []string` | Every `Vulnerability` node of type `cve` or `euvd`, sorted and deduped. |
| `VulnNodes(varve.Stream) map[string]varve.NodeID` | Every `Vulnerability` node's lower-cased `vulnID` to its node id. |
| `PkgPurls(varve.Stream) []string` | The `purl` of every `PkgVersion` node, sorted and deduped. |
| `Derive(varve.Stream) []Claim` | Scanner evidence to claims, by `(label, collector)`, ordered by id. |
| `Severity{System, Score, Elements}` | One score a source states, normalised. VulnerableCode's V3 API calls the score `value`; a FederatedCode advisory calls it `score`. |
| `CVSS([]Severity) (Severity, bool)` | The first severity whose system starts `cvssv` **and** whose score parses as a number. One advisory mixes `cvssv3.1`, `cvssv4`, `generic_textual`, `epss` and `rhas` in one list. |
| `EPSS([]Severity) (Severity, bool)` | The first severity whose system is exactly `epss`. |
| `(Severity).Version() string` | What follows a CVSS system's `cvssv` prefix: `3.1`, or `3`. Empty for a non-CVSS system. |

## `pkg/enrich/euvd`

| Identifier | Role |
|---|---|
| `DefaultURL` | ENISA's public API base. |
| `New(baseURL string, client *http.Client) (*Enricher, error)` | A bad URL is an error; a nil client is a 20 s-timeout client. |
| `(*Enricher).Source()`, `(*Enricher).Enrich(ctx, enrich.Input)` | One `GET <base>/search?text=<name>&size=10` per vulnerability name. |
| `ErrStatus` | A non-2xx answer from the API. |

## `pkg/enrich/vulnerablecode`

| Identifier | Role |
|---|---|
| `DefaultURL` | `https://public2.vulnerablecode.io`. `public.vulnerablecode.io` answered 500 on every path on 2026-09-03. |
| `UserAgent` | `VCIO_API_AGENT`. The server rejects any `/api/` request with another User-Agent with 403. There is no API key (ADR 0031 amendment). |
| `New(baseURL string, client *http.Client) (*Enricher, error)` | A bad URL is an error; a nil client is a 20 s-timeout client. |
| `(*Enricher).Source()`, `(*Enricher).Enrich(ctx, enrich.Input)` | One `GET <base>/api/v3/affected-by-advisories?purl=<purl>` per `PkgVersion` node. One advisory becomes one `affected` claim about the package plus a fact set on every alias vulnerability the stream already carries. |
| `ErrStatus` | A non-200 answer from the API. |

## `pkg/enrich/federatedcode`

| Identifier | Role |
|---|---|
| `PackagesPrefix`, `VulnerabilitiesDir`, `VulnerabilitiesFile` | The fixed pieces of the `aboutcode.hashid` 0.2.0 layout: `aboutcode-packages`, `aboutcode-vulnerabilities`, `vulnerabilities.yml`. |
| `BitCounts` | `aboutcode.hashid`'s `BIT_COUNT_BY_ECOSYSTEM`: how many bits of a purl's hash name the bucket its type lives in. An absent type uses 0 bits. |
| `CorePurl(string) (string, error)` | Normalises a purl and drops version, qualifiers and subpath: the string the hash is taken over. `ErrPurl` (wrapped). |
| `PurlHash(corePurl string, bits int) string` | `get_purl_hash`: sha256 -> big-endian `big.Int` -> mod 2**bits -> `%0*x`. |
| `PackagePath{Bucket, Core}`, `(PackagePath).Dir()` | Where one package's data files sit. `Dir` joins the two. |
| `PathFor(purl string) (PackagePath, error)` | `get_package_base_dir`. |
| `VulnerabilityPath(vcid string) string` | Where one VCID's file sits: characters 5 and 6 of the VCID name its directory. |
| `PackageEntry{Purl, AffectedBy, Fixing}` | One entry of a `vulnerabilities.yml` file. |
| `Advisory{VulnerabilityID, Aliases, Summary, Severities, References}`, `Severity`, `Reference` | One `aboutcode-vulnerabilities` file. Its `Severity` is the YAML shape; `enrich.Severity` is the normalised one. |
| `ParsePackageEntries([]byte)`, `ParseAdvisory([]byte)` | A malformed document is a wrapped error, never a partial result. |
| `(Advisory).Facts() []enrich.FactValue` | What the advisory states about the vulnerability itself, in claim order. An empty value is not a fact. |
| `Request{Subjects, Vulns}` | What a caller wants replayed: exact versioned purl to its `PkgVersion` node, and lower-cased vulnerability id to its `Vulnerability` node. A replay hangs claims on nodes the caller already holds and never invents one. |
| `Result{Packages, Commits, Claims, Missing}` | One replay's outcome: the counts a job receipt reports. |
| `Open(ctx, dir, url string) (*Repo, error)` | Opens the clone at `dir`, cloning it from `url` when `dir` holds none, and fetches an existing one. Neither possible is `ErrNoRepo`. |
| `(*Repo).Replay(ctx, Request) (Result, error)` | Walks each subject's data history and returns one claim per fact per commit, each `ValidFrom` and `FetchedAt` the commit's committer time. Claims come back oldest first. |

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
| `Prop*` constants | The property-key vocabulary, alongside `Label*` and `Edge*`. `pkg/enrich` reads evidence nodes back by these names, so a key is a cross-package contract. |
| `CanonQualifiers`, `KVPair` | Purl qualifier canonicalisation. |

## `pkg/config`

| Identifier | Role |
|---|---|
| `Load(io.Reader) (Config, error)`, `LoadFile(path)` | Parse and validate `pipeline.yaml`. Unknown keys fail. |
| `Config{Receivers, Processors, Sink}` | The validated pipeline definition. A library caller may build it directly. |
| `Receivers{Files, OCI, S3, GCS}` and the four receiver structs | Absent receiver is `nil`. `Poll == 0` means one pass. |
| `Processors{ValidTime, Enrich, Expand}` | Guard bounds, enrichment policy, expansion budget. |
| `EnrichProcessor{Policy, EUVDURL, VulnerableCode}` | The org's `enrich.Policy` plus the endpoints the enrichers this build carries need. Absent block means the zero policy, `euvd.DefaultURL` and `vulnerablecode.DefaultURL` at `us`. |
| `VulnerableCodeProcessor{URL, Jurisdiction}` | The VulnerableCode endpoint and the jurisdiction of the host it names, from `processors.enrich.vulnerablecode.{url, jurisdiction}`. `Hosted()` renders it as the map `ParsePolicy` takes; it is the one place naming `SourceVulnerableCode`. |
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
- `assemble` formatting helpers: `fmtTime`, `fmtTimePtr`, `formatFloat`, `toNodeIDs`.
- `guacseam.collectWith`, `parseWorkers`, `processAndParse`, `drainExpansion`, `expansionHandler`, and the collector builders.
- `varve` retry internals: `backoff`, `parseRetryAfter`, `sleepUntil`, `ingestErrorBody`.
- `pipeline.sourcesFromConfig`, `anyPolling`, `noopObserver`, `fold`.
- `config.wire*` structs. The YAML shape is documented in the README, not in Go.
