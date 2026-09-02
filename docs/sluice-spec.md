# sluice — Specification & Roadmap

sluice is a standalone Go project: the collection layer for software
supply-chain metadata (SBOMs, attestations, vulnerability and VEX documents)
that writes a **native property graph** into [Varve], the bitemporal graph
database. It reuses [GUAC] as a library for everything GUAC is good at —
collecting and parsing two dozen document formats — and replaces everything
downstream of parsing: no GraphQL server, no generic backend abstraction, no
intermediate ontology. Structurally it is to supply-chain graphs what the
OpenTelemetry Collector is to telemetry: receivers → processors → one sink.

Grilling session: **2026-08-06**. Sources: the viability study
(`varve/docs/design/2026-08-06-sluice-viability.md`), the proven mapping
experiment (`varve/refs/guac`, branch `feat/varve-backend`), Varve's bulk
ingest wire contract (`varve/docs/book/src/reference/bulk-ingest.md`), and
the `varve/gallery/guac` demo. Vocabulary pinned in §2; divergences in §7.

[Varve]: https://github.com/ravan/varve
[GUAC]: https://github.com/guacsec/guac

## 1. The idea in one paragraph

GUAC's pipeline has a clean seam: collectors emit documents, parsers turn
them into `[]assembler.IngestPredicates` (a pure-data IR of 17 predicate
kinds), and an injected assembler function writes them somewhere. sluice
keeps everything upstream of that seam as imported library code and replaces
the assembler: predicates are mapped — with deterministic, content-derived
ids — into a flattened property-graph model and streamed as bulk NDJSON to
Varve's `POST /v1/ingest` (~166k records/s, idempotent upsert, per-record
valid time). One binary offers a config-driven daemon (`run`) and a one-shot
CLI (`ingest`) built on the same pipeline. Document-native timestamps become
first-class **valid time** under a sanity guard, so the graph answers both
"what did we know at T?" and "what was true at T?" — something stock GUAC
structurally cannot.

## 2. Domain model (settled)

### 2.1 Pipeline vocabulary (settled)

| Term | Meaning | Implementation |
|---|---|---|
| **Receiver** | A source of documents (files dir, OCI ref, S3, GCS, GitHub releases, deps.dev) | GUAC `Collector` implementations, imported |
| **Document** | One collected supply-chain artifact + provenance | GUAC `processor.Document`, imported |
| **Parser stage** | Format detection/verification + per-format parsing + ingest-time enrichment | GUAC `process.Process` + `parser.ParseDocumentTree`, imported |
| **Predicates** | The IR between parsing and assembly: 17 predicate lists of plain input structs | GUAC `assembler.IngestPredicates`, imported |
| **Processor** | A pipeline stage acting on predicates or purls: enrichment scanners, expansion, valid-time guard, batching | sluice code (scanners themselves imported from GUAC) |
| **Assembler** | Predicates → graph records. The heart of sluice; net-new code | `pkg/assemble` |
| **Record stream** | The canonical output: bulk-NDJSON node/edge records with `_id`s and valid time | `pkg/varve` emits it; the wire contract is Varve's `docs/book/src/reference/bulk-ingest.md` |
| **Decorator** | An embedding module's hook: sees one document (bytes, digest, source, origin, valid time) plus the records assembled for it, and returns extra records that join the same stream and the same transaction. Runs after assemble, before the sink, in both modes. An error skips only that document | `pkg/pipeline.Decorator`; the caller supplies them via `Deps.Decorators` |
| **Sink** | The single destination: `POST /v1/ingest` on the Varve writer, optionally into a named graph (`?graph=`) | `pkg/varve` client |
| **Receipt** | Per-run outcome: node/edge counts, transactions, basis, valid-time fallbacks, expansion budget use, skipped documents, decorated and decorate-failed documents | sluice code |

There is exactly **one** sink kind and **one** record stream format. There is
no exporter registry (§7). Anything else that wants the data consumes the
same NDJSON (a file sink for debugging falls out for free and is not a
product feature).

### 2.2 Reuse rule (settled)

**If a GUAC package is backend-blind, it is imported, never copied.** That
covers all receivers, the processor, all 13 registered parsers, the
OSV/deps.dev/ClearlyDefined/EOL enrichment scanners, purl helpers, and the
`IdentifierStrings` plumbing. Net-new code is limited to: the assembler, the
valid-time guard, the Varve client, the pipeline shell, and configuration.
The deterministic-id derivation is ported (as new, table-driven-tested code)
from the `feat/varve-backend` branch — knowledge transfer, not a code
dependency.

### 2.3 Graph model (settled)

Flattened two-level package model; GUAC's 4-level trie
(PkgType→PkgNamespace→PkgName→PkgVersion) is retired — it existed to serve
GraphQL hierarchy hydration, which no longer exists (§7).

**Identity nodes**

| Label | `_id` scheme (illustrative) | Properties |
|---|---|---|
| `PkgVersion` | `pkg:v:<type>/<ns>/<name>/<version>+<canonQuals>+<subpath>` | `type`, `namespace`, `name`, `version`, `qualifiers` (canonical `k=v&…`), `subpath`, `purl` |
| `PkgName` | `pkg:n:<type>/<ns>/<name>` | `type`, `namespace`, `name` — exists as the attach point for ALL_VERSIONS (MatchFlags) evidence |
| `SrcName` | `src:n:…` (full natural key incl. tag/commit) | `type`, `namespace`, `name`, `tag`, `commit` |
| `Artifact` | `art:<algo>:<digest>` (lowercased) | `algorithm`, `digest` |
| `Builder` | `bld:<uri>` | `uri` |
| `Vulnerability` | `vuln:<type>/<id>` (lowercased); `vuln:novuln` sentinel | `type`, `vulnID` |
| `License` | `lic:<name>` or `lic:<sha256>` for inline texts | `name`, `inline`, `listVersion` |

`PkgName -[PkgHasVersion]-> PkgVersion` is the only structural package edge.
Type- and namespace-level queries are property filters, not hops.

**Evidence nodes** — one node per assertion, labelled by predicate kind
(`IsDependency`, `IsOccurrence`, `HasSBOM`, `CertifyVuln`, `Vex`, `HasSlsa`,
`CertifyScorecard`, `CertifyLegal`, `HasSourceAt`, `CertifyBad`,
`CertifyGood`, `HashEqual`, `PkgEqual`, `VulnEqual`, `VulnMetadata`,
`HasMetadata`, `PointOfContact`), `_id` = `<kind>:sha256(subject-id, object-id,
all spec fields)`. All InputSpec fields are stored as flat properties;
small ordered lists (SLSA predicate pairs, scorecard checks) are packed with
the branch's `encodeKV` scheme. Evidence is a node, not edge properties,
because multiple assertions of the same kind can link the same endpoints
with different provenance.

**Edges** carry **semantic labels** (`DependsOn`, `SubjectOf`, `Affects`, …
— final vocabulary pinned by the S1 golden files), never a generic label
with a `kind` property. This diverges from the `feat/varve-backend` branch's
`:E {kind}` scheme (§7): label-anchored traversal is what Varve's planner
prunes on. Every edge gets an explicit `props._id` = `<srcId>|<label>|<dstId>`
so edge replay is idempotent too.

The exact id derivations live in `internal/assemble/ids*.go` and are pinned
by table-driven tests; this table is orientation, not authority (§5).

### 2.4 Valid time (settled)

Every record's `valid_from` is the document's native assertion timestamp —
`CertifyVuln.timeScanned`, VEX statement time, SBOM creation time, scorecard
`timeScanned`, SLSA `finishedOn` — **when it passes the guard**:

1. Not earlier than the configured floor (default `2000-01-01T00:00:00Z`).
2. Not later than now + configured skew tolerance (default 5m).

Outside the bounds, or absent, `valid_from` falls back to ingest time and
the fallback is **counted in the receipt and metrics** — a CI host with a
1970 clock can never silently rewrite graph history. Identity nodes
(packages, artifacts, …) take the earliest valid time of any document
asserting them in the stream; supersede-upsert makes repeats harmless.

### 2.5 Expansion (settled)

Opt-in, in-process: each parsed document's `IdentifierStrings` purls feed
the imported deps.dev receiver as new documents, bounded by a configured
budget (max documents per run, default 500) and depth 1 by default. Budget
exhaustion is reported in the receipt, never silent. GUAC's `guaccsub` gRPC
service is not run (§8) — it coordinates multiple GUAC processes; this is
one process.

### 2.6 Retry & idempotency semantics (settled)

The stream is chunk-atomic, not stream-atomic (Varve contract). The retry
story after any failure is **full-stream replay**: because every node and
edge carries a deterministic `_id`, replay supersedes in place. A failed
document is skipped-and-counted; a failed chunk fails the run with the
committed progress reported (mirroring Varve's error body).

## 3. Architecture (settled)

- **Repo**: `~/suse/repo/github/ravan/sluice` — its own git repository,
  sibling of varve. Go module `github.com/ravan/sluice`. Apache-2.0.
  Go 1.26. (Go 1.26 is GUAC *main*'s floor; the pinned release below declares
  `go 1.25.0`, so 1.26 is our choice, not a constraint — §10.1.)
- **Independence**: sluice never imports varve code and varve never
  imports sluice. The only coupling is Varve's public HTTP wire
  contracts (`/v1/ingest`, `/v1/tx`, `/v1/query`, `/v1/status`).
- **GUAC dependency**: `require github.com/guacsec/guac` at a **pinned
  upstream release** — **v1.1.0**, the latest release as of 2026-08-06. No
  `replace` directives, no fork dependency. Renovate or dependabot watches the
  pin. Predicate-facing code uses the genqlient *client* types, never the
  GraphQL server model (§10.1).

```
sluice/
  cmd/sluice/      cobra entry: run, ingest, version
  pkg/pipeline/    builds receiver→parser→processor→assembler→decorator→sink from config
  pkg/guacseam/    the ONLY place GUAC behavior is invoked
                   (collector.Collect, process.Process, parser.ParseDocumentTree)
  pkg/assemble/    Predicates → record stream; ids; the 17 mappings; golden tests
  pkg/validtime/   the guard (one implementation)
  pkg/varve/       /v1/ingest streaming client (421/429/retry, per-attempt token, ?graph=), receipt, Merge
  pkg/config/      YAML schema + the one validator
  pkg/metrics/     Prometheus counters; satisfies pipeline.Observer
  docs/            this spec, api.md (the library surface), plans/, HANDOVER batons
```

Hard boundaries: GUAC *behavioral* entry points are called only from
`pkg/guacseam` (GUAC's plain data types — `IngestPredicates`, input
specs, `processor.Document` — may appear anywhere). `pkg/assemble`
knows nothing of HTTP; `pkg/varve` knows nothing of GUAC. There is one
config validator, one valid-time guard, and one stream dedup rule
(`varve.Merge`).

Self-observability: the daemon exposes Prometheus metrics (documents by
outcome, records emitted, valid-time fallbacks, expansion budget, sink
retries) and structured logs; the one-shot mode prints the receipt.

## 4. UX model (settled)

Two entry points, one pipeline implementation:

- `sluice run --config pipeline.yaml` — the product. Long-running;
  receivers poll where the underlying GUAC collector supports it; graceful
  shutdown drains in-flight documents.
- `sluice ingest <kind> <target> [--scan-vulns …] [--varve-addr …]` —
  sugar that assembles the same pipeline from flags, runs one pass, prints
  the receipt, exits non-zero if any document failed.

The daemon is what CI/Kubernetes deploys; the one-shot is what demos,
galleries, and ad-hoc backfills use. Both honor the same config model — a
flag is shorthand for a config field, never a different behavior.

## 5. Data formats (shape sketch)

Record stream (authority: Varve's `docs/book/src/reference/bulk-ingest.md`;
the emitter is `internal/varve`):

```jsonl
{"type":"node","labels":["PkgVersion"],"props":{"_id":"pkg:v:golang/github.com/x/mod/v1.2.0++","purl":"pkg:golang/github.com/x/mod@v1.2.0","type":"golang","namespace":"github.com/x","name":"mod","version":"v1.2.0"},"valid_from":"2026-03-01T12:00:00Z"}
{"type":"edge","label":"DependsOn","src":"isdep:9f…","dst":"pkg:v:…","props":{"_id":"isdep:9f…|DependsOn|pkg:v:…"},"valid_from":"2026-03-01T12:00:00Z"}
```

Constraints the emitter enforces by construction: flat props, absent-means-
omitted (never `null`), no nested values, strings/bools/ints/floats only.

Pipeline config (authority: `internal/config`):

```yaml
receivers:
  files: {path: ./sboms, poll: 30s}
  oci:   {refs: ["ghcr.io/org/img:tag"]}
processors:
  enrich:     {vulns: true, licenses: false, eol: false, deps_dev: false}
  expand:     {deps_dev: true, max_docs: 500}
  valid_time: {floor: "2000-01-01T00:00:00Z", future_skew: 5m}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN}
```

There is no `graph`/namespace field: Varve's wire contract has no such
parameter, so a config key naming one would be a lie the validator could not
enforce (corrected 2026-08-06 during S0 planning; the earlier sketch showed
`graph: guac`).

## 6. Non-negotiable invariants

1. sluice imports no varve code; Varve is reached only through its
   public wire contracts.
2. Every emitted node and edge carries a deterministic, content-derived
   `_id`. Replaying any input stream is idempotent: counts stable, no
   duplicates.
3. The emitter never writes `null` or nested property values; absence is
   omission.
4. Backend-blind GUAC code is imported, never copied. The GUAC dependency
   is a pinned upstream release; no `replace` directives.
5. `valid_from` is document-derived only within the guard bounds; every
   fallback is counted and reported. No silent backdating, ever.
6. One graph model. No alternative shapes behind flags.
7. Edge labels are semantic; no generic edge label discriminated by a
   property.
8. The daemon and the one-shot CLI build the same pipeline from the same
   config model.
9. Every bounded behavior (expansion budget, chunking, guard fallback,
   skipped documents) reports what it dropped or clamped.
10. Slice N never breaks slice N−1's demo.

## 7. Documented divergences

| Divergence | Their position | Ours, and why |
|---|---|---|
| Package/source shape | GUAC: 4-level trie, each level a node | 2-level flat (PkgVersion + PkgName). The trie serves GraphQL hierarchy hydration, which we dropped; property filters replace two hop levels |
| Query surface | GUAC: GraphQL API (guacgql), visualizer, guacone queries | None in this project. Reads are native Varve GQL; the `feat/varve-backend` branch remains a working GraphQL shim if compatibility is ever demanded |
| Assertion time | GUAC: `timeScanned`/`knownSince` are ordinary properties | First-class bitemporal valid time (guarded), per record — the product's headline capability |
| Transitive expansion | GUAC: guaccsub gRPC service coordinating processes | In-process, budget-bounded purl feedback into the imported deps.dev receiver |
| Collector genericity | OTel Collector: exporter plugin registry, many wire formats | Single canonical record stream, single sink kind. Building an exporter framework before a second real consumer exists is the inner-platform trap |
| Ingest transport | `feat/varve-backend` branch: rendered GQL programs over `/v1/tx` (evidence edges ~409/s) | Bulk NDJSON over `/v1/ingest` (~166k records/s), which shipped after the branch concluded |
| Edge encoding | branch: generic `:E {kind: …}` edges | Semantic edge labels — Varve's planner prunes on labels, and `varve`'s edge-predicate work showed property-discriminated edges defeat pruning |
| Package layout | Go convention for an application: `internal/` | `pkg/` since `v0.1.0` (2026-09-02). Silt embeds sluice as a library and Go forbids importing another module's `internal/`. Moved with history, no shims; `v0.x` signals the API may still move |
| Extension point | OTel Collector: processor plugins over a batch | One `Decorator` hook per document, after assemble and before the sink. A batch-level hook could not tell which bytes made which records; a pre-assemble hook would see no Sluice ids to link to |

## 8. Deferred (consciously)

- **guaccsub sidecar** — coordinates multiple GUAC processes; we run one.
  Revisit if a fleet of sluice instances ever shares expansion state.
- **NATS / blob-store event mode** — the receiver/emitter seams make it
  additive; v1 is a single-process pipeline.
- **Re-certification loop** — periodic re-scan driven by a Varve GQL query
  ("evidence older than N") feeding the imported certifier REST clients.
  Ingest-time enrichment covers v1; needs its own slice when demanded.
- **GraphQL read shim** — only if a GUAC-ecosystem tool must be pointed at
  Varve; the branch already implements the demo/neo4j query subset.
- **Additional sinks / CSV / Arrow request format** — no second real
  consumer exists; the NDJSON stream is the extension point.
- **Multi-writer topologies** — `/v1/ingest` is writer-only; one sluice
  feeding one writer is the supported topology until Varve grows one.
- **GitHub-release receiver** — GUAC v1.1.0 exposes its only `GithubClient`
  constructor (`NewGithubClient`) from
  `github.com/guacsec/guac/internal/client/githubclient`, an `internal/`
  package unreachable from this module, and `github.NewGithubCollector`
  hard-requires a non-nil client of that internal type. Wiring it needs
  either a fork/`replace` (violates §6 inv. 4) or a reimplemented GitHub
  release-API client (net-new, not backend-blind — violates §2.2). Deferred
  from S5 pending an upstream release that exports a client constructor.
  (2026-08-07, S5 planning; see §10.6.)

## 9. Roadmap — vertical slices

Slice namespace: `S0…` (product). Every slice is a full vertical cut and is
demo-able; slice N never breaks slice N−1's demo. **S1 is the keystone** —
it carries the flattened-model decision and falsifies it against a real
corpus as early as dependencies allow.

### S0 — Walking skeleton
*The thinnest end-to-end thread: one SBOM becomes queryable graph nodes.*
New repo with module, pinned GUAC dep, CI (build + lint + test), a
docker-compose Varve, and `sluice ingest files <dir>` that runs one SPDX
document through the imported processor/parser and emits only the package
identity nodes to `/v1/ingest`. No evidence, no daemon, no config file.
**Done when:** a person clones the repo, runs `just demo`, and a native
Varve GQL query returns the PkgVersion nodes of the sample SBOM — twice in a
row with identical counts (idempotency visible from day one).

### S1 — The whole graph, flattened (keystone)
*All 17 predicate mappings into the 2-level model, proven against the corpus
the old backend already ingested.*
Port the id derivations with their table-driven tests; implement every
predicate mapping with a golden-file NDJSON test; build the parity harness
that ingests GUAC's 65-document `exampledata` corpus and checks counts
against the branch's known numbers (IsDependency 1269, HasSBOM 30,
CertifyVuln 27, PkgVersion 669, PkgName 643 — trie levels absent by design).
**Done when:** a person ingests the corpus in one command and runs a
blast-radius query in native GQL — CVE → affected PkgVersions → dependents —
getting the same answers the gallery demo produced, in fewer hops.

### S2 — Bitemporal honesty
*Document timestamps become guarded valid time.*
Timestamp extraction per predicate kind, the guard with configurable
floor/skew, fallback counting in receipt and metrics.
**Done when:** a person ingests a backdated SBOM archive, asks
`FOR VALID_TIME AS OF` last year, and sees last year's beliefs; then ingests
a doctored epoch-0 document and sees it land at ingest time with the
fallback counted in the printed receipt.

### S3 — The collector shape
*Config-driven daemon: the OTel-collector identity becomes real.*
`pipeline.yaml` (receivers/processors/sink), `sluice run`, the files
receiver polling a directory, graceful drain on shutdown, Prometheus
metrics, structured logs, 421/429/retry handling in the sink.
**Done when:** a person starts the daemon, drops an SBOM into the watched
directory, sees it appear in the graph within one poll interval, and reads
the ingest counters off the metrics endpoint — while the S0–S2 one-shot
commands still work unchanged.

### S4 — Enrichment and expansion
*One SBOM in, a certified neighborhood out.*
Wire the imported OSV/ClearlyDefined/EOL/deps.dev scanners as processors
(config-gated), plus the in-process, budget-bounded deps.dev expansion.
**Done when:** a person ingests a single SBOM with `enrich.vulns` and
`expand.deps_dev` on, and the graph shows CertifyVuln evidence from OSV and
scorecard/source facts for transitive dependencies never present in any
uploaded document — with the expansion budget usage in the receipt.

### S5 — Receiver breadth
*Every place supply-chain documents live, one config stanza away.*
OCI registry, S3, GCS, and GitHub-release receivers wired into config and
the one-shot CLI, each with a smoke path; polling where the underlying GUAC
collector supports it.
**Done when:** a person points a config stanza at a real OCI image ref and
the image's attached SBOM/attestations appear in the graph, demonstrated for
at least OCI + one bucket store.

### S6 — Full dress: gallery, benchmark, crash-replay
*Everything under real conditions, replacing the guacgql gallery.*
A demo script (clean volumes, Garage/S3-backed Varve) running collect →
enrich → query → time-travel; an ingest benchmark against the branch's
recorded numbers; a kill-9-mid-stream + full-replay test proving invariant 2
under failure.
**Done when:** `demo.sh` runs end-to-end from clean volumes on a laptop:
ingests the corpus via sluice, shows the blast-radius and valid-time
queries, prints benchmark numbers alongside the old backend's, and the
crash-replay leaves counts identical to a clean single run.

### Sequencing notes

S0 → S1 → S2 are strictly ordered (skeleton before mappings, mappings
before temporal semantics). S3 depends on S1 only, so it may start before
S2 lands if parallelized, but S2 ships first to keep the model complete
before the mechanism spreads. S4 requires S3 (processors live in the
pipeline config). S5 requires S3 and can run in parallel with S4. S6 is
last and gates on everything. The quality tooling each slice depends on
arrives no later than the slice itself: CI in S0; golden files and the
corpus parity harness inside S1, before the bulk of the mappings are
written against them.

## 10. Verified integration facts

Established by measurement or source reading, not assumption. Every slice may
rely on these without re-deriving them; a slice that finds one **false** must
correct it here, dated, rather than working around it locally.

### 10.1 GUAC library surface (verified 2026-08-06 against `v1.1.0`)

- The pin is **v1.1.0**. `refs/guac`'s `feat/varve-backend` base is
  `v1.1.0-171` (main, July 2026) — code read from that branch may use APIs the
  pinned release lacks. Verify against the tag, not the branch.
- **Parser output uses the genqlient client types.** Predicates carry
  `pkg/assembler/clients/generated.PkgInputSpec`, not
  `pkg/assembler/graphql/model.PkgInputSpec`. The `feat/varve-backend` branch
  used the server model because it *implemented* the backend interface;
  sluice consumes parser output, so `graphql/model` must appear nowhere in
  this repo — and neither must `helpers.PkgInputSpecToPurl`, which is bound to
  that server type. Use `helpers.PkgToPurl`, whose parameter order is
  `(type, namespace, name, version, subpath, qualifierList)` — **subpath before
  qualifiers**, qualifiers a flat alternating key/value `[]string`.
- `IngestPredicates.GetPackages(ctx)` returns the deduplicated package set
  drawn from *every* predicate list, keyed by GUAC's own purl-derived key. It
  is the node set a bulk writer wants; a document asserting only
  `CertifyLegal`/`HasSBOM` still yields its packages.
- `collector.RegisterDocumentCollector` writes a **package-global** registry.
  Any code path that registers must `DeregisterDocumentCollector` when done, or
  the second pass in a process fails with an overwrite error. This bites S5
  hardest (many receivers, and tests that register several).
- The four `ParseDocumentTree` scan flags are the only enrichment switch; with
  all four `false`, parsing makes no outbound call (relied on by CI).

### 10.2 Varve wire behaviour (probed 2026-08-06 against `varved` from varve `main`)

- `POST /v1/ingest` with `authorization: Bearer …` and
  `content-type: application/x-ndjson` accepts the flattened record shape of
  §2.3/§5 as written. `system_time` comes back RFC3339 with sub-second
  precision.
- Replaying an identical body returns identical `nodes`/`edges`/`transactions`
  and a **new** `basis`, and node counts are unchanged — supersede-upsert
  confirmed end to end (§6 inv. 2).
- Semantic edge labels traverse directly: `-[:PkgHasVersion]->` works, no
  property predicate needed (§6 inv. 7).
- **Two distinct error body shapes** must both be handled by the sink client —
  the bulk-ingest fast-fail body and `varved`'s generic error body:

  ```json
  {"error":"line 1: missing field `dst`","committed":{"nodes":0,"edges":0,"transactions":0,"basis":0}}
  {"code":"misdirected_request","message":"request must be sent to writer","writer":"http://writer:8080"}
  ```

  The first accompanies a 422 on a bad record; the second covers
  401/406/408/421/429/503. S3 owns following the 421 writer redirect and
  honouring 429 `Retry-After`.

### 10.3 Running Varve locally (as of 2026-08-06)

- `ghcr.io/ravan/varve` is **not published yet** — varve carries no release
  tags, so the image only exists once its release workflow runs. Until then the
  image is built locally from a sibling varve checkout:
  `docker build -f Dockerfile -t sluice/varve:local ${VARVE_SRC:-../varve}`
  (S0 provides `just varve-image`). Compose references
  `image: ${VARVE_IMAGE:-sluice/varve:local}` and carries **no `build:`
  stanza**, so the switch to the published image is one environment variable.
  This is a build-time convenience only; §6 inv. 1 is untouched — nothing
  imports varve code, and the running coupling is still only the HTTP contract.
- A single-node demo Varve needs only `roles = ["writer","query","compactor"]`,
  `[log] backend = "memory"`, `[storage] backend = "memory"`,
  `[server.http] listen` + `advertised_address`, and one `[auth.static]` token.
  **Memory backends are deliberate for S0–S5 demos**: the distroless image runs
  as `nonroot`, so a root-owned named volume is unwritable, and durability is
  not what those slices demonstrate. S6 replaces this with the Garage/S3-backed
  topology its own "done when" requires.
- Test fixtures are copied from GUAC's `internal/testing/testdata/exampledata`
  (that tree is `internal/`, so it cannot be imported) with provenance and the
  Apache-2.0 attribution recorded next to them.

### 10.4 Verified 2026-08-06 during S1 planning

- **`testdata/sboms/small-spdx.json` is adapted, not verbatim.** Its three
  `"packageName"` keys were changed to the SPDX-standard `"name"` key because
  GUAC v1.1.0's SPDX parser reads `json:"name"` (`spdx/tools-golang`). The
  demo's package set `{text, quote, sampler}` depends on this adaptation; the
  fixture stays adapted (S0 Deviation 6a, ratified).
- **`SrcName` `_id` includes tag and commit** — `src:n:<type>/<ns>/<name>@<tag>@<commit>`
  (§2.3), diverging from the `feat/varve-backend` branch, which excluded them.
  Two refs to a repo at different commits are therefore distinct nodes.
- **Edge labels are the branch's edge-kind strings promoted to first-class
  labels** (`:X`, never `:E {kind:'X'}`), per §6 inv. 7: Varve's planner prunes
  on labels, so semantic edge kinds must be labels.
- **GUAC v1.1.0's file collector cannot ingest gzip.** Its encoding guesser
  handles only bzip2 (`.bz2`) and zstd (`.zst`); a `.gz` document parses as
  `type: UNKNOWN` and fails. The gallery blast-radius corpus (`.spdx.json.gz`)
  must be decompressed before ingest.
- **Parity numbers measured under the v1.1.0 pin differ from the branch's**
  (taken on v1.1.0-171). Over GUAC v1.1.0's exampledata `*.json` (57 files, 15
  unparseable-and-skipped) the flattened model yields PkgVersion ≈ 606, PkgName
  ≈ 580, IsDependency ≈ 1094 (deduped), HasSBOM 27, CertifyVuln 17 — same shape
  as the branch's 669/643/1269/30/27, with the trie levels absent by design.
  The exact numbers are pinned by the committed parity golden, not this prose.
- exampledata contains **zero** `CertifyBad` / `CertifyGood` / `HashEqual` /
  `PkgEqual` / `PointOfContact` instances — those five mappings are proven by
  unit goldens, not by the corpus.

### 10.5 Verified 2026-08-07 during S2 planning

- **Varve accepts a top-level per-record `valid_from`.** It is either an RFC3339
  string — exactly GQL's `TIMESTAMP` parse, sub-second accepted — or an integer
  count of microseconds. Absent ⇒ the record is valid from *now* to the end of
  time. `valid_from` must be a top-level sibling of `props`, never a property;
  unknown record fields are rejected (422). `valid_from >= valid_to` is a 422,
  and we never emit `valid_to`. (Ref
  `varve/docs/book/src/reference/bulk-ingest.md`.)
- **Valid-time travel grammar.** `FOR VALID_TIME AS OF <datetime>` (also
  `FROM… TO`, `BETWEEN… AND`, `ALL`) is a prefix *before* `MATCH`; `<datetime>`
  is `TIMESTAMP '<RFC3339>'` or `DATE '<YYYY-MM-DD>'`. Omitting the clause =
  `AS OF now` on both axes — this is why S0/S1's clause-free queries still return
  current state. `valid_from(var)` / `valid_to(var)` project the bound-in-time
  fields in `RETURN`. (Ref `varve/docs/book/src/gql/temporal.md`.)
- **GUAC v1.1.0's SPDX parser derives `HasSBOM.KnownSince` from
  `creationInfo.created`** via `time.Parse(time.RFC3339, …)`; a `created` that is
  not valid RFC3339 fails the whole document (nil predicates, skipped).
  `IsDependency`/`IsOccurrence` from an SPDX carry no native timestamp. (Ref
  `pkg/ingestor/parser/spdx/parse_spdx.go`.)
- **`valid_from` = the record's guarded native timestamp.** The evidence node
  retains its raw timestamp property, so property and `valid_from` diverge
  exactly when the guard fired — the fallback is visible in the graph, not only
  the receipt.

### 10.6 Verified 2026-08-07 during S5 planning

- **Every receiver implements `collector.Collector`** (`RetrieveArtifacts` +
  `Type`) and is driven through the package-global registry +
  `collector.Collect`; register/deregister of the whole configured set must be
  centralised in one place (§10.1). Importable constructors under the v1.1.0
  pin: `file.NewFileCollector(ctx, path, poll, interval)`;
  `oci.NewOCICollector(ctx, ds, poll, interval, rcOpts...)` and
  `oci.NewOCIRegistryCollector(ctx, ds, poll, interval, rcOpts...)`, fed by
  `inmemsource.NewInmemDataSources(&datasource.DataSources{OciDataSources |
  OciRegistryDataSources: …})`, with
  `oci.BuildRegClientOptions(oci.ExtractRegistryHosts(refs),
  oci.OCIClientOptions{InsecureSkipTLSVerify: …})` for plain-HTTP / local
  registries; `s3.NewS3Collector(s3.S3CollectorConfig{…})` (bucket-list mode
  when `Poll=false`; SQS / message-provider polling needs `Queues`);
  `gcs.NewGCSCollector(gcs.WithBucket(b), gcs.WithClient(*storage.Client),
  gcs.WithPolling(interval))` — the `*storage.Client`
  (`cloud.google.com/go/storage`) resolves Application Default Credentials at
  construction, so GCS collection is proven only with real credentials, never
  a local hermetic demo.
- **GitHub-release is not wireable on the v1.1.0 pin** — see §8: its only
  client constructor is in GUAC's `internal/`, so S5 ships OCI + S3 + GCS and
  defers GitHub.
- **Local hermetic S5 demo.** OCI is demoed against a local registry holding an
  image with an attached SPDX artifact; the bucket store is demoed with MinIO
  (S3-compatible) in list mode. Both satisfy S5's "OCI + one bucket store"
  done-when; GCS (needs GCP ADC) and GitHub (deferred) are not in the local
  demo. New docker-compose services for the demo sit behind a `receivers`
  compose profile so the S0–S4 demos (`docker-compose up -d`) start only
  `varve` and stay unbroken (§6 inv. 10).
