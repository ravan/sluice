# Changelog

## v0.4.0 — 2026-09-03

### Added

- `pipeline.ErrNoEnricher`. A policy naming a source this build has no enricher
  for used to be skipped in silence: nothing ran, and nothing said so. It is now
  recorded in `Receipt.EnrichFailed`, counted through
  `Observer.EnrichFailed`, and logged at warn. A source the policy itself
  refuses (`eu_only`, or simply not listed) stays silent — that is the cap doing
  its job, not a fault.

## v0.3.0 — 2026-09-03

### Changed

- `enrich.Claim.Fact` is now `enrich.Fact`, not `string`. The fact names are a
  closed set (`FactAffected`, `FactCVSS`, `FactReference`, …, listed in
  `Facts`), and `Fact` is part of a claim's identity: a misspelling used to
  mint a second node instead of replaying onto the first. `ParseFact` validates
  a name read off the wire; `ErrUnknownFact` is wrapped.
- `assemble.EvidenceID` takes a `varve.NodeLabel`, not a `string`. Its `kind`
  argument was always the evidence node's own label, and all eighteen callers
  were casting one to feed it.
- `pipeline.Observer.EnrichFailed` takes an `enrich.Source`, not a `string`.
  `pkg/metrics` now imports `pkg/enrich` and converts at the Prometheus label.

### Added

- `assemble.Prop*`: the property-key vocabulary, alongside the existing
  `Label*` and `Edge*` constants. `pkg/enrich` reads evidence nodes back by
  these names (`subjectId`, `collector`, `documentRef`, the per-scanner value
  keys), so a key is a contract between the two packages, not private
  spelling. Both the write and the read sites now name the constant.
- `enrich.Prop*`: the same for a `Claim` node's own properties.
- `enrich.FactValue`: a fact paired with the value a source states for it,
  replacing an unexported pair in `Derive` and a `[][2]string` in the EUVD
  enricher.
- Doc comments on every exported identifier in `pkg/metrics`.

### Fixed

- `pkg/assemble` file names. `map_a.go` … `map_e.go` named nothing a reader
  could predict; the mappings are now grouped by subject in
  `map_dependency.go`, `map_vulnerability.go`, `map_provenance.go`,
  `map_legal.go`, `map_annotation.go` and `map_equality.go`, with the shared
  scalar renderings in `format.go`. No behaviour change; the tests move with
  them.

## v0.2.0 — 2026-09-03

### Added

- `pkg/enrich`: the org's enrichment policy as the pipeline enforces it
  (`Policy`, `ParsePolicy`, `Allows`, `ScanFlags`), the six `Source` names, the
  `Jurisdictions` table behind `eu_only`, the `Claim` record (`ID`, `Records`),
  the `Enricher` seam, `VulnNames` and `Derive` (scanner evidence to claims).
- `pkg/enrich/euvd`: an enricher for ENISA's EUVD API, keyed by vulnerability
  name. `DefaultURL`, `New`, `ErrStatus`.
- `Receipt.Claims` and `Receipt.EnrichFailed []EnrichError`; `Observer.ClaimsEmitted`
  and `Observer.EnrichFailed`; metrics `sluice_claims_total` and
  `sluice_enrich_failures_total{source}`. A failed enrichment is counted and
  listed; the document is still ingested.
- `Deps.Enrichers`: the enrichers this deployment built. The config's policy
  picks and orders them.
- `ingest` flags `--enrich SOURCE` (repeatable, priority order), `--eu-only`
  and `--euvd-url`.

### Changed

- `processors.enrich` is now `{sources: [...], eu_only: bool, euvd: {url: ...}}`.
  `config.EnrichProcessor` is `{Policy, EUVDURL}`.

### Removed

- The four scan booleans `processors.enrich.{vulns,licenses,eol,deps_dev}` and
  the flags `--enrich-vulns`, `--enrich-licenses`, `--enrich-eol`,
  `--enrich-deps-dev`. The policy's `sources` list replaces them; there is no
  alias.

## v0.1.1 — 2026-09-03

### Fixed

- `assemble`: `HasSlsa` and `CertifyScorecard` evidence ids were not stable
  across runs. GUAC delivers SLSA predicates and Scorecard checks in map
  order, and the id hashed them in that order. `encodeKV` now sorts the
  pairs, so a replay of the same attestation makes the same node. Ids of
  existing `HasSlsa` and `CertifyScorecard` nodes change once.

## v0.1.0 — 2026-09-02

First tagged release. Sluice is now importable as a library. `v0.x` means the
public API may still change between minor versions.

### Added

- `pkg/` packages: `assemble`, `config`, `guacseam`, `metrics`, `pipeline`,
  `validtime`, `varve`. Moved from `internal/` with history. See `docs/api.md`.
- `pipeline.Decorator`: a hook that runs after assemble and before the sink,
  once per document, in both one-shot and poll mode. Its records merge into
  the document's stream and travel in the same `POST /v1/ingest`. An error
  skips only that document; `Receipt.DecorateFailed` lists it.
- `Receipt.Decorated`, `Receipt.DecorateFailed`; `Observer.DocumentDecorated`,
  `Observer.DocumentDecorateFailed`; metrics
  `sluice_documents_decorated_total`, `sluice_documents_decorate_failed_total`.
- `varve.Merge`: the one stream dedup rule (by id, first record wins,
  earliest non-zero `valid_from` wins).
- `varve.ClientConfig.TokenProvider` and `varve.StaticToken`: the bearer
  token is fetched once per HTTP attempt.
- `varve.ClientConfig.Graph`: sends `?graph=<name>` to ingest into a named
  Varve graph. `sluice ingest --varve-graph` and `sink.varve.graph` set it.
- `assemble.AssembleResult.ValidFrom` and `.Fallback`: the document-level
  valid time.
- `guacseam.Parsed` and `guacseam.Origin`.

### Changed

- `guacseam.PredicateFunc` is replaced by `guacseam.DocumentFunc`, which
  receives a `Parsed` value carrying the raw document.
- `pipeline.Run` assembles every document alone and merges in one-shot mode.
  The wire output is the same set of records; the parity test proves it.
- `sluice ingest` reads the token from the env var the config names
  (`VARVE_TOKEN` for the CLI) instead of a hard-coded name.

### Requires

- Varve `v1.1.0` or later for `?graph=`. Older writers ignore the parameter
  and write to their default graph.
