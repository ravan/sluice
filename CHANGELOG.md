# Changelog

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
