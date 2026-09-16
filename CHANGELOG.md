# Changelog

## v0.11.0 — 2026-09-16

### Fixed

- `pkg/enrich/euvd` claimed `cvss = "0"` for every record EUVD answers
  `baseScore: null` for, which is most of them. 0.0 is itself a CVSS score,
  meaning no impact, so the claim stated the opposite of the truth. The score
  fields are pointers now, and a record with no score states no score claim.
  A fact EUVD answered blank is dropped for the same reason: a claim node
  whose value prop is empty states nothing.

### Added

- A `scanner` enrichment source, `pkg/enrich/scanner`. It reads what a scan
  document states about the vulnerabilities it found and returns it as claims:
  the description, the score, the scoring version, the vector, the published
  and updated dates, the fixed version and the references. It calls no host —
  the scanner already asked the databases, and the document carries what they
  said. Each claim's `Ref` names the database the scanner credited, so two
  databases that disagree about a score are two claims and a reader can see
  which said which.

  This is the seam for what a document states and the graph vocabulary has no
  node for. GUAC has nowhere to put a vulnerability's description — its
  `HasMetadata` takes a package, a source or an artifact, never a
  vulnerability — and its `VulnMetadata` keeps a score without the vector or
  the database behind it. Both facts were in the document and both were lost.

## v0.10.0 — 2026-09-15

### Added

- A parser for the cosign vulnerability attestation
  (`https://cosign.sigstore.dev/attestation/vuln/v1`), whose
  `scanner.result` is a whole Trivy report. GUAC's guesser filed it as a
  generic in-toto statement with no parser, so every such document was
  skipped; `pkg/guacseam/cosignvuln` types it first and parses it. Each
  finding becomes `CertifyVuln` on the package Trivy names and on every
  subject that names a purl, its CVSS scores become `VulnMetadata`, its
  vendor ids become `VulnEqual`, and a subject with a purl and a digest
  becomes `IsOccurrence`. A subject with neither, as OBS writes today, is
  ignored and the findings still land on the affected packages.

## v0.9.0 — 2026-09-14

### Added

- `Deps.PrepareWorkers` spreads the per-document stage — assemble, enrich and
  the decorator chain — over several goroutines. `pipeline.AutoWorkers` asks
  for one worker per core less one; zero and one keep the serial pipeline, so
  nothing changes for a caller that does not ask. The receipt and the sink
  still see documents in arrival order at any width, so a run's output does
  not depend on it.

  Above one worker the pipeline calls every `Decorator` and every `Enricher`
  from more than one goroutine and in no fixed order. That is why it is
  opt-in: a decorator that counts, caches or allocates per document has to
  guard its own state first.

### Breaking changes

- Package and edge IDs escape field delimiters. Evidence hashes and scalar
  key-value and ID lists use byte-length prefixes. Existing graphs require
  [replay into a fresh graph](docs/identity-migration.md).
- `varve.Value` is a concrete scalar with private fields. `Str`, `Int`, `Float`,
  and `Bool` are constructors. Replace type assertions with `AsString`, `AsInt`,
  `AsFloat`, and `AsBool`. Uninitialized values and non-finite floats fail marshaling.
- Writer redirects require a trusted origin. Configure additional origins with
  `ClientConfig.TrustedWriters` or `sink.varve.trusted_writers`. HTTPS cannot
  downgrade to HTTP.
- Metrics default to `127.0.0.1:9464`. Set `--metrics-addr :9464` for all interfaces.

### Fixed

- Concurrent collection runs own their receivers and bound outstanding document
  positions while preserving arrival order.
- Exhausted sink retries terminate polling with committed progress. Shutdown
  drains accepted work for up to 30 seconds, configurable through `Deps.DrainTimeout`.
- Scanner errors and malformed expansion documents appear in receipts.
  Clean OSV scans no longer produce affected claims.
- HTTP response allocation is bounded, metrics connections have timeouts, and
  vulnerable dependencies are upgraded. See the [dependency audit](docs/security-audit.md).

## v0.8.0 — 2026-09-06

### Added

- Two facts about where a package comes from: `supplier`, the organisation one
  source names as supplying it, and `origin_country`, that supplier's ISO 3166-1
  alpha-2 code.
- Three sources that state them. `sbom` reads the per-component supplier fields a
  CycloneDX or SPDX document already carries. `purl` reads a namespace table:
  `golang.org/x/` is Google, `rpm/opensuse/` is the openSUSE Project. Neither
  calls a host, so an install names their jurisdiction through `Policy.Hosted`.
  `ecosystems` asks packages.ecosyste.ms who owns the repository the package is
  published from.
- `enrich.Input.Document` carries the document's own bytes, which is what the
  `sbom` source reads. It is nil when the pipeline holds none.

## v0.7.1 — 2026-09-03

### Fixed

- A FederatedCode replay reads what the fetch downloaded. `Open` fetches, but a
  fetch moves the remote ref and never the local branch or `HEAD`, and
  `(*Repo).Replay` walked from `HEAD`. Every replay after the first therefore
  read the clone as it was made and ignored the new commits it had just pulled.
  `Open` now resolves the remote's copy of the checked-out branch once and every
  history walk starts there; a repository with no remote still walks `HEAD`.
- `federatedcode.VulnerabilityPath` returns `ErrVCID` for a vulnerability id too
  short to name the directory it is filed under. It used to build
  `aboutcode-vulnerabilities//<id>.yml`, a path that reads correctly and matches
  no file.

### Added

- `(enrich.SourceRunner).String()` — `run_by_enricher`, `run_by_scanner`,
  `run_by_replay` — so a log line or a test failure names the runner instead of
  its ordinal.
- Doc comments on `federatedcode.Advisory`, `Severity`, `Reference`,
  `ParsePackageEntries` and `ParseAdvisory`.

### Internal

- `TestRunnersCoverSources` asserts the `runners` table names every entry of
  `enrich.Sources` and nothing else. The table's comment claimed a new source
  could not land there by accident; it could, and would then have fallen through
  `Runner`'s default to `RunByEnricher` and collected an `ErrNoEnricher` per
  document — the bug v0.7.0 set out to fix.
- `gocognit.min-complexity` 30 → 25. The repo is clean at 25 with the named
  backlog exclusions unchanged, so the looser threshold was hiding nothing.
- `enrich.SourceFederatedCode` is deliberately absent from
  `enrich.Jurisdictions`, for the same reason `vulnerablecode` is: the replay
  reads a local clone and calls no host, so where the data came from is the
  operator's mirror choice. Recorded in the comment.

## v0.7.0 — 2026-09-03

### Added

- `enrich.Source.Runner()` and the `enrich.SourceRunner` set — `RunByEnricher`,
  `RunByScanner`, `RunByReplay` — so a source says what produces its claims. A
  source no table names is `RunByEnricher`, so a genuinely missing enricher is
  still reported.
- `enrich.SourceFederatedCode`, AboutCode's FederatedCode data. Nothing calls it
  over the network: a host job replays a git clone of it.
- `enrich.Severity{System, Score, Elements}` with `CVSS`, `EPSS` and
  `(Severity).Version()`. The CVSS selection rule — the first severity whose
  system starts `cvssv` *and* whose score parses as a number — is subtle and
  identical for both vulnerability sources, so it lives once.
- `pkg/enrich/federatedcode`: the `aboutcode.hashid` 0.2.0 path arithmetic
  (`CorePurl`, `PurlHash`, `PathFor`, `VulnerabilityPath`), the two YAML readers
  (`ParsePackageEntries`, `ParseAdvisory`, `Advisory.Facts`) and the git replay
  (`Open`, `(*Repo).Replay`). A replay's claims are dated by the commits that
  wrote them, so `ValidFrom` is what the source knew and when, not when we read
  it.

### Fixed

- A GUAC scanner source is no longer reported as missing an enricher. `osv`,
  `clearlydefined`, `eol` and `deps_dev` run inside the parser gated by
  `Policy.ScanFlags()`, and never have an `enrich.Enricher`; `pipeline.Run`
  looked one up for every allowed source and recorded `ErrNoEnricher` when it
  found none. An org whose `enrich.sources` named one collected a false
  enrichment failure per document. `enrichDocument` now skips a source whose
  `Runner()` is not `RunByEnricher`.

### Changed

- `pkg/enrich/vulnerablecode` moved onto `enrich.Severity`: its unexported
  `cvssOf` and its inline EPSS loop are gone, and `cvssPrefix` and `epssSystem`
  moved to `severity.go`. No claim value changes.
- `github.com/go-git/go-git/v5` and `github.com/package-url/packageurl-go` are
  direct dependencies now; `pkg/enrich/federatedcode` imports both.


## v0.6.0 — 2026-09-03

### Added

- `config.VulnerableCodeProcessor.Hosted`, the one place that names
  `enrich.SourceVulnerableCode` when building `Policy.Hosted`. `config.Load` and
  the ingest command each built the same one-entry map by hand.

### Changed

One breaking change. This is a pre-release: there is no compatibility path.

- **Breaking.** `enrich.Claim` has no jurisdiction field, and `Records()` moved
  off it. `enrich.Policy.Stamp` returns the new `enrich.StampedClaim`, which
  holds the jurisdiction unexported and exposes it through `Jurisdiction()`.
  `Stamp` is its only constructor, so an enricher cannot state where its own
  host sits and the pipeline cannot forget to ask the policy — in v0.5.0 both
  were doc comments, and both are compile errors now. The `enrich.Enricher`
  interface is unchanged and still returns `[]Claim`: an enricher that never
  touched the field needs no edit.

### Internal

Neither item changes an exported name or a behaviour.

- `config.Load` split into one function per stanza — `receiversFrom`,
  `validTimeFrom`, `enrichFrom`, `expandFrom`, `sinkFrom`, and the shared
  `parsePoll` the four receivers each had a copy of. Every error string is
  unchanged and all new functions are unexported; a new stanza now adds a
  function instead of a branch. Cognitive complexity went 89 → under the limit,
  and the file's six nested-block findings went to zero.
- The lint gate widened past the standard set: `bodyclose`, `errorlint`,
  `gocognit`, `gocritic`, `nestif` and `nolintlint`, with findings uncapped and
  each rule proved to fire. `gosec` and `revive` stay off, each for a reason
  written in `.golangci.yml` rather than left as an unexplained gap.
  `varve.Client.Ingest` (60), `pipeline.Run` (66) and `guacseam.collectWith`
  (40) are named backlog exclusions carrying their number and their seam — a new
  complex function in the same file still fails.

## v0.5.0 — 2026-09-03

### Added

- `pkg/enrich/vulnerablecode`, the second enrichment source. It asks AboutCode's
  VulnerableCode which advisories affect the packages a document names, with one
  `GET /api/v3/affected-by-advisories?purl=<purl>` per `PkgVersion` node. Every
  request carries `User-Agent: VCIO_API_AGENT`; the server answers 403 without
  it. There is no API key. One advisory becomes one `affected` claim about the
  package, plus a fact set on every alias vulnerability the stream already
  carries.
- `enrich.FactAdvisoryID` and `enrich.FactFixedBy`.
- `enrich.VulnNodes` and `enrich.PkgPurls`, the two stream helpers an enricher
  needs to find its subjects.
- `enrich.AllJurisdictions`, `enrich.ParseJurisdiction` and
  `enrich.ErrUnknownJurisdiction`.
- `enrich.Policy.Hosted` and `enrich.Policy.JurisdictionOf`. A source whose host
  is a deployment choice takes its jurisdiction from the install, not from a
  fixed table. A source no table names is `Other`, which `eu_only` refuses: the
  cap fails closed.

### Changed

Three breaking changes. This is a pre-release: there is no compatibility path.

- `enrich.ParsePolicy` takes a third argument, `hosted
  map[Source]Jurisdiction`. A builder method was rejected: a builder call that
  is forgotten is invisible.
- `enrich.Claim.Jurisdiction` is set by the pipeline, never by an enricher.
  `enrich.Policy.Stamp` writes it after `Derive` and after each enricher, so the
  same fact is no longer held in two places where they can disagree.
  `enrich.Derive` and the EUVD enricher no longer set the field.
- `config.EnrichProcessor` gains `VulnerableCode`, read from
  `processors.enrich.vulnerablecode.{url, jurisdiction}`. An absent block means
  the public instance at `us`.

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
