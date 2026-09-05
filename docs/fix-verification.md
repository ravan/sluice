# Fix verification

This records the fixes for the twelve findings in [things-to-fix.md](things-to-fix.md).

| Finding | Result | Regression evidence |
| --- | --- | --- |
| 1. Redirect disclosure | Both HTTP and writer redirects require trusted origins, preserve POST and graph routing, and reject HTTPS downgrades. | `pkg/varve/client_security_test.go`, `pkg/varve/client_graph_test.go` |
| 2. Concurrent collection | Each run drives its own collectors without GUAC's global registry. | `TestConcurrentCollectionsOwnTheirDocuments` |
| 3. Vulnerable dependencies | Named dependencies and other fixable scanner findings are upgraded. | [Dependency audit](security-audit.md), `go.mod`, `go.sum` |
| 4. Slow metrics connections | Header, read, write, and idle timeouts bound connections. The default listener is loopback. | `TestMetricsServerClosesIncompleteHeaders` |
| 5. Package identity collisions | Package components and qualifiers escape delimiters. | `TestPackageIdentityBoundaries`, `TestDistinctQualifiersKeepSeparateEvidence`; [migration](identity-migration.md) |
| 6. Evidence field collisions | Evidence fields, key-value pairs, and ID lists use byte-length prefixes. Edge fields escape separators. | `TestEvidenceFieldBoundaries`, `TestPackageIdentityBoundaries` |
| 7. Scalar values | Private concrete representation, constructors, typed accessors, and validated marshaling replace the interface. | `TestValueScalars`, `TestInvalidValuesCannotReachWire` |
| 8. Polling document loss | Exhausted sink failures stop the run with committed progress. A fresh file receiver replays unchanged files. | `TestRunPollStopsAfterSinkFailure`, `TestExpansionSinkFailureStopsPollWithCommittedProgress` |
| 9. Shutdown drain | Intake cancellation starts a bounded processing grace period, including the final one-shot write. | `TestAcceptedWorkDrainsAfterCancellation`, `TestDrainDeadlineAbortsBlockedProcessing`, `TestOneShotFinalFlushUsesDrainContext`, `TestPollingSinkDrainsAcceptedWrite` |
| 10. Memory bounds | Credits bound outstanding sequence positions; HTTP response bodies have a 1 MiB limit. | `TestOutstandingPositionsBoundedBehindSlowFirstParse`, `TestIngestResponseLimit` |
| 11. Clean OSV claims | The `vuln:novuln` sentinel does not produce an affected claim. | `TestCleanOSVScanHasNoAffectedClaim` |
| 12. Missing failures | Scanner errors enter `EnrichFailed`; malformed expansion documents enter `Skipped`. | `TestScannerFailureSurvivesInReceipt`, `TestExpansionFailuresReachPipelineReceipt`, `pkg/guacseam/expand_test.go` |

The additional `readYAML` observation is addressed by restricting its generic
constraint to `Advisory | []PackageEntry`. The `Sink`, `Decorator`, and `Enricher`
interfaces retain their roles.

## Reproduce the checks

All commands below passed on 2026-09-05 using Go 1.27.1 and golangci-lint
v2.13.2. `gofmt -l .` produced no output. Both vulnerability scans reported
zero called or imported-package vulnerabilities and the documented module-only
OpenPGP advisory.

```sh
go build ./...
go test ./...
go test -race ./...
go vet ./...
golangci-lint run ./...
git diff --check
govulncheck -show verbose ./...
GOOS=linux GOARCH=amd64 govulncheck -show verbose ./...
```

The linter version is pinned in `.github/workflows/ci.yml`. The vulnerability
audit records scanner and Go versions, platform coverage, and the remaining
module-only advisory. Live service demos require their documented infrastructure
and are separate from these local regression checks.
