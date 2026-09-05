# Dependency security audit

Audit date: 2026-09-05. Scanner: `govulncheck` v1.7.0. Toolchain:
Go 1.27.1. Source scans covered `./...` on darwin/arm64 and linux/amd64.
Both scans exited successfully with zero called vulnerabilities, zero
vulnerabilities in imported packages, and one advisory in a required module.

The scan commands were:

```sh
go install golang.org/x/vuln/cmd/govulncheck@v1.7.0
govulncheck -show verbose ./...
GOOS=linux GOARCH=amd64 govulncheck -show verbose ./...
```

## Updated dependencies

| Dependency | Selected version | Advisory addressed |
| --- | --- | --- |
| go-git/v5 | v5.19.2 | [GO-2026-6214](https://pkg.go.dev/vuln/GO-2026-6214): reference path traversal |
| regclient | v0.11.5 | [GHSA-qvqc-4c52-x6qp](https://github.com/regclient/regclient/security/advisories/GHSA-qvqc-4c52-x6qp): registry credential disclosure |
| golang.org/x/crypto | v0.56.0 | [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355), [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354), [GO-2026-6303](https://pkg.go.dev/vuln/GO-2026-6303) |
| moby/buildkit | v0.31.1 | [GO-2026-6255](https://pkg.go.dev/vuln/GO-2026-6255), [GO-2026-6256](https://pkg.go.dev/vuln/GO-2026-6256), [GO-2026-4859](https://pkg.go.dev/vuln/GO-2026-4859), [GO-2026-4858](https://pkg.go.dev/vuln/GO-2026-4858) |
| google.golang.org/grpc | v1.82.1 | [GO-2026-6061](https://pkg.go.dev/vuln/GO-2026-6061), [GO-2026-4762](https://pkg.go.dev/vuln/GO-2026-4762) |
| aws-sdk-go-v2/aws/protocol/eventstream | v1.7.13 | [GO-2026-5764](https://pkg.go.dev/vuln/GO-2026-5764) |
| in-toto-golang | v0.11.0 | [GO-2026-5547](https://pkg.go.dev/vuln/GO-2026-5547) |
| go-jose/v4 | v4.1.4 | [GO-2026-4945](https://pkg.go.dev/vuln/GO-2026-4945) |
| klauspost/compress | v1.18.7 | [GO-2026-5841](https://pkg.go.dev/vuln/GO-2026-5841) |
| go.opentelemetry.io/otel and sdk | v1.44.0 | [GO-2026-5426](https://pkg.go.dev/vuln/GO-2026-5426), [GO-2026-5158](https://pkg.go.dev/vuln/GO-2026-5158) |
| golang.org/x/mod | v0.40.0 | [GO-2026-6180](https://pkg.go.dev/vuln/GO-2026-6180), [GO-2026-6179](https://pkg.go.dev/vuln/GO-2026-6179) |

`go.mod` and `go.sum` also include the transitive upgrades required by these
versions. All packages passed `go test ./...` after the upgrades.

## Remaining advisory

[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) applies to
`golang.org/x/crypto/openpgp` and its subpackages at every version. No fixed
version exists. Neither platform's scan found these packages in the imported
package graph. `go list -deps ./...` also contained no
`golang.org/x/crypto/openpgp` package. The application still requires
`golang.org/x/crypto` for other packages, including SSH. This is a module-level
finding with no affected imported package; it does not justify removing SSH or
suppressing vulnerability scanning.

The findings describe the source and Go 1.27.1 standard library used for these
scans. Builds made with a different Go release need a scan with that toolchain.
