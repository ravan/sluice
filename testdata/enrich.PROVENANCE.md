# Enrich demo fixture provenance

`testdata/enrich/express.spdx.json` is a hand-authored minimal SPDX-2.3
document modelling the package shape syft emits. Its single package,
`pkg:npm/express@4.17.1`, is chosen deliberately:

1. OSV has advisories for it (`GHSA-qw6h-vgh9-j6wx`, `GHSA-rv95-896h-c2vc`), so
   `--enrich-vulns` yields `CertifyVuln`; and
2. deps.dev has its dependency graph **with github-hosted source repos**, so
   `--expand-deps-dev` yields `HasSourceAt` and `CertifyScorecard` for the
   transitive dependencies. An Apache-hosted package would not: its
   `gitbox.apache.org` source URLs cannot be parsed by GUAC v1.1.0's
   `helpers.VcsToSrc`, so `Source` stays nil and no `HasSourceAt`/`CertifyScorecard`
   is emitted (see the S4 re-plan Remediation in `docs/plans/product/S4.md`).

`creationInfo.created` is set to `2024-01-01T00:00:00Z`, which sits inside the
valid-time guard bounds, so ingesting this fixture triggers no valid-time
fallback.

This fixture exercises the S4 enrichment/expansion path against the live OSV and
deps.dev services. It is not part of any hermetic unit test.

`express.spdx.json` is the only file in `testdata/enrich/` because the GUAC
file collector ingests every file in the target directory; this provenance file
therefore lives at the `testdata/` root, outside the collected directory.
