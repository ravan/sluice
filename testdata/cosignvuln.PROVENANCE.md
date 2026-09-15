# cosign vulnerability attestation fixture

`cosignvuln/alertmanager-0-0.34.0.x86_64-21.8.trivy_vuln.intoto.json` is the
Trivy vulnerability attestation OBS published for the Orchid container
`alertmanager-0`, build `0.34.0-21.8`, `x86_64`, scanned 2026-09-01.

- Source: the `orchid` attestation tree,
  `attestations/Devel:Orchid:Containers/alertmanager-0/containers/x86_64/`.
- Copied on 2026-09-15.
- Predicate type: `https://cosign.sigstore.dev/attestation/vuln/v1`;
  `predicate.scanner.result` is a Trivy JSON report (schema 2).

Trimmed so the fixture stays small and still exercises every branch of the
parser: the two `Results[].Packages` inventories, `Metadata.Layers`,
`ImageConfig.history` and `ImageConfig.rootfs` are removed, the OCI labels
are cut to the `org.opencontainers.image.*` set plus the two OBS ones, and
each finding's `Description` is cut to 120 characters. The subject is left
as OBS wrote it, `{"name": "", "digest": {"sha256": ""}}`, because that is
the case the parser has to survive.

The two findings (CVE-2026-56854 with alias GO-2026-6303, and GO-2026-5932)
against `pkg:golang/golang.org/x/crypto@v0.54.0` are unchanged.
