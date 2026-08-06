# Provenance — S6 gallery Garage/S3 deploy assets

The following four files were copied from the sibling varve checkout at
`../varve/deploy/` on 2026-08-07 for the S6 full-dress gallery
(`docker-compose.gallery.yml`, `just benchmark`, `just crash-replay`,
`just gallery`):

- `garage.toml`            ← `../varve/deploy/garage.toml` (verbatim)
- `garage-init.sh`         ← `../varve/deploy/garage-init.sh` (verbatim, kept executable)
- `Dockerfile.garage-init` ← `../varve/deploy/Dockerfile.garage-init` (verbatim)
- `varve-writer.toml`      ← `../varve/deploy/varve-writer.toml`

The **sole edit** applied to any copied file is the `varve-writer.toml`
`[auth.static]` token value, changed to `sluice-demo-token` so it matches
this repo's `Justfile` `VARVE_TOKEN` and every existing `query()` helper. Every
other line — roles, log/storage backends, endpoints, keys, listen address — is
exactly as copied.

These are **TEST/DEMO-ONLY** fixed material: the access key, secret key,
`rpc_secret`, and auth token are reproducible demo credentials, not production
secrets, and carry no confidentiality claim.

Copying proven demo config with provenance is the established pattern in this
repo (cf. `deploy/varve.toml`, the copied testdata). It does not touch §6
invariant 1: no varve *code* is imported — the only coupling to Varve remains
the HTTP wire contract.
