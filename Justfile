# sluice developer tasks.

# Demo-only bearer token (matches deploy/varve.toml). Exported so `sluice
# ingest` and scripts/demo.sh pick it up without a flag.
export VARVE_TOKEN := "sluice-demo-token"

# Full check suite: build, vet, format check, race tests.
check:
    go build ./...
    go vet ./...
    @test -z "$(gofmt -l .)" || { echo "gofmt needed on:"; gofmt -l .; exit 1; }
    go test -race ./...

# Run the linter.
lint:
    golangci-lint run

# Build the local Varve image from a sibling varve checkout (override VARVE_SRC).
varve-image:
    docker build -f "${VARVE_SRC:-../varve}/Dockerfile" -t sluice/varve:local "${VARVE_SRC:-../varve}"

# Bring the demo stack up (detached).
varve-up:
    docker-compose up -d

# Tear the demo stack down and remove its volumes.
varve-down:
    docker-compose down -v

# Run the end-to-end S0 demo (brings the stack up, ingests twice, asserts idempotency).
demo:
    scripts/demo.sh

# Run the S1 blast-radius demo (CVE -> affected images in native GQL; asserts 7 affected / 0 controls).
blast-radius:
    scripts/blast-radius.sh

# Run the S2 valid-time demo (backdated time-travel + epoch-0 guard with counted fallback; two fresh stacks).
valid-time:
    scripts/valid-time.sh

# Run the S3 collector demo (config-driven daemon: drop an SBOM -> appears within one poll interval; /metrics counters; graceful SIGTERM drain).
collector:
    scripts/collector.sh

# Run the S4 enrichment/expansion demo (one SBOM -> OSV CertifyVuln + deps.dev source facts for transitive deps; expansion budget in the receipt). Requires live network to OSV + deps.dev.
enrich:
    scripts/enrich.sh

# Run the S5 receiver-breadth demo (OCI local registry + S3/MinIO: each ingests the SBOM, PkgVersion +3, idempotent on replay). Requires docker + container access to an OCI attach tool (oras) and an S3 client (mc).
receivers:
    scripts/receivers.sh

# Run the S6 benchmark leg (bulk /v1/ingest throughput on the Garage/S3 durable stack; records/s + evidence-edges/s vs the branch's ~409/s §7; PASSES the >=409 gate). Requires `just varve-image` first, then docker.
benchmark:
    scripts/benchmark.sh

# Run the S6 crash-replay leg (kill -9 mid-stream -> partial commit -> full replay heals to identical 606/580/1094 counts, §6 inv. 2 under failure). Requires `just varve-image` first, then docker.
crash-replay:
    scripts/crash-replay.sh

# Run the S6 full-dress gallery (Garage/S3-backed, clean volumes; blast-radius + valid-time + benchmark + crash-replay). Requires `just varve-image` first, then docker.
gallery:
    scripts/gallery.sh
