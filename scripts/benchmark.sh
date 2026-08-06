#!/bin/sh
# S6 benchmark leg: bulk /v1/ingest throughput on the Garage/S3-backed durable
# stack. Assembles the whole exampledata corpus into ONE deduplicated record
# stream and POSTs it once (sluice bench files), reporting records/s and
# evidence-edges/s against the two spec reference numbers — the feat/varve-backend
# branch's ~409 evidence-edges/s over /v1/tx (§7) and Varve's ~166k records/s
# /v1/ingest capability (§1). The Step-1 gate is the oracle: `bench` exits
# non-zero unless it strictly beats the branch's per-edge rate, and under `set -e`
# that aborts this script.
# REQUIRES `just varve-image` (sluice/varve:local) + docker. Drives the
# SEPARATE docker-compose.gallery.yml; the S0-S5 stack is untouched.
set -eu

COMPOSE="${COMPOSE:-docker-compose -f docker-compose.gallery.yml}"
: "${VARVE_PORT:=8080}"
: "${VARVE_TOKEN:=sluice-demo-token}"
export VARVE_TOKEN
BASE="http://127.0.0.1:${VARVE_PORT}"

fail() {
	echo "!! FAIL: $1" >&2
	$COMPOSE logs >&2 || true
	exit 1
}

trap '$COMPOSE down -v >/dev/null 2>&1 || true' EXIT

echo ">> bringing the durable stack down (clean state) and back up --build"
$COMPOSE down -v >/dev/null 2>&1 || true
$COMPOSE up -d --build

echo ">> waiting for ${BASE}/healthz (Garage forming + writer is slower than the memory stack)"
i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/healthz" 2>/dev/null || true)" = "200" ]; do
	i=$((i + 1))
	if [ "$i" -ge 120 ]; then
		fail "writer did not become healthy after ${i}s"
	fi
	sleep 1
done
echo "   healthy after ${i}s"

echo ">> building sluice"
go build -o ./sluice ./cmd/sluice

echo ""
echo "== bulk /v1/ingest benchmark: exampledata corpus in ONE POST =="
./sluice bench files internal/assemble/testdata/corpus --varve-addr "${BASE}"

echo ""
echo "OK benchmark: the bulk /v1/ingest path beat the branch's ~409 evidence-edges/s baseline (spec §7)"
