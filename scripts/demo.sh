#!/bin/sh
# S0 walking-skeleton demo: bring up a local Varve stack, ingest the SBOM corpus
# twice, and assert the second pass is idempotent with the first (§6 inv. 2).
# Leaves the stack running; tear it down with `just varve-down`.
set -eu

COMPOSE="${COMPOSE:-docker-compose}"
: "${VARVE_PORT:=8080}"
: "${VARVE_TOKEN:=sluice-demo-token}"
export VARVE_TOKEN
BASE="http://127.0.0.1:${VARVE_PORT}"

query() {
	curl -sS -X POST "${BASE}/v1/query" \
		-H "authorization: Bearer ${VARVE_TOKEN}" \
		-H 'content-type: application/json' \
		--data "{\"gql\":\"$1\"}"
}

count() {
	# $1 = node label; echoes the integer count(*) for that label.
	query "MATCH (n:${1}) RETURN count(*) AS c" | grep -o '"c":[0-9]*' | grep -o '[0-9]*'
}

echo ">> bringing the stack down (clean state) and back up"
$COMPOSE down -v >/dev/null 2>&1 || true
$COMPOSE up -d

echo ">> waiting for ${BASE}/healthz"
i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/healthz" 2>/dev/null || true)" = "200" ]; do
	i=$((i + 1))
	if [ "$i" -ge 60 ]; then
		echo "!! varve did not become healthy after ${i}s; container logs follow:" >&2
		$COMPOSE logs >&2 || true
		exit 1
	fi
	sleep 1
done
echo "   healthy after ${i}s"

echo ">> building sluice"
go build -o ./sluice ./cmd/sluice

echo ">> run 1: ingest ./testdata/sboms"
./sluice ingest files ./testdata/sboms --varve-addr "${BASE}"
pv1=$(count PkgVersion)
pn1=$(count PkgName)
echo "   after run 1: PkgVersion=${pv1} PkgName=${pn1}"

echo ">> run 2: ingest the identical corpus (must be idempotent)"
./sluice ingest files ./testdata/sboms --varve-addr "${BASE}"
pv2=$(count PkgVersion)
pn2=$(count PkgName)
echo "   after run 2: PkgVersion=${pv2} PkgName=${pn2}"

echo ">> asserting idempotency and expected counts"
if [ "$pv1" != "$pv2" ] || [ "$pn1" != "$pn2" ] || [ "$pv1" != "3" ] || [ "$pn1" != "3" ]; then
	echo "!! FAIL: expected 3/3 identical across both runs; got run1 ${pv1}/${pn1}, run2 ${pv2}/${pn2}" >&2
	$COMPOSE logs >&2 || true
	exit 1
fi
echo "   OK: both runs report PkgVersion=3 PkgName=3 — idempotent supersede-upsert (§6 inv. 2)"

echo ">> traversal: MATCH (n:PkgName)-[:PkgHasVersion]->(v:PkgVersion) RETURN v._id AS id, v.purl AS purl"
query "MATCH (n:PkgName)-[:PkgHasVersion]->(v:PkgVersion) RETURN v._id AS id, v.purl AS purl"
echo ""
echo ">> demo complete. The stack is still running; tear it down with: just varve-down"
