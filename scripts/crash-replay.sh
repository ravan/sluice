#!/bin/sh
# S6 crash-replay leg: §6 invariant 2 (replay heals to identical counts) UNDER
# FAILURE. On ONE fresh Garage/S3-backed durable graph, background a real
# per-document ingest, kill -9 the instant the graph shows partial progress, then
# replay the full corpus. A full-stream replay supersedes in place (§2.6), so the
# graph heals to the EXACT clean-run counts — the committed parity golden
# (internal/assemble/testdata/parity.golden.json): PkgVersion 606, PkgName 580,
# IsDependency 1094. The count assertion is the oracle.
# REQUIRES `just varve-image` (sluice/varve:local) + docker. Drives the
# SEPARATE docker-compose.gallery.yml; the S0-S5 stack is untouched.
set -eu

COMPOSE="${COMPOSE:-docker-compose -f docker-compose.gallery.yml}"
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
	# $1 = node label. varve returns an empty row set (not a c:0 row) when nothing
	# matches, so an empty extraction means a count of zero.
	c=$(query "MATCH (n:${1}) RETURN count(*) AS c" | grep -o '"c":[0-9]*' | grep -o '[0-9]*' | head -n1)
	echo "${c:-0}"
}

fail() {
	echo "!! FAIL: $1" >&2
	$COMPOSE logs >&2 || true
	exit 1
}

trap '$COMPOSE down -v >/dev/null 2>&1 || true' EXIT

echo ">> bringing the durable stack down (clean state) and back up --build"
$COMPOSE down -v >/dev/null 2>&1 || true
$COMPOSE up -d --build

echo ">> waiting for ${BASE}/healthz"
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
echo "== crash run: kill -9 mid-stream, then full replay =="
CORPUS=internal/assemble/testdata/corpus
# background a real ingest; per-document POSTs give a mid-stream window
./sluice ingest files "$CORPUS" --varve-addr "$BASE" >crash.log 2>&1 &
pid=$!
# kill the instant the graph shows partial progress (first committed doc)
i=0
until [ "$(count PkgVersion)" -ge 1 ]; do
	kill -0 "$pid" 2>/dev/null || break   # process finished before we caught it
	i=$((i + 1)); [ "$i" -ge 600 ] && fail "no ingest progress before timeout"
	sleep 0.1
done
partial=$(count PkgVersion)
kill -9 "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true          # reap; SIGKILL exit code is irrelevant
echo "   crash: killed mid-stream at PkgVersion=${partial} (clean full run = 606)"
[ "$partial" -ge 1 ] && [ "$partial" -lt 606 ] \
	|| fail "expected a mid-stream partial 1..605, got ${partial}"
# full-stream replay supersedes in place (§2.6); parser skips make ingest
# exit non-zero, which is expected here and NOT the oracle — hence `|| true`
./sluice ingest files "$CORPUS" --varve-addr "$BASE" >replay.log 2>&1 || true

pv=$(count PkgVersion); pn=$(count PkgName); dep=$(count IsDependency)
[ "$pv" -eq 606 ] && [ "$pn" -eq 580 ] && [ "$dep" -eq 1094 ] \
	|| fail "replay did not heal to golden counts: got PkgVersion=${pv} PkgName=${pn} IsDependency=${dep} (want 606/580/1094)"

echo ""
echo "OK crash-replay: partial=${partial} -> replay healed to 606/580/1094 (identical to a clean single run, §6 inv. 2 under failure)"
