#!/bin/sh
# S2 valid-time demo: document timestamps become guarded, first-class valid time.
# Two clean scenarios, each on its own fresh stack so they never interfere:
#   1. A backdated SBOM (created 2025-01-15) is time-travelled with
#      FOR VALID_TIME AS OF — present at 2025-06, absent at 2024-01 — from the
#      SAME graph, proving valid time drives the answer.
#   2. A doctored epoch-0 SBOM (created 1970-01-01) is rejected by the guard to
#      ingest time and the fallback is counted in the printed receipt; nothing is
#      silently backdated to 1970, yet the record is visible AS OF now.
# The queries are the binding oracle: the script exits non-zero on any violation.
# Reuses S0's docker-compose.yml + deploy/varve.toml stack; tear it down with
# `just varve-down`.
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
	# $1 = node label; $2 = optional valid-time prefix, e.g.
	# "FOR VALID_TIME AS OF TIMESTAMP '2025-06-01T00:00:00Z' ". varve returns an
	# empty row set (not a c:0 row) when nothing is valid at the AS-OF instant, so
	# an empty extraction means a count of zero.
	c=$(query "${2:-}MATCH (n:${1}) RETURN count(*) AS c" | grep -o '"c":[0-9]*' | grep -o '[0-9]*' | head -n1)
	echo "${c:-0}"
}

fail() {
	echo "!! FAIL: $1" >&2
	$COMPOSE logs >&2 || true
	exit 1
}

bring_up() {
	echo ">> bringing the stack down (clean state) and back up"
	$COMPOSE down -v >/dev/null 2>&1 || true
	$COMPOSE up -d

	echo ">> waiting for ${BASE}/healthz"
	i=0
	until [ "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/healthz" 2>/dev/null || true)" = "200" ]; do
		i=$((i + 1))
		if [ "$i" -ge 60 ]; then
			fail "varve did not become healthy after ${i}s"
		fi
		sleep 1
	done
	echo "   healthy after ${i}s"
}

echo ">> building sluice"
go build -o ./sluice ./cmd/sluice

# --- Scenario 1: backdated SBOM -> valid-time travel ------------------------
echo ""
echo "== Scenario 1: backdated SBOM (created 2025-01-15) -> FOR VALID_TIME AS OF =="
bring_up

echo ">> ingest ./testdata/valid-time/backdated"
./sluice ingest files ./testdata/valid-time/backdated --varve-addr "${BASE}"

present=$(count PkgVersion "FOR VALID_TIME AS OF TIMESTAMP '2025-06-01T00:00:00Z' ")
echo "   PkgVersion AS OF 2025-06-01: ${present:-0}"
[ "${present:-0}" -ge 1 ] || fail "expected >=1 PkgVersion AS OF 2025-06-01, got ${present:-0}"

absent=$(count PkgVersion "FOR VALID_TIME AS OF TIMESTAMP '2024-01-01T00:00:00Z' ")
echo "   PkgVersion AS OF 2024-01-01: ${absent:-0}"
[ "${absent:-0}" = "0" ] || fail "expected 0 PkgVersion AS OF 2024-01-01 (before creation), got ${absent:-0}"

echo "OK: backdated beliefs appear only once valid time reaches the 2025-01-15 created instant"

# --- Scenario 2: epoch-0 SBOM -> guard + counted fallback -------------------
echo ""
echo "== Scenario 2: doctored epoch-0 SBOM (created 1970-01-01) -> guard + counted fallback =="
bring_up

echo ">> ingest ./testdata/valid-time/epoch (capturing the receipt)"
receipt=$(./sluice ingest files ./testdata/valid-time/epoch --varve-addr "${BASE}")
echo "$receipt"

fallbacks=$(printf '%s\n' "$receipt" | grep -o 'fallbacks=[0-9]*' | grep -o '[0-9]*' | head -n1)
echo "   receipt fallbacks: ${fallbacks:-0}"
[ "${fallbacks:-0}" -ge 1 ] || fail "expected receipt fallbacks>=1 (guard rejected the 1970 timestamp), got ${fallbacks:-0}"

at1970=$(count PkgVersion "FOR VALID_TIME AS OF TIMESTAMP '1970-06-01T00:00:00Z' ")
echo "   PkgVersion AS OF 1970-06-01: ${at1970:-0}"
[ "${at1970:-0}" = "0" ] || fail "expected 0 PkgVersion AS OF 1970 (nothing silently backdated), got ${at1970:-0}"

now=$(count PkgVersion)
echo "   PkgVersion AS OF now: ${now:-0}"
[ "${now:-0}" -ge 1 ] || fail "expected >=1 PkgVersion AS OF now (record landed at ingest time), got ${now:-0}"

echo "OK: epoch-0 timestamp rejected to ingest time, fallback counted, record visible now but not at 1970"

echo ""
echo ">> valid-time demo complete. The stack is still running; tear it down with: just varve-down"
