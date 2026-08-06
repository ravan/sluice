#!/bin/sh
# S4 enrichment/expansion demo: one small SBOM in -> a certified neighborhood out.
# Ingest express@4.17.1 twice against a fresh stack:
#   1. Baseline (no enrichment/expansion) proves the fixture parses under GUAC.
#   2. --enrich-vulns --expand-deps-dev folds OSV CertifyVuln evidence onto the
#      SBOM's package AND fetches its transitive dependencies (deps.dev) as new
#      documents, so PkgVersion grows above the baseline and source facts appear
#      that the SBOM never carried. The per-run expansion budget is reported in
#      the printed receipt (expanded=N).
# The queries are the binding oracle: the script exits non-zero on any violation.
# REQUIRES live network to OSV (api.osv.dev) and deps.dev (api.deps.dev) — this
# is inherent to S4's "done when". Reuses S0's docker-compose.yml + deploy/varve.toml
# stack; tear it down with `just varve-down`.
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

bring_up

# --- Baseline: no enrichment/expansion, proves the fixture parses --------------
echo ""
echo "== Baseline: ingest ./testdata/enrich (no enrichment/expansion) =="
./sluice ingest files ./testdata/enrich --varve-addr "${BASE}"

base="$(count PkgVersion)"
echo "   PkgVersion (baseline): ${base}"
[ "${base:-0}" -ge 1 ] || fail "fixture did not parse under GUAC's SPDX parser (baseline PkgVersion=0)"

base_hsa="$(count HasSourceAt)"
echo "   HasSourceAt (baseline): ${base_hsa}"

# --- Enrich + expand the same SBOM --------------------------------------------
echo ""
echo "== Enrich + expand: --enrich-vulns --expand-deps-dev --expand-max-docs 25 =="
receipt="$(./sluice ingest files ./testdata/enrich --varve-addr "${BASE}" --enrich-vulns --expand-deps-dev --expand-max-docs 25)"
echo "$receipt"

# Budget reported in the receipt (expansion budget usage).
exp="$(printf '%s' "$receipt" | grep -o 'expanded=[0-9]*' | grep -o '[0-9]*' | head -n1)"
echo "   receipt expanded: ${exp:-0}"
[ "${exp:-0}" -ge 1 ] || fail "expected receipt expanded>=1 (deps.dev expansion); needs deps.dev reachability (--expand-deps-dev)"

# Transitive packages appeared (idempotent upsert => any increase is expansion).
after="$(count PkgVersion)"
echo "   PkgVersion (after expansion): ${after}"
[ "${after:-0}" -gt "${base:-0}" ] || fail "expected PkgVersion to grow above baseline ${base} via expansion, got ${after}"

# OSV enrichment folded onto the SBOM's package.
cv="$(count CertifyVuln)"
echo "   CertifyVuln: ${cv}"
[ "${cv:-0}" -ge 1 ] || fail "expected CertifyVuln>=1 (OSV enrichment); needs OSV reachability (--enrich-vulns)"

# Source facts for transitive deps (baseline had ${base_hsa}; deps.dev source facts came from expansion).
hsa="$(count HasSourceAt)"
echo "   HasSourceAt: ${hsa}"
[ "${hsa:-0}" -ge 1 ] || fail "expected HasSourceAt>=1 (deps.dev source facts from expansion); needs deps.dev reachability"

# Scorecard facts for transitive deps (deps.dev scorecard facts from expansion, absent at baseline).
cs="$(count CertifyScorecard)"
echo "   CertifyScorecard: ${cs}"
[ "${cs:-0}" -ge 1 ] || fail "expected CertifyScorecard>=1 (deps.dev scorecard facts from expansion); needs deps.dev reachability"

echo ""
echo "OK: base=${base} after=${after} CertifyVuln=${cv} HasSourceAt=${hsa} CertifyScorecard=${cs} expanded=${exp}"
echo ">> enrichment/expansion demo complete. The stack is still running; tear it down with: just varve-down"
