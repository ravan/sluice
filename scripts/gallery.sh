#!/bin/sh
# S6 full-dress gallery (the spec's S6 "demo.sh"): everything under real
# conditions on a Garage/S3-backed durable Varve, from clean volumes. Five legs,
# each on a fresh durable stack:
#   1. Collect + blast-radius query  (CVE-2021-44228 -> exactly 7 affected / 0 controls)
#   2. Valid-time travel (backdated) (present AS OF 2025-06, absent AS OF 2024-01)
#   3. Valid-time guard (epoch-0)    (fallback counted; nothing AS OF 1970, present AS OF now)
#   4. Benchmark      (delegated to scripts/benchmark.sh; the >=409 edges/s gate is the oracle)
#   5. Crash-replay   (delegated to scripts/crash-replay.sh; heals to 606/580/1094)
# Enrichment is NOT in the hermetic gallery (it needs live network); it stays the
# S4 demo, `just enrich`.
# REQUIRES `just varve-image` (sluice/varve:local) + docker. Drives the
# SEPARATE docker-compose.gallery.yml; the S0-S5 stack is untouched (§6 inv. 10).
set -eu

COMPOSE="${COMPOSE:-docker-compose -f docker-compose.gallery.yml}"
: "${VARVE_PORT:=8080}"
: "${VARVE_TOKEN:=sluice-demo-token}"
export VARVE_TOKEN
BASE="http://127.0.0.1:${VARVE_PORT}"

# Blast-radius oracle (identical to scripts/blast-radius.sh).
VULN_ID="vuln:osv/cve-2021-44228"
AFFECTED_RE='solr|flink|neo4j|druid|elasticsearch|sonarqube|logstash'
CONTROL_RE='kibana|odoo|jenkins|tomcat|nginx'
BLAST_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../testdata/blast-radius" && pwd)"

query() {
	curl -sS -X POST "${BASE}/v1/query" \
		-H "authorization: Bearer ${VARVE_TOKEN}" \
		-H 'content-type: application/json' \
		--data "{\"gql\":\"$1\"}"
}

count() {
	# $1 = node label; $2 = optional valid-time prefix. An empty row set means 0.
	c=$(query "${2:-}MATCH (n:${1}) RETURN count(*) AS c" | grep -o '"c":[0-9]*' | grep -o '[0-9]*' | head -n1)
	echo "${c:-0}"
}

fail() {
	echo "!! FAIL: $1" >&2
	$COMPOSE logs >&2 || true
	exit 1
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/gallery-blast.XXXXXX")"
cleanup() {
	rm -rf "$WORKDIR"
	$COMPOSE down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

bring_up() {
	echo ">> bringing the durable stack down (clean volumes) and back up --build"
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
}

echo ">> building sluice"
go build -o ./sluice ./cmd/sluice

# --- Leg 1: collect + blast-radius query ------------------------------------
echo ""
echo "== Leg 1: collect + blast-radius query (CVE-2021-44228 -> 7 affected / 0 controls) =="
bring_up

echo ">> decompressing the SBOMs into ${WORKDIR} (GUAC v1.1.0 cannot read gzip, §10)"
for gz in "$BLAST_DIR"/*.spdx.json.gz; do
	base=$(basename "$gz" .gz)
	gunzip -c "$gz" >"$WORKDIR/$base"
done
cp "$BLAST_DIR/cve-2021-44228.json" "$WORKDIR/cve-2021-44228.json"
echo "   work dir contains $(ls -1 "$WORKDIR" | wc -l | tr -d ' ') files (expect 13)"

echo ">> ingest ${WORKDIR}"
./sluice ingest files "$WORKDIR" --varve-addr "${BASE}"

GQL="MATCH (vid:Vulnerability {_id: '${VULN_ID}'}) <-[:CertifyVulnVulnerability]- (cv:CertifyVuln) <-[:CertifyVulnSubject]- (bad:PkgVersion) <-[:IsDependencyObject]- (d:IsDependency) <-[:IsDependencySubject]- (product:PkgVersion) -[:IsOccurrenceSubject]-> (occ:IsOccurrence) -[:IsOccurrenceArtifact]-> (art:Artifact) -[:HasSbomSubject]-> (s:HasSBOM) RETURN DISTINCT product._id AS product ORDER BY product"
RESP=$(query "$GQL")
products=$(printf '%s' "$RESP" | grep -o '"product":"[^"]*"' | sed 's/^"product":"//; s/"$//' | sort -u)
echo ">> affected products:"
printf '%s\n' "$products" | sed 's/^/   /'

total=$(printf '%s\n' "$products" | grep -c . || true)
aff=$(printf '%s\n' "$products" | grep -Ec "$AFFECTED_RE" || true)
ctl=$(printf '%s\n' "$products" | grep -Ec "$CONTROL_RE" || true)
if [ "$total" != "7" ] || [ "$aff" != "7" ] || [ "$ctl" != "0" ]; then
	fail "expected 7 affected / 0 controls; got total=${total} affected=${aff} controls=${ctl}"
fi
echo "OK blast-radius: ${aff} affected, ${ctl} controls"

# --- Leg 2: valid-time travel (backdated) -----------------------------------
echo ""
echo "== Leg 2: valid-time travel (backdated SBOM, created 2025-01-15) =="
bring_up

echo ">> ingest ./testdata/valid-time/backdated"
./sluice ingest files ./testdata/valid-time/backdated --varve-addr "${BASE}"

present=$(count PkgVersion "FOR VALID_TIME AS OF TIMESTAMP '2025-06-01T00:00:00Z' ")
echo "   PkgVersion AS OF 2025-06-01: ${present:-0}"
[ "${present:-0}" -ge 1 ] || fail "expected >=1 PkgVersion AS OF 2025-06-01, got ${present:-0}"

absent=$(count PkgVersion "FOR VALID_TIME AS OF TIMESTAMP '2024-01-01T00:00:00Z' ")
echo "   PkgVersion AS OF 2024-01-01: ${absent:-0}"
[ "${absent:-0}" = "0" ] || fail "expected 0 PkgVersion AS OF 2024-01-01 (before creation), got ${absent:-0}"
echo "OK valid-time travel: backdated beliefs appear only once valid time reaches the 2025-01-15 created instant"

# --- Leg 3: valid-time guard (epoch-0) --------------------------------------
echo ""
echo "== Leg 3: valid-time guard (doctored epoch-0 SBOM, created 1970-01-01) =="
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

nowc=$(count PkgVersion)
echo "   PkgVersion AS OF now: ${nowc:-0}"
[ "${nowc:-0}" -ge 1 ] || fail "expected >=1 PkgVersion AS OF now (record landed at ingest time), got ${nowc:-0}"
echo "OK valid-time guard: epoch-0 rejected to ingest time, fallback counted, visible now but not at 1970"

# --- Leg 4: benchmark (self-contained) --------------------------------------
echo ""
echo "== Leg 4: benchmark (bulk /v1/ingest throughput; >=409 edges/s gate is the oracle) =="
sh scripts/benchmark.sh

# --- Leg 5: crash-replay (self-contained) -----------------------------------
echo ""
echo "== Leg 5: crash-replay (kill -9 mid-stream -> replay heals to 606/580/1094) =="
sh scripts/crash-replay.sh

echo ""
echo "OK gallery: blast-radius (7/0) + valid-time travel + valid-time guard + benchmark + crash-replay all passed on the durable Garage/S3 stack"
