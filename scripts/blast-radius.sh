#!/bin/sh
# S1 blast-radius demo: from CVE-2021-44228 (Log4Shell), traverse the native
# property graph — certified-vulnerable log4j PkgVersions -> their dependents
# that carry their own SBOM — and assert exactly the seven AFFECTED images fall
# out, with none of the five CONTROL images. This is the demo's whole claim, so
# the 7/0 verdict is an assertion: the script exits non-zero on any violation.
# Reuses S0's docker-compose.yml + deploy/varve.toml stack and leaves it up;
# tear it down with `just varve-down`.
set -eu

COMPOSE="${COMPOSE:-docker-compose}"
: "${VARVE_PORT:=8080}"
: "${VARVE_TOKEN:=sluice-demo-token}"
export VARVE_TOKEN
BASE="http://127.0.0.1:${VARVE_PORT}"

# The CVE attestation's vulnerability id, lowercased type/id per the assembler.
VULN_ID="vuln:osv/cve-2021-44228"

# The MANIFEST truth table: seven AFFECTED images, five CONTROL images.
AFFECTED_RE='solr|flink|neo4j|druid|elasticsearch|sonarqube|logstash'
CONTROL_RE='kibana|odoo|jenkins|tomcat|nginx'

CORPUS_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../testdata/blast-radius" && pwd)"

query() {
	curl -sS -X POST "${BASE}/v1/query" \
		-H "authorization: Bearer ${VARVE_TOKEN}" \
		-H 'content-type: application/json' \
		--data "{\"gql\":\"$1\"}"
}

# Work dir holding ONLY the 13 plain files handed to the file collector, which
# ingests every file in the dir with no extension filter. Cleaned on exit.
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/blast-radius.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT INT TERM

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

echo ">> decompressing the twelve SBOMs into ${WORKDIR} (GUAC v1.1.0 cannot read gzip, spec §10)"
for gz in "$CORPUS_DIR"/*.spdx.json.gz; do
	base=$(basename "$gz" .gz)
	gunzip -c "$gz" >"$WORKDIR/$base"
done
cp "$CORPUS_DIR/cve-2021-44228.json" "$WORKDIR/cve-2021-44228.json"
echo "   work dir contains $(ls -1 "$WORKDIR" | wc -l | tr -d ' ') files (expect 13)"

echo ">> building sluice"
go build -o ./sluice ./cmd/sluice

echo ">> ingest ${WORKDIR}"
./sluice ingest files "$WORKDIR" --varve-addr "${BASE}"

echo ">> sanity: the CVE vulnerability node exists"
vcount=$(query "MATCH (v:Vulnerability {_id:'${VULN_ID}'}) RETURN count(*) AS c" | grep -o '"c":[0-9]*' | grep -o '[0-9]*')
echo "   Vulnerability ${VULN_ID}: count=${vcount:-0}"
if [ "${vcount:-0}" = "0" ]; then
	echo "!! FAIL: no Vulnerability node ${VULN_ID}; ingested vulnerability ids follow:" >&2
	query "MATCH (v:Vulnerability) RETURN v._id AS product" >&2 || true
	echo >&2
	$COMPOSE logs >&2 || true
	exit 1
fi

echo ">> blast-radius query: CVE -> vulnerable PkgVersions -> dependents with their own SBOM"
GQL="MATCH (vid:Vulnerability {_id: '${VULN_ID}'}) <-[:CertifyVulnVulnerability]- (cv:CertifyVuln) <-[:CertifyVulnSubject]- (bad:PkgVersion) <-[:IsDependencyObject]- (d:IsDependency) <-[:IsDependencySubject]- (product:PkgVersion) -[:IsOccurrenceSubject]-> (occ:IsOccurrence) -[:IsOccurrenceArtifact]-> (art:Artifact) -[:HasSbomSubject]-> (s:HasSBOM) RETURN DISTINCT product._id AS product ORDER BY product"
RESP=$(query "$GQL")
echo "$RESP"
echo ""

products=$(printf '%s' "$RESP" | grep -o '"product":"[^"]*"' | sed 's/^"product":"//; s/"$//' | sort -u)

echo ">> affected products:"
printf '%s\n' "$products" | sed 's/^/   /'

total=$(printf '%s\n' "$products" | grep -c . || true)
aff=$(printf '%s\n' "$products" | grep -Ec "$AFFECTED_RE" || true)
ctl=$(printf '%s\n' "$products" | grep -Ec "$CONTROL_RE" || true)

echo ">> asserting the oracle: exactly 7 affected, 0 controls"
if [ "$total" != "7" ] || [ "$aff" != "7" ] || [ "$ctl" != "0" ]; then
	echo "!! FAIL: expected 7 affected / 0 controls; got total=${total} affected=${aff} controls=${ctl}" >&2
	$COMPOSE logs >&2 || true
	exit 1
fi
echo "OK: ${aff} affected, ${ctl} controls"

echo ">> demo complete. The stack is still running; tear it down with: just varve-down"
