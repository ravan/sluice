#!/bin/sh
# S5 receiver-breadth demo: prove the OCI and S3 receivers ingest an SBOM into
# varve. Two legs, each against a FRESH graph. Both legs use the same fixture
# (testdata/sboms/small-spdx.json), and assembly is an idempotent upsert
# (§6 inv. 2), so a shared graph could never show the second leg's +3 rise —
# hence a clean stack per leg (mirrors scripts/valid-time.sh's two fresh stacks).
#   S3 leg  : upload the SBOM into a MinIO bucket, `ingest s3`, assert PkgVersion
#             rose by 3, then re-ingest and assert it is unchanged (idempotency).
#   OCI leg : attach the SBOM to a local-registry image as an application/spdx+json
#             referrer, `ingest oci --oci-insecure`, assert +3, re-ingest unchanged.
# The counts are the binding oracle: the script exits non-zero on any violation.
# The receiver back-ends run behind the compose `receivers` profile, so S0-S4 demos
# (no profile) are untouched. Container tools (minio/mc, ghcr.io/oras-project/oras)
# reach the published ports via host.docker.internal, so the host needs only docker.
# The stack is torn down (down -v) on exit.
set -eu

COMPOSE="${COMPOSE:-docker-compose}"
: "${VARVE_PORT:=8080}"
: "${VARVE_TOKEN:=sluice-demo-token}"
: "${REGISTRY_PORT:=5001}"
: "${MINIO_PORT:=9000}"
: "${MINIO_USER:=minioadmin}"
: "${MINIO_PASS:=minioadmin}"
export VARVE_TOKEN
BASE="http://127.0.0.1:${VARVE_PORT}"
SBOM_DIR="testdata/sboms"
ORAS_IMAGE="${ORAS_IMAGE:-ghcr.io/oras-project/oras:v1.2.0}"
MC_IMAGE="${MC_IMAGE:-minio/mc:latest}"

trap '$COMPOSE --profile receivers down -v >/dev/null 2>&1 || true' EXIT

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

wait_http() {
	# $1 = url, $2 = name. Waits for HTTP 200.
	i=0
	until [ "$(curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || true)" = "200" ]; do
		i=$((i + 1))
		if [ "$i" -ge 60 ]; then
			fail "$2 did not become ready after ${i}s"
		fi
		sleep 1
	done
}

bring_up() {
	echo ">> bringing the receivers stack down (clean state) and back up"
	$COMPOSE --profile receivers down -v >/dev/null 2>&1 || true
	$COMPOSE --profile receivers up -d
	wait_http "${BASE}/healthz" varve
	wait_http "http://127.0.0.1:${REGISTRY_PORT}/v2/" registry
	wait_http "http://127.0.0.1:${MINIO_PORT}/minio/health/live" minio
	echo "   varve, registry and minio are ready"
}

s3_leg() {
	echo ""
	echo "== S3/MinIO leg =="
	bring_up
	bucket="sboms-demo"
	echo ">> mc: create bucket ${bucket} and upload the SBOM"
	docker run --rm --entrypoint /bin/sh -v "$PWD/${SBOM_DIR}:/w" "$MC_IMAGE" -c \
		"mc alias set d http://host.docker.internal:${MINIO_PORT} ${MINIO_USER} ${MINIO_PASS} >/dev/null && mc mb -p d/${bucket} >/dev/null && mc cp /w/small-spdx.json d/${bucket}/sboms/small-spdx.json" \
		|| fail "MinIO bucket setup / upload failed"

	base="$(count PkgVersion)"
	echo ">> ingest s3 ${bucket} (baseline PkgVersion=${base})"
	AWS_ACCESS_KEY_ID="${MINIO_USER}" AWS_SECRET_ACCESS_KEY="${MINIO_PASS}" \
		./sluice ingest s3 "${bucket}" --s3-url "http://localhost:${MINIO_PORT}" \
		--s3-region us-east-1 --s3-path sboms/ --varve-addr "${BASE}" || fail "ingest s3 failed"
	after="$(count PkgVersion)"
	echo "   PkgVersion after ingest: ${after}"
	[ "${after}" -eq "$((base + 3))" ] || fail "S3: PkgVersion ${base} -> ${after}, want a rise of 3"

	echo ">> ingest s3 again (must be idempotent)"
	AWS_ACCESS_KEY_ID="${MINIO_USER}" AWS_SECRET_ACCESS_KEY="${MINIO_PASS}" \
		./sluice ingest s3 "${bucket}" --s3-url "http://localhost:${MINIO_PORT}" \
		--s3-region us-east-1 --s3-path sboms/ --varve-addr "${BASE}" || fail "ingest s3 (replay) failed"
	replay="$(count PkgVersion)"
	echo "   PkgVersion after replay: ${replay}"
	[ "${replay}" -eq "${after}" ] || fail "S3: replay changed PkgVersion ${after} -> ${replay} (§6 inv. 2)"
	echo "   OK S3: base=${base} after=${after} replay=${replay}"
}

oci_leg() {
	echo ""
	echo "== OCI leg =="
	bring_up
	# docker push and sluice reach the registry as localhost; the oras container
	# reaches the same published port as host.docker.internal (same repo either way).
	ref_host="localhost:${REGISTRY_PORT}/demo:latest"
	ref_ctr="host.docker.internal:${REGISTRY_PORT}/demo:latest"
	echo ">> push a base image and attach the SBOM as an application/spdx+json referrer"
	docker pull -q hello-world:latest >/dev/null || fail "pulling hello-world failed"
	docker tag hello-world:latest "${ref_host}"
	docker push -q "${ref_host}" >/dev/null || fail "pushing base image failed"
	docker run --rm -w /w -v "$PWD/${SBOM_DIR}:/w" "$ORAS_IMAGE" attach \
		--plain-http --artifact-type application/spdx+json \
		"${ref_ctr}" small-spdx.json:application/spdx+json || fail "oras attach failed"

	base="$(count PkgVersion)"
	echo ">> ingest oci ${ref_host} --oci-insecure (baseline PkgVersion=${base})"
	./sluice ingest oci "${ref_host}" --oci-insecure --varve-addr "${BASE}" || fail "ingest oci failed"
	after="$(count PkgVersion)"
	echo "   PkgVersion after ingest: ${after}"
	[ "${after}" -eq "$((base + 3))" ] || fail "OCI: PkgVersion ${base} -> ${after}, want a rise of 3"

	echo ">> ingest oci again (must be idempotent)"
	./sluice ingest oci "${ref_host}" --oci-insecure --varve-addr "${BASE}" || fail "ingest oci (replay) failed"
	replay="$(count PkgVersion)"
	echo "   PkgVersion after replay: ${replay}"
	[ "${replay}" -eq "${after}" ] || fail "OCI: replay changed PkgVersion ${after} -> ${replay} (§6 inv. 2)"
	echo "   OK OCI: base=${base} after=${after} replay=${replay}"
}

echo ">> building sluice"
go build -o ./sluice ./cmd/sluice

s3_leg
oci_leg

echo ""
echo "OK: both receiver legs ingested the SBOM (PkgVersion +3) and are idempotent on replay."
echo ">> receivers demo complete; the stack has been torn down."
