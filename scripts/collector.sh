#!/bin/sh
# S3 collector demo: the config-driven daemon made real. Start `sluice run`
# on a pipeline.yaml, drop an SBOM into the watched dir, watch it appear in the
# graph within one poll interval, read the ingest counters off /metrics, and
# prove a graceful (exit 0) SIGTERM drain. Reuses S0's docker-compose.yml +
# deploy/varve.toml stack; tear it down with `just varve-down`.
# The observations are the binding oracle: the script exits non-zero on any violation.
set -eu

COMPOSE="${COMPOSE:-docker-compose}"
: "${VARVE_PORT:=8080}"
: "${VARVE_TOKEN:=sluice-demo-token}"
: "${METRICS_ADDR:=127.0.0.1:9464}"
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

dump_daemon_log() {
	if [ -n "${WATCH_DIR:-}" ] && [ -f "${WATCH_DIR}/daemon.log" ]; then
		echo "--- daemon.log ---" >&2
		cat "${WATCH_DIR}/daemon.log" >&2
	fi
}

fail() {
	echo "!! FAIL: $1" >&2
	$COMPOSE logs >&2 || true
	dump_daemon_log
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

# 1. fresh stack + build the daemon
bring_up
echo ">> building sluice"
go build -o ./sluice ./cmd/sluice

# 2. a fresh EMPTY watch dir + a hermetic pipeline.yaml (the collector os.Stats
#    the dir at startup, so it must exist and stay empty until the daemon is up)
WATCH_DIR="$(mktemp -d)"
cat >"${WATCH_DIR}/pipeline.yaml" <<EOF
receivers:
  files:
    path: ${WATCH_DIR}
    poll: 2s
processors:
  valid_time:
    floor: "2000-01-01T00:00:00Z"
    future_skew: 5m
sink:
  varve:
    addr: "http://127.0.0.1:${VARVE_PORT}"
    token_env: VARVE_TOKEN
EOF

# 3. start the daemon in the background; wait (bounded) for its /healthz
echo ">> starting the daemon (watching ${WATCH_DIR}, metrics on ${METRICS_ADDR})"
./sluice run --config "${WATCH_DIR}/pipeline.yaml" --metrics-addr "${METRICS_ADDR}" --log-format text >"${WATCH_DIR}/daemon.log" 2>&1 &
DAEMON_PID=$!
trap 'kill "$DAEMON_PID" 2>/dev/null || true' EXIT

echo ">> waiting for http://${METRICS_ADDR}/healthz"
i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' "http://${METRICS_ADDR}/healthz" 2>/dev/null || true)" = "200" ]; do
	i=$((i + 1))
	if [ "$i" -ge 30 ]; then
		dump_daemon_log
		fail "daemon /healthz did not come up after ${i} tries"
	fi
	sleep 1
done
echo "   daemon healthy after ${i}s"

# 4. the graph starts empty for this label
start=$(count PkgVersion)
echo "   PkgVersion at start: ${start}"
[ "${start}" = "0" ] || fail "expected 0 PkgVersion at start, got ${start}"

# 5. drop an SBOM; it appears within a few 2s poll intervals
echo ">> dropping small-spdx.json into the watched dir"
cp ./testdata/sboms/small-spdx.json "${WATCH_DIR}/"
i=0
until [ "$(count PkgVersion)" -ge 3 ]; do
	i=$((i + 1))
	if [ "$i" -ge 30 ]; then
		dump_daemon_log
		fail "PkgVersion did not reach >=3 within ~${i}s (one poll interval is 2s)"
	fi
	sleep 1
done
echo "   PkgVersion reached $(count PkgVersion) after ~${i}s"

# 6. read the ingest counter off /metrics
ingested="$(curl -s "http://${METRICS_ADDR}/metrics" | grep '^sluice_documents_total{outcome="ingested"}' | awk '{print $2}')"
echo "   sluice_documents_total{outcome=ingested}: ${ingested:-0}"
[ "${ingested:-0}" -ge 1 ] || fail "expected documents_total{ingested} >= 1, got ${ingested:-0}"
curl -s "http://${METRICS_ADDR}/metrics" | grep -q 'sluice_records_emitted_total' \
	|| fail "expected a sluice_records_emitted_total series on /metrics"

# 7. graceful drain on SIGTERM -> exit 0
echo ">> sending SIGTERM for a graceful drain"
kill -TERM "$DAEMON_PID"
if wait "$DAEMON_PID"; then rc=0; else rc=$?; fi
trap - EXIT
[ "$rc" = "0" ] || fail "daemon exited ${rc} on SIGTERM, want 0 (graceful drain)"
echo "   daemon exited 0 on SIGTERM"

# 8. done
rm -rf "$WATCH_DIR"
echo ""
echo "OK: SBOM dropped -> appeared within one poll interval; ingest counters on /metrics; graceful SIGTERM drain (exit 0)"
echo ">> collector demo complete. The stack is still running; tear it down with: just varve-down"
