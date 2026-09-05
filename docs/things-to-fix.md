I found issues worth fixing before calling this production-ready: credential disclosure,
graph-identity collisions, unsafe concurrent collection, and document loss during outages and
shutdown. The interface design is mostly focused, but the scalar-value boundary does not meet
your desired guarantees.

Reviewed the current silt-0a checkout. No repository files changed.

Security findings

1. [P1] Writer redirects disclose credentials and document contents.
   pkg/varve/client.go:266 accepts any HTTP/HTTPS writer URL, then attaches the bearer token
   again. A compromised endpoint—or an attacker controlling an HTTP response—can redirect
   ingestion elsewhere. I reproduced an HTTPS → HTTP redirect forwarding the token
   successfully. Require explicitly trusted writer destinations, reject TLS downgrades, and
   apply the same policy to ordinary HTTP redirects.

2. [P1] Concurrent pipeline runs can ingest each other’s documents.
   pkg/guacseam/collect.go:219 registers receivers in GUAC’s unsynchronized, process-global
   registry. Each collection run reads the entire registry. Concurrent embedded runs can mix
   sources across sinks/graphs, fail registration, or race on the map. Give each run
   ownership of its collectors; a mutex around registration alone is insufficient.

3. [P1] Pinned dependencies contain relevant security vulnerabilities.
   go.mod pins go-git v5.16.5, with clone/fetch call paths reaching reference-storage
   operations affected by path traversal; the advisory fixes this in v5.19.2. It also pins
   regclient v0.8.3, affected by registry-credential disclosure through external blob URLs,
   fixed in v0.11.5. Update these and audit the remaining scanner results. These are
   advisory-backed exposures, not locally demonstrated exploits. Go vulnerability report,
   regclient advisory.

4. [P2] The metrics listener permits indefinite slow connections.
   cmd/sluice/run.go:122 creates an HTTP server without timeouts and defaults to listening on
   all interfaces. A reachable client can retain connections by sending incomplete headers.
   Configure header, idle, and write timeouts appropriate for metrics traffic. Go HTTP server
   documentation.

Standards and type design

5. [P1] Distinct valid package URLs produce identical node IDs.
   pkg/assemble/ids.go:40 joins qualifier values without escaping. These two valid inputs
   collide:

   pkg:generic/example@1?arch=x%26distro%3Dy
   pkg:generic/example@1?arch=x&distro=y

   Both become pkg:v:generic//example/1+arch=x&distro=y+. Deduplication then combines
   distinct packages and their vulnerability evidence. Use an unambiguous identity encoding
   and plan migration for existing IDs.

6. [P1] Evidence hashing loses field boundaries before hashing.
   pkg/assemble/kv.go:15 joins fields with \x1f, which input strings may contain. I
   reproduced equal evidence IDs for ("a\x1fb", "c") and ("a", "b\x1fc"). Actual metadata
   key/value fields permit this ambiguity. SHA-256 cannot correct it. Length-prefix fields or
   serialize a canonical string array; fix encodeKV similarly.

7. [P2] Value does not enforce its advertised scalar-only contract.
   pkg/varve/record.go:25 permits nil interface values and pointers to scalar types.
   Embedding a permitted type also lets callers introduce composite values. I confirmed a
   missing Prop.Value serializes as null without error, although the wire contract rejects
   it.

   Replace this interface with a concrete scalar value using private representation,
   constructors, typed accessors, and validated marshaling. That also removes the scattered
   assertions in assembly and enrichment.

On your specific any requirement: there are no production map[string]any maps. The one
production use is readYAML[T any] (pkg/enrich/federatedcode/replay.go:251), which preserves
compile-time typing and introduces no cast. A literal ban can narrow its constraint to the
supported result types. Sink, Decorator, and Enricher are small, purposeful interfaces; I
would retain them.

Specification and behavior

8. [P1] Polling loses failed documents after retries are exhausted.
   pkg/pipeline/pipeline.go:366 logs a sink failure and returns success to collection. The
   file collector will not emit that unchanged file again. An outage can therefore leave
   permanent gaps after service recovery. Retain failed streams for replay or fail the run
   with committed progress, as specification §2.6 requires.

9. [P1] Shutdown cancels accepted work instead of draining it.
   pkg/guacseam/collect.go:246 uses the signal-canceled context for queued processing and
   downstream writes. SIGTERM aborts those writes; polling swallows the errors, and the CLI
   reports “drained.” Separate intake cancellation from a bounded processing/drain context.

10. [P2] A slow early document defeats the bounded worker pool.
    pkg/guacseam/collect.go:258 keeps consuming later results into an unlimited reorder map
    while waiting for an earlier result. This retains document bytes and parsed predicates.
    Bound outstanding sequence positions, not just channel capacities. Network response
    allocation also needs limits at pkg/varve/client.go:232.

11. [P2] Clean OSV scans generate “affected” claims.
    pkg/enrich/derive.go:33 converts GUAC’s vuln:novuln sentinel into FactAffected. I
    reproduced this. Queries counting affected claims can flag clean packages. Filter the
    sentinel or represent clean scans explicitly.

12. [P2] Some enrichment and expansion failures disappear from receipts.
    pkg/pipeline/pipeline.go:228 bypasses failure reporting for GUAC scanner sources, whose
    errors are only logged upstream. pkg/guacseam/expand.go:59 silently skips malformed
    expansion documents. Both can report incomplete ingestion without the promised failure
    accounting.

go test ./..., go test -race ./..., and go vet ./... passed. Local probes reproduced the
redirect leak, both identity collisions, null serialization, and the clean-scan claim bug.
Dependency scanning completed using Go 1.26 because the installed scanner could not analyze
Go 1.27; its standard-library findings therefore do not describe your current Go 1.27.1
build.
