slice: S6
date: 2026-08-07
status: done
spec: docs/sluice-spec.md
plan: docs/plans/product/S6.md
next: roadmap complete — S6 was the last slice (full-dress gallery). No further /slice-plan.
notes:
- All 7 steps executed TDD/in order; sequential mode (plan offered no fan-out
  group, so the requested "subagent development" degraded to sequential per skill).
- Acceptance: all 6 items demonstrated live and green (recorded in the plan's
  Deviations section). Benchmark ~38-39k edges/s (PASS, ~93-96x the >=409 gate);
  crash-replay healed to 606/580/1094; gallery all 5 legs green from clean volumes;
  S0-S5 unbroken (docker-compose up -d starts only varve, just demo green).
- Contract fact note (ratify next revision): deploy/varve-writer.toml keeps the
  verbatim source's advertised_address="http://writer:8080" (plan prose said
  127.0.0.1:8080); only the auth token was changed. All demos POST from host to
  127.0.0.1:8080 and pass — a lone writer emits no 421, so verbatim is correct.
- Transient crash.log/replay.log are written to repo root by crash-replay.sh (as
  the verbatim block prescribes) and are NOT gitignored; .gitignore was outside
  Touches. Consider adding them if a clean post-demo git status matters.
gotchas:
- The gallery compose build context MUST be the repo root (Dockerfile.garage-init
  does `COPY deploy/garage-init.sh`); docker-compose.gallery.yml sets context: .
- `docker-compose config --services` on the default file lists only `varve`
  (registry/minio are profile-gated); both are still defined — S0-S5 untouched.
