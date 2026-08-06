# Valid-time demo fixture provenance

The two fixtures under `testdata/valid-time/` are copies of
`testdata/sboms/small-spdx.json` (itself adapted from GUAC v1.1.0 exampledata,
Apache-2.0), each with a single altered timestamp so the S2 valid-time guard can
be exercised end to end:

- `backdated/small-spdx.json`: `created` set to `2025-01-15T00:00:00Z` (a
  backdated but in-bounds instant) so `FOR VALID_TIME AS OF` time-travel is
  observable — the SBOM's records are absent before 2025-01-15 and present after.
- `epoch/small-spdx.json`: `created` set to `1970-01-01T00:00:00Z` (valid
  RFC3339, so the SPDX parser still accepts it; the guard is what rejects it,
  falling back to ingest time and counting the fallback).

Each fixture's `documentNamespace` gains a distinct suffix
(`/valid-time-backdated`, `/valid-time-epoch`) so the two are separate SBOMs. The
three package names are unchanged. Every other byte is identical to the source
fixture.

Each fixture is the only file in its directory because the GUAC file collector
ingests every file in the target directory; this provenance file therefore lives
at the `testdata/` root, outside any collected directory.

## License / attribution

GUAC is licensed under the Apache License, Version 2.0
(https://www.apache.org/licenses/LICENSE-2.0). These fixtures are redistributed
under that same license; all rights and attributions remain with the GUAC
authors.
