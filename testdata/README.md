# SBOM test fixtures

`sboms/small-spdx.json` is adapted from GUAC's test corpus at
`github.com/guacsec/guac/internal/testing/testdata/exampledata/small-spdx.json`
(pinned release v1.1.0). GUAC is licensed under Apache-2.0.

Two adaptations were needed so the fixture exercises GUAC v1.1.0's SPDX parser
(see S0 plan Deviations, and spec §4/§10):

1. The three package entries' `packageName` keys were changed to the
   SPDX-2.2-standard `name` key. GUAC parses SPDX via `spdx/tools-golang`,
   whose package name field is tagged `json:"name"`; with the upstream
   `packageName` key the names unmarshal empty and the whole document fails to
   parse (`unable to parse purl pkg:guac/pkg/@: purl is missing name`). With
   `name`, GUAC's guac-purl fallback yields the three packages `text`,
   `quote`, `sampler` (§4).

2. This README lives in `testdata/`, not in `testdata/sboms/`, because GUAC's
   file collector ingests every file in the directory it is pointed at. A
   README inside the corpus would be collected as an unparseable document and
   counted as a skipped failure.
