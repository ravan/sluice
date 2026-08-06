# Corpus provenance

The `*.json` fixtures in `internal/assemble/testdata/corpus/` are copied verbatim
from GUAC v1.1.0:

- Source: `github.com/guacsec/guac@v1.1.0`
- Path in module: `internal/testing/testdata/exampledata/*.json`
- Copied on 2026-08-07 from the local Go module cache (`go env GOMODCACHE`).

Because that tree lives under GUAC's `internal/`, it cannot be imported and is
copied instead. Only the `*.json` documents are copied; the compressed
(`.bz2`/`.zst`), XML, and directory entries in that source tree are excluded.

## License / attribution

GUAC is licensed under the Apache License, Version 2.0
(https://www.apache.org/licenses/LICENSE-2.0). See the `LICENSE` file in the
GUAC repository. These fixtures are redistributed under that same license; all
rights and attributions remain with the GUAC authors.
