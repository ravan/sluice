# VulnerableCode fixture provenance

`testdata/vulnerablecode/affected-by-lodash-4.17.21.json` is the body
AboutCode's VulnerableCode returned on 2026-09-03 for

    GET https://public2.vulnerablecode.io/api/v3/affected-by-advisories?purl=pkg:npm/lodash@4.17.21
    User-Agent: VCIO_API_AGENT

recorded verbatim. It is public vulnerability data about lodash.

The `User-Agent` header is not optional. `VCIOUserAgentMiddleware` rejects any
request to `/api/` whose header is not exactly `settings.VCIO_USER_AGENT`,
default `VCIO_API_AGENT`, with `403 {"detail": "Unauthorized client..."}`. The
project's own API documentation states the header and says requests without it
are rejected. No API key is involved; a key only raises the rate limit from 10
requests a minute to 30.

Use `public2.vulnerablecode.io`. On 2026-09-03 `public.vulnerablecode.io`
answered HTTP 500 on every path, its home page included.

The API is **V3**. `/api/v2/...` answers 404: upstream `vulnerablecode/urls.py`
routes `/api/v3/` only. See the [ADR 0031 amendment](../docs/adr/0031-slice-2-split-into-2a-and-2b.md).

Response shape, from `vulnerabilities/api_v3.py`
`AffectedByAdvisoryV3Serializer`: `{count, next, previous, results[]}` where
each result carries `advisory_id`, `advisory_uid`, `url`, `aliases[]`,
`summary`, `severities[]`, `weaknesses[]`, `references[]`, `exploitability`,
`weighted_severity`, `risk_score`, `related_ssvc_trees`, `fixed_by_packages[]`,
`todo_count`, `is_curation`, `curating_advisories`.

A severity is `{url, value, scoring_system, scoring_elements}`, plus
`published_at` when set. Observed in this capture: `value` may be the empty
string, a number as a string (`"6.5"`), or a word (`"MODERATE"`);
`scoring_system` values include `cvssv3.1` and `generic_textual`, and the git
export also carries `epss`, `rhas` and `cvssv3`. `url` may be `null`.

`testdata/vulnerablecode/affected-by-empty.json` is the shape returned for a
purl with no advisories: `{"count":0,"next":null,"previous":null,"results":[]}`,
HTTP 200.

Both files sit under `testdata/vulnerablecode/`, which is never a receiver
path, so the file collector does not see them.
