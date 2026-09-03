# EUVD fixture provenance

`testdata/euvd/search-cve-2024-3094.json` is the body ENISA's European
Vulnerability Database returned on 2026-09-03 for

    GET https://euvdservices.enisa.europa.eu/api/search?text=CVE-2024-3094&size=1

recorded verbatim. It is public vulnerability data about the xz backdoor. The
field names are the API's: `id`, `enisaUuid`, `description`, `datePublished`,
`dateUpdated`, `baseScore`, `baseScoreVersion`, `baseScoreVector`,
`references` (newline separated), `aliases` (newline separated), `assigner`,
`epss`, `enisaIdProduct`, `enisaIdVendor`. Dates are `Jan 2, 2006, 3:04:05 PM`.

`testdata/euvd/search-empty.json` is the body the same endpoint returned for
`text=CVE-2099-99999`, a name no record carries: `{"items":[],"total":0}`,
HTTP 200.

Also observed on 2026-09-03: `GET /api/enisaid?id=EUVD-2024-31700` returns one
item of the same shape (HTTP 200); `GET /api/vulnerability?id=CVE-2024-3094`
returns HTTP 403 whatever the headers. The enricher uses `search`.

Both files sit under `testdata/euvd/`, which is never a receiver path, so the
file collector does not see them.
