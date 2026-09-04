# testdata/federatedcode

Recorded 2026-09-03 from AboutCode's published FederatedCode data repository,
<https://github.com/aboutcode-data/vulnerablecode-data>, branch `main`.

That repository is the "single repo" layout of the `aboutcode.hashid` 0.2.0
scheme: every `aboutcode-packages-<type>-<purl-hash>` bucket is a directory
rather than its own git repository, and the vulnerability files live beside
them under `aboutcode-vulnerabilities/`.

## `vulnerabilities-npm-lodash.yml`

Source path: `aboutcode-packages-npm-026/npm/lodash/vulnerabilities.yml`.

`026` is `get_purl_hash("pkg:npm/lodash", 10)`. npm is a 10-bit ecosystem in
`aboutcode.hashid`'s `BIT_COUNT_BY_ECOSYSTEM`.

The upstream file is 1199 lines, one entry per published lodash version. The
first three entries are kept verbatim; nothing else is changed.

## `VCID-4wn8-fck1-aaaq.yml`

Source path: `aboutcode-vulnerabilities/4w/VCID-4wn8-fck1-aaaq.yml`. The
directory is characters 5 and 6 of the VCID.

The upstream file is 867 lines, almost all of it a daily EPSS history. Kept
verbatim: `vulnerability_id`, `aliases`, `summary`, `weaknesses`, the first
four `severities` entries and the first three `references` entries.

The four severities are the reason this file is the parser fixture. They are a
`generic_textual` scored `Medium`, an `rhas` scored `Important`, a `cvssv3`
scored `2.9` with a vector, and an `epss` scored `0.00103`. A source mixes
scoring systems in one list and a score can be a word, so the `cvss` fact is
the first entry whose system starts with `cvssv` **and** whose score parses as
a number.

## What was not recorded

AboutCode also publishes a newer federation layout: a configuration file at
<https://github.com/aboutcode-data/aboutcode-data> describing data clusters
with `number_of_repos` and `number_of_dirs`, served from `purls-<type>-<n>`
and `security-advisories` repositories. Its bucket arithmetic is not
`aboutcode.hashid`'s, and on 2026-09-03 its package data was only partly
populated. Silt slice 2c targets the `aboutcode.hashid` scheme above.
