# Identity encoding

Package IDs retain the `pkg:n:` and `pkg:v:` prefixes. Each component escapes percent signs, slashes, plus signs, pipes, carriage returns, and newlines before concatenation. A slash within a namespace therefore appears as `%2F`. Qualifier keys and values use URL query escaping and sort by key, then value. The complete qualifier field receives the same component escaping as other package fields.

Edge IDs retain the `<src>|<label>|<dst>` layout. Each field escapes percent signs and pipes before concatenation. The `src` and `dst` record fields still contain the original node IDs.

Evidence hashes use SHA-256 over fields encoded as decimal byte length, a colon, and the field bytes. For example, `("a", "bc")` encodes as `1:a2:bc`. Empty fields encode as `0:`. No separator follows a field. The encoding distinguishes an empty field from an absent field and accepts embedded separators without ambiguity.

The scalar properties `predicates` and `checks` contain key-value pairs sorted by key, then value. Both fields in each pair use the same length-prefix encoding. ID-list properties such as `members`, `builtFrom`, and `declaredLicenses` also use length prefixes. An empty list encodes as an empty string.

These changes require the [graph rebuild procedure](identity-migration.md).
