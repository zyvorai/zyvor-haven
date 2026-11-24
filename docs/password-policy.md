# Password policy

haven-idp checks new passwords (admin reset, emailed-link reset, bootstrap)
against a realm policy string, a Keycloak-style list of terms joined by
` and `:

```
length(12) and digits(1) and notCommon() and notPersonal() and notBreached()
```

Terms with a number are numeric minimums. Unknown or malformed terms are
ignored (so a policy imported from Keycloak never breaks); an empty policy
accepts everything. Checks run in the order written and the first failure is
returned.

## Terms

| Term | Meaning |
|---|---|
| `length(n)` | at least n characters |
| `digits(n)`, `upperCase(n)`, `lowerCase(n)`, `specialChars(n)` | at least n of that class |
| `notCommon()` | not in the embedded weak-password list (see below) |
| `notPersonal()` | does not contain the user's name, username or email local part |
| `notBreached()` | not in an operator-supplied breach filter; does nothing until one is loaded |

`notCommon`, `notPersonal` and `notBreached` are case-insensitive and the
parentheses are optional (`notCommon` works too).

## `notCommon()`

The password is lower-cased and trimmed, then rejected if any of these is in
the list:

1. the password itself;
2. the password with up to 3 trailing digits or symbols removed (letters are
   never removed, and at least 4 characters must remain);
3. any of the above after leet-speak folding: `0`->o, `1`->l (and, separately,
   `1`->i), `3`->e, `4`->a, `5`->s, `7`->t, `@`->a, `$`->s.

So `Password1`, `p@ssw0rd`, and `Dragon!!` are rejected. Unicode normalisation
(NFKC) is not applied: only simple lower-casing.

### What the list is, honestly

The list shipped with the binary is **pattern-derived, 71,156 entries, not a
breach corpus**. No real common-password list was available when it was built,
and nothing is fetched at build or run time. It is generated deterministically
by `internal/idp/password/gen_common.go` from keyboard walks, every 4-digit
number, month/season/weekday + year, about 200 first names + digits/years, and
about 250 famous words with 60 typical suffixes. It catches lazy passwords; it
does not know what real attackers' dictionaries contain. Operators who need
real coverage should use `notBreached()` with a filter built from a corpus they
trust. Replacing `common.txt` with a real list (sorted, lower-case, one per
line) needs no code change.

Cost: about 0.68 MB of embedded text; the map is built once on first use. A
check takes roughly 0.3 to 0.9 microseconds after that.

## `notPersonal()`

Needs the user, so it only works through `CheckPolicyFor(policy, pw, Personal{...})`.
Plain `CheckPolicy` has no user context and accepts for this term. The password
is rejected if it contains, case-insensitively and also after the leet folding
above, the username, the part of the email before `@`, the first name or the
last name. Identifiers shorter than 4 characters are ignored so short names do
not reject half the world. The email domain is not checked.

## `notBreached()`

A bloom filter over SHA-1 digests of breached passwords. It has no false
negatives and a configurable false-positive rate (so a few strong passwords
may be rejected). **Haven ships no breach corpus.** Until the operator builds a
filter and registers it with `password.SetBreachFilter` (loaded with
`password.LoadBreachFilter(path)`), the term accepts every password.
`SetBreachFilter` is safe for concurrent use; `nil` unregisters.

`password.BuildBreachFilter(r, fpRate)` builds one from lines of plaintext
passwords or SHA-1 hex digests (also `HASH:count` lines as published by
haveibeenpwned). A plaintext password of exactly 40 hex characters is read as
a digest. At 0.1% false positives the filter costs about 14.4 bits (1.8 bytes) per entry;
building holds 20 bytes per line in memory. Matching is on the exact password
as typed. The check is entirely local: no password, prefix or hash leaves the
process. The command-line and `HAVEN_IDP_BREACH_FILTER` wiring is not part of
this change.

## Error messages

Messages are specific but never echo the password or any hash, and only say
which kind of rule failed: "too common", "contains your name or email",
"appears in a known breach".
