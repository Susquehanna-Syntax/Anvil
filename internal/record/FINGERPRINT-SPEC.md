# FINGERPRINT-SPEC.md — the authoritative definition of `anvil-fp/v1`

**Status:** normative. **Version:** `anvil-fp/v1`. **Last amended:** 2026-08-08.

This document is the single definition of Anvil's finding-identity algorithm. It is deliberately
**in-tree**: `plan/` is gitignored, so a second producer working from a clone of this repository must
be able to read the complete algorithm here and nowhere else, and emit byte-identical digests.

`plan/40-record-and-storage.md`'s "Fingerprint Specification" section remains the record of *why* the
research-branch conflict was resolved the way it was. It is a **summary**, not the definition.
`internal/record/CRITIQUE-01.md` (finding 1) proved the summary insufficient by re-implementing its
four-clause `normalized_match` text in Python and obtaining `55e27b07…` where the committed golden for
`sast-01-go-sql-string-concat` is `13c60ccf…`. The orchestrator ruled on 2026-08-08 that the
implementation was right and the specification incomplete, and that the fix was to write the
specification down completely. This file is that ruling discharged. **Where this document and
`plan/40-record-and-storage.md` disagree, this document governs.**

`internal/record/fingerprint.go` implements it. `internal/record/fingerprint_spec_test.go` asserts that
the machine-checkable parts of this document — the reserved-word list and the algorithm constants —
are exactly the ones in the code, so the two cannot drift apart silently.

---

## 0. The versioning rule — read before editing anything below

**Every rule in this document is load-bearing on stored identity.** Changing *any* of it —
adding one reserved word, moving one threshold by one, reordering two normalization steps, altering a
token's spelling — changes digests that are already stored, and a changed digest means a finding is
reported resolved and re-opened as new: `first_seen_at` resets, age-based ranking resets, every
fingerprint-keyed suppression silently stops applying, and every `handoff` row keyed on the old digest
is orphaned. Nothing logs an error when this happens. That is the exact failure `plan/00-SPINE.md` S6
exists to prevent: *"two producers emitting different hashes means regression matching silently fails
forever."*

> **Any change to this document's algorithm is an `anvil-fp/v2` event, never a `v1` edit.**

`fingerprint.go`'s `fingerprintReservedWords` comment says the same thing, and the two must keep saying
it. Shipping `v2` means: bump the algorithm name, dual-write both `v1` and `v2` values into
`finding_fingerprint` for one full retention cycle, match on `v1 OR v2` during that cycle, then retire
`v1`. Do not edit a golden digest to make a test pass.

The **prose, rationale and examples** in this document may be improved freely. Only the rules may not.

---

## 1. Primitives

### 1.1 Field separator

Fields are joined with **U+001F**, the ASCII Unit Separator (`"\x1f"`), in the exact order each tier
lists. Nothing else separates them; there is no prefix, suffix, length prefix, or trailing separator.

U+001F was chosen over a printable glyph because a printable separator can occur inside a snippet or a
symbol name and silently move a field boundary — hashing `("a‖b", "c")` and `("a", "b‖c")` would
collide. U+001F cannot appear in normalized source text.

### 1.2 Field guard

Before joining, **every** field is checked. A field containing any character in `U+0000`–`U+001F` or
`U+007F` (C0 controls and DEL) is **rejected with an error**; the digest is not computed. U+001F is the
case that matters, but the whole control range is rejected, because none of these can legitimately
appear in a canonicalised path, rule id, symbol path, route template, purl, advisory id, or normalized
match — and a newline in one of them means the caller passed raw, uncanonicalised text.

An empty **field list** is rejected. An empty **field value** is legal wherever the tier says so
(`enclosing_symbol_path`, `param_name`), and is hashed as a zero-length field, which keeps the field
count constant.

### 1.3 Digest

    DIGEST = lowercase hex-encoded SHA-256 of the UTF-8 bytes of the joined string

Exactly **64 lowercase hex characters. Never truncated.** Uppercase hex is not a valid digest and must
be rejected rather than folded — a store that accepted both would hold two rows for one finding and
defeat `UNIQUE (target_id, fingerprint)`.

All string handling is on **UTF-8 bytes**. No Unicode normalization (NFC/NFD) is applied anywhere; see
§9.

---

## 2. The four tiers

Exactly four tiers exist. Each is a fixed, ordered field list. A wrong field *order* produces a
perfectly valid-looking 64-hex digest that is silently incompatible, so the order below is normative.

### 2.1 Tier SAST — `evidence_class ∈ {sast_reachable, sast_static_only}`

    sha256( target_id ␟ "sast" ␟ rule_id_versioned ␟ repo_relpath
          ␟ enclosing_symbol_path ␟ normalized_match ␟ ordinal )

Seven fields.

| # | Field | Derivation | Empty allowed |
|---|---|---|---|
| 1 | `target_id` | verbatim | no |
| 2 | `"sast"` | the literal string `sast`, for **both** evidence classes | — |
| 3 | `rule_id_versioned` | verbatim, e.g. `opengrep.go.sqli@2026.07.1` | no |
| 4 | `repo_relpath` | §7.1 `CanonicalRepoRelPath` | no (nor after canonicalisation) |
| 5 | `enclosing_symbol_path` | verbatim, e.g. `pkg/mod.py::ClassA.method_b` | **yes** |
| 6 | `normalized_match` | §3, from the raw snippet | no (nor after normalization) |
| 7 | `ordinal` | §4, rendered as a base-10 integer with no padding and no sign | no; negative is rejected |

Field 2 is the literal `sast` and **not** the evidence class, so a finding upgraded from
`sast_static_only` to `sast_reachable` keeps its identity.

`enclosing_symbol_path` may be empty because a match in top-level module code, a config file, or a
template has no enclosing symbol, and rejecting those would make them unfingerprintable.

**Never hashed by this tier:** line number, column number, the literal (non-normalized) snippet text,
`advisory_id`, the evidence class, any timestamp.

### 2.2 Tiers SCA and HOST — one formula, parameterised

    sha256( target_id ␟ detector_kind ␟ advisory_id ␟ purl_base ␟ locator )

Five fields. `detector_kind` is the literal `sca` for repository dependencies and `host` for operating
system packages. It is the only thing keeping a repo dependency and a host package with the same
advisory apart, and it must be present: without it a host finding (`remediable_by_agent=false`) could
upsert over an agent-remediable dependency finding.

| # | Field | Derivation |
|---|---|---|
| 1 | `target_id` | verbatim |
| 2 | `detector_kind` | the literal `sca` or `host` |
| 3 | `advisory_id` | **verbatim, not case-folded** — GHSA identifiers mix case meaningfully and folding would fork identity against the advisory table |
| 4 | `purl_base` | §7.2 `PurlBase` |
| 5 | `locator` | SCA: `manifest_relpath` through §7.1. Host: `"<package_manager>:<host_identifier>"`, §7.3 |

**Never hashed by these tiers:** the version string. Bumping `1.2.3` → `1.2.4` while still inside the
vulnerable range must not mint a new finding; resolution is proved by re-evaluating `advisory_affects`,
never by an identity change. `PurlBase` strips the version defensively even if a caller passes it.

### 2.3 Tier DAST — `evidence_class = dast_confirmed`

    sha256( target_id ␟ "dast" ␟ rule_id_versioned ␟ http_method ␟ route_template
          ␟ injection_point ␟ param_name ␟ evidence_class_detail )

Eight fields.

| # | Field | Derivation | Empty allowed |
|---|---|---|---|
| 1 | `target_id` | verbatim | no |
| 2 | `"dast"` | the literal string `dast` | — |
| 3 | `rule_id_versioned` | verbatim, e.g. `nuclei:CVE-2021-44228@a1b2c3d` | no |
| 4 | `http_method` | §7.4: trimmed, then upper-cased | no |
| 5 | `route_template` | §6 `CanonicalRouteTemplate` — a **derived** value | no (nor after derivation) |
| 6 | `injection_point` | one of `query`, `body`, `header`, `cookie`, `path`; any other value is rejected | no |
| 7 | `param_name` | verbatim. A parameter **name**, never a parameter **value** | **yes** |
| 8 | `evidence_class_detail` | one of `responseStackTrace`, `statusCodeFlip`, `dbErrorString`, `timingSideChannel`, `reflectedPayload`, `other`; any other value is rejected | no |

Fields 6 and 8 are independent facts — *where* the payload went in versus *how* the defect was
observed. An SQL injection proved by a database error string and one proved by a timing side channel on
the same parameter are different findings with different remediation evidence.

`param_name` may be empty: a whole-body, raw-request, or path-segment injection has no single named
parameter.

**Never hashed by this tier:** host, port, scheme, the concrete payload string, any session token, any
timestamp.

---

## 3. `normalized_match` — the complete algorithm

This section is the one CRITIQUE-01 proved was under-specified. It is stated here in full. A
re-implementation that follows §3.1–§3.6 and the word list in §3.5 reproduces the committed SAST
goldens exactly.

The algorithm is **one left-to-right pass over Unicode code points**, with no lookbehind beyond the
output buffer and no lookahead beyond skipping spaces. It is a single language-agnostic lexer, not N
parsers: Anvil's SAST tier is an opengrep subprocess that returns text, and the language is not
reliably known at fingerprint time. Determinism, not semantic perfection, is the property identity
needs.

### 3.1 Preprocessing

1. Replace every `"\r\n"` with `"\n"`.
2. Replace every remaining `"\r"` with `"\n"`.

Both replacements are global and are applied in that order. (Order matters only in that step 1 must
precede step 2, or a CRLF would become two newlines.)

The result is then decoded as a sequence of Unicode code points and scanned. Two output helpers are
used below:

- **emit(s)** appends the characters of `s` to the output.
- **emitSpace()** appends a single space **only if** the output is non-empty and does not already end
  in a space. It never produces two consecutive spaces and never produces a leading space.

### 3.2 The scan

At each position, the **first** matching rule below is applied. The rules are ordered; the order is
normative.

| # | Condition at the current character `c` | Action |
|---|---|---|
| 1 | `c` is whitespace (Unicode `IsSpace`: `\t \n \v \f \r`, space, U+0085, U+00A0, and the Unicode space separators) | consume the whole whitespace run; `emitSpace()` |
| 2 | `c` is `/` and the next character is `/` | consume to the next `\n` (not consuming it) or to end of input; `emitSpace()` |
| 3 | `c` is `#` | consume to the next `\n` (not consuming it) or to end of input; `emitSpace()` |
| 4 | `c` is `/` and the next character is `*` | consume through the closing `*/`; if there is none, consume to end of input; `emitSpace()` |
| 5 | `c` is `"`, `'` or `` ` `` | consume the string literal per §3.3; `emit("<STR>")` |
| 6 | `c` is an ASCII digit `0`–`9` | consume the number token per §3.4; `emit("<NUM>")` |
| 7 | `c` is an identifier-start character | consume the identifier and dispose of it per §3.6 |
| 8 | anything else | append `c` verbatim; advance one character |

**Identifier-start** is: `_`, `$`, or any character with Unicode general category L (`IsLetter`).
**Identifier-part** is: `_`, `$`, any letter, or any digit (`IsDigit`, i.e. Unicode category Nd — not
only ASCII).

Note the consequences, which are accepted and stable:

- `#` is a line comment, so a C/C++ preprocessor directive or a C# `#region` inside a snippet is
  dropped. Match snippets rarely contain them.
- `'` is a string delimiter, so a Rust lifetime (`'static`) or a Lisp quote consumes to the next `'`.
- Rule 3 is tested before rule 4 is reachable for `#`, and rule 2 before rule 4 for `//`, so `//*` is a
  line comment, not a block comment.

### 3.3 String literals

Having consumed the opening delimiter `q` (one of `"`, `'`, `` ` ``), scan forward:

- If the current character is `\` **and `q` is not** `` ` ``, skip **two** characters (the backslash and
  whatever follows it, including a closing delimiter or another backslash) and continue.
- If the current character is `q`, consume it and stop.
- Otherwise consume one character and continue.
- If input ends first, stop.

Backslash escapes are therefore honoured inside `"` and `'` and **not** inside `` ` `` — matching Go's
raw string literals, where a backslash has no special meaning.

Exactly one `<STR>` is emitted per literal, regardless of its contents or length. No space is emitted
around it.

### 3.4 Number tokens

Having seen an ASCII digit, consume characters while **either**:

- the character is a letter (`IsLetter`), a digit (`IsDigit`), `_`, or `.`; **or**
- the character is `+` or `-` **and** the immediately preceding *input* character was `e` or `E`.

Stop at the first character satisfying neither. Exactly one `<NUM>` is emitted.

This grammar deliberately makes each of the following a **single** token: `0xFF`, `1_000`, `3.14f`,
`1e-9`, `1E+10`, `100L`, `0b1010`, `12.5e-3`. It also means `1.2.3` is one token, and that a number
immediately followed by a letter (`42px`) is one token. A number can never *start* a token that begins
with a letter, because rule 7 would have matched first.

### 3.5 Identifier disposition — the rules the summary omitted

Having consumed an identifier `word`, apply the **first** matching clause:

| Clause | Condition | Emit | Why |
|---|---|---|---|
| **(a)** | `word` is in the reserved-word list below | `word` verbatim | A keyword is not a name a refactor renames. Abstracting `for`, `return` or `int` would erase the statement's shape and merge structurally different code. |
| **(b)** | the output so far, **ignoring trailing spaces**, ends in `.`, `->`, or `::` | `word` verbatim | `word` is a member, field, method or qualified name — API surface, not churn. Abstracting it would normalise `request.getParameter(userInput)` and `config.getName(key)` to the same string, destroying nearly all discriminating power and pushing the whole burden of distinguishing findings onto `ordinal`, the least stable field in the tier. |
| **(c)** | the next non-space **input** characters are `::` | `word` verbatim | The **left** operand of `::` is a namespace or type name in every language that has the operator (C++, Rust, PHP, Ruby) — never a local variable. Abstracting it would violate "replace local identifiers" outright **and** collapse `Ns::Helper(v)` and `Other::Helper(v)` — two calls into two different namespaces — onto one digest. |
| **(d)** | the next non-space **input** character is `(` | `word` verbatim | `word` is a callee name: the sink the rule actually matched. `exec(x)` and `spawn(x)` are different findings. |
| **(e)** | otherwise | `$N` | `word` is a local. `N` counts **distinct spellings** in first-occurrence order starting at 1, and every later occurrence of the same spelling maps to the same `$N`. This is what survives a rename. |

Clause (b) asks about the **output**; clauses (c) and (d) ask about the **input**. That asymmetry is
deliberate: (b) looks at what has already been decided (a `.` survives step 8 verbatim, so it is
visible in the output), while (c) and (d) look ahead at text not yet scanned.

**Why (b) treats `.` and `->` differently from (c)'s `::`.** The *left* operand of `.` or `->` is
usually a receiver bound to a local (`db.Query(q)`, `p->Field`), so it **is** abstracted — a lexer
cannot tell a Go package qualifier from a receiver variable, and guessing wrong in the other direction
would fork the digest of unchanged code, which is the worse failure. The *left* operand of `::` is
never a local, so it is preserved. Both operands to the *right* of any of the three are preserved by
(b).

The metavariable counter and the spelling→`$N` map are **per call** to the normalizer: they start empty
for every snippet. `$1` in one finding has no relationship to `$1` in another.

The map must never be iterated. Numbering comes from a counter advanced in source order. (In Go, map
iteration order is randomised per process; a re-implementation that numbered by iterating a hash map
would produce a stable-but-wrong order within a run and a different one in the next, which is the
cross-process nondeterminism `TestCorpusDigestsAreStableAcrossProcesses` exists to catch.)

#### The reserved-word list, verbatim

This is a **union** across the languages Anvil's SAST tier covers (Go, Java, C#, C/C++,
JavaScript/TypeScript, Python, Ruby, PHP): keywords, literal keywords and self-references, and
primitive/built-in type names. It is a union on purpose — a per-language list would require knowing the
language at fingerprint time, which the opengrep subprocess boundary does not reliably give us, and a
wrong language guess would change the digest of unchanged code. The union is a fixed, deterministic
function of the token text alone.

The cost is accepted: an identifier named `class` in a language where `class` is not reserved is
preserved rather than abstracted. That is stable under re-scan, which is the property that matters.

Matching is **exact and case-sensitive**. `None` is in the list; `NONE` is not. Whitespace-separated,
sorted in byte order (uppercase before lowercase), **193 entries**:

<!-- ANVIL-FP-RESERVED-WORDS: BEGIN -->
```text
False NULL None True abstract and any as
assert async await base begin bigint bool boolean
break byte case catch chan char checked class
clone cls complex128 complex64 const constexpr continue debugger
decimal declare def default defer del delete do
double echo elif else elseif elsif end endforeach
endif endwhile ensure enum error except exit explicit
export extends extern fallthrough false final finally float
float32 float64 fn for foreach friend from func
function global go goto if implements implicit import
in include include_once inline instanceof insteadof int int16
int32 int64 int8 interface internal iota is keyof
lambda let lock long match module mutable namespace
native never new nil none nonlocal not null
nullptr object operator or out override package params
pass print private protected public raise range readonly
redo ref register require require_once require_relative rescue retry
return rune sbyte sealed select self short signed
sizeof stackalloc static strictfp string struct super switch
symbol synchronized template this throw throws trait transient
true try type typedef typeof uint uint16 uint32
uint64 uint8 uintptr ulong unchecked undefined union unknown
unless unsafe unsigned until use ushort using var
virtual void volatile wchar_t when while with xor
yield
```
<!-- ANVIL-FP-RESERVED-WORDS: END -->

`fingerprint_spec_test.go` asserts this block is exactly the set in `fingerprint.go`, is sorted, and
has no duplicates.

### 3.6 Final trim

The output has leading and trailing **spaces** removed (`TrimSpace` over the whole result). Because
`emitSpace()` never emits doubled spaces and no other rule emits whitespace, the result contains no
`\t`, `\n`, `\r`, and no run of two spaces — which is what lets it pass §1.2's field guard.

A snippet that normalises to the **empty string** (comments and whitespace only) is **rejected**: it
carries no identity.

### 3.7 Worked examples

Each of these is pinned by a test.

| Input | Output |
|---|---|
| `rows, err := db.Query("SELECT * FROM users WHERE name = '" + name + "'")` | `$1, $2 := $3.Query(<STR> + $4 + <STR>)` |
| `os.system("rm -rf " + path)` | `$1.system(<STR> + $2)` |
| `a = b + a + b` | `$1 = $2 + $1 + $2` |
| `rows := db.Query(userInput)` | `$1 := $2.Query($3)` |
| `for i := range items { return nil }` | `for $1 := range $2 { return nil }` |
| `value = compute(x)  # trailing note` | `$1 = compute($2)` |
| `a = 0xFF + 1_000 + 3.14f + 1e-9` | `$1 = <NUM> + <NUM> + <NUM> + <NUM>` |
| `s = "a \" b" + t` | `$1 = <STR> + $2` |
| `p->Field = Ns::Helper(v)` | `$1->Field = Ns::Helper($2)` |
| `std::vector<int> v = Foo::Bar::make(x)` | `std::vector<int> $1 = Foo::Bar::make($2)` |
| `Ns::Helper(v)` | `Ns::Helper($1)` |
| `Other::Helper(v)` | `Other::Helper($1)` |
| `totalCount := len(itemsList)` | `$1 := len($2)` |
| `a\n/* one\n   two */\nb` | `$1 $2` |
| `  // nothing here \n\n` | *(empty — rejected)* |

Trace of the first row, to remove all doubt:

1. `rows` — identifier, not reserved; output is empty so (b) fails; next non-space is `,` so (c) and
   (d) fail → `$1`.
2. `,` → verbatim. Space → one space.
3. `err` → `$2`. Space, `:`, `=` → verbatim (`:=` is two applications of rule 8). Space.
4. `db` — next non-space is `.`, not `::` or `(` → `$3`.
5. `.` → verbatim.
6. `Query` — output ends in `.` → clause (b) → `Query` verbatim. (Clause (d) would also have fired.)
7. `(` → verbatim.
8. `"SELECT * FROM users WHERE name = '"` — a double-quoted string; the `'` inside is ordinary
   content → `<STR>`.
9. ` + ` → space, `+`, space. `name` → `$4` (a new spelling).
10. ` + ` then `"'"` → `<STR>`, then `)` → verbatim.

---

## 4. `ordinal` and its grouping key

`ordinal` is the **0-based index of this match among all matches of the same rule in the same file
whose `normalized_match` is identical**. It exists because without it two identical macro-expanded or
generated call sites in one file hash identically and the second finding is **lost** on upsert against
`UNIQUE (target_id, fingerprint)`. Losing a finding is worse than churning one.

**Grouping key** — four components, joined with U+001F for comparison purposes only (never hashed as a
group):

    target_id ␟ rule_id_versioned ␟ CanonicalRepoRelPath(repo_relpath) ␟ normalized_match

`target_id` is included because the specification's grouping is implicitly per-target; passing two
targets' candidates in one batch would otherwise cross-index them.

**Ordering within a group** — ascending by, in order:

1. source line number,
2. source column number,
3. the candidate's original index in the batch (a stable tiebreak).

Line and column are used **only** for this ordering. They are never hashed and never reach the digest.
The sort must be stable.

**Known limitation, inherited from the specification rather than chosen here.** Inserting a third
identical call site above two existing ones shifts their ordinals and therefore their digests. The
alternative — dropping the ordinal — silently loses one of two findings on upsert, which is worse.
research/07 §3's matching cascade (exact hit, then rule+path+line_hash, then rule+symbol_hash) is what
recovers identity in that case; the fingerprint alone cannot. CRITIQUE-01 findings 4 and 5 raise two
sharper forms of this and are **not ruled on** — see §10.

---

## 5. `repo_relpath`, `purl_base`, `locator`, `http_method`

*(§6 covers `route_template` separately; it is the longest.)*

### 5.1 `CanonicalRepoRelPath` — see §7.1
### 5.2 `PurlBase` — see §7.2
### 5.3 host locator — see §7.3
### 5.4 `http_method` — see §7.4

---

## 6. `route_template` — a DERIVED value

The specification has always defined this field as derived: *"numeric/UUID/hash path segments replaced
with a placeholder token."* CRITIQUE-01 finding 2 proved the derivation was not implemented, and that
no fixture could detect it because all three DAST fixtures arrived pre-templated.

**Ruling (2026-08-08): area 40 owns the fingerprint, so area 40 canonicalises.** A DAST producer emits
whatever route it observed — concrete or already templated in its own syntax. `CanonicalRouteTemplate`
derives the hashed template. This keeps **one owner**. If templating were the producer's job, two
producers seeing one defect at `/api/users/12345/orders` would emit `/api/users/12345/orders`,
`/api/users/{id}/orders` and `/api/users/:id/orders` — three digests, one defect, no error, regression
matching silently dead. This matters more than the SAST case because the DAST tier is what earns
"verified fixed" under `plan/00-SPINE.md` S7, and a reproduction that cannot be matched to its prior
finding cannot prove a fix.

### 6.1 The placeholder token

    <VAR>

One frozen token for every volatile segment class. Angle brackets are chosen for the same reason
`<STR>` uses them: RFC 3986 excludes `<` and `>` from every production a path segment can use, so they
must be percent-encoded to appear in a real URL, and a literal segment therefore cannot collide with
the placeholder. `<VAR>` is also itself recognised as an already-templated segment (§6.3, rule P),
which makes `CanonicalRouteTemplate` **idempotent** — a record read out of the store and
re-fingerprinted keeps its identity.

### 6.2 Steps, in order

1. If the input contains `?` or `#`, drop everything from the **first** occurrence of either. A query
   string or fragment in a "template" carries concrete values — exactly what templating removes — and
   `injection_point` plus `param_name` already record which query parameter was targeted.
2. Replace every `\` with `/`.
3. While the string contains `//`, replace every `//` with `/`.
4. If the string is now empty, the result is empty (and the DAST tier rejects it).
5. If the string does not start with `/`, prepend `/`.
6. If the string is longer than one character, remove a single trailing `/`.
7. If the string is exactly `/`, the result is `/`.
8. Otherwise split the string after the leading `/` on `/`, and replace every **volatile** segment
   (§6.3) with `<VAR>`. Re-join with `/` and prepend `/`.

Case is preserved on non-volatile segments: URL paths are case-sensitive and `/Search` is a different
route from `/search` on most servers. The UUID and hex predicates in §6.3 are themselves
case-insensitive, because the same identifier rendered in upper hex is the same identifier.

Percent-encoding is **not** decoded. Decoding could introduce a `/` and change the segment structure,
and a producer that percent-encodes a whole segment has emitted a different route.

### 6.3 Which segments are volatile

A segment is volatile if **any** of the following holds. Rules are evaluated in this order; the outcome
is the same token either way, but the order makes each rule independently testable. An empty segment is
never volatile.

| Rule | Name | Predicate |
|---|---|---|
| **P** | already templated | length ≥ 2 **and** (starts `{` and ends `}`) **or** (starts `<` and ends `>`) **or** starts `:` |
| **N** | numeric | non-empty and every character is an ASCII digit `0`–`9` |
| **U** | UUID | length exactly 36; `-` at 0-based offsets 8, 13, 18 and 23; every other character an ASCII hex digit (`0-9A-Fa-f`) |
| **H** | long hex | length ≥ **16** and every character an ASCII hex digit |
| **O** | long opaque | length ≥ **20**, every character ASCII alphanumeric (`A-Za-z0-9`), containing **at least one digit and at least one letter** |

**Rule P** accepts all three placeholder syntaxes in common use — OpenAPI/ASP.NET `{id}`,
Express/Rails/Sinatra `:id`, Flask/Werkzeug `<id>` (including converter prefixes like
`<int:user_id>`) — and normalises them onto the same token as a concrete segment. It also ignores the
placeholder's **name**: `{userId}` and `{id}` are the same token. This is mandatory, not cosmetic: a
DAST crawler, an OpenAPI document checked into the repo, and a route table exported from a framework
will disagree about which syntax and which name to use for the same route, and that disagreement must
not fork identity.

### 6.4 The thresholds, and why they are conservative

**The governing asymmetry.** Over-templating merges two genuinely distinct routes into one identity and
loses a finding on upsert against `UNIQUE (target_id, fingerprint)` — silently. Under-templating only
leaves a volatile route un-merged, which the DAST producer can still repair by emitting `{id}` itself.
Under-templating is the recoverable direction, so both thresholds sit well above any plausible
human-authored path segment.

**`routeHexSegmentMinLen = 16`** (rule H). The hex alphabet's letters are only `a`–`f`; a 16-character
English word drawn from `{a,b,c,d,e,f}` plus digits does not exist — the longest such words
(`defaced`, `cabbage`) are seven letters. Meanwhile every hash form Anvil will meet in a URL clears it:
MD5 is 32, SHA-1 is 40, SHA-256 is 64, a dash-free UUID is 32. A **short git object id (7–12
characters) is deliberately NOT templated**, because 7 hex characters is also a plausible slug.

**`routeOpaqueSegmentMinLen = 20`** (rule O). Measured against the longest plausible single-word route
segments: `recommendations` (15), `misrepresentation` (17), `internationalization` (20). None contains
a digit — which is why the **digit requirement carries most of the safety here**, not the length alone.
Real opaque tokens clear the bar comfortably: a base64url session token is 22+ characters and a base32
token is 26+.

Rule O's three restrictions each buy something specific, and dropping any of them over-templates:

- **Alphanumeric only** (no `-`, `_`, `.`) keeps slugs out. `release-notes-2026-08` is 21 characters
  and carries a digit; it is route structure, not an identifier, and merging every dated release note
  onto one digest is exactly the over-templating failure. The cost is accepted: a **base64url token
  containing `-` or `_` is left un-templated**.
- **A digit is required**, which excludes the long all-letter words that do reach 20 characters.
- **A letter is required**, so a purely numeric run is attributed to rule N rather than rule O.

### 6.5 Worked examples

Volatile (all → `<VAR>`):

    12345   0   4192
    3f2504e0-4f89-11d3-9a0c-0305e82c3301   3F2504E0-4F89-11D3-9A0C-0305E82C3301
    3f2504e04f8911d39a0c0305e82c3301        (32 hex, rule H)
    e3b0c44298fc1c14                        (16 hex, rule H at the threshold)
    da39a3ee5e6b4b0d3255bfef95601890afd80709
    dXNlcjEyMzQ1Njc4OTAxMg                  (22 alnum with digits, rule O)
    {id}   {userId}   :id   :userId   <int:user_id>   <uuid:order_id>   <VAR>

Preserved (never templated):

    v1   v2   me   users   api   latest   oauth2   utf8   Search
    internationalization        (20 letters, no digit)
    recommendations
    release-notes-2026-08       (hyphenated slug)
    user_profile_settings       (underscored slug)
    deadbeef                    (8 hex, below 16)
    cafebabecafebab             (15 hex, below 16)
    a1b2c3d                     (short git object id)
    report.pdf   2026-08-08

Whole routes:

| Input | Output |
|---|---|
| `/api/v1/users/12345/orders` | `/api/v1/users/<VAR>/orders` |
| `/api/v1/users/{id}/orders` | `/api/v1/users/<VAR>/orders` |
| `/api/v1/users/:userId/orders` | `/api/v1/users/<VAR>/orders` |
| `api//v1/users/12345//orders/?debug=1` | `/api/v1/users/<VAR>/orders` |
| `/12345/orders/6789` | `/<VAR>/orders/<VAR>` |
| `/api/v1/users/me/orders` | `/api/v1/users/me/orders` |
| `/` | `/` |

`testdata/fingerprint_corpus/dast-04-idor-concrete-numeric-and-uuid-segments.json` is the fixture that
proves the derivation happens, with twelve mutations that must all produce one digest.

---

## 7. The remaining canonicalisations

Each of these was applied by the implementation but absent from the summary text (CRITIQUE-01 finding
9). They are normative.

### 7.1 `CanonicalRepoRelPath`

Applied to SAST `repo_relpath` and to the SCA locator (`manifest_relpath`). In order:

1. Replace every `\` with `/`.
2. While the string contains `//`, replace every `//` with `/`.
3. While the string starts with `./`, remove those two characters.
4. Remove a single leading `/` if present.
5. Remove a single trailing `/` if present.

So `./cmd/x.go`, `/cmd/x.go`, `cmd\x.go` and `cmd/x.go` are one path.

It deliberately does **not** case-fold — POSIX paths are case-sensitive and folding would merge two
genuinely distinct files. It does **not** resolve `..` — a path escaping the repo root is the caller's
bug and must not be silently rewritten into a different file. See §9 for what this does *not* achieve.

### 7.2 `PurlBase`

Reduces a package URL to its version-free base, `pkg:type/namespace/name`.

1. Trim surrounding whitespace. Reject an empty string.
2. The first four characters must be `pkg:`, compared **case-insensitively**; otherwise reject.
3. Take everything after `pkg:` and truncate it at the first `#` (subpath), then at the first `?`
   (qualifiers), then at the first `@` (version) — in that order.
4. Remove a single trailing `/`. Reject if nothing remains.
5. Lower-case everything up to the first `/` (the type). Reject if there is no `/` (a type but no name).
6. The result is `"pkg:"` + the processed remainder.

The scheme and type are lower-cased because the purl specification defines both as case-insensitive
with a lowercase canonical form. The **namespace and name are left alone**, because their
case-sensitivity is type-dependent and folding them could merge two distinct packages.

Truncating at the first raw `@` is safe against namespaced packages: purl requires a literal `@` inside
a namespace or name to be percent-encoded as `%40` (as in `pkg:npm/%40angular/core@13.0.0`), so the
first raw `@` can only be the version delimiter.

This step is the **enforcement point** for "the version string is never hashed": a caller who passes
the full versioned purl by mistake still gets a version-free fingerprint.

### 7.3 Host locator

    lower(trim(package_manager)) + ":" + trim(host_identifier)

The manager is lower-cased because `APT` and `apt` are the same manager and a case difference between
two scanner versions would fork every host finding at once. The identifier is **not** case-folded and
is otherwise verbatim: architecture and suffixes are meaningful to the manager (`openssl:amd64`).

A `package_manager` containing `:` is **rejected** — it is the locator's own delimiter, and allowing it
would make `a:b` + `c` indistinguishable from `a` + `b:c`. An empty manager or identifier (after
trimming) is rejected.

### 7.4 `http_method`

Trim surrounding whitespace, then upper-case. Reject if empty before trimming-and-checking, or if the
trimmed result contains any internal whitespace (it must be a single token).

RFC 9110 methods are case-sensitive and canonically uppercase; a producer sending `get` must not fork
identity from one sending `GET`.

Case folding uses the Unicode default case mappings, which are locale-independent. There is no
Turkish-I hazard.

---

## 8. Machine-checked constants

`fingerprint_spec_test.go` parses this block and asserts every value equals the corresponding constant
in `fingerprint.go` / `contract.go`.

<!-- ANVIL-FP-CONSTANTS: BEGIN -->
```text
FingerprintAlgV1            = anvil-fp/v1
FingerprintFieldSeparator   = U+001F
FingerprintDigestHexLen     = 64
NormalizedStringToken       = <STR>
NormalizedNumberToken       = <NUM>
NormalizedMetavarPrefix     = $
NormalizedRouteSegmentToken = <VAR>
routeHexSegmentMinLen       = 16
routeOpaqueSegmentMinLen    = 20
```
<!-- ANVIL-FP-CONSTANTS: END -->

---

## 9. What this algorithm does NOT do

Stated so the gaps are visible rather than assumed covered.

- **No Unicode normalization.** A path or symbol containing a precomposed versus decomposed accented
  character hashes differently. This is the macOS-checkout case (CRITIQUE-01 finding 8c).
- **No case folding of repo paths.** A Windows producer may legitimately report `Internal/API/Store.go`
  where a Linux producer reports `internal/api/store.go`. Different digests (finding 8a).
- **Backslash rewriting is lossy on POSIX.** A real Linux file named `a\b.go` canonicalises onto
  `a/b.go` and collides with the genuinely different file at that path (finding 8b).
- **`NormalizeMatch` does not strip C0 controls.** A snippet containing `NUL`, `BEL`, `ESC` or a raw
  `\x1f` survives normalization and is then rejected by §1.2, so the finding cannot be hashed at all
  (finding 7).
- **`rule_id_versioned` is hashed with its ruleset version.** An opengrep or nuclei-templates release
  bump re-mints every SAST and DAST fingerprint at once (finding 6).
- **`enclosing_symbol_path` is hashed but is not in the ordinal grouping key**, so deleting an
  unrelated function above a match can churn that match's ordinal and therefore its digest (finding 4).
- **Two semantically different sinks can share a `normalized_match`** (`exec(cmd)` and `exec(other)`
  both give `exec($1)`), leaving `ordinal` as the only discriminator; swapping the two lines swaps the
  two findings' identities (finding 5).
- **`primaryLocationLineHash` is not produced here.** It is not an `anvil-fp/v1` tier; it is a separate,
  line-dependent partial fingerprint for GitHub code-scanning de-duplication (finding 3).

None of these is ruled on by this document. See §10.

---

## 10. Provenance

| Date | Change |
|---|---|
| 2026-08-08 | Document created. Discharges the R.3 blocker-1 ruling: `normalized_match` was defined only in Go, so R.16's mandated independent oracle could not reproduce the SAST goldens and a second producer implementing from the written text would diverge silently. §3 is the algorithm written down completely; §5 and §7 close CRITIQUE-01 finding 9. |
| 2026-08-08 | §6 added. Discharges the R.3 blocker-2 ruling: `route_template` was specified as derived and derived by nobody. Templating is implemented in `CanonicalRouteTemplate` and owned by area 40. Two DAST goldens moved as a result — `dast-01` `ca801b8d…` → `199c3b5f…` and `dast-03` `84fe311d…` → `5fc15c55…`; `dast-02` and every SAST, SCA and host golden are unchanged. Nothing had been stored under the old digests, so this is a correction of an unimplemented clause, not a `v2` event. |

**Open, not ruled on.** CRITIQUE-01 findings 3, 4, 5, 6, 7, 8, 10 and 11 remain open. They are listed
in §9 so no downstream area assumes they are handled. Findings 4, 5 and 6 in particular each require an
orchestrator ruling before `anvil-fp/v1` is treated as final, and findings 4 and 6 would be `v2` events
if ruled in favour of the critic.

---

## Appendix Z — Where this specification is still under-determined

Recorded by the orchestrator on 2026-08-07, from the independent-oracle verification that closed
blocker 1. **These are not known bugs. They are places where the prose admits more than one reading and
the corpus happens not to distinguish them** — which is the same defect as blocker 1, one level down and
not yet triggered.

The verification that closed blocker 1 was real: an implementer working from this document alone,
forbidden from reading `fingerprint.go`, reproduced all 8 committed digests and 42/42 mutations on the
first run with no iteration. But **MATCH means this document is sufficient for what the corpus
exercises**, and the corpus exercises a narrow slice. Anyone extending the corpus, and `R.16` in
particular, should resolve these first — each one is cheap to settle now and expensive to discover as a
digest divergence later.

| # | Where | The ambiguity | What the oracle guessed |
|---|---|---|---|
| Z1 | §3.2 rule 1 | *"the Unicode space separators"* names category **Zs**, but Go's `unicode.IsSpace` implements the **White_Space** property, which also includes U+2028 (Zl) and U+2029 (Zp). | Included both. **Unverified** — no fixture contains non-ASCII whitespace. |
| Z2 | §3.5 clauses (c), (d) | *"the next non-space input characters"* — "non-space" is never defined and need not mean the same class as rule 1's "whitespace". | Used the full whitespace class, so `Ns\n::Helper(v)` preserves `Ns`. A narrower reading abstracts it. |
| Z3 | §6.3 rule P | *"length >= 2 and (starts { and ends }) or (starts < and ends >) or starts :"* — and/or precedence in prose is genuinely ambiguous. | Read as `len>=2 AND (A or B or C)`. The alternative parse differs for the one-character segment `:`. |
| Z4 | §4 (ordinals) | **Not exercised by the corpus at all.** Every SAST fixture supplies a pre-computed `ordinal` in its `input`; no fixture supplies a batch of candidates with line/column for an implementer to derive ordinals from. | Nothing — untested end to end. An independent implementation could get the grouping key wrong and still pass every current fixture. |
| Z5 | §3 generally | Only two snippet shapes appear (a Go `.`-selector call and a Python `.`-selector call) plus comment/CRLF/rename variants. **Unexercised:** §3.2 rule 4 block comments, §3.3 backtick raw strings and their no-escape rule, §3.4 `<NUM>` entirely, and most of the reserved-word list. | Nothing — those paths have no fixture. |
| Z6 | fixture schema | The fixture JSON uses `evidence_signal` where the spec's field is `evidence_class_detail`, and `repo_rel_path` where the spec says `repo_relpath`. The spec never states the fixture schema, so the mapping is inferred by eye. | Mapped by inspection. Unambiguous in practice, but it is an undocumented interface. |

**Z4 is the one that matters most.** The ordinal grouping key is what keeps a finding's identity stable
when an unrelated edit moves it, and it is the single least-tested part of the algorithm. It also
already carries an unresolved `CRITIQUE-01` finding (the key omits `enclosing_symbol_path`, so an edit
elsewhere in the same file can churn a live finding's identity). Settling Z4 and that finding together
is the obvious next move on this algorithm.

**Resolving any of these is an `anvil-fp/v2` event if it changes a digest, and a v1 clarification if it
does not.** Determine which before editing, not after.
