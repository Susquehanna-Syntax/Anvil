# CRITIQUE-01 — R.3, critique of R.1 (Record Field Contract) and R.2 (Fingerprint Specification)

**Step:** R.3 · **Reviewed:** `internal/record/contract.go`, `internal/record/CONTRACT.md`,
`schemas/anvil-record-v1.schema.json`, `internal/record/fingerprint.go`,
`internal/record/fingerprint_test.go`, `testdata/fingerprint_corpus/*.json`, against
`plan/40-record-and-storage.md` (Record Field Contract + Fingerprint Specification),
`plan/00-SPINE.md` S1/S6/S7/S12, and `plan/IMPLEMENTATION-PLAN.md` §6.

**Date:** 2026-08-08 · **Branch:** `feat/phase1-record-store` · **No code was modified by this pass.**

---

## 0. WHICH GUARANTEE THIS DOCUMENT ACTUALLY PROVIDES — READ THIS FIRST

**This was a SAME-FAMILY critic.** The critic and both implementers (R.1, R.2) are Anthropic models.
`plan/00-ROUTING.md` originally required a **different model family** here precisely so that a shared
blind spot could not survive review; the owner withdrew external routes on 2026-08-07 because running
them means copying `plan/` — deliberately private — to a third-party provider. See the OWNER DECISION
block at the top of `00-ROUTING.md`.

**A later reader must not record this as a cross-family critique.** The cross-family guarantee
`00-ROUTING.md` asked for on data-integrity work has *not* been obtained, and nothing in this document
supplies it. What compensation was applied:

- Findings were sought by refutation, not assessment: the implementations were assumed wrong.
- Every claim below was checked against the **files**, not against the implementers' prose. The
  implementers' reasoning in doc comments is extensive and persuasive; it was treated as a claim to be
  falsified, and in three places (findings 2, 3, 8) the doc comment states something the code does not do.
- Determinism was proved **empirically in two separate OS processes**, not by rereading the code and not
  by trusting reported output.
- The one property that most needed an outside check — *can an independent re-implementation of the
  written specification reproduce the committed digests?* — was answered by **writing that
  re-implementation** (in Python, from the plan text, without reading `fingerprint.go`'s lexer) and
  comparing digests. It cannot. That is finding 1, and it is the finding a same-family reviewer was most
  likely to miss by nodding along with the Go code.

**A residual same-family risk remains and cannot be closed here:** anything both the implementer and this
critic consider self-evidently correct about hashing, canonicalisation or SARIF was not challenged by an
outside vocabulary.

---

## 1. VERDICT

| Question R.3 must answer | Verdict |
|---|---|
| Every `00-SPINE.md` S6 field present in the contract | **PASS** (§3, field by field) |
| Fingerprint determinism | **PASS** — proved cross-process (§4) |
| Fingerprint excludes volatile fields | **PASS with one reservation** — package version, line, column, host, port, scheme, payload, timestamp all excluded and proved; the *ruleset* version is hashed and its churn is unbounded (finding 6) |
| Six frozen enums (§6) match, no second copy | **PASS** — literal by literal, three sources agree (§5) |
| Goldens are committed and compared, not regenerated | **PASS** (§6) |
| `CONTRACT.md` ⇄ `contract.go` ⇄ schema agree | **PASS** on all six enums and all S6 fields; one open decision unrecorded (finding 11) |
| **Is `anvil-fp/v1` "one algorithm, defined once" as S6 requires?** | **FAIL** — findings 1 and 2 |

**Overall: FAIL.** Two blockers. Per the packet's stop condition, R.4 must not start until they are ruled
on. Note carefully that **neither blocker is a bug in the Go code**: the code is clean, well-tested and
internally consistent. Both are failures of the *written specification* to be the thing S6 says it must
be — the single, reproducible definition. Fixing them is an orchestrator ruling on
`plan/40-record-and-storage.md`, not a rewrite of `fingerprint.go`.

---

## 2. GATE OUTPUT — real, re-run by this critic, `-count=1` throughout

```
$ gofmt -l .
(no output)

$ go vet ./...
(no output)

$ go build ./...
(no output)

$ go test -count=1 ./...
ok      github.com/Susquehanna-Syntax/Anvil/cmd/anvil   0.348s
?       github.com/Susquehanna-Syntax/Anvil/cmd/anvil-dast      [no test files]
?       github.com/Susquehanna-Syntax/Anvil/internal/buildpin   [no test files]
ok      github.com/Susquehanna-Syntax/Anvil/internal/record     0.677s

$ go test -count=1 -v ./internal/record/ | grep -c "^--- PASS"
129
```

R.1's `contract_test.go` still passes alongside R.2's additions. Go 1.26.5.

---

## 3. `00-SPINE.md` S6 — one verdict per required field

S6's required set, in the order S6 lists it. "Where" cites the Go symbol; every row was additionally
checked to exist in `schemas/anvil-record-v1.schema.json` and to be described identically in
`CONTRACT.md`.

| # | S6 field | Verdict | One-line reason |
|---|---|---|---|
| 1 | `anvil/state` | **PASS** | `State` + `PropAuditState`; six literals exactly as §6 froze them. |
| 2 | `anvil/version` | **PASS** | `PropAuditVersion = "anvil/version"`, present in schema and CONTRACT.md; correctly **not** hashed by any fingerprint tier. |
| 3 | per-half `status` | **PASS** | `HalfStatus` + `PropRunStatus`; `running\|sealed\|failed\|timed_out\|skipped`, matching §6's G5 ruling including the added `timed_out`. |
| 4 | per-half `sealedAt` | **PASS** | `PropRunSealedAt`; required in schema on a sealed half. |
| 5 | `anvil/trust` on every string originating outside Anvil | **PASS** | `Trust` with the three S6 literals, carried as an *object* not a bare enum (CONTRACT.md deviation 3) so one result can hold several provenances; `LegalForExternalString()` enforces the rule at the type level. The richer container is a strict improvement over the plan's table and does not change the literals. |
| 6 | `dast_status` | **PASS** | `DastStatus` + `PropAuditDastStatus`; all nine §6 literals, `skipped_no_manifest` kept distinct from `not_run` as G3+G6 requires. |
| 7 | `dast_coverage` | **PASS** | `PropRunDastCoverage`. |
| 8 | `target_provenance` | **PASS** | `TargetProvenance`, five literals; the G4+G7 split is honoured — the boot/reachability meaning is kept here and D's provisioning-path enum is the separate `TargetProvisioning` (`ephemeral_manifest\|live_url_authorized`). Both fields exist; neither was merged. |
| 9 | `remediable_by_agent` (host findings `false`) | **PASS** | `PropResultRemediableByAgent`; `Validate()` rejects `EvidenceClassHost` with `RemediableByAgent == true` (contract.go ~line 2317). Enforced in code, per S7's instruction. |
| 10 | `INSUFFICIENT_CONTEXT` as a verdict, not a confidence float | **PASS** | `VerdictInsufficientContext = "insufficient_context"`; a separate `anvil/confidence` exists but the verdict is a first-class enum value. |
| 11 | `as_of` | **PASS** | `Advisory.AsOf`; `Validate()` rejects a zero value when an advisory is linked. |
| 12 | `staleness_seconds` | **PASS** | `Advisory.StalenessSeconds`; non-negative enforced. |
| 13 | `parse_degraded` | **PASS** | `parseDegraded` in contract.go, schema and CONTRACT.md. |
| 14 | `endpoint_coverage` | **PASS** | `endpointCoverage` in contract.go and schema. |
| 15 | `inventory_provenance` | **PASS** | `InventoryProvenance` (`runtime_spec\|repo_spec\|static_extraction\|crawl`), in all three sources. |
| 16 | sanitizer state on any reproducer | **PASS** | `Repro.Env.Sanitizers []string`, `json:"sanitizers"`, schema-required; `Validate()` rejects `nil` and demands an empty array for a stock build, which is the right call — `null` and "no sanitizers" are different claims. |
| 17 | ASLR state on any reproducer | **PASS** | `Repro.Env.AslrEnabled bool`, `json:"aslrEnabled"`, schema-required. Key spelling identical in all three sources. |
| 18 | **One fingerprint algorithm, defined once, in the record** | **FAIL** | See findings 1 and 2. The algorithm is defined once *in Go*; the written specification is not sufficient to reproduce it, and one specified step of it is not implemented at all. |
| 19 | Ship a conformance test asserting identical digests on a fixed corpus | **PASS for R.2, at risk for R.16** | The corpus exists (7 fixtures, exceeding the 2/2/1/1 minimum) and is asserted. R.16's *independent* conformance oracle cannot currently be written to pass — finding 1. |

S6's closing "Ordering" paragraph (re-cut the queue on every version bump; reserve a configurable
fraction of budget for late DAST arrivals) is a scheduler requirement, not a record field, and is not
in R.1's or R.2's scope. **It is not checked here and must not be assumed covered.**

---

## 4. DETERMINISM — hunted first, proved empirically

### 4.1 Static hunt

`fingerprint.go` was read in full for the usual leaks. Grep, then reading:

```
$ grep -n "time\.\|rand\.\|filepath\.\|os\.\|runtime\.\|unsafe\.\|sync\.\|GOOS\|PathSeparator" internal/record/fingerprint.go
819:            // fingerprinted is rejected here rather than at hash time.        <- a comment, not a call

$ grep -n "range " internal/record/fingerprint.go
262:    for i, f := range fields          <- slice
817:    for i, c := range cands           <- slice
851:    for i, k := range order           <- slice
```

- **Map iteration:** the only two maps are `metavars` (NormalizeMatch) and `fingerprintReservedWords`.
  Both are read by key lookup only; neither is ranged over. Metavariable numbering comes from
  `nextMetavar`, a counter advanced in source order, not from map order. **Clean.**
- **Time / randomness / pointers / addresses:** none reachable. `Digest` is a pure function of its
  arguments. **Clean.**
- **Sorting:** `AssignSastOrdinals` uses `sort.SliceStable` with a total order (group key, then Line,
  then Column, then original index), so ties cannot reorder. **Clean.**
- **Locale-dependent case folding:** `strings.ToUpper`/`ToLower` are used (HTTP method, purl type, host
  package manager). Go's non-`Special` casers are Unicode-default and locale-independent — there is no
  Turkish-I hazard. **Clean.** (Unicode *normalization* is a different matter — finding 8.)

### 4.2 Empirical proof, in two separate OS processes

Not two calls in one process — the failure mode that matters (per-process map seed, address-space state)
is invisible that way. The test binary was compiled once and executed **twice as independent
processes**, each printing the digest of every corpus fixture:

```
$ go test -count=1 -c -o $SCRATCH/record.test.exe ./internal/record
$ cd internal/record
$ ANVIL_FINGERPRINT_CROSS_PROCESS_CHILD=1 $SCRATCH/record.test.exe \
      -test.run='^TestCorpusDigestsAreStableAcrossProcesses$' -test.count=1 | grep ANVIL-FP > procA.txt
$ ANVIL_FINGERPRINT_CROSS_PROCESS_CHILD=1 $SCRATCH/record.test.exe \
      -test.run='^TestCorpusDigestsAreStableAcrossProcesses$' -test.count=1 | grep ANVIL-FP > procB.txt

ANVIL-FP-DIGEST dast-01-sqli-error-based-body          ca801b8d64fdabf43aad112e3b62c53211cf369a66683c12352081357eb9d125
ANVIL-FP-DIGEST dast-02-xss-reflected-query            bbe1a200328dfd7415d4a209384515a7ae01cb0494a896e69ba2bf565299c489
ANVIL-FP-DIGEST dast-03-path-traversal-no-param-name   84fe311debbc87f852e1f4e17a3242d071169448c5852a00b1b32316fb30b036
ANVIL-FP-DIGEST host-01-openssl-debian                 c6d2c1a505849bf987d9a03a5a3ce8ab6053a9ae5e0d154d332b464bb69e5953
ANVIL-FP-DIGEST sast-01-go-sql-string-concat           13c60ccf8ec84530e075db4190005b03bc87050210065398fd48088683bb1aa6
ANVIL-FP-DIGEST sast-02-python-shell-command           d2239ee40c3f9da1cc9db3417962e3794b0c5baca0409015ff331a0aea095242
ANVIL-FP-DIGEST sca-01-log4shell-maven                 c3208f00ab0f426a1c2cbb2ccf0033881bb4bf6cb506763dea0840f03dd24cd8

$ diff procA.txt procB.txt
IDENTICAL
```

Every digest also equals the `expected_digest` committed in the corresponding fixture.

**Verdict: determinism PASS.** R.2's own `TestCorpusDigestsAreStableAcrossProcesses` is a genuine
cross-process check and not theatre; this critic re-ran the same property independently of it.

### 4.3 Windows vs POSIX path separators

Anvil targets Linux and is being developed on Windows, so a separator leak would be invisible on one
platform. Checked specifically:

- `CanonicalRepoRelPath` and `CanonicalRouteTemplate` are **pure string manipulation**. Neither imports
  `path/filepath`, `os.PathSeparator`, nor anything platform-conditional. The whole file imports only
  `crypto/sha256`, `encoding/hex`, `fmt`, `sort`, `strconv`, `strings`, `unicode`.
- `sast-01`'s `repo_rel_path_in_windows_form` mutation (`.\internal\api\store.go`) and `sca-01`'s
  `manifest_path_in_windows_form` mutation (`services\api\pom.xml`) both reproduce the base digest, and
  they passed here on Windows.
- The one hazard the conversion introduces is the reverse direction — see finding 8(b).

**No separator leak. PASS.**

---

## 5. THE SIX FROZEN ENUMS — compared literal by literal against §6

`plan/IMPLEMENTATION-PLAN.md` §6's enum block was compared character by character against
`internal/record/contract.go`, `schemas/anvil-record-v1.schema.json` and `internal/record/CONTRACT.md`.

| Enum | §6 literals | contract.go | schema `$defs` | CONTRACT.md |
|---|---|---|---|---|
| `anvil/state` | 6 | ✅ identical | ✅ identical | ✅ identical |
| `anvil/status` (per half) | 5 | ✅ | ✅ | ✅ |
| `anvil/dastStatus` | 9 | ✅ | ✅ | ✅ |
| `anvil/target.provenance` | 5 | ✅ | ✅ | ✅ |
| `anvil/target.provisioning` | 2 | ✅ | ✅ | ✅ |
| `anvil/verdict` | 3 | ✅ | ✅ | ✅ |
| `handoff.state` | 13 | ✅ | ✅ | ✅ |

No drift, no omission, no extra literal, no case difference, no ordering difference in any of the three
sources. §6's "lowercase snake_case is the record's convention" holds for all six.

**Did R.2 introduce a second, drifting copy? No.** `fingerprint.go` declares **no enum type**. It
consumes `DetectorKindSCA`, `DetectorKindHost`, `InjectionPoint` and `EvidenceSignal` from
`contract.go`, and validates the latter two through `ValidateInjectionPoint`/`ValidateEvidenceSignal`
rather than re-listing their literals. `TestTierValidationRejectsIncompleteInput` proves a
SCREAMING_CASE injection point and an off-spec `db_error_string` are both rejected. The one blemish is
two private duplicated string literals — finding 10, minor, and **not** a §6 violation because they are
not an enum declaration.

`InjectionPoint` and `EvidenceSignal` are camelCase (`dbErrorString`), which looks like a violation of
§6's snake_case sentence. It is not: neither is one of the six frozen enums, both come from the
Fingerprint Specification's own camelCase text, and `CONTRACT.md` line 443–446 records the reconciliation
explicitly. Consistent across all three sources. **No finding.**

---

## 6. GOLDENS — do they regenerate themselves?

**No. PASS.**

- `testdata/fingerprint_corpus/*.json` are committed data files carrying `hashed_fields` and
  `expected_digest`. `TestCorpusFixturesProduceTheirDocumentedDigest` compares the implementation's field
  list **and** digest against them; nothing writes back.
- There is **no `-update` flag, no `os.WriteFile`, no golden-regeneration path** anywhere in
  `fingerprint_test.go`. The file contains an explicit, correct block (lines 429–444) forbidding one.
- `strictUnmarshal` uses `DisallowUnknownFields`, so a misspelled fixture key fails loudly instead of
  silently defaulting a hashed field to `""` and locking in a wrong digest. That is the right paranoia.
- Independent check by this critic: each fixture's `expected_digest` was recomputed **outside Go**, in
  Python, as `sha256(U+001F.join(hashed_fields))`. All seven matched, and all seven matched the Go
  output in §4.2. So the fixtures are internally consistent and the Go code agrees with them.

**The reservation:** that check proves `expected_digest = H(hashed_fields)`. It does **not** prove
`hashed_fields` is what the *written specification* produces from `input`. That is exactly what R.16
exists to prove, and finding 1 shows it currently cannot.

---

## 7. NUMBERED GAPS

### BLOCKER 1 — `normalized_match` is defined only in Go, so R.16's mandated independent oracle cannot reproduce the SAST goldens

`plan/40-record-and-storage.md` defines the SAST tier's hardest field in four clauses:

```
normalized_match := strip comments; collapse whitespace runs to a single space;
                     replace string/numeric literals with <STR>/<NUM>;
                     replace local identifiers with positional $1..$N in first-occurrence order.
```

`fingerprint.go`'s `NormalizeMatch` implements those four **plus at least nine rules the specification
never states**: a ~200-entry cross-language reserved-word list held verbatim (lines 1120–1172);
identifiers after `.`, `->` or `::` held verbatim; identifiers before `::` held verbatim; identifiers
before `(` held verbatim (lines 1051–1068); CRLF folding; which comment syntaxes exist (`//`, `#`,
`/*…*/`); which string delimiters exist (`"`, `'`, `` ` ``) and where backslash escapes apply; the
number-token grammar (`0xFF`, `1_000`, `3.14f`, `1e-9` are each one token); and a final trim.

This critic re-implemented the **specification text only** in Python — no reserved-word list, no
selector/callee/scope exceptions, everything else deliberately matched to the Go choices so the
divergence is attributable to the identifier rule alone — and rehashed the committed fixtures:

```
sast-01-go-sql-string-concat
  spec-text normalized_match : '$1, $2 := $3.$4(<STR> + $5 + <STR>)'
  committed normalized_match : '$1, $2 := $3.Query(<STR> + $4 + <STR>)'
  spec-text digest           : 55e27b07806178f7afd55b9178523ac45dd92b5e9aefcb00b2011f6d4cea2eed
  committed expected_digest  : 13c60ccf8ec84530e075db4190005b03bc87050210065398fd48088683bb1aa6
  *** DIVERGES ***

sast-02-python-shell-command
  spec-text normalized_match : '$1.$2(<STR> + $3)'
  committed normalized_match : '$1.system(<STR> + $2)'
  spec-text digest           : 3ef752ff8836e5edacf8a8f8e38b895d41d816183147604d2445c884db7d09c0
  committed expected_digest  : d2239ee40c3f9da1cc9db3417962e3794b0c5baca0409015ff331a0aea095242
  *** DIVERGES ***
```

**Why this is a blocker and not a nit.** R.16's packet requires an oracle that "re-implements the
algorithm text above from scratch, **not** by importing `internal/record/fingerprint.go`, so the oracle
is independent". Any such oracle produces the digests on the left. R.16 then has exactly two ways to go
green, and the plan forbids both: read `fingerprint.go` (destroys independence) or copy
`expected_digest` (the test file's own header at lines 31–33 forbids it, correctly). The spine-mandated
conformance gate is therefore unsatisfiable as written.

It is also the S6 failure itself, one level up. S6's rule is "**One fingerprint algorithm, defined
once, in the record.**" Today the authoritative definition of `normalized_match` is Go source. A second
producer — the plan's whole premise is that there will be more than one — implementing from
`plan/40-record-and-storage.md` will emit different digests and nothing will surface it. The header
comment of `fingerprint_test.go` asserts the `hashed_fields` "were derived BY HAND from the algorithm
text"; for the two SAST fixtures that derivation must have used knowledge not present in the algorithm
text, and this critic could not reproduce it. **Claim not supported by the artifact.**

**Proposed fix (orchestrator ruling, not a code change).** Amend the Fingerprint Specification to carry
the full normalization: the reserved-word list verbatim, the selector/callee/scope-resolution rules, the
comment syntaxes, the string delimiters and escape handling, the number-token grammar, CRLF folding and
the trim — and state that any edit to that list is an `anvil-fp/v2` event, which `fingerprint.go` line
1118 already says. Alternatively rule the other way and re-route R.2 to the literal four-clause text,
accepting the loss of discriminating power the implementer argues against at lines 900–907. Either
ruling is defensible; leaving it undecided is not, because R.16 will hit it and the cheapest thing R.16
can do is quietly weaken its own oracle.

---

### BLOCKER 2 — the DAST tier's only specified normalization is not implemented, and no fixture covers it

The specification defines the DAST tier's route field as a **derived** value:

```
route_template := numeric/UUID/hash path segments replaced with a placeholder token.
```

`CanonicalRouteTemplate` (fingerprint.go:702–720) does not do this. It strips a query string or
fragment, collapses slash runs, adds a leading slash and trims a trailing one. It performs **zero**
segment templating. `DastInput`'s doc comment (line 575) reassigns the work to the caller —
"RouteTemplate is the path with volatile segments templated" — which the plan does not say.

Consequence, and it is precisely S6's named failure: two producers observing the same defect at
`/api/users/12345/orders` will emit `/api/users/12345/orders`, `/api/users/{id}/orders` and
`/api/users/:id/orders` respectively. Three digests, one defect, no error, regression matching silently
dead. Worse than the SAST case, because the DAST tier is the one that earns "verified fixed" under S7 —
a DAST reproduction that cannot be matched to its prior finding cannot prove a fix.

All three DAST fixtures (`dast-01`, `dast-02`, `dast-03`) arrive **already templated**
(`/api/v1/users/{id}/orders`, `/search`, `/files/{path}`), so the corpus cannot detect this. There is no
test anywhere that feeds a concrete numeric or UUID segment.

**Proposed fix:** implement the templating in `CanonicalRouteTemplate` — replace segments matching
all-digits, a UUID, and a long hex/base32/base64 run with a single frozen placeholder token, with the
patterns written into the specification — and add a DAST fixture whose input carries
`/api/v1/users/12345/orders` and a UUID segment, with a mutation proving a different id yields the same
digest. If the orchestrator instead rules that templating belongs to the DAST producer (area D), then
`plan/40-record-and-storage.md` must say so, D's packet must own it with a named test, and the
specification's `route_template :=` line must be struck — otherwise two areas each believe the other
does it.

---

### MAJOR 3 — `primaryLocationLineHash` is required by the contract, assigned to the fingerprint engine by the plan, and implemented by nobody

- `plan/40-record-and-storage.md` line 653 lists `result.partialFingerprints["primaryLocationLineHash"]`
  as **"required when a physical location exists"**, producer column **"fingerprint engine"**, consumer
  column "GitHub upload path only (R.14)".
- `contract.go:2328` makes it a hard `Validate()` failure:
  `partialFingerprints["primaryLocationLineHash"] is required when a physical code location exists`.
- `fingerprint.go:77–83` declines to implement it and reassigns production to R.14: *"It is not an
  anvil-fp/v1 tier … it lives under `PartialFingerprintPrimaryLocationLineHash` and is owned by the
  GitHub projection (R.14)."*

The technical argument for keeping a line-dependent hash out of this file is good. But the plan's
producer column says fingerprint engine, and R.2 unilaterally moved it. Net effect **today**: no code in
the tree can construct a SARIF result with a physical code location that passes `Validate()`. R.4 (the
store) and every SAST producer will hit this.

**Proposed fix:** an explicit ruling on the owner, plus whichever of these follows — R.2 ships a
separate `PrimaryLocationLineHash(...)` helper in its own file (identity untouched, no line number one
import from `Digest`), or R.14's packet is amended to own it and `plan/40`'s producer column is corrected
to say so. Do not leave `Validate()` enforcing a field with no producer.

---

### MAJOR 4 — the ordinal group key omits `enclosing_symbol_path`, so an unrelated edit elsewhere in the file churns a finding's identity

`AssignSastOrdinals` (fingerprint.go:824–833) groups on
`TargetID | RuleIDVersioned | CanonicalRepoRelPath | NormalizeMatch(Snippet)` — faithfully following the
specification's "index among all matches of the same `rule_id` in the same `repo_relpath` whose
`normalized_match` is IDENTICAL". `enclosing_symbol_path` is **hashed** but is **not** in the group key.

Failing scenario:

1. `store.go` contains `func A() { … exec(x) … }` at line 10 and `func B() { … exec(y) … }` at line 50.
   Both normalise to `exec($1)`.
2. They are already distinguishable — `enclosing_symbol_path` differs — so they cannot collide.
   Nevertheless they land in one ordinal group: A gets 0, B gets 1.
3. Someone deletes `func A` for unrelated reasons.
4. B's ordinal drops to 1 → 0. **B's digest changes.** B is reported resolved and re-opened as new.
   `first_seen_at` resets, age-based ranking resets, any suppression keyed on B's fingerprint silently
   stops applying, and a `handoff` row keyed on the old digest is orphaned.

Adding `enclosing_symbol_path` to the group key removes the churn entirely and loses nothing: within one
symbol, ordinal still breaks the duplicate-call-site collision that motivated it (`fingerprint.go:37–41`).
`TestAssignSastOrdinals` sets `EnclosingSymbolPath: "sym"` on every candidate, so the case is untested.
This requires a one-line specification amendment as well as the code change, since the group key is
spec text.

---

### MAJOR 5 — normalization is aggressive enough that two different sinks share a `normalized_match`, and identity then rests on the least stable field

The implementer's own test documents it (`fingerprint_test.go:1063–1076`): `exec(cmd)` and `exec(other)`
both normalise to `exec($1)`, because `exec` is a preserved callee and the argument is abstracted.

That is intended for renames. The consequence is not: two *semantically different* call sites — one
executing `cmd`, one executing `other` — are distinguished **only by `ordinal`**, which is derived from
line order. Swap the two lines and the two findings **swap identities**. Not churn — misattribution.
A triage verdict, a suppression, a `handoff` row and a "verified fixed" claim all transfer to the wrong
finding, and every field of both records still looks internally consistent.

`fingerprint.go:784–790` records the ordinal's instability as a known limitation and points at
research/07's matching cascade to recover. That cascade does not help here: both findings are live, both
digests exist, and the cascade has nothing to disambiguate on. No test asserts against the swap.

**Proposed fix:** either narrow abstraction so an argument identifier's *role* survives (e.g. abstract
only identifiers appearing more than once, or keep the first argument of a preserved callee), or accept
the risk explicitly in the specification and require the store to alert when two findings in one
(rule, path, normalized) group exchange ordinals between scans. Silent acceptance is the one option that
should not survive.

---

### MAJOR 6 — a ruleset version bump re-mints every SAST and DAST fingerprint, with no bound and no migration

`rule_id_versioned` is hashed in both the SAST (fingerprint.go:387–395) and DAST (638–647) tiers, per the
specification. `fingerprint_test.go:529` pins `"different rule version"` as *required* to change the
digest, and `fingerprint.go:319–321` argues the case: "a rule that changed what it matches is a different
rule."

The argument is sound for a rule whose semantics changed. It is applied, however, to a token that moves
on the **ruleset's** release cadence — the fixtures use `opengrep…@2026.07.1` and
`nuclei:…@2026.07.1`. opengrep and nuclei-templates ship routinely; S7 already requires nuclei-templates
to be "pinned by commit SHA and diffed before promotion", i.e. bumped deliberately and often. Every such
bump resolves and re-opens **the entire SAST and DAST finding population at once**, resetting
`first_seen_at`, resetting age-based ranking, dropping every fingerprint-keyed suppression, and orphaning
every `handoff` row — with no error anywhere. The plan's only migration protocol (dual-write `v1` and
`v2` for one retention cycle) covers **algorithm** version changes, not rule-version changes, so nothing
absorbs this.

R.3's remit is explicitly "exclusion of volatile fields". A token that turns over on a weekly-to-monthly
cadence, driven by an upstream project rather than by the scanned code, is volatile.

**Proposed fix (one of):** hash the rule id **without** its version and carry the version as an unhashed
result attribute — the rule's *identity* is stable even when its ruleset ships; or extend the dual-write
migration protocol to cover ruleset bumps, with the store matching `old_rule_version OR new_rule_version`
for one cycle; or record an explicit accepted-risk ruling in `plan/40-record-and-storage.md` stating that
ruleset bumps mass-reset finding identity and naming what compensates. The current position — hash it,
pin the behaviour in a test, say nothing about the consequence — is the one that fails silently.

---

### MINOR 7 — a C0 control byte in a snippet makes a finding unfingerprintable instead of being normalized away

`NormalizeMatch` collapses whitespace and drops comments, but any other character falls through to
`out = append(out, c)` verbatim (fingerprint.go:1070–1073). A C0 control that is not
`unicode.IsSpace` — `NUL`, `BEL`, `ESC`, `\x1f` itself — therefore survives normalization, and `Digest`
then rejects the whole field (fingerprint.go:262–271). `Sast` returns an error and the finding **cannot
be hashed at all**.

`Digest`'s rejection is right — a field carrying `U+001F` would move a field boundary. The gap is that
`NormalizeMatch` does not guarantee its output is hashable, so the failure lands on the producer as a
hard error. If any caller drops errored findings (the natural thing to do in a scan loop), a real
vulnerability on a line containing a stray control byte becomes invisible. S7's threat model makes this
worth closing: an attacker who can land a byte in a source file, a generated file or a vendored blob can
make the finding on that line unreportable.

**Proposed fix:** have `NormalizeMatch` strip C0 and DEL the way it strips comments, and add a test that
`Sast` succeeds on a snippet containing `\x00` and `\x1f`. Keep `Digest`'s rejection as the backstop.

*Confidence note: confirmed by reading the code path, **not executed** — this critic's packet forbids
adding a test file. `unicode.IsSpace` covers `\t \n \v \f \r`, space, U+0085 and U+00A0, and not `\x00`
or `\x07`, so those reach the `default` branch.*

---

### MINOR 8 — `CanonicalRepoRelPath`'s stated goal is not achieved, and its backslash rewrite can merge two distinct POSIX files

The doc comment (fingerprint.go:669–671) claims backslash conversion exists "so a Windows producer and a
Linux producer scanning the same repository agree". Three ways they still do not:

- **(a) Case.** The function deliberately does not case-fold (lines 674–677), with a correct reason.
  But Windows filesystems are case-insensitive, so a Windows producer may legitimately report
  `Internal/API/Store.go` where a Linux producer reports `internal/api/store.go`. Different digests.
  `TestCanonicalRepoRelPath` pins case preservation as intended, which pins the divergence too.
- **(b) Backslash is a legal POSIX filename character.** A real Linux file named `a\b.go` canonicalises
  onto `a/b.go` and collides with the genuinely different file at that path. Rare, but it is a
  *collision* — two findings, one identity, one lost on upsert — which the whole ordinal mechanism
  exists to prevent.
- **(c) Unicode form.** No NFC/NFD normalization anywhere. A path or symbol containing a precomposed
  vs decomposed accented character hashes differently, which is the macOS-checkout case.

**Proposed fix:** narrow the doc claim to what is true ("separator form only"), or add NFC normalization
and decide the case question explicitly. (b) is cheap to fix — reject a path containing a backslash on
POSIX rather than rewriting it — but needs a ruling, since the Windows-producer fixture depends on the
rewrite.

---

### MINOR 9 — five undocumented canonicalizations sit between fixture input and hashed field

Each is defensible; none appears in `plan/40-record-and-storage.md`'s algorithm text, and each is another
way R.16's oracle will diverge (same root cause as finding 1, listed separately because writing them
down is nearly free):

| Canonicalization | Where | In the spec text? |
|---|---|---|
| HTTP method upper-cased and trimmed | fingerprint.go:617–623 | no |
| Route query string / fragment stripped, slashes collapsed, leading `/` added, trailing `/` trimmed | 702–720 | no |
| purl scheme and type lower-cased | 736–739, 764–769 | no |
| purl subpath / qualifiers / version stripped | 750–758 | version yes, `?`/`#` no |
| host package manager lower-cased and trimmed; `:` forbidden in it | 472–474, 529–535 | no |
| repo path: backslashes, slash runs, leading `./` and `/`, trailing `/` | 678–689 | no |

The corpus *tests* all of them via mutations, which is good, and pins them against future drift. It just
does not make them reproducible from the specification.

---

### MINOR 10 — two of four tiers take their hashed discriminator from a private literal, two from the contract enum

`tierTokenSast = "sast"` and `tierTokenDast = "dast"` (fingerprint.go:195–201) duplicate the values of
`DetectorKindSast` and `DetectorKindDast`, while the SCA and host tiers hash `string(kind)` taken from
the contract enum (line 501). The stated reason is to avoid confusing the tier token with the *evidence
class* — but `DetectorKind` is not the evidence class; `EvidenceClass` is, and it is a separate type with
`sast_reachable`/`sast_static_only`. `DetectorKind` already means exactly what the tier token means.

Not a §6 violation (no enum is declared, no shared vocabulary is redefined) and not a bug today —
`TestTiersUseTheirSpecifiedDiscriminator` asserts both spellings. It is a second copy of a hashed
literal, in the one file whose entire premise is that a second copy of a hashed value is how
`anvil-fp/v1` got two meanings in the first place.

**Proposed fix:** use `string(DetectorKindSast)` / `string(DetectorKindDast)` and keep the comment
explaining why the tier token is not the evidence class.

---

### MINOR 11 — an R.2 decision that `CONTRACT.md` explicitly assigns to R.2 was never recorded

`CONTRACT.md` deviation 2 (lines 429–432): *"`partialFingerprints["regionSha256"]` reserved … **R.2
decides whether to populate it**, and R.2 may strike it if the algorithm has no use for it."*

`fingerprint.go` never mentions `regionSha256`. The decision is neither made nor struck; it has silently
become nobody's. `research/24` names `fingerprint.region_sha256` non-negotiable for the coding-agent
handoff, so R.9/R.10 will meet it again with no ruling to consult.

**Proposed fix:** R.2 (or the orchestrator) records one sentence in `CONTRACT.md` — populated by X, or
struck — before R.4.

---

## 8. WHAT THIS PASS DID *NOT* CHECK

Stated so the gap is visible rather than assumed covered:

- **No cross-family review was obtained.** See §0.
- `contract.go` is ~104 KB. Its **six frozen enums, every S6 field, and the validation rules touching
  them** were read closely. Its SARIF projection, JSON round-trip and the remainder of `Validate()` were
  not audited line by line; `contract_test.go`'s 129 passing assertions were re-run, not re-derived.
- The **schema** was compared for enum literals and S6 field presence. It was not validated against a
  JSON Schema meta-schema, and no instance document was validated against it by this pass.
- S6's **ordering / budget-reservation** requirement is out of R.1's and R.2's scope and was not checked
  anywhere.
- Finding 7 is reasoned from the code path, not executed — this packet forbids adding a test file.
- The claim that the corpus `hashed_fields` were "derived by hand from the algorithm text" is
  **unverifiable from the artifact** and, for the two SAST fixtures, is contradicted by finding 1's
  experiment. Treat the goldens as pinning `fingerprint.go`'s behaviour, which is still worth having.

---

## 9. WHAT R.4 MAY AND MAY NOT ASSUME

**May assume, now proved:** the six frozen enums are correct and singly-sourced across Go, schema and
prose; every S6 field exists; digests are 64 lowercase hex, never truncated, deterministic across
processes and platforms; the package version, line, column, host, port, scheme, payload and timestamps
are all excluded by construction and by test; `UNIQUE (target_id, fingerprint)` is safe to build on for
the SCA and host tiers.

**May not assume:** that a second producer implementing from `plan/40-record-and-storage.md` will emit
the same SAST or DAST digest (findings 1, 2); that `route_template` is normalized by anything
(finding 2); that a SAST finding's identity survives an unrelated deletion in the same file (finding 4)
or a ruleset bump (finding 6); that `primaryLocationLineHash` has a producer (finding 3).

Findings 1 and 2 are blockers. Per the packet's stop condition, R.1 or R.2 — or, more likely here, the
Fingerprint Specification section of `plan/40-record-and-storage.md` — must be rerouted and re-reviewed
to all-PASS before R.4 starts.
