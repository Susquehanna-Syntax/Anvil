# REVIEW-A.13 — critic verdict on A.11 (Trivy-DB / Grype-DB warm-start accelerator)

**Verdict: FAIL.** Two blockers, two majors, two minors.

**This was a SAME-FAMILY critic.** The packet routes A.13 to an OpenCode
`openai/gpt-5.5-fast` route; that route is withdrawn (plan/00-ROUTING.md OWNER
DECISION, 2026-08-07). This review was performed by a Claude subagent — the same
model family that produced A.11. Correlated blind spots are therefore *not*
excluded, and this verdict must never be recorded as "cross-family critic: PASS".
Compensation applied: every claim was checked against the file, the suite was
re-run locally with `-count=1`, and every finding below was proved by a probe
that made the defect happen rather than by argument.

Scope reviewed: `internal/mirror/accelerator/trivydb.go` (1200 lines),
`internal/mirror/accelerator/grypedb.go` (435), `accelerator_test.go` (961).
Cross-read for authority: `internal/ingest/license/tiers.go`,
`internal/ingest/config/feeds.go`, `internal/collector/repo/trivy.go`,
`mirror/.gitignore`, root `.gitignore`, plan/00-SPINE.md S1/S5/S7/S8/S12.

---

## Packet's three named checks

| # | Packet check | Result | Citation |
|---|---|---|---|
| 1 | No write path under `mirror/tier{0,1,2}` | **FAIL** | `trivydb.go:425-447` (`guardNotTiered`) — see B-1 |
| 2 | Schema-v5 rejection test present and correct | **PASS**, with a gap | `grypedb.go:284-290`; test `accelerator_test.go:658-707`. Gap: no equivalent check exists for Trivy — see m-2 |
| 3 | Manifest marks pulled content `consume_only` | **PASS** | written `trivydb.go:635`; refused-on-read `trivydb.go:625-629`; asserted `accelerator_test.go:223-231` |

Check 3 is genuinely well built: the flag is force-set on every write, and a
manifest read back with `consume_only:false` is refused rather than corrected.
That is the right call and the reasoning at `trivydb.go:236-240` is sound.

Check 1 fails. The guard is correctly *shaped* — inverting `license.CheckWritePath`
rather than re-deriving the rule is exactly right and answers the packet's
question 2 in A.11's favour — but the authority it delegates to compares paths
case-sensitively, and A.11 is the component that performs the actual filesystem
write on a case-insensitive host.

---

## BLOCKERS

### B-1. A full warm start writes the un-redistributable database *into* `mirror/tier2` on Windows

`trivydb.go:425-447`. `guardNotTiered` delegates to `license.CheckWritePath`,
which at `internal/ingest/license/tiers.go:1376-1380` does
`clean != want && !strings.HasPrefix(clean, want+"/")` — a **byte-exact,
case-sensitive** comparison against `TierDir(tier)` = `mirror/tier2`. Windows
(this project's declared dev host, and the platform `slashClean` at
`trivydb.go:408` exists to accommodate) resolves `MIRROR\Tier2` and `mirror\tier2`
to the same directory. The guard does not.

`guardCacheRoot` (`trivydb.go:455-478`) partially masks this: it checks both `abs`
and `real`, and `resolveExistingAncestor` canonicalises case for components that
**already exist on disk**. It does not canonicalise components that do not exist
yet — which is the ordinary first-run case, because the accelerator creates its
own tree (`WarmStartWith`, `trivydb.go:720`).

Probe, run on this host:

```
=== RUN   TestProbe_WarmStartWritesIntoCaseVariedQuarantine
    PROBE CONFIRMED: warm start wrote 2 file(s) reachable under mirror/tier2:
      [\mirror\tier2\mirror\accelerator\.cache\accelerator-manifest.json
       \mirror\tier2\mirror\accelerator\.cache\trivy-db.tar.gz]
--- FAIL
```

`CacheDir` was `<root>\MIRROR\Tier2\mirror\accelerator\.cache`; the walk that
found the files walked `<root>\mirror\tier2`. Both the manifest and the pulled
Trivy DB layer landed inside the share-alike quarantine, and `WarmStartWith`
returned `nil`. `TestWarmStartIntoTheQuarantineIsRefusedAndWritesNothing`
(`accelerator_test.go:501-518`) and
`TestAFullWarmStartLeavesEveryTierDirectoryUntouched` (`:524-559`) both pass,
because every path in their tables is lower-case.

The direct-guard form fires too, with no filesystem involved:

```
=== RUN   TestProbe_GuardIsCaseSensitiveOnACaseInsensitiveFilesystem
    PROBE CONFIRMED: guardNotTiered("C:\build\anvil\MIRROR\Tier2\mirror\accelerator\.cache") = nil
```

Everything else in this table is clean. I ran the whole attack list from the
packet against `guardNotTiered` — absolute POSIX and Windows roots, `..`
traversal (`internal/mirror/accelerator/../../../mirror/tier2/ubuntu`), backslash
separators, UNC/extended-length (`\\?\C:\mirror\tier2`), a caller-supplied
`CacheDir`, and a `.cache` symlink pointing at the quarantine — and every one is
correctly refused. Case is the single hole.

**Fix (A.11 side, not the frozen gate):** fold case before the tier comparison in
`guardNotTiered` on case-insensitive platforms — or, better, compare
`strings.EqualFold`-style tails unconditionally, since no legitimate cache root
distinguishes `Tier2` from `tier2`. Do **not** patch
`internal/ingest/license/tiers.go`; the gate is frozen and its exact-match
semantics may be load-bearing for A.4's admission path. The accelerator is the
one asserting a filesystem property, so the accelerator owns the fold. Add the
case-varied path to both tables in `TestWritePathNeverResolvesIntoTheLicenceTieredMirror`.

### B-2. The default cache directory is git-trackable — `git add -A` publishes the artifact

`trivydb.go:143`: `DefaultCacheDir = "internal/mirror/accelerator/.cache"`, i.e.
inside the working tree. It is matched by no `.gitignore` in this repo.

```
$ git check-ignore -v internal/mirror/accelerator/.cache/trivy-db.tar.gz
(exit 1 — not ignored)

$ git add -An internal/mirror/accelerator/.cache
add 'internal/mirror/accelerator/.cache/accelerator-manifest.json'
add 'internal/mirror/accelerator/.cache/trivy-db.tar.gz'
```

That stages ~165 MB (100 MB Trivy DB + 65 MB Grype DB) of an artifact whose
publishers state **no** redistribution terms into a public Apache-2.0 repository.
That *is* redistribution. It is the exact harm the whole package is built to
prevent, and the packet's own framing applies: unrecoverable once published.

The header comment at `trivydb.go:39` claims "NEVER SERVED — no code path
re-serves, re-publishes or re-packages it." True of Go code, and
`TestPackageExposesNoWayToServeOrRepublishTheArtifact` (`:856-915`) proves it
well. But `git push` is not a Go code path, and the repo already knows this:
`mirror/.gitignore` exists for precisely this reason and says so in prose —
*"a file that git cannot carry is a file no Anvil commit can author."* A.11 did
not apply its own repo's rule to its own directory.

**Fix:** ship `internal/mirror/accelerator/.gitignore` containing `.cache/`, and
add a test that asserts it — the same posture `mirror/.gitignore` and
`eval/tools/opengrep/.gitignore` already take. A `.gitignore` with no test is a
line somebody deletes in a merge.

---

## MAJOR

### M-1. The registry chooses where the operator's credential is sent

`trivydb.go:981-1009`. `exchangeToken` parses `realm` out of the registry's
`WWW-Authenticate` header, checks only that it parses and has a non-empty host
(`:987-989`), then sends the credential to it:

```go
if secret := readCredential(ctx); secret != "" {
    req.SetBasicAuth("x-access-token", secret)
}
```

There is no check that the realm host is the registry host. Spine S7 requires
"Re-validate scope on **every request including every redirect hop**; never
follow cross-host redirects." A.11 enforces that for redirects
(`httpClient`, `trivydb.go:911-920`) and for the Grype listing's archive
reference (`resolveArchiveURL`, `grypedb.go:371-375`) — and then leaves the
token realm, which is *also* third-party content naming a host, entirely
unchecked. The realm hop is a fresh request, so `CheckRedirect` never sees it.

Probe:

```
=== RUN   TestProbe_CredentialLeaksToAttackerNamedTokenRealm
    PROBE CONFIRMED: credential sent to http://127.0.0.1:59194 (a host named by
    the registry, not by config); basic user="x-access-token" pass=<the configured secret>
```

The mock registry only ever answered `401` with
`Bearer realm="<attacker>/token"`. The ops-provisioned PAT left for a host that
appears nowhere in the configuration.

This is reachable from three real positions, not just a compromised ghcr.io:
an operator-run pull-through cache (Aqua's own post-outage advice, and the
stated purpose of `RegistryBase` per `trivydb.go:116-120`), a typo'd registry
host, and — because of M-2 — any on-path attacker when the base is `http://`.

`TestCredentialIsReadByEnvNameAndNeverPersisted` (`:342-383`) does not catch it:
the mock's realm is its own `m.server.URL` (`accelerator_test.go:103`), so the
same-host case is the only one exercised. The test proves the secret is not
*persisted*; nothing proves it is not *sent elsewhere*.

**Fix:** require `tu.Host == rc.base.Host` before `SetBasicAuth`, or at minimum
before attaching any credential — refuse a cross-host realm outright, matching
`resolveArchiveURL`'s existing wording. Add the probe above as a permanent test.

### M-2. Cleartext `http` is accepted, contradicting the documented refusal and voiding the Grype opt-out's stated justification

`Config`'s `ErrBadConfig` doc (`trivydb.go:214-216`) says the error covers
"an http URL where https is required". No code enforces it.
`newRegistryClient` (`trivydb.go:884-886`) accepts `http` explicitly, and
`normalise` (`trivydb.go:369-373`) checks the Grype listing URL for emptiness
only — no scheme check at all.

```
=== RUN   TestProbe_PlainHTTPIsAccepted
    PROBE CONFIRMED: newRegistryClient accepted "http://registry.internal.example" (cleartext)
    PROBE CONFIRMED: normalise accepted a cleartext grype listing URL "http://grype.example/databases/v6/latest.json"
```

Two consequences:

1. Combined with M-1, an on-path attacker can inject the `401` + realm and take
   the PAT off the wire without compromising anything.
2. `AllowUnverifiedArchiveChecksum` is justified in the source
   (`grypedb.go:104-106`, `:411-413`, `:425-427`) and in KNOWN LIMITS
   (`trivydb.go:79-83`) by "TLS is the only integrity evidence". Over `http`
   there is no TLS, so the opt-out's entire stated safety basis is absent while
   the manifest still records `checksum_verified:false` as though the operator
   made the documented trade.

I accept that the tests need `http` (`httptest.NewServer` is plaintext, and
`accelerator_test.go:30-36`'s no-network rule depends on it). That is solvable —
gate the relaxation on a loopback host check, or on an explicit
`AllowInsecureTransport` field parallel to `AllowUnverifiedArchiveChecksum` so
the choice is visible the same way. What is not acceptable is a doc comment that
describes a refusal the code does not make.

---

## MINOR

### m-1. Trivy's `schema_version` in the manifest is asserted, never verified

`trivydb.go:815` writes `SchemaVersion: TrivyDBSchemaVersion` (the constant `2`)
unconditionally, regardless of `cfg.Trivy.Reference`. `Reference` is
operator-settable (`trivydb.go:292-294`) and *is* recorded faithfully at `:810`.
So an operator who sets `Reference: "3"` gets a manifest reading
`{"reference":"3","schema_version":2}` — a field that states something nobody
checked, in a file whose whole purpose is to tell a future operator what is on
this disk. Contrast Grype, which records the schema it actually parsed
(`grypedb.go:319`, `SchemaVersion: major`).

The comment at `trivydb.go:126-130` argues the tag *is* the schema for this
artifact. That is true for the default and false for any override, and the code
permits the override.

**Fix:** derive `SchemaVersion` from `Reference` (refuse a reference that is not
a bare schema integer or a digest), or omit the field for Trivy rather than
fabricate it.

### m-2. Digest verification proves transport integrity, not provenance — and the manifest overstates it

Packet question 5. For Trivy: the manifest is fetched by **tag** over an
unauthenticated channel (`fetchManifest`, `trivydb.go:944-976`), the layer digest
is read out of *that* response (`selectTrivyLayer`, `:844-862`), and the blob is
then checked against it (`fetchBlob`, `:1130-1134`). Whoever controlled the
manifest response controlled the digest. The record is then written with
`ChecksumVerified: true` (`:816`).

This is **disclosed** — KNOWN LIMITS at `trivydb.go:76-78` says so plainly, and
that disclosure is the reason this is minor rather than major. Two residual
gaps: (a) no cosign/sigstore verification and no digest-pinned default reference,
so there is no path by which an operator *could* get provenance; (b)
`checksum_verified: true` on disk reads as a stronger claim than "matched a
digest from the same untrusted response", and the manifest is the artifact an
operator reads months later without this source file. Recommend renaming the
field or adding `verified_against: "registry manifest (unsigned)"`.

---

## Attacks that did NOT find anything — recorded so they are not re-run

- **Path traversal / absolute / separator / symlink into the mirror.** All
  refused. `cachePath` (`trivydb.go:509-524`) re-guards *after* the join, which
  is the check that matters, and the escape assertion at `:520` is correct.
  `resolveExistingAncestor` correctly handles the not-yet-created root that
  `filepath.EvalSymlinks` would otherwise reject outright. The `.cache`-symlink
  probe is already covered by `accelerator_test.go:563-583`.
- **Does it re-derive the tier rule instead of asking the gate?** No. It asks —
  `guardNotTiered` calls `license.CheckWritePath` for all four
  `config.LicenseTierValues()` and refuses on *acceptance*
  (`trivydb.go:436-444`). That inversion is the right answer to the packet's
  section-6 defect class, and `TestGuardAgreesWithTheLicenceGate`
  (`accelerator_test.go:449-464`) pins it against drift. B-1 is a defect in the
  delegated comparison, not in the delegation.
- **Second fingerprint.** None. No call to `internal/record` anywhere; the only
  `sha256` use is content integrity, correctly and prominently disambiguated at
  `trivydb.go:61-70`.
- **Enum literals.** No bare enum strings. `config.LicenseTierValues()` is used
  as the constant source at `trivydb.go:436`.
- **Absence/failure changing correctness (packet question 4).** No. The package
  exports no reader — no `Lookup`, `Open`, `Query`, or byte-returning function —
  and `TestPackageExposesNoWayToServeOrRepublishTheArtifact` enforces that
  structurally at the AST level, including a `checked == 0` guard against
  vacuous passing. `DefaultConfig()` is disabled, `WarmStart` on it is a proven
  no-op that creates no directory (`accelerator_test.go:154-168`), every error
  is advisory, and both sources are attempted independently with joined errors
  (`trivydb.go:729-766`). The consumer is an external binary pointed at
  `CacheDir()`; `internal/collector/repo/trivy.go` defaults `SkipDBUpdate: true`
  and `Validate` refuses `SkipDBUpdate:false` with no `DBRepository`
  (`ErrDBUpdateUnrouted`), so a cold cache produces a failed scan, not a fast
  clean one. This is the strongest part of A.11 and it is well done.
- **Tier-2-derived data laundering into tier 0/1 (packet question 3).** No
  directory-level laundering: the accelerator never reads `mirror/` at all. The
  data-provenance concern is real but narrower than feared — the Trivy DB does
  aggregate the exact CC-BY-SA-4.0/ODbL sources tier 2 quarantines (Ubuntu OVAL,
  Alpine secdb), and the manifest's `outside_licence_mirror: true` records that
  the *directory* carries no tier while saying nothing about the tiers of the
  data inside it. Mitigating: `internal/collector/repo/trivy.go:368-374` carries
  Trivy's own `DataSourceID`/`DataSourceName` through to `finding.source`, so
  attribution survives into the findings cache. What does not exist anywhere is a
  `DataSourceID` → licence-tier mapping. Not A.11's to build, and not a finding
  against it — but it is an **unowned cross-area gap** and A.17/A.19 should be
  told before findings are published.

---

## Environment note for the orchestrator

`go test -count=1 ./...` is currently **red repo-wide**, at
`internal/ingest/sanitize.TestNoProductionImporterYet`
(`sanitize_test.go:2008`). It is a deliberate tripwire in a frozen package,
tripped by sibling packets that now import `internal/ingest/sanitize`
(`internal/collector/host/collect.go`, `internal/collector/repo/trivy.go`,
`internal/ingest/bootstrap/bootstrap.go`, `internal/ingest/poller/poller.go`).
Nothing to do with A.11 — `go test -count=1 ./internal/mirror/accelerator/`
passes on its own — but somebody owns retiring that tripwire and updating
`sanitize.go`'s KNOWN LIMITS item 1, and no packet in my scope does.

## What I could not verify

- `go test -race` did not run (cgo unavailable on this Windows host, per the
  standing note). CI on Linux must run it. A.11 has one mutable shared field —
  `registryClient.token` (`trivydb.go:876`) — written in `exchangeToken` and read
  in `do`. Both happen on one goroutine per warm start today, but `WarmStartWith`
  has no guard against two concurrent calls sharing a cache root, and two
  concurrent warm starts would race on the manifest read-modify-write
  (`trivydb.go:723-765`) with no lock file. Not probed; flag for the race build.
- Real-registry behaviour. GHCR redirects blob GETs to
  `pkg-containers.githubusercontent.com`; `httpClient`'s cross-host redirect
  refusal (`trivydb.go:915-918`) would reject that hop, so the production Trivy
  pull may never have succeeded against real ghcr.io. Correctly no test asserts
  this (S7 forbids the network at test time and the packet forbids it too), but
  the stop condition "Accelerator pulls succeed against a mocked OCI registry" is
  satisfied by a mock that does not model the redirect the real registry issues.
  Worth one manual operator-run check before A.21 depends on it.

## Blocking status

Per the packet's stop condition — *"any redistribution-path finding blocks A.21
until resolved"* — **B-1 and B-2 are redistribution-path findings and A.21 is
blocked.** M-1 should be treated as blocking independently: it is a credential
egress to an attacker-named host, and the credential is the ops-provisioned PAT.
