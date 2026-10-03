# Lane A conformance corpus (A.21)

Every file in this directory is **hand-written to the publisher's documented
shape**. None of it was produced by running any part of Anvil.

That rule is not decoration. A test whose corpus comes from the implementation
asserts that the implementation still does what it did the day the corpus was
captured — which is a change-detector, not a test. Recorded output also
presupposes a successful run, and this project already has one live example of
what that hides: the Trivy E2E job found that the SCA collector cannot run at
all without a pre-seeded database, because every prior test used a recorded
report.

## Provenance, file by file

| File | Shape transcribed from | What it is here for |
|---|---|---|
| `feeds.yaml` | `internal/ingest/config`'s documented schema and `feeds.example.yaml` | The harness's own feed table. Exit criterion 1 forbids feed facts in Go, and a harness that built its rows in Go would be exempting itself from the rule it checks. `${BASE}` is substituted with the in-process test server's origin, because the port is assigned by the kernel. |
| `cvelistv5/CVE-2026-1001.json` | CVE Record Format 5.1 | The chain's main advisory, and the **injection corpus**: its description carries U+200B, U+202E, U+200D and an HTML comment holding an instruction addressed to a model. `anvilinjectionprobe` is the token the harness searches for to prove the comment did not reach the index. |
| `cvelistv5/CVE-2026-1002.json` | CVE Record Format, `dataVersion: 5.9` | A record schema the parser has never seen. Exit criterion 23: persisted with `parse_degraded = 1`, never dropped. |
| `cvelistv5/CVE-2026-1003.json` | CVE Record Format, `state: REJECTED` | Exit criterion 22: tombstoned, kept, and removed from the search index. This is the record that exposed the A.8/A.14 index divergence. |
| `osv/GHSA-deb-2026-0001.json` | OSV schema 1.6, Debian ecosystem | Carries the publisher's own ecosystem spelling, `Debian:11`. It is here to demonstrate a gap — SEAM 1 in `lanea_test.go` — not to pass a check. |
| `kev/known_exploited_vulnerabilities.json` | CISA KEV catalogue | Two entries, and the feed whose registry metadata says `NOASSERTION` over a CC0 body (exit criterion 10). |
| `alpine/v3.19-main.json` | Alpine `secdb` branch file | The one publisher in this corpus whose decoder writes the cache's own short ecosystem vocabulary (`apk`), so it is the one that reaches the comparator. Produces the harness's single end-to-end finding. |
| `redhat/RHSA-2026-0001.json` | Red Hat CSAF/VEX 2.0 | A backported fix as an RPM NEVRA. Its `fixed` product id is what exposed the arch-suffix defect in `SplitNEVRA`. |
| `trivy/report.json` | Trivy JSON report, `SchemaVersion: 2`, `Class: lang-pkgs` | Exercises `repo.ParseReport` with no binary present. `lang-pkgs` and not `os-pkgs` because the collector deliberately skips os-pkgs as the host collector's territory — which is exactly why the repository half and the comparator have disjoint domains (SEAM 3). |
| `inventory/corpus-probe-packages.json` | `internal/collector/host`'s `Package` JSON tags | Host-shaped packages chosen to intersect this corpus. **It is NOT a recording of `internal/collector/host` and is never evidence about it** — the chain runs `host.Collect` for real wherever a package manager exists and cites that for the host-inventory link. These rows stay because no real inventory can ever intersect a synthetic corpus. **Note what is missing: there is no purl field, because `host.Package` has none.** That absence is SEAM 2. |
| `licence/cc0-1.0-excerpt.txt` | The CC0 1.0 Universal deed | The publisher licence body the gate is given. Its digest is pinned in a manifest the harness generates at run time, because a pin written by hand is a number nobody checked. |
| `licence/tier0-notes.md` | `mirror/tier0/LICENSE-NOTES.md`'s shape | Anvil's own record. It can only make the gate's conclusion stricter; it never admits a feed on its own. |

## Identifiers

Every identifier is synthetic and in a range no publisher uses:
`CVE-2026-1001`…`CVE-2026-1006`, `GHSA-deb1-2026-0001`, `RHSA-2026:0001`.
Every host named anywhere is under `.invalid`. Nothing in this directory
resolves, and the harness makes no network call: its only listener is an
in-process `httptest` TLS server.
