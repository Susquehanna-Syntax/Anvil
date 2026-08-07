# Anvil Spine Decision C — Control-Plane Language And Runtime

## Recommendation

**Go** is the control-plane language and runtime, because it is the only candidate that can natively link
(not merely subprocess) five of Anvil's nine load-bearing dependencies — Nuclei, Syft, Grype and OSV-Scanner
officially, Trivy at maintainer-caveated risk — while every other integration surface (ZAP, llama-server,
opengrep, SARIF, SQLite) is either language-agnostic (HTTP/YAML) or available to Go on terms at least as
good as any competitor; the one place a second language legitimately survives is a small, separate **Python**
worker process for the ONNX encoder, which is already architecturally isolated behind HTTP by branch 05's own
serving design and therefore never needs to be the control-plane's language at all.

## Integration Surface

Every row below was verified in-session; URLs, versions and dates are as fetched 2026-08-06 unless noted.

| Dependency | How Anvil must talk to it | Native SDK available in which languages | Subprocess viable? | Evidence URL |
|---|---|---|---|---|
| **Nuclei** | Go SDK **or** CLI (`-jsonl`, `-sarif-export`) | **Go only** — official SDK `github.com/projectdiscovery/nuclei/v3/lib`, v3.11.0, published 2026-07-06, MIT, entry points `NewNucleiEngineCtx`/`ExecuteCallbackWithCtx` returning typed `*output.ResultEvent` | Yes — CLI is the only path for every non-Go language | https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/lib |
| **Trivy** | CLI (JSON/SARIF/CycloneDX output) **or** import Go source under `pkg/` | **Go only, and unofficially even there.** `pkg/scan`, `pkg/detector`, `pkg/report`, `pkg/fanal`, `pkg/module/api`, `pkg/types` are importable, but a Trivy maintainer states plainly: *"You can use Trivy's code directly. There's no REST/RPC API."* — no documented API-stability contract for `pkg/`. Module is pre-1.0 (v0.73.0, 2026-08-03). | Yes — CLI+JSON is the de facto supported integration path for every language including Go | https://pkg.go.dev/github.com/aquasecurity/trivy ; https://github.com/aquasecurity/trivy/discussions/3553 |
| **Syft** | CLI **or** Go library | **Go only** — README states "A CLI tool **and Go library**"; ships example programs (`create_simple_sbom`, `source_from_registry`, etc.); v1.50.0, published 2026-07-27, Apache-2.0 | Yes | https://pkg.go.dev/github.com/anchore/syft |
| **Grype** | CLI **or** Go library | **Go only** — public packages `grype/match`, `grype/matcher/{java,python,golang,javascript,dotnet,ruby,rust,...}`, `grype/db`, `grype/presenter` (incl. SARIF output); v0.116.1, published 2026-07-28, Apache-2.0 | Yes | https://pkg.go.dev/github.com/anchore/grype |
| **OSV-Scanner** | CLI **or** Go library | **Go only** — `pkg/osvscanner` and `pkg/models` are the documented public packages; module `github.com/google/osv-scanner/v2`, v2.4.0, published 2026-06-18, Apache-2.0 | Yes | https://pkg.go.dev/github.com/google/osv-scanner/v2 ; https://api.github.com/repos/google/osv-scanner |
| **opengrep** | CLI only | **None, in any language.** OCaml core (`opengrep-core`, OCaml 5.5.0) plus a Python-CLI wrapper compiled with Nuitka into a self-contained binary. Releases page (v1.26.0, 2026-07-24) ships only platform tarballs (`opengrep-core_linux_x86.tar.gz`, `_osx_aarch64`, `_windows_x86.zip`) — no library artifact, no FFI, no bindings documented anywhere in the repo. This is a wash across every candidate language. | Yes — the **only** option, LGPL-2.1 | https://github.com/opengrep/opengrep/releases ; https://github.com/opengrep/opengrep |
| **OWASP ZAP** | HTTP REST API in daemon mode (`-daemon`, default port **8080**, `http://zap/<format>/<component>/<operation>/...`) **or** declarative YAML via Automation Framework (`-cmd -autorun plan.yaml`) | **None needed.** ZAP is a JVM application; Anvil never links it — it talks HTTP or writes a YAML file. Fully language-agnostic. | N/A — long-running daemon or one-shot java invocation, same for every language | https://www.zaproxy.org/docs/api/ |
| **llama.cpp / llama-server** | HTTP, OpenAI-compatible: `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, plus `/health`, `/slots` | **None needed.** llama-server is "pure C/C++ HTTP server based on httplib... and llama.cpp." Language-agnostic HTTP client suffices for any control-plane language. | N/A — always-on HTTP daemon | https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md |
| **ONNX Runtime** | In-process C-API binding, **or** — per branch 05's own serving recipe — a separate always-on worker process behind an OpenAI-style/local HTTP boundary alongside the llama-server tiers | **Official (Microsoft-maintained):** Python, C++, C, C#, Java, JavaScript (Web/Node/React Native), Objective-C. **Community-only, cgo-required even in Go's case:** Go (`yalue/onnxruntime_go`, MIT, third-party, loads the ONNX Runtime shared library via cgo), Rust, Ruby, Julia. | If run as a separate worker (branch 05's design): yes, trivially — it's just another HTTP peer. If forced in-process: only in an officially-bound language | https://onnxruntime.ai/docs/get-started/ ; https://github.com/yalue/onnxruntime_go |
| **SQLite + FTS5** | Embedded library, linked into the control-plane binary | **cgo path (mattn/go-sqlite3):** confirmed FTS5 support via build tag `sqlite_fts5` ("When this option is defined in the amalgamation, version 5 of the full-text search engine is added"), MIT, v1.14.49, published 2026-07-29 — but requires `CGO_ENABLED=1` + a C compiler at build time. **Pure-Go path (modernc.org/sqlite):** v1.56.0, published 2026-08-03, "CGo-free port of the C SQLite3 library" via transpilation — **FTS5 support is NOT VERIFIED**: no mention in its README, its `sqlite.go` source, its pkg.go.dev docs, or any open/closed GitHub issue found in-session. | N/A — embedded | https://pkg.go.dev/github.com/mattn/go-sqlite3 ; https://pkg.go.dev/modernc.org/sqlite ; https://sqlite.org/fts5.html (confirms FTS5 is a compile-time option, "disabled by default for the source-tree configure script") |
| **SARIF 2.1.0** | Library to produce/parse/merge results (ZAP and Nuclei both natively emit SARIF per branches 15/22; Anvil must merge, not generate from nothing) | **Go:** `owenrumney/go-sarif`, Unlicense, actively pushed 2026-07-29, explicitly versions the 2.1.0 package path (`report/v210/sarif`). **.NET (spec's home ecosystem):** official Microsoft `sarif-sdk`, pushed 2026-08-05 (same-day activity), 224 stars, license field `NOASSERTION` on the repo despite being a Microsoft OSS project. **Python:** not independently verified this session — treat as an open question, not an assumption. | n/a (library, not a process) | https://api.github.com/repos/owenrumney/go-sarif ; https://api.github.com/repos/microsoft/sarif-sdk |

## Why This Language

Score the table, not a preference. Five of the nine rows (Nuclei, Trivy, Syft, Grype, OSV-Scanner) are
Go-native tools. For four of them Go gets an **officially documented library API** in addition to the CLI;
for Trivy it gets an unofficial-but-real one a maintainer explicitly points people at ("use Trivy's code
directly"). No other language gets *any* of these five as anything but a subprocess. That is not a matter of
taste — it is a strict dominance result: choosing Go weakly dominates every other candidate on this axis and
loses nothing on any other row, because:

- **ZAP and llama-server are HTTP daemons.** They do not care what language calls them. Choosing Python,
  Rust, or Java buys nothing here that Go lacks.
- **opengrep is subprocess-only for everyone.** OCaml core, no FFI, no bindings in any language verified.
  This row is a wash across the whole language space — it cannot argue for or against Go.
- **ONNX Runtime is the one row where Go is not officially supported** — but branch 05 already designed
  around this before this document existed: the SAST encoder is specified as its own always-on ONNX Runtime
  *worker process*, addressed by a config-declared base URL exactly like the two llama-server detection
  tiers, not as a library call inside the orchestrator. That means the control plane's actual requirement
  on ONNX Runtime is "own an HTTP client," which every language satisfies equally. Go's missing official
  binding only matters if that architectural boundary is later erased — see Decision Triggers.
- **SQLite is a partial win, not a clean one.** Go can get FTS5 today, but only through `mattn/go-sqlite3`
  and cgo, not through the pure-Go driver (whose FTS5 support this session could not verify at all). This
  is a real, load-bearing caveat on the "install-friction" argument (see (a) below and Risks) — but it is a
  *narrow* cgo dependency (a C compiler at build time, producing a single output binary afterward), not the
  kind of heavyweight runtime dependency that embedding ONNX Runtime or opengrep in-process would require.
- **SARIF 2.1.0 has an actively maintained Go library** that targets 2.1.0 specifically and is exactly the
  shape Anvil needs (merge ZAP's and Nuclei's native SARIF output into one record) — not a gap Go needs to
  route around.

Weighing the six factors the brief asks for, in order:

**(a) Single-binary distribution / install friction.** `CGO_ENABLED=0` cross-compilation produces a static
binary per target OS/ARCH with no runtime dependency beyond whatever Anvil chooses to fork-exec (opengrep,
Trivy, ZAP's JVM, llama-server). This is the sharpest fit to "minimal compute... easy to install and run" of
any candidate — a self-hoster downloads one file. The FTS5-driven cgo requirement (see SQLite row) is the one
crack in this story: the build step needs a C toolchain, though the *deployed artifact* is still one binary.

**(b) Does the control plane need any in-process ML at all?** No, and this is the single biggest reason the
decision is easier than it looks. Branch 05's serving recipe already puts every model — two detection
LLMs, the on-demand coding agent, and the ONNX encoder — behind config-declared HTTP endpoints. "Control
plane" as scoped in this task (poll feeds, drive scanners, call model endpoints, provision/probe DAST
targets, assemble the audit record, write SQLite, enforce the auth gate, expose the CI trigger) is,
end-to-end, an HTTP-and-subprocess orchestrator. Nothing in that job description does floating-point tensor
math.

**(c) The ONNX encoder path, if forced in-process.** Official bindings are Python, C++, C, C#, Java, JS,
Objective-C — not Go, not Rust. If a future measurement (Decision Trigger 1) forces the encoder in-process
for latency reasons, Go is not the language to do it in; Python or C++ is. That is exactly why this document
does not recommend collapsing that boundary, and exactly why Python is named as the one place a second
language survives.

**(d) systemd / cgroups / subprocess supervision / daemon ergonomics.** Go's standard library `os/exec` plus
`context` gives clean timeout/cancellation semantics for supervising opengrep, Trivy, a ZAP JVM process, and
llama-server child processes — the exact shape of Anvil's job. `coreos/go-systemd` (Apache-2.0, pushed
2026-07-23, 2,703 stars) supplies socket activation, `sd_notify`, journal and D-Bus integration natively, so
the control plane can be a first-class `Type=notify` systemd unit without shelling out to anything.

**(e) cgo implications for SQLite if Go is chosen.** Addressed above: the pure-Go path exists
(`modernc.org/sqlite`) and removes cgo for everything *except* FTS5, whose support in that driver is
unverified rather than confirmed-absent — a genuine open question, not a settled negative. The safe default
is `mattn/go-sqlite3` with the `sqlite_fts5` build tag, accepting a build-time (not run-time) C-toolchain
dependency. This is a materially smaller compromise than the alternative of not having FTS5 at all, which
would undercut branch 07's entire retrieval design.

**(f) Ecosystem risk / vendor-or-fork.** All five Go-native dependencies (Nuclei, Trivy, Syft, Grype,
OSV-Scanner) are MIT or Apache-2.0 and, being Go, are trivially `go vendor`-able or forkable into Anvil's own
module graph in the same language the rest of the project is written in — no cross-language port required if
upstream ever relicenses or goes dark (a risk branch 15 already documents happening to `sqlite-vss` and
Grype's own v5→v6 DB migration). Choosing a non-Go control plane would mean any such fork carries a
forced language migration on top of the fork itself.

## Where Python Survives

Concretely, three places, none of them the control plane's own runtime:

1. **The ONNX encoder worker**, if and only if it stays the separate process branch 05 already specifies.
   Python has the official ONNX Runtime binding; this is the natural implementation language for that one
   small, isolated service, reached by the Go control plane over the same kind of local HTTP boundary used
   for the llama-server tiers. It is never imported into the orchestrator process.
2. **Offline model training and fine-tuning** for the SAST/DAST detection models (branch 03's domain) —
   entirely out of the control plane's runtime path, run on different hardware, on a different schedule,
   producing artifacts (GGUF/ONNX files) that the control plane only ever *serves*, never *trains*.
3. **The evaluation harness** — the KL-divergence quantization checks branch 05 recommends running against
   Anvil's own corpus before shipping a quant, and the labelled (code-chunk → advisory) retrieval-quality set
   branch 07 recommends before adding vector search. Both are one-shot or periodic offline scripts, not
   services the control plane calls at request time.

Nowhere else. Not the SQLite layer, not SARIF assembly, not the scanner-driving code, not the CI trigger
surface, not the authorization gate. Every one of those sits squarely in the "orchestrate subprocesses and
HTTP peers" job the control plane exists to do, and Go covers it with a strictly larger native-linking
surface than Python would.

## Consequences

**What this makes easy:**
- A single static binary a self-hoster downloads and runs, satisfying the "easy to install" constraint
  directly, with `coreos/go-systemd` giving a clean systemd unit for free.
- Native, typed linking to the entire deterministic-scanner core (Nuclei officially; Syft, Grype,
  OSV-Scanner officially; Trivy unofficially) instead of shelling out and parsing text for most of Anvil's
  SCA/SAST-adjacent detection work — fewer process spawns, fewer serialization boundaries, directly serving
  "minimal compute."
- Clean subprocess supervision (timeouts, cancellation, resource limits) for the pieces that must stay
  subprocesses regardless of language: opengrep, ZAP's JVM, llama-server.
- SARIF merge/assembly against an actively maintained, version-pinned 2.1.0 Go library.

**What this makes hard:**
- If the ONNX encoder is ever pulled in-process (Decision Trigger 1), Go cannot do it on official tooling —
  the project would need to accept a community/cgo-wrapped binding (real risk: `yalue/onnxruntime_go` is a
  single-maintainer project) or keep the encoder as a satellite process forever, which is in fact the
  currently recommended design, not a workaround.
- SQLite's "pure Go, zero cgo" story is not fully available if FTS5 must be guaranteed; the practical answer
  is a narrow, build-time-only cgo dependency, which is a small but real departure from the cleanest version
  of the single-binary pitch.
- Trivy's `pkg/` surface carries no maintainer-promised API stability, so linking it natively means pinning
  a specific version and re-validating on every upgrade rather than trusting semver.

**What this forecloses:**
- A one-process, one-language design where the control plane also does in-process tensor math — this was
  never actually on the table once branch 05's HTTP-fronted serving recipe is taken as given, regardless of
  which language is picked for the control plane.
- Treating Trivy's Go packages as a long-term stable contract without an explicit vendoring/pinning policy.
- A "we'll just reuse this Python scanner-glue script inline" pattern — any Python component must cross the
  same HTTP boundary as the model servers, by design, not by oversight.

## Risks

The strongest argument against this pick is Python, stated fairly, not as a straw man:

Python has **official, first-class ONNX Runtime bindings** where Go has none. If Anvil's actual production
profile turns out to need thousands of (advisory × code-chunk) encoder calls per scan and the HTTP round-trip
to a separate worker dominates wall-clock time at that volume — a real possibility branch 05 does not rule
out, since its own throughput numbers are all for the *generative* tiers, not the encoder — then collapsing
encoder and orchestrator into one Python process removes an entire network hop and a serialization boundary,
and Python could do that natively where Go structurally cannot. In that world, Python's control plane would
subprocess all five deterministic Go scanners (a real cost — no native linking, more parsing, more process
spawns) but would gain a zero-copy, zero-IPC encoder path. Python's install story is also not without answer:
tools like PyInstaller or `uv`-managed self-contained environments exist, even if this document did not
verify a specific one to the same standard as Go's `CGO_ENABLED=0` story. **This is a real trade-off, not a
false one** — Go wins on breadth of native integration across the deterministic-scanner core; Python would
win on depth of integration with the one dependency (ONNX Runtime) that is arguably the most architecturally
sensitive of the nine, if the isolated-worker design does not hold up under load. The recommendation here
rests on trusting branch 05's own architecture — model serving, including the encoder, stays behind HTTP —
which is a decision this document did not re-litigate and treats as a given input.

A second, smaller risk: four of the five "Go-native" wins are asymmetric in confidence. Nuclei, Syft, Grype
and OSV-Scanner all explicitly brand themselves as libraries; Trivy does not, and a maintainer's own words
("no REST/RPC API... use Trivy's code directly") is closer to "you're on your own" than to an endorsement.
If Trivy's internal package layout churns across releases, Anvil's native-linking advantage there degrades
to what any subprocess-only language already has — CLI plus JSON.

## Decision Triggers

What evidence would flip this pick, or a piece of it:

1. **A measured latency profile showing the ONNX-worker HTTP round-trip is the dominant cost** in the SAST
   hot loop at Anvil's real corpus scale (thousands of advisory×chunk pairs per scan). This would argue for
   collapsing the encoder into the orchestrator process — and if that happens, Python (official ONNX binding)
   or C++ becomes the stronger control-plane pick, not Go. This is the single trigger most likely to actually
   fire, because branch 05 flags the encoder's throughput as unmeasured relative to the generative tiers.
2. **Confirmation, one way or the other, of FTS5 support in `modernc.org/sqlite`.** If confirmed present,
   Go's single-binary story becomes airtight (no cgo anywhere) and the pick strengthens with no change of
   direction. If confirmed *absent* by a maintainer statement, the cgo-via-`mattn/go-sqlite3` fallback becomes
   mandatory rather than optional, which is worth knowing explicitly rather than assuming.
3. **Trivy publishing (or explicitly disclaiming) a stability contract for its `pkg/` API.** A published
   contract raises confidence in native linking; an explicit "do not use as a library" statement would drop
   Trivy to CLI-subprocess-only for Anvil, same as every other language — no flip, but a real downgrade of
   one row's evidence.
4. **Project maintainer capability.** If Anvil's actual contributor base is overwhelmingly Python-fluent and
   Go-inexperienced, that is a legitimate, non-technical reason to reconsider that this document's evidence
   base cannot settle — it is the owner's call, not a fact this research can adjudicate.
5. **opengrep growing an official FFI, C API, or WASM build.** Would not flip anything on its own (it is
   currently a wash across all languages), but would be worth re-checking if it ever changes, since it is
   currently the one dependency with zero binding options anywhere.

## Sources

| ID | What | URL | Fetched | Credibility | Limitation |
|---|---|---|---|---|---|
| C1 | ONNX Runtime official vs. community language bindings | https://onnxruntime.ai/docs/get-started/ | 2026-08-06 | A | Official docs page; "community-projects" grouping read from nav structure, not a single explicit sentence |
| C2 | opengrep repo — OCaml implementation, LGPL-2.1, CLI-only, no bindings found | https://github.com/opengrep/opengrep | 2026-08-06 | A | README-level read; did not exhaustively audit every subdirectory for a hidden binding |
| C3 | opengrep releases — v1.26.0 (2026-07-24), OCaml-compiled platform binaries, no library artifact | https://github.com/opengrep/opengrep/releases | 2026-08-06 | A | Releases page only; does not itself state "no bindings exist," inferred from absence of any binding artifact |
| C4 | mattn/go-sqlite3 — cgo requirement, FTS5 via `sqlite_fts5` build tag, MIT, v1.14.49 (2026-07-29) | https://pkg.go.dev/github.com/mattn/go-sqlite3 | 2026-08-06 | A | pkg.go.dev rendering of README; not the raw LICENSE file |
| C5 | modernc.org/sqlite — pure-Go/cgo-free, transpiled amalgamation, v1.56.0 (2026-08-03); FTS5 NOT found in docs | https://pkg.go.dev/modernc.org/sqlite ; https://pkg.go.dev/modernc.org/sqlite#section-readme | 2026-08-06 | B | Absence-of-evidence, not evidence-of-absence — thorough search (README, source file, docs page, issue search) found no FTS5 mention, but a maintainer was not directly asked |
| C6 | modernc-org/sqlite source (`sqlite.go`) — no "fts5" string found | https://github.com/modernc-org/sqlite/blob/master/sqlite.go | 2026-08-06 | B | Large generated-adjacent file; fetch tool may not have scanned the entire file |
| C7 | modernc-org/sqlite GitHub issue search for "fts5" — zero results | https://github.com/search?q=repo%3Amodernc-org%2Fsqlite+fts5&type=issues | 2026-08-06 | B | Zero results is weak evidence either way |
| C8 | sqlite.org — FTS5 is a compile-time option, disabled by default for source-tree configure | https://sqlite.org/fts5.html | 2026-08-06 | A | Canonical primary source |
| C9 | aquasecurity/trivy Go module — `pkg/` structure, Apache-2.0, v0.73.0 (2026-08-03) | https://pkg.go.dev/github.com/aquasecurity/trivy | 2026-08-06 | A | pkg.go.dev auto-generated package listing |
| C10 | Trivy maintainer statement: "You can use Trivy's code directly. There's no REST/RPC API." | https://github.com/aquasecurity/trivy/discussions/3553 | 2026-08-06 | B | Single discussion comment, not a formal policy doc; may be stale relative to current `pkg/module/api` |
| C11 | anchore/syft — official "CLI tool and Go library," v1.50.0 (2026-07-27), Apache-2.0 | https://pkg.go.dev/github.com/anchore/syft | 2026-08-06 | A | README self-description taken as authoritative |
| C12 | anchore/grype — public Go packages, v0.116.1 (2026-07-28), Apache-2.0 | https://pkg.go.dev/github.com/anchore/grype | 2026-08-06 | A | pkg.go.dev listing |
| C13 | google/osv-scanner v2 — `pkg/osvscanner`, `pkg/models`, v2.4.0 (2026-06-18) | https://pkg.go.dev/github.com/google/osv-scanner/v2 | 2026-08-06 | A | pkg.go.dev listing |
| C14 | google/osv-scanner repo metadata — Apache-2.0, active, pushed 2026-08-06 | https://api.github.com/repos/google/osv-scanner | 2026-08-06 | A | GitHub API metadata |
| C15 | projectdiscovery/nuclei/v3/lib — official Go SDK, v3.11.0 (2026-07-06), MIT | https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/lib | 2026-08-06 | A | pkg.go.dev listing; corroborates branch 15's independent finding |
| C16 | llama-server — pure C/C++ HTTP server, OpenAI-compatible endpoints | https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md | 2026-08-06 | A | README-level read |
| C17 | ZAP REST API — daemon mode, port 8080, URL pattern; Automation Framework YAML | https://www.zaproxy.org/docs/api/ | 2026-08-06 | A | Official docs; corroborates branch 15/22 independently |
| C18 | owenrumney/go-sarif — targets SARIF 2.1.0, Unlicense | https://github.com/owenrumney/go-sarif | 2026-08-06 | A | GitHub page render |
| C19 | owenrumney/go-sarif repo metadata — active, pushed 2026-07-29 | https://api.github.com/repos/owenrumney/go-sarif | 2026-08-06 | A | GitHub API metadata |
| C20 | microsoft/sarif-sdk repo metadata — official Microsoft, active, pushed 2026-08-05 | https://api.github.com/repos/microsoft/sarif-sdk | 2026-08-06 | A | GitHub API metadata; license field is `NOASSERTION` despite being a real Microsoft OSS repo — GitHub's detector limitation, not a licensing red flag |
| C21 | yalue/onnxruntime_go — community/third-party Go wrapper, cgo-based, MIT | https://github.com/yalue/onnxruntime_go | 2026-08-06 | A | README-level read; confirms Go's ONNX path is unofficial and cgo-dependent |
| C22 | go.dev — `CGO_ENABLED=0` cross-compilation produces static binaries without a C toolchain | https://go.dev/doc/install/source#environment | 2026-08-06 | A | Official Go docs |
| C23 | coreos/go-systemd — socket activation, journal, D-Bus, unit files; Apache-2.0, pushed 2026-07-23 | https://api.github.com/repos/coreos/go-systemd | 2026-08-06 | A | GitHub API metadata |
| C24 | Trivy/Syft/Grype/Nuclei/OSV-Scanner licenses and maintenance state | (see branches 12, 15, 22 of Anvil's own research) | n/a — cross-referenced, not independently refetched for license text | A (inherited) | This document trusts prior branches' verified license findings rather than re-fetching LICENSE files already fetched there; version/date facts above were independently re-verified this session |
