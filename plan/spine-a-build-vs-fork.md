# Anvil Spine Decision A — Build vs Fork

**Audit date:** 2026-08-06. **Method:** GitHub REST API + raw.githubusercontent.com + rendered docs only, fetched
in-session. No repository was cloned. 21 primary fetches were made against three candidates; the 25-attempt budget
was not exhausted, so this stops on completeness, not on the cap.

## Recommendation

**BUILD.** None of the three candidates gives Anvil a working, license-clean, drop-in component for any of its
eight subsystems once the evidence is checked past the README — the best any of them offers is a design
*reference*, and in one case (`shellphish/artiphishell`) the component that looked most relevant is architecturally
built on `CodeQL`, which Anvil's own prior research (`research/10-prior-art-and-landscape.md`, S8) already
established is legally prohibited for Anvil's use case. `trailofbits/buttercup` is the best-engineered of the
three and the easiest to de-cloud, but forking it would force Anvil to AGPL-3.0 (against the project's already-made
Apache-2.0 decision) and it hard-requires paid frontier LLM APIs — exactly the dependency Anvil exists to remove.
`OSS-CRS` (`github.com/ossf/oss-crs`) is real, MIT-licensed, and actively maintained — this resolves the single
highest-leverage unverified item from prior research — but it is a fuzzing-harness orchestration framework for
OSS-Fuzz-format C/Java/multilang targets, not a SAST/DAST/correlation/advisory pipeline for arbitrary Linux
servers and repos; it does not overlap with what branch 15 already solved for Anvil's DAST tier (Nuclei/ZAP, no
CRS involved), and its own architecture doc marks deduplication, monitoring, and Azure support as **"(planned)"**,
not shipped. **Do not vendor or depend on any of the three.** Build Anvil's pipeline as already scoped by branches
01–24 (SARIF wire format, opengrep + Nuclei/ZAP for detection, DefectDojo for the regression DB), and treat
OSS-CRS's orchestration pattern — isolated per-component containers, `prepare → build-target → run` lifecycle,
per-job CPU/memory/LLM-budget limits, LiteLLM-proxy-compatible model routing — as a **studied reference only**
for Anvil's CI/trigger-orchestration and target-provisioning design, revisited (not forked) if OSS-CRS's planned
dedup/monitoring layer ships and proves reusable.

This overturns branch 10's "fork `artiphishell`" recommendation. Branch 10 verified artiphishell's license and
maintenance metadata correctly but did not open the repository tree, so it did not see the CodeQL coupling or the
Azure/private-wiki-gated deployment documented below. It also resolves branch 10's own flagged gap and critique
14's contradiction C10 and Missing-Branch item 5: OSS-CRS exists, is MIT, and is real — it just does not solve the
problem either branch assumed it would.

## Candidate Assessment

| Repo | Licence (from LICENSE file) | Last push | Archived | Build system | Azure/cloud coupling | Runnable locally? | Evidence URL |
|---|---|---|---|---|---|---|---|
| `shellphish/artiphishell` | **MIT** — verbatim MIT text, "Copyright (c) 2024 AIxCC Finals" | 2025-08-27 | No | Per-component Dockerfiles + Bash-generated `docker-compose` for dev; **official path is Terraform (Azure) + Helm + Tailscale mesh VPN**, driven by `infra/Makefile` | **High.** README's only documented deployment is `Azure Container Registry (Terraform) → build/push images → Terraform AKS-style cluster → Helm install`, gated behind Tailscale VPN credentials and a competition API key. A `local_run/generate_local_docker_compose.sh` alternative exists but its `env.sh` hardcodes unreachable-looking UCSB lab hosts (`wiseau.seclab.cs.ucsb.edu`, `beatty.unfiltered.seclab.cs.ucsb.edu`) for LLM/retrieval/embedding routing and leaves `FUNC_RESOLVER_URL`, `ANALYSIS_GRAPH_BOLT_URL`, `PERMANENCE_SERVER_URL`, `CODEQL_SERVER_URL` unset with no public docs — real setup docs live on a **private** wiki (`github.com/shellphish-support-syndicate/artiphishell/wiki`, linked but not fetchable) | **Hard.** Official path requires Azure + Tailscale + a competition-only API. Local path exists in-tree but depends on several undocumented internal services and is not self-explanatory from public files alone | `https://raw.githubusercontent.com/shellphish/artiphishell/main/LICENSE`; `https://raw.githubusercontent.com/shellphish/artiphishell/main/README.md`; `https://raw.githubusercontent.com/shellphish/artiphishell/main/local_run/env.sh` |
| `trailofbits/buttercup` | **AGPL-3.0** — verbatim GNU AGPLv3 text | **2026-08-03** | No | `Makefile` driving Helm/Kubernetes; **dual path by design**: `make setup-local` → Minikube on Docker Desktop/Colima, or `make setup-azure` → AKS via Terraform (`deployment/*.tf`) | **Low for dev, opt-in for prod.** `deployment/README.md` is a fully worked, troubleshot local-Minikube guide (resource sizing tables, common-error fixes, ARM64/Apple-Silicon notes) with **no Azure requirement**; AKS Terraform exists only as a separately-invoked production path (`make setup-azure`) | **Yes, well-documented**, on Docker Desktop/Colima + Minikube + Helm + kubectl, 8GB+ RAM. Caveat: the *system* runs locally, but the *Patcher* requires a paid OpenAI/Anthropic/Google API key — no self-hosted/open-weight inference path is documented anywhere in the repo | `https://raw.githubusercontent.com/trailofbits/buttercup/main/LICENSE`; `https://raw.githubusercontent.com/trailofbits/buttercup/main/README.md`; `https://raw.githubusercontent.com/trailofbits/buttercup/main/deployment/README.md`; `https://raw.githubusercontent.com/trailofbits/buttercup/main/Makefile` |
| `ossf/oss-crs` (OSS-CRS, arXiv:2603.08566) | **MIT** — verbatim MIT text, "Copyright (c) 2025 OSS-CRS Contributors" | **2026-08-05** (i.e. yesterday) | No | Python package (`oss_crs`, run via `uv run oss-crs ...`) driving **Docker Compose per CRS plugin**; shared `libCRS` client library; each CRS (fuzzer, Atlantis variant, Claude-Code/Codex/Gemini-CLI wrapper, etc.) is a separate `compose.yaml`, not vendored source | **None today.** Repo tree contains **zero** `.tf`/Azure files; architecture doc states explicitly: *"Currently supports local execution via Docker Compose, with Azure deployment planned."* Local Docker Compose + cgroups is the only implemented mode | **Yes, natively** — this is the only mode that exists. The simplest bundled CRS (`crs-libfuzzer`) needs neither cloud nor an LLM key. LLM-backed CRS plugins support an overridable `base_url`/proxy config (documented for routing through "an external LiteLLM instance"), which is at least architecturally compatible with a self-hosted open-weight endpoint — **not verified end-to-end** | `https://api.github.com/repos/ossf/oss-crs`; `https://raw.githubusercontent.com/ossf/oss-crs/main/LICENSE`; `https://raw.githubusercontent.com/ossf/oss-crs/main/README.md`; `https://raw.githubusercontent.com/ossf/oss-crs/main/docs/design/architecture.md` |

**Star/fork counts (GitHub API, fetched 2026-08-06):** artiphishell 137★/32 forks, 358,611 KB tree (~350 MB, not
767 MB — that figure belongs to Atlantis, per branch 10, not artiphishell); buttercup 1,630★/181 forks, 20,466 KB
tree (~20 MB; most weight is pulled Docker images, not repo content); oss-crs 134★/22 forks, 57,258 KB tree
(~56 MB), 40 open issues against 134 stars (high ratio for its age — consistent with young, actively-used, not
abandoned).

**README/docs quality, ranked:** buttercup is unambiguously best — three green CI badges, a fully worked
troubleshooting guide with an explicit resource-vs-outcome table, a Quick Reference and Manual Setup guide.
OSS-CRS is second — dated meeting notes (`docs/meeting/2026-04-06` through `2026-07-27`) showing a live,
organized effort, a real architecture doc, and 40+ example CRS wrappers, but core pieces are self-labeled
"(planned)." Artiphishell is worst for an outside adopter — the *public* README is a competition runbook (secrets
to export, Azure resource-group names to invent) and the actual development documentation is behind a private
wiki this session could not reach.

## Per-Subsystem Verdict

| Anvil subsystem | Fork gives... | Why |
|---|---|---|
| Advisory ingestion | **Nothing** (all three) | None of the three ingest CVE/GHSA/advisory text at all. Artiphishell's static tier consumes CodeQL/SARIF findings, not advisory prose; Buttercup starts from an OSS-Fuzz crash, not an advisory; OSS-CRS has no advisory concept — it targets pre-built fuzz harnesses. |
| Deterministic SCA/host scanning | **Nothing** (all three) | No package-version or host-CVE matcher exists in any of the three; this was already correctly routed to Trivy/OSV-Scanner/Grype independent of any fork (`research/10`). |
| Static recall + model adjudication | **Useful reference only** (artiphishell); **nothing** (buttercup, oss-crs) | Artiphishell has real machinery here (`components/codeql`, `libs/libcodeql`, `semgrep`, `codechecker`, `sarifguy`, `discoveryguy` — 29 files reference `CODEQL_SERVER_URL` alone) and the SARIF-first discovery→triage shape is worth studying. But the working engine underneath is **CodeQL**, which Anvil cannot legally invoke for its stated use case (`research/10`, S8: CI/CD analysis of non-GitHub-hosted, sometimes non-open-source code is expressly prohibited). Buttercup's `program-model` does code indexing (cscope-based) for the *patcher*, not detection. OSS-CRS has no static-analysis component at all. |
| Dynamic (DAST) target provisioning and probing | **Useful reference only, and a scoped one** (oss-crs); **nothing usable** (artiphishell, buttercup) | All three "dynamic" tiers are **source-level fuzzing** (libFuzzer/AFL++/Jazzer against an OSS-Fuzz-format build harness), not web-app HTTP probing. Anvil's actual DAST tier — provisioning a running target and probing it with Nuclei/ZAP — was already solved independently by `research/15` with **no reference to any AIxCC CRS**. OSS-CRS's `oss-crs-infra` (builder-sidecar / runner-sidecar / lifecycle, per-job cpuset+memory+LLM-budget isolation) is a genuinely good reference for the target-lifecycle harness gap branch 19 flagged, but it operates on OSS-Fuzz project layout, not arbitrary Linux services, so it is not a working component for Anvil's DAST tier as scoped. |
| SAST↔DAST correlation into one record | **Nothing** (all three) | No candidate produces a single record correlating a static finding with a dynamic proof-of-exploitability the way Anvil's design (and SARIF-as-envelope, per `research/10`/`research/15`) requires. Artiphishell's `sarifguy` aggregates static SARIF only. |
| Storage/regression DB | **Nothing** (all three) | Artiphishell's telemetry (InfluxDB) and internal graph store are pipeline bookkeeping, not a public dedup/regression DB. Buttercup keeps no durable cross-run regression store. OSS-CRS's architecture doc lists "deduplication and monitoring services" as **"(planned)"** — does not exist yet. `research/10` already routed this to DefectDojo (BSD-3-Clause), independent of any fork. |
| Coding-agent consumption + patch validation | **Useful reference, closest of the three to a real pattern** (oss-crs); **useful reference with real caveats** (buttercup); **useful reference, license-poisoned** (artiphishell) | Buttercup's multi-agent Patcher (validate by rebuild + retest) is the most mature working *pattern* — but it hard-requires OpenAI/Anthropic/Google keys with no self-hosted path documented, and is AGPL-3.0. OSS-CRS ships modular adapters (`crs-claude-code`, `crs-codex`, `crs-gemini-cli`, `crs-copilot-cli`, `crs-opencode`, `crs-bug-finding-template`, `crs-patch-ensemble`) each as an isolated, separately-licensed container behind a documented LLM-proxy override — the cleanest shape to study, not to fork, since it still consumes OSS-Fuzz crash input, not Anvil's audit record. Artiphishell's `patcherq`/`patchery`/`patch-validation-testing` exist but are entangled with the CodeQL/AIxCC "challenge project" format and documented only in the unreachable private wiki. |
| CI/trigger orchestration | **Useful reference, strongest of the three** (oss-crs); **useful reference** (buttercup); **weakest reference** (artiphishell) | OSS-CRS's `prepare → build-target → run` lifecycle with per-component resource/LLM-budget isolation via Docker Compose is MIT, local-native, and the most directly transferable *design*, though "monitoring" is explicitly unshipped. Buttercup's Orchestrator/scheduler is real and tested (3 green CI badges) but AGPL-3.0 and coupled to its own task/competition-API protocol. Artiphishell's orchestration is the least portable — an AIxCC-competition-specific pipeline (`pipeline.yaml`, `aixcc-infra`, Azure Terraform, Tailscale) that assumes infrastructure Anvil does not have and should not want. |

**Bottom line on the table: zero cells say "working component."** The best rating anywhere is "useful reference,"
and it clusters on OSS-CRS for orchestration/target-provisioning and, more weakly, on Buttercup for the
patch-validation *pattern*. Every subsystem still needs to be built.

## What Forking Costs

- **De-clouding.** Artiphishell: not really "de-clouding" so much as reverse-engineering — the official path is
  Azure/Tailscale/competition-API only, the alternate local path depends on several undocumented internal services
  (`FUNC_RESOLVER_URL`, `ANALYSIS_GRAPH_BOLT_URL`, `PERMANENCE_SERVER_URL`, `CODEQL_SERVER_URL`) with no public
  documentation, and the real docs are behind a private wiki this session could not reach. This is comparable
  effort to building fresh, except on top of ~350 MB of AIxCC-specific code you don't yet understand. Buttercup:
  the local path already exists and is well documented, so the real cost is **de-frontier-ing** — ripping out the
  Patcher's OpenAI/Anthropic/Google-coupled agent calls and replacing them with a self-hosted open-weight serving
  path that does not exist in the codebase today. That is a load-bearing rewrite of the component that matters
  most, not a config change. OSS-CRS: no de-clouding needed (it is already local-only), but it needs
  **domain-porting** — retargeting from OSS-Fuzz project layout (pre-built fuzz harness required) to Anvil's actual
  scope of arbitrary Linux servers and code repositories, which is a different input contract, not a deployment
  detail.
- **Licence propagation.** Buttercup is AGPL-3.0; adopting it as a real dependency forces all of Anvil to AGPL-3.0,
  reversing the project's already-made Apache-2.0 decision. Artiphishell's wrapper code is MIT, but its most
  relevant working pipeline cannot legally run for Anvil's purpose without removing CodeQL — at which point what's
  left is a shell, not a working system, and the MIT licence bought nothing. OSS-CRS's MIT core cleanly isolates
  each plugin's own licence (Atlantis-derived plugins carry GPL-3.0, Buttercup-seed-gen-derived plugins carry
  AGPL-3.0 lineage) as separate, optionally-built Docker images that never link into the orchestrator — the same
  "MIT/Apache core, license-separate plugin" pattern `research/15` already recommends for `nmap`/`sqlmap`. This is
  the only one of the three where "fork the orchestrator" would not itself import copyleft — but see the table
  above: the orchestrator alone is not a working component for any Anvil subsystem as scoped.
- **Maintenance of an unmaintained archive.** Artiphishell: last pushed 2025-08-27, ~1 year stale as of this
  writing, competition-archive provenance, 2 open issues (more likely evidence of no external users than of
  quality), no CI badges surfaced, no public roadmap — a fork freezes Anvil onto a codebase nobody outside
  Shellphish can help maintain. Buttercup: pushed 2026-08-03, active, well-tested — genuinely low maintenance risk
  if the AGPL-3.0 and frontier-LLM issues were acceptable, which they are not for Anvil as scoped. OSS-CRS: pushed
  2026-08-05, actively developed under the OpenSSF umbrella (not a single lab), but young (created 2025-11-03,
  first design-doc meeting notes from 2026-04-06) with core capabilities explicitly marked "(planned)" — a
  different risk (immaturity) than Artiphishell's (abandonment), but still not something to depend on for
  subsystems it hasn't built yet.

## What Building Costs

Anvil is not rebuilding these — prior research already routed them to existing, permissively-licensed, non-CRS
tools, and this branch found no reason to change that: fuzzing engines (AFL++/libFuzzer/Jazzer — `research/16`),
web-app DAST engines (Nuclei/ZAP, driven not built — `research/15`), the SARIF 2.1.0 wire format (`research/10`,
`research/15`), deterministic SCA (Trivy/OSV-Scanner/Grype — `research/10`, `research/12`), and the
dedup/regression DB (DefectDojo — `research/10`). What Anvil genuinely has to build, with no working component
found in any of the three candidates:

1. **Advisory ingestion and CWE-routed candidate generation** — untouched by all three candidates.
2. **Static recall + model adjudication on Anvil's own opengrep/CWE pipeline** — Artiphishell's version exists but
   runs on a legally-unusable engine (CodeQL); nothing to inherit but the SARIF-first shape, which Anvil already
   planned to use.
3. **SAST↔DAST correlation into one audit record with a runtime-proof gate** — the piece `research/10` itself
   called Anvil's most defensible novelty; no candidate attempts it.
4. **A target-lifecycle/provisioning harness** for standing up ephemeral scan targets under a resource and time
   budget — this is the one place a candidate (OSS-CRS's builder-sidecar/runner-sidecar/lifecycle pattern) is
   worth deliberately studying as a reference architecture before writing Anvil's own, since it is the best
   evidence in this landscape that the shape works in production today.
5. **A coding-agent adapter layer** that can swap in a self-hosted open-weight model — OSS-CRS's per-plugin
   LLM-proxy override (`example/crs-claude-code`, `crs-codex`, `crs-gemini-cli`, `crs-bug-finding-template`) is
   the closest published example of this shape and is worth reading before designing Anvil's own, but it is not
   reusable as-is because it consumes OSS-Fuzz crash artifacts, not Anvil's SARIF-based audit record.
6. **CI/trigger orchestration matched to Anvil's own hardware-tier model** (per critique branch 14's Missing
   Branch 3) — none of the three ship this against Anvil's actual constraint set, though OSS-CRS's
   `prepare → build-target → run` lifecycle with per-job cpuset/memory/LLM-budget limits is the most directly
   transferable design idea found in this landscape.

## Decision Triggers

- **If Anvil's DAST scope is deliberately expanded to include source-level fuzz-harness bug-finding** (beyond the
  web-app HTTP-probing scope `research/15` already settled), OSS-CRS's Compose-based target-provisioning
  orchestration becomes worth a real integration test, not just a reference read — it is MIT, local-native, and
  modular by design, which none of the fuzzing-tier alternatives are.
- **If OSS-CRS ships its planned deduplication/monitoring layer** and it proves schema-compatible with or
  preferable to DefectDojo, re-open the storage/regression-DB subsystem specifically against OSS-CRS, not against
  Artiphishell or Buttercup, which do not attempt this at all.
- **If Buttercup's maintainers document a self-hosted/open-weight inference path for the Patcher**, removing the
  hard OpenAI/Anthropic/Google dependency, re-evaluate it for the patch-validation subsystem specifically — but
  the AGPL-3.0 licence-propagation cost against Anvil's Apache-2.0 decision would still have to be accepted
  deliberately, not absorbed silently.
- **If Anvil's owner decides AGPL-3.0 is acceptable for the whole project** (reversing the prior Apache-2.0
  decision), Buttercup's Orchestrator and Patcher become materially stronger fork targets for the
  CI-orchestration and patch-validation subsystems specifically — this does not change the verdict for advisory
  ingestion, SCA, static adjudication, correlation, or storage, which remain "nothing" regardless of licence.
- **If someone obtains and reads Artiphishell's private wiki** and confirms the undocumented `local_run` service
  dependencies can be cheaply stubbed and CodeQL swapped for opengrep, its static-analysis component set
  (`semgrep`, `codechecker`, `sarifguy`, `discoveryguy`) becomes worth a second look as a design reference — not as
  a fork, given the codebase's 1-year staleness and the scale of the CodeQL excision required.
- **If a close read of one specific OSS-CRS adapter** (`example/crs-bug-finding-template` or
  `example/crs-patch-ensemble`) shows it is trivially retargetable from OSS-Fuzz-crash input to Anvil's audit
  record, that single adapter — not the framework — becomes a legitimate literal-fork candidate for the
  coding-agent-consumption subsystem. Not evaluated at this depth in this session; flagged as the most promising
  unexplored thread.

## Sources

| ID | What | URL | Fetched-date | Credibility | Limitation |
|---|---|---|---|---|---|
| T1 | shellphish/artiphishell repo metadata (license, pushed_at, archived, stars, forks, size) | https://api.github.com/repos/shellphish/artiphishell | 2026-08-06 | A | Metadata only |
| T2 | artiphishell LICENSE (raw, verbatim MIT) | https://raw.githubusercontent.com/shellphish/artiphishell/main/LICENSE | 2026-08-06 | A | File content only; confirms API's `spdx_id: MIT` this session (unlike Atlantis, this repo's badge and file agree) |
| T3 | artiphishell README (official Azure/Terraform/Helm/Tailscale deployment instructions) | https://raw.githubusercontent.com/shellphish/artiphishell/main/README.md | 2026-08-06 | A | Public README only; links to a private wiki not fetchable in-session |
| T4 | artiphishell full repo tree (recursive) | via `gh api repos/shellphish/artiphishell/git/trees/main?recursive=1` | 2026-08-06 | A | Tree listing (paths only), used to locate `components/codeql`, `libs/libcodeql`, `local_run/`, `infra/`, `aixcc-infra/` |
| T5 | artiphishell `local_run/env.sh` and `local_run/generate_local_docker_compose.sh` (raw) | https://raw.githubusercontent.com/shellphish/artiphishell/main/local_run/env.sh | 2026-08-06 | A | Reveals hardcoded UCSB lab hostnames and unset internal-service env vars; reachability of those hosts not tested |
| T6 | GitHub code search: files in artiphishell referencing `CODEQL_SERVER_URL` | via `gh api search/code -f q='CODEQL_SERVER_URL repo:shellphish/artiphishell'` | 2026-08-06 | A | Confirms 29 files depend on CodeQL client/server; does not prove CodeQL is unavoidable, only that it is deeply wired in |
| T7 | trailofbits/buttercup repo metadata | https://api.github.com/repos/trailofbits/buttercup | 2026-08-06 | A | Metadata only |
| T8 | buttercup LICENSE (raw, verbatim AGPL-3.0) | https://raw.githubusercontent.com/trailofbits/buttercup/main/LICENSE | 2026-08-06 | A | File content only |
| T9 | buttercup README (quick start, system requirements, LLM provider requirement) | https://raw.githubusercontent.com/trailofbits/buttercup/main/README.md | 2026-08-06 | A | Public README; confirms `research/10`'s prior finding still holds as of today |
| T10 | buttercup full repo tree (recursive) | via `gh api repos/trailofbits/buttercup/git/trees/main?recursive=1` | 2026-08-06 | A | Used to confirm no CodeQL dependency and locate `deployment/*.tf` |
| T11 | buttercup `Makefile` (raw) | https://raw.githubusercontent.com/trailofbits/buttercup/main/Makefile | 2026-08-06 | A | Confirms `setup-local` (Minikube) vs `setup-azure` (AKS) as separate, explicit targets |
| T12 | buttercup `deployment/README.md` (raw, local Minikube guide) | https://raw.githubusercontent.com/trailofbits/buttercup/main/deployment/README.md | 2026-08-06 | A | Confirms local path is fully documented and does not require Azure |
| T13 | buttercup `.gitmodules` | https://raw.githubusercontent.com/trailofbits/buttercup/main/.gitmodules | 2026-08-06 | A | Only one submodule (`buttercup-cscope`); no hidden CodeQL dependency found |
| T14 | OSS-CRS paper abstract and code-availability statement | https://arxiv.org/abs/2603.08566 | 2026-08-06 | B | Fetched via a summarizing tool, not a direct PDF read; used only to locate the repo pointer, which was then independently verified at grade A (T15–T19) |
| T15 | ossf/oss-crs repo metadata | https://api.github.com/repos/ossf/oss-crs | 2026-08-06 | A | Metadata only; confirms MIT via API, cross-checked against file body (T16) |
| T16 | oss-crs LICENSE (raw, verbatim MIT) | https://raw.githubusercontent.com/ossf/oss-crs/main/LICENSE | 2026-08-06 | A | File content only |
| T17 | oss-crs README (quick start, multi-environment claim, LLM proxy override) | https://raw.githubusercontent.com/ossf/oss-crs/main/README.md | 2026-08-06 | A | Public README; "deploy to Azure (coming soon)" is a project claim, cross-checked against the repo tree (T18) which contains no Azure/Terraform files |
| T18 | oss-crs full repo tree (recursive) | via `gh api repos/ossf/oss-crs/git/trees/main?recursive=1` | 2026-08-06 | A | Confirms zero `.tf`/azure files and zero CodeQL references; lists 40+ `example/crs-*` plugin directories |
| T19 | oss-crs example CRS compose file (`crs-libfuzzer`) | https://raw.githubusercontent.com/ossf/oss-crs/main/example/crs-libfuzzer/compose.yaml | 2026-08-06 | A | Confirms per-plugin compose isolation pattern and that the simplest plugin needs no LLM key |
| T20 | oss-crs architecture design doc | https://raw.githubusercontent.com/ossf/oss-crs/main/docs/design/architecture.md | 2026-08-06 | A | Primary source for "(planned)" status of Azure/dedup/monitoring — the load-bearing caveat for this report's recommendation |
| T21 | oss-crs `example/atlantis-multilang-given_fuzzer` directory listing | via `gh api repos/ossf/oss-crs/git/trees/main?recursive=1` (filtered) | 2026-08-06 | A | Confirms the Atlantis-derived plugin is a single `compose.yaml` (external image reference), not vendored GPL source inside the MIT core |

**Not independently re-verified this session (carried from prior research, cited only, not re-fetched):**
`research/10`'s CodeQL CLI licence terms (S8), Nuclei/ZAP recommendation (`research/15`), and DefectDojo pick
(`research/10`, S25) — this branch's scope was the three named CRS candidates, not re-auditing branches already
settled with primary-source evidence.

**Stop condition met:** all three candidates assessed from primary sources, the per-subsystem table is complete,
and OSS-CRS's repository was found and verified rather than remaining an open item — the branch stops here at 21
of a possible 25 fetches.
