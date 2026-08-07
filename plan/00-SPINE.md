# Anvil — Locked Architecture Spine

**Read this before writing any implementation step.** These decisions are settled by the research corpus
in `research/` (25 reports, 760 sourced rows, two audits and an audit-of-the-audit). They are **not open
for re-litigation by component workers.** If your area's evidence genuinely contradicts something here,
do not silently diverge — write the conflict into your `## Conflicts With Spine` section and let the
orchestrator resolve it.

Authoritative background: `research/MASTER-REPORT.md`. Adversarial critique: `research/14-critique-and-gaps.md`.
Licence ground truth: `research/13-license-compatibility-audit.md` as corrected by `research/13a-license-audit-adversarial-review.md`.

---

## S0. What Anvil is

An open-source, **profit-free**, self-hostable system that finds vulnerabilities in Linux servers and code
repositories and proposes fixes. Self-hosted, locally-served open-weight models. Never browses the live
web at inference time.

## S1. The spec was wrong in four places. These are the corrected requirements.

The owner's original eight requirements did not survive research. The corrected form is binding:

| # | Original | Corrected — this is what you implement |
|---|---|---|
| 1 | A small model skims the codebase for one CVE at a time | **Two lanes.** *Lane A (deterministic, zero inference):* SBOM/host package matching by version comparator — owns dependency and host findings. *Lane B (first-party source):* a deterministic recall tier produces candidates; the small model **adjudicates a short candidate list**. **Never form the N×M cross product.** |
| 3 | SAST and DAST results written together into one record | **One audit identity, two independently-sealed halves, a re-entrant consumer.** The record seals per half. |
| 5 | An 8-hour buffer file, then deleted | **Collapsed.** One SQLite store of record + a `handoff` table + a regenerable tmpfs packet. "8 hours" is a **claim timeout**, not a deletion policy and not a confidentiality control. |
| 8 | Scrape advisory feeds so the model never browses the web | **Scoped.** Ingestion serves Lane A. Lane B's label space is **CWE 4.20** (944 classes, a few MB, no delta feed needed). Advisory-text conditioning is an explicitly-scoped **vendored/backported code** feature. |

**Requirement #4a, added:** a cheap triage gate runs before the coding agent. With no orchestrator tier,
it is the only thing between a false positive and a committed code change.

**Why (short form):** CVE/OSV/GHSA describe vulnerable *package versions*; a version comparator answers
that exactly and for free. First-party source has no package identity and therefore no CVE. The
advisory-conditioned path costs **20×–760× more prefill than a single pass** over the same repo, and the
deterministic scanner it was meant to replace is its **prerequisite**, not its alternative.

## S2. The number that decides whether Anvil is affordable

**Candidates emitted per scan by the deterministic pre-filter.** Instrument it on day one. It, not model
size, determines feasibility. Under ~500 per full scan and ~50 per push, the model tier costs ~17 min and
~2 min. In the thousands, the design does not work and must be re-scoped.

## S3. Evaluation before construction

The corpus names **twelve decisive experiments and assigns owners to none**. Two of them can *delete the
detection-model tier entirely*, turning Anvil into a deterministic scanner with an LLM patcher — a
smaller, cheaper, possibly better system:

1. **Advisory-permutation ablation.** Feed the model an *unrelated* advisory. If `EXHIBITS` verdicts flip
   >80%, it reads the advisory and the design is validated. <50% means CVE ingestion is decoration.
2. **Code-metrics baseline.** A logistic regression over classic code metrics reportedly matches LLMs at
   this task. If it does here, the model tier does not exist.

**The evaluation harness is Milestone 0.** No component is selected before it runs.

## S4. Component picks (all provisional on S3; all licence-verified unless noted)

| Layer | Pick | Licence |
|---|---|---|
| SCA + host | **Trivy** (one binary: host + repo + SBOM; documents its false-positive defence) | Apache-2.0 |
| Source recall | **opengrep** engine + **`AikidoSec/opengrep-rules`** | LGPL-2.1 / MIT |
| SAST adjudicator | **Qwen3.5-2B** — *verify a text-only variant exists first, the 3.5 line is vision-language* | Apache-2.0 |
| DAST engine | **Nuclei** always-on; **ZAP** for scheduled full scans | MIT / Apache-2.0 |
| DAST model | **same base as SAST**, larger context + turn budget, hard turn cap | — |
| Attack surface | runtime spec probe → repo specs → static route extraction → browser crawl **last** | Apache-2.0 |
| Target env | declared `.anvil/target.yaml` → Compose → gVisor → default-deny egress netns | Apache-2.0 |
| Dynamic analysis | sanitizer-instrumented test suite (ASan+UBSan); **ARVO** as validation oracle | BSD-2-Clause |
| Coding agent | **Qwen3-Coder-Next** (3B active / 80B total — RAM-bound, not VRAM-bound) | Apache-2.0 |
| Serving | **llama.cpp / llama-server** + **ONNX Runtime** for the encoder path | MIT |
| Record | **SARIF 2.1.0** + versioned `anvil/*` extension + derived task cards | OASIS |
| Store | **SQLite** WAL + FTS5, single writer | public domain |
| Ingestion | tiered conditional GET → SQLite cache, bootstrapped from bulk archives | — |
| Scheduling | systemd timer + `.anvil/policy.yml`, Renovate-shaped match/apply rules | — |

**Not vLLM in v1.** Its multi-LoRA design requires fine-tuned adapters that must not exist before S3.

**Gemma 4 is eligible — this reverses an earlier exclusion.** Verified 2026-08-06 by the orchestrator
against Google's own terms page: *"For Gemma 4 terms, see the Gemma 4 license"*, which resolves to
Apache-2.0. The remote-restriction clause (*"Google reserves the right to restrict (remotely or
otherwise) usage of any of the Gemma Services…"*) belongs to the **old Gemma Terms of Use**, which
Gemma 4 is carved out of — so the kill-switch objection that disqualified Gemma 1–3 does **not** reach
Gemma 4. Branch 14 was right and branch 13 was over-cautious. Gemma 4 is therefore a legitimate
candidate for the adjudicator role alongside Qwen3.5-2B, which matters because the Qwen3.5 line is
vision-language and its footprint estimates are consequently wrong.
**Caveat, and it is not optional:** verify the licence of the *specific* Gemma 4 variant at selection
time. Qwen is documented to split licences **by parameter count inside one family**, so a sibling's
licence proves nothing about the one you ship.

## S5. Hard exclusions — do not design these in

**CodeQL** (CLI terms forbid CI/CD database generation and non-open-source targets; the restriction
attaches to the *target*, so Anvil's own licence is irrelevant) · **Semgrep-maintained rules** (internal
business use only) · **`opengrep/opengrep-rules`** (archived, NOASSERTION, LGPL-2.1 + Commons Clause —
use `AikidoSec/opengrep-rules`) · **CIS Benchmark content in any form**, including rules written by
reading one · **Gemma 1–3 / Llama / StarCoder2 / Mistral-MNPL weights** · **DiverseVul** (no licence) ·
**vendored ExploitDB** · **Metasploit modules** · **PoC-aggregator code** · **AFL++** (AGPL-3.0 in its
LICENSE regardless of its README — use honggfuzz) · **FuzzDB `web-backdoors/`** · **`code:` protocol
Nuclei templates** (251 exist; they execute arbitrary commands on the Anvil host).

## S6. The record — required fields beyond stock SARIF

Branch 18's schema was written without visibility into what five other branches needed. All of these are
**required**, not optional:

`anvil/state`, `anvil/version`, per-half `status` + `sealedAt` · `anvil/trust: {untrusted |
anvil_generated | verified}` **on every string originating outside Anvil** · `dast_status`,
`dast_coverage`, `target_provenance` (a target that failed to boot must be distinguishable from "scanned
clean") · `remediable_by_agent` (host findings are `false`) · `INSUFFICIENT_CONTEXT` as a valid detector
verdict, not just a confidence float · `as_of` / `staleness_seconds` / `parse_degraded` · `endpoint_coverage`,
`inventory_provenance` · sanitizer + ASLR state on any reproducer.

**One fingerprint algorithm, defined once, in the record.** Two branches specified different `/v1`
algorithms under the same name; two producers emitting different hashes means regression matching
silently fails forever. Ship a conformance test asserting identical digests on a fixed corpus.

**Ordering:** re-cut the work queue on every version bump and **reserve a configurable fraction (default
50%) of remaining budget for late DAST-confirmed arrivals** — otherwise incremental publication silently
inverts the priority scheme, because nothing is DAST-confirmed when the queue is first cut.

## S7. Safety and trust — enforce in code, not documentation

- **Never auto-merge.** Propose only. Best measured security-patch rate on real CVEs is 34.0%.
- **Only a DAST reproduction that now fails earns "verified fixed."** A clean SAST rescan does not:
  detectors reach 10.16–13.82% true-positive on vulnerabilities that persist after an incomplete patch.
- **The host agent is read-only** — no package manager in a mutating mode, not behind a flag.
- **The authorization kernel is a pure function of `(target, scope, attestation, clock)`**, compiled
  separately from the model runtime, with a build-time test that fails if the dependency graph inverts.
  **No model ever holds a network handle.** Re-validate scope on **every request including every redirect
  hop**; never follow cross-host redirects.
- **`security.txt` resolves a reporting channel and never grants permission** (RFC 9116 says so). Enforce
  at the type level so the inevitable contributor proposal fails to compile.
- **Prompt injection:** sanitize at ingest, not at prompt time. The **DAST response body is the
  highest-risk field** — up to 32 KB of attacker-controlled bytes fed to a repo-credentialed agent.
  Hash-and-reference by default; inline only a regex-extracted evidence span. Pin nuclei-templates by
  commit SHA and diff before promotion.

## S8. Licence posture

**Apache-2.0 for the core.** Justified by the one-way valve (Apache can flow into GPL/AGPL later, never
the reverse), the §4 NOTICE mechanism matching Anvil's long attribution list, and the fact that the only
two tools copyleft would buy (AFL++, SSLyze) are replaced on independent technical grounds.

**Do not justify it by the patent grant** — §3 runs from *contributors over their own contributions* and
does nothing about the third-party patent (US10043004B2, SAST↔DAST correlation, expires ≈2035) that
branch 18 flagged. An outbound licence is not a freedom-to-operate instrument.

**sqlmap** ships as a separately distributed GPL-3.0 plugin under four rules: (i) separate git repo,
separate release artifact, separate package name, never vendored into the core tree; (ii) separate
**process** — the core loads no plugin code into its address space; (iii) the interface is a documented
**tool-agnostic data contract** (SARIF or versioned JSON), because an interface named `SqlmapDriver` is
arguably itself "designed specifically to execute sqlmap"; (iv) all sqlmap-specific knowledge lives on
the GPL side.

**nmap is an open decision, not a settled exclusion.** NPSL's derivative-work terms bind distribution by
parties who *accept the licence*, and the licence disclaims binding vendors whose practices fair use
already permits. Dropping it is prudence, not compulsion — and the proposed replacements were never
checked for coverage (nuclei's `network/` templates presuppose a known host and port; they do no
discovery).

**Greenbone/OpenVAS — flag resolved, item stands.** The Lane A planner reported that "Greenbone VT
content" had zero support in the research corpus and omitted it. Orchestrator-verified 2026-08-06: it is
**extensively sourced** — 17 mentions in `research/15-dast-tooling-landscape.md`, which quotes Greenbone's
own licence page (*"The OPENVAS COMMUNITY FEED is a database licensed under the Open Data Commons Open
Database License version 1.0 (ODbLv1)"*), plus coverage in 13, 13a, 14 and the master report. The planner
grepped only its own three input files, where Greenbone legitimately does not appear. **Its action was
right and its reason was wrong:** Greenbone belongs to the dynamic/host tier, not Lane A's feed table. The
ODbL share-alike quarantine requirement stands unchanged.

**Compliance mechanics:** an SPDX allowlist CI gate that reads **LICENSE file bodies, never API
metadata** (seven artifacts return `NOASSERTION` over a real licence; one hides a *restrictive* one), with
a manual-override field carrying the quoted operative sentence. Pin exact model revision SHAs and archive
each model's LICENSE at that revision. Share-alike sources live in segregated directories with their own
LICENSE files.

## S9. Hardware tiers — "minimal compute" was never quantified; it is now

| Tier | Machine | What runs |
|---|---|---|
| **S** | 8 GB / 4 core, no GPU | SAST only; coding agent remote; **DAST off** |
| **M** | 32 GB / 8 core | SAST + DAST against declared ephemeral targets; coding agent remote |
| **L** | 64 GB+ / GPU | everything local |

**DAST is an opt-in tier, not a concurrent default.** Its cost is dominated by provisioning and
containment, not model parameters: environment construction is the primary bottleneck, only **56.1%** of
repos shipping a Dockerfile produce a buildable image, and the best agentic environment builder reaches
**37.7%**. For most targets the DAST half will be empty — which is exactly why `dast_status` is required.

### S9-AMENDED — DAST ships as a separate distribution artifact, not a config flag

**Resolved by the orchestrator 2026-08-06**, escalated from the DAST area. The original S9 modelled DAST
as a config-gated capability inside one binary (`dast.enabled=false` at Tier S). The DAST planner
correctly objected that this **does not address the legal concern it was meant to address**: research/20
raised UK CMA **s.3A(2)** — supplying an article *"believing that it is likely to be used"* in an offence,
two years on indictment, with no research defence on the face of the statute — and a config flag inside a
single shipped binary still supplies the probing capability to everyone who installs it.

**Decision: split the distribution.**
- **`anvil`** — core. Lane A, Lane B, record, store, remediation. **No network probing capability
  compiled in.** This is the artifact distros package and most users install.
- **`anvil-dast`** — the dynamic tier. A separate release artifact, separately installed, requiring
  explicit attestation before it will probe anything.

Four reasons, in descending force:
1. It is the **only** form that addresses the supply concern. A boolean does not.
2. The separate-artifact machinery **is already required** — S8 mandates exactly this shape for the
   GPL-3.0 sqlmap driver. Marginal cost is low because the mechanism must exist anyway.
3. **Retrofitting is materially more expensive than deciding now**, once users depend on a single binary.
4. It gives distro packagers a clean choice and composes cleanly with the tier matrix: Tier S simply does
   not install `anvil-dast`.

**Not a legal conclusion.** I am not a lawyer; this is a risk-posture decision that makes the exposure
smaller and the packaging honest. The underlying legal question stays flagged, not resolved.

## S10. Naming the orchestrator honestly

Removing the "orchestrator tier" removed an *extra LLM tier*, which is what the owner actually retracted.
It did not remove the orchestration: four branches each specified part of one (consumption protocol with
leases and ledgers, a correlator process, sixteen validation gates, a target-lifecycle harness). Implement
it as **one named scan controller with one state machine and one owner**, or it will be re-implemented
inconsistently in four places.

---

## S11. BUILD — do not fork an AIxCC CRS. (Spine A, resolved 2026-08-06)

This **overturns the research corpus**, which recommended forking `shellphish/artiphishell`. Full
evidence: `plan/spine-a-build-vs-fork.md`. Across all eight Anvil subsystems, every candidate returns
"nothing" or "useful reference only" — **never a working component**.

- **`shellphish/artiphishell` (MIT, verified):** its static-analysis pipeline is wired to **CodeQL** —
  a `components/codeql` directory plus `libs/libcodeql`, orchestrator-verified. CodeQL is on Anvil's hard
  exclusion list (S5) for licence reasons that attach to the *target*, not to Anvil. The one subsystem
  where this fork looked most valuable is the one it poisons. Its deployment path is Azure Terraform +
  Helm + a Tailscale mesh gated by competition credentials, and its real docs sit behind a private wiki.
- **`trailofbits/buttercup` (AGPL-3.0, verified, active):** best-engineered of the three, with a genuine
  local Minikube path. But it **hard-requires paid OpenAI/Anthropic/Google API keys with no open-weight
  path** — precisely the dependency Anvil exists to remove — and forking forces all of Anvil to AGPL-3.0.
- **OSS-CRS (`ossf/oss-crs`) — the research's "single highest-leverage unverified item", now resolved.**
  It is real: MIT, 134★, pushed 2026-08-05, under OpenSSF, local-Docker-Compose-native with no Azure in
  tree. But it is a **fuzzing-harness orchestration framework for OSS-Fuzz-format targets**, not a
  SAST/DAST correlation pipeline. It does not overlap with what Anvil needs.

**Use OSS-CRS as a design reference, not a dependency.** Its orchestration pattern is the strongest
reference available for Anvil's scan controller (S10): isolated per-component containers, a
budget-limited `prepare → build → run` lifecycle, and LiteLLM-proxy-compatible model routing.

**Open thread:** whether an OSS-CRS adapter (`example/crs-bug-finding-template`, `crs-patch-ensemble`)
could be retargeted from OSS-Fuzz-crash input to Anvil's SARIF record was not evaluated at depth. Worth
one bounded spike before the remediation tier is built — not a blocker.

## S12. Go for the control plane. (Spine C, resolved 2026-08-06)

Full evidence: `plan/spine-c-language.md`.

**Five of nine load-bearing dependencies are Go-native** — Nuclei, Trivy, Syft, Grype, OSV-Scanner — and
offer native library linking no other language gets. The rest are language-agnostic: ZAP and llama-server
are HTTP daemons; opengrep is an OCaml CLI with **zero bindings in any language**, so subprocess is the
only option everywhere and Go loses nothing. Go strictly dominates without giving ground.

**No cgo required.** `modernc.org/sqlite` translates the whole SQLite C source to Go and supports FTS5
(orchestrator-verified) — so the SQLite + FTS5 store, the single static binary, and cross-compilation all
hold together. Do **not** reach for `mattn/go-sqlite3`, which needs cgo and a C toolchain.

**Where Python survives — exactly three places, none of them control-plane runtime:**
1. The **ONNX encoder worker** — a separate always-on process addressed over HTTP, never an in-process
   library call. Python has official ONNX Runtime bindings; Go has only a community cgo wrapper.
2. Offline model training, if S3 ever justifies it.
3. The evaluation harness and KL-divergence quantisation checks.

**The honest counter-argument, recorded so it can be tested:** if the encoder HTTP round-trip dominates
latency at real scan volume — thousands of advisory×code-chunk pairs per scan, a cost never measured —
then collapsing encoder and orchestrator into one process becomes attractive, and Python becomes the
stronger pick, trading native Go scanner linking for zero-IPC encoder access. **Measure encoder RTT under
realistic pair volume during Milestone 0 before this is irreversible.**

**Carry as risk, not settled:** Trivy exposes no REST/RPC API and its maintainers direct users to "use
Trivy's code directly", with no `pkg/` API stability contract. Treat native Trivy linking as
vendor-pin-and-monitor, and keep a CLI fallback path.
