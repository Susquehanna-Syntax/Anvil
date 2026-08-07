# Anvil Implementation — Licence Compliance

## Overview

Anvil ships as Apache-2.0 with a segregated quarantine for share-alike sources (Ubuntu OVAL/USN, Alpine secdb, Greenbone ODbL feed). This plan assembles seven newly-verified artifacts and enforces a license-file-reading CI gate that catches the eight NOASSERTION-hiding-real-licence trap. Core work is mechanical: archiving model revisions at exact SHAs, fixing two self-inconsistencies in the audit (sqlmap GPL versioning, MITRE ATT&CK year hardcoding), and translating the sqlmap plugin boundary from prose into four verifiable rules. The gate reads actual LICENSE bodies, never metadata.

## Dependency Summary

| Artifact | Licence | Source | Action | Obligation |
|----------|---------|--------|--------|------------|
| Gemma 4 weights | Apache-2.0 | spine-b-open-licences.md A1 | Pin revision SHA; archive LICENSE | §4 NOTICE duty |
| go-apispec | Apache-2.0 | spine-b A2 | Archive NOTICE file | §4 NOTICE duty; NOTICE aggregation |
| llama-swap | MIT | spine-b A3 | Track revision SHA | Attribution in docs |
| Valkey | BSD-3-Clause | spine-b A4 | Track SHA; document no-endorsement | No-endorsement clause §3 |
| Docker Engine | Apache-2.0 | spine-b A5 | Redistribute only Apache-2.0 license | §4 NOTICE duty |
| Docker Compose | Apache-2.0 | spine-b A6 | Redistribute only Apache-2.0 license | §4 NOTICE duty |
| Qwen/Qwen3-Coder-30B-A3B-Instruct | Apache-2.0 | spine-b A7 | Pin revision SHA; archive LICENSE | §4 NOTICE duty; parameter-count variance risk |
| iris-sast/cwe-bench-java | MIT | spine-b A8 (implicit in A7 item count) | Track for experiments only | No redistribution duty; reference rights only |

## Steps

### Serial Phase 1: License File Assembly
**Dependency:** none

```
Step ID:          C.1
Phase/group:      serial
Depends on:       none
Backend/model:    orchestrator-inline
Objective:        Create repository root LICENSE (Apache-2.0), NOTICE (Apache §4 aggregation), and THIRD-PARTY-LICENSES.md.
Scope and files:  WRITE: LICENSE, NOTICE, THIRD-PARTY-LICENSES.md
Forbidden actions: none
Inputs/artifact refs: research/13-license-compatibility-audit.md (obligations table, C lines), research/13a-license-audit-adversarial-review.md (R5 subprocess guidance)
Expected output schema: Three files with exact Apache-2.0 text (LICENSE), aggregated NOTICE duties (NOTICE), and MIT/BSD attribution table (THIRD-PARTY-LICENSES.md).
Validation/evidence required: LICENSE must contain full Apache License 2.0 text; NOTICE must list each Apache-2.0 artifact with operative clause; THIRD-PARTY-LICENSES.md must index all permissive non-Apache dependencies.
Stop condition: All three files exist and LICENSE body matches SPDX canonical Apache-2.0.
Why this model:   Templated file creation from audit tables; no judgment needed.
```

### Serial Phase 2: Share-Alike Quarantine Structure
**Dependency:** C.1

```
Step ID:          C.2
Phase/group:      serial
Depends on:       C.1
Backend/model:    Claude Code subagent (haiku)
Objective:        Create data/share-alike/ directory tree with separate LICENSE files for each share-alike source per S8 requirement.
Scope and files:  WRITE: data/share-alike/ubuntu/LICENSE (CC-BY-SA-4.0), data/share-alike/alpine/LICENSE (CC-BY-SA-4.0), data/share-alike/openvas-feed/LICENSE (ODbL-1.0), data/share-alike/.gitkeep
Forbidden actions: Do not merge directories; do not include share-alike content in NOTICE; do not create root data/LICENSES/ yet
Inputs/artifact refs: research/13-license-compatibility-audit.md table B (B12, B13, B22); 00-SPINE.md S8
Expected output schema: Four directories with 4 LICENSE files containing full license text for each source.
Validation/evidence required: Each LICENSE file contains verbatim license text; no cross-references between quarantine directories; data/share-alike/ is isolated from core repo layout and explicitly marked in gitignore.
Stop condition: Directory structure created with all four license files; verify CC-BY-SA-4.0 text is identical in ubuntu/ and alpine/; ODbL-1.0 is distinct in openvas-feed/.
Why this model:   Fast bounded chore: copy four license bodies to file locations; verify directory isolation; no synthesis.
```

### Parallel Group 3: Seven Newly-Closed Items — Model Revision Pinning
**Dependency:** C.2

```
Step ID:          C.3
Phase/group:      parallel group 3
Depends on:       C.2
Backend/model:    Claude Code subagent (haiku)
Objective:        Pin exact Gemma 4, Qwen3-Coder-30B-A3B-Instruct, and llama-swap model revision SHAs; archive each model's LICENSE file at that revision.
Scope and files:  WRITE: data/LICENSES/GEMMA4-LICENSE (Apache-2.0), data/LICENSES/QWEN-CODER-30B-LICENSE (Apache-2.0), data/LICENSES/LLAMA-SWAP-LICENSE (MIT); READ: research/spine-b-open-licences.md A1, A7
Forbidden actions: Do not modify the LICENSE text; do not create subdirectories for each model; do not re-fetch model metadata (use spine-b revision dates)
Inputs/artifact refs: spine-b-open-licences.md A1 (Gemma 4, links to https://ai.google.dev/gemma/apache_2), A7 (Qwen model card at 2025-12-03), research/13a item 8 (llama-swap verified MIT)
Expected output schema: Three files with (1) full Apache-2.0 text for Gemma 4 and Qwen model, (2) full MIT text for llama-swap, plus a CSV row in data/LICENSES/MODEL-REVISION-PINS.csv listing model ID, SHA, license, archive date.
Validation/evidence required: Each archived LICENSE is byte-identical to the primary source at the pinned SHA; MODEL-REVISION-PINS.csv references spine-b fetch dates; Qwen parameter-count variance risk is documented in comments.
Stop condition: Three LICENSE files exist in data/LICENSES/; MODEL-REVISION-PINS.csv has three rows with SHAs and fetch dates; verify Qwen model name and parameter count match spine-b A7 exactly.
Why this model:   Mechanical assembly of revision data and license archiving; bounded chore with no synthesis.
```

```
Step ID:          C.4
Phase/group:      parallel group 3
Depends on:       C.2
Backend/model:    Claude Code subagent (haiku)
Objective:        Archive go-apispec NOTICE file and Docker Engine/Compose Apache-2.0 license texts; add to Anvil's NOTICE aggregation.
Scope and files:  WRITE: data/LICENSES/GO-APISPEC-NOTICE, data/LICENSES/DOCKER-ENGINE-LICENSE, data/LICENSES/DOCKER-COMPOSE-LICENSE; READ/APPEND: research/spine-b-open-licences.md A2, A5, A6
Forbidden actions: Do not modify or paraphrase NOTICE/LICENSE content; do not create separate directories per component
Inputs/artifact refs: spine-b A2 (go-apispec NOTICE excerpt), A5–A6 (Docker Engine/Compose Apache-2.0 source URLs); research/13-license-compatibility-audit.md C3 (ZAP Apache-2.0 as reference for §4 duties)
Expected output schema: Three files: GO-APISPEC-NOTICE (verbatim from spine-b), DOCKER-ENGINE-LICENSE and DOCKER-COMPOSE-LICENSE (full Apache-2.0 text); update root NOTICE file to reference these three in NOTICE aggregation table.
Validation/evidence required: go-apispec NOTICE matches spine-b excerpt verbatim; Docker files contain full Apache-2.0 § 4 text; root NOTICE updated to list all three under "Apache-2.0 §4 Dependencies."
Stop condition: Three archive files created in data/LICENSES/; root NOTICE file contains entries for all three with source attribution.
Why this model:   Mechanical transcription and file organization; archive assembly only.
```

```
Step ID:          C.5
Phase/group:      parallel group 3
Depends on:       C.2
Backend/model:    Claude Code subagent (haiku)
Objective:        Archive Valkey BSD-3-Clause LICENSE and iris-sast/cwe-bench-java MIT license; document no-endorsement clause and evaluation scope.
Scope and files:  WRITE: data/LICENSES/VALKEY-LICENSE, data/LICENSES/CWE-BENCH-JAVA-LICENSE, data/LICENSES/MODEL-REVISION-PINS.csv append; READ: spine-b A4, A8
Forbidden actions: Do not modify license text; do not create separate directories
Inputs/artifact refs: spine-b A4 (Valkey BSD-3-Clause excerpt, no-endorsement clause), A8 (iris-sast/cwe-bench-java MIT); research/13a correction item 3 (Valkey as a recommended dependency in verdict F9)
Expected output schema: Two files (VALKEY-LICENSE with full BSD-3-Clause text, CWE-BENCH-JAVA-LICENSE with full MIT text); append to MODEL-REVISION-PINS.csv with note that iris-sast is eval-only.
Validation/evidence required: BSD-3-Clause clause 3 is present verbatim in VALKEY-LICENSE; iris-sast entry is marked "EVAL-ONLY" in pins CSV; comment in VALKEY-LICENSE flags the no-endorsement clause as a conduct duty for marketing.
Stop condition: Two license files created; MODEL-REVISION-PINS.csv updated with iris-sast eval-only annotation; root NOTICE or compliance metadata references Valkey no-endorsement restriction.
Why this model:   Bounded archive task with one special annotation (no-endorsement duty, eval-only scope).
```

### Serial Phase 4: Defect Fixes
**Dependency:** C.3, C.4, C.5

```
Step ID:          C.6
Phase/group:      serial
Depends on:       C.3, C.4, C.5
Backend/model:    Claude Code subagent (haiku)
Objective:        Fix sqlmap GPL version in audit matrix row C6 from GPL-2.0-only to GPL-2.0-or-later; cite operative license text.
Scope and files:  READ: research/13-license-compatibility-audit.md (C6 row, Unsettled Questions); WRITE: plan/80-compliance.md (this file) update in Conflicts With Spine, data/LICENSE-OVERRIDES.csv (new file documenting the fix)
Forbidden actions: Do not modify the primary audit file (13.md); do not change the recommendation text
Inputs/artifact refs: research/13-license-compatibility-audit.md C6 text "GPL v2 (June 1991)"; research/13a E3 correction (or-later with quoted operative sentence); 00-SPINE.md S8 (recommends sqlmap as GPL plugin)
Expected output schema: New row in data/LICENSE-OVERRIDES.csv: sqlmap | original: GPL-2.0-only, corrected: GPL-2.0-or-later | "Version 2 (or later) with the clarifications and exceptions described below" | C6 matrix row
Validation/evidence required: Override CSV cites operative sentence from sqlmap LICENSE verbatim; Conflicts With Spine section flags the audit self-inconsistency (matrix vs. recommendation); CI gate configuration (step C.11) treats sqlmap as -or-later.
Stop condition: LICENSE-OVERRIDES.csv created with sqlmap entry; Conflicts With Spine section written; evidence that recommendation already says or-later is recorded.
Why this model:   Text correction tied to a specific primary source quote; bounded chore.
```

```
Step ID:          C.7
Phase/group:      serial
Depends on:       C.3, C.4, C.5
Backend/model:    Claude Code subagent (haiku)
Objective:        Make MITRE ATT&CK copyright year dynamic (derived from release date) rather than hard-coded 2026; template the notice for CI-time substitution.
Scope and files:  WRITE: data/NOTICES/ATTACK-NOTICE-TEMPLATE.txt (with {YEAR} placeholder); READ: research/13-license-compatibility-audit.md obligations table (B9 entry), research/13a E4 correction
Forbidden actions: Do not commit 2026 literal into the template; do not hard-code any future year
Inputs/artifact refs: research/13a E4 (page renders "© 2015 – 2026" dynamically; template the year); research/13-license-compatibility-audit.md B9 exact string requirement
Expected output schema: Template file with "{YEAR} The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." and a footnote explaining substitution is done at CI time or release time.
Validation/evidence required: ATTACK-NOTICE-TEMPLATE.txt contains {YEAR} placeholder; root NOTICE or COMPLIANCE-NOTES.md explains the substitution rule; CI gate step documents how year is injected.
Stop condition: Template file created and referenced in NOTICES directory; mechanism for year substitution is documented in CI gate specification (step C.11).
Why this model:   Templating task tied to audit correction E4; straightforward substitution logic.
```

### Serial Phase 5: sqlmap Plugin Boundary Specification
**Dependency:** C.6

```
Step ID:          C.8
Phase/group:      serial
Depends on:       C.6
Backend/model:    Claude Code subagent (sonnet)
Objective:        Specify the four enforceable sqlmap plugin boundary rules as an architectural decision document with interface definitions and validation gates.
Scope and files:  WRITE: plan/PLUGIN-SQLMAP-BOUNDARY.md (new architecture spec); READ: research/13-license-compatibility-audit.md C6, research/13a R3 (sqlmap escape analysis), 00-SPINE.md S8 (four rules)
Forbidden actions: Do not propose implementation; do not refer to non-existent code; do not leave any rule vague
Inputs/artifact refs: research/13a R3 items 1–4 (the four coupling points: repo separation, process separation, tool-agnostic interface, GPL-side knowledge); 00-SPINE.md S8 verbatim rule text
Expected output schema: Markdown document with four sections: (1) separate git repo/release/package, (2) separate process with address-space isolation, (3) tool-agnostic SARIF/JSON data contract, (4) sqlmap-specific knowledge. Each section includes: rationale, operative constraint, validation test, and a reference to spine-b correction R3.
Validation/evidence required: Each rule is stated as an objective constraint (not a preference); rule 3 includes an example of what "tool-agnostic" means (what SqlmapDriver interface name would violate it); CI gate (step C.11) can verify rules 1 and 2 syntactically.
Stop condition: PLUGIN-SQLMAP-BOUNDARY.md is complete and self-contained; four rules are numbered and independently checkable; reference to R3 research correction is explicit.
Why this model:   Moderate synthesis: translate prose legal/architectural analysis into checkable rules; requires judgment on interface design implications.
```

### Serial Phase 6: SPDX CI Gate Design and Implementation
**Dependency:** C.8

```
Step ID:          C.9
Phase/group:      serial
Depends on:       C.8
Backend/model:    Claude Code subagent (sonnet)
Objective:        Design the SPDX license-file-reading CI gate; specify manual-override schema and the eight NOASSERTION-trap artifacts that need hard-coded overrides.
Scope and files:  WRITE: SPEC-SPDX-GATE.md (design doc); READ: research/13-license-compatibility-audit.md (methodology note, method section; tables A–C), research/13a (entire adversarial review for coverage of NOASSERTION traps)
Forbidden actions: Do not implement code; do not reference GitHub license API (gate must read file bodies only); do not assume override field will be optional
Inputs/artifact refs: research/13-license-compatibility-audit.md methodological warning (six NOASSERTION trap artifacts: ComplianceAsCode, osquery, wazuh, CVEfixes, commix, kev-data; seventh in A16 Foundation-Sec-8B; eighth in research/13a E2 PurpleLlama); spine-b-open-licences.md (seven newly-verified clean items)
Expected output schema: Markdown spec with sections: (1) gate logic (read LICENSE/COPYING/NOTICE files, parse SPDX tags), (2) hard-coded override table with all eight artifacts, operative license clause in quotes, (3) manual-override field schema (JSON: artifact_id, operative_sentence, override_date, justification), (4) failure modes and reroute conditions.
Validation/evidence required: Spec explicitly names all eight NOASSERTION traps by repository name; each override entry includes the actual licence text from primary source; spec states "never use GitHub API spdx_id"; manual-override is not optional for gate to proceed on unknown artifacts.
Stop condition: SPEC-SPDX-GATE.md is complete and architecture-ready; eight override table entries are present with source citations from research/13 or research/13a.
Why this model:   Architectural design work requiring synthesis of audit findings, routing logic, and error modes; moderate complexity.
```

```
Step ID:          C.10
Phase/group:      serial
Depends on:       C.9
Backend/model:    Claude Code subagent (sonnet)
Objective:        Implement the SPDX license-file-reading gate in Go as a standalone binary with hard-coded override logic and manual-override field validation.
Scope and files:  WRITE: cmd/license-gate/main.go, cmd/license-gate/overrides.go, cmd/license-gate/schema.go (JSON override records); READ: SPEC-SPDX-GATE.md, data/LICENSES/* (for testing), data/LICENSE-OVERRIDES.csv (sqlmap fix artifact)
Forbidden actions: Do not call any GitHub API; do not make override table dynamic/external; do not skip validation of manual-override JSON; do not accept NOASSERTION from GitHub metadata
Inputs/artifact refs: SPEC-SPDX-GATE.md from C.9, research/13-license-compatibility-audit.md sources list (for test data), 00-SPINE.md S8 (exclusion list)
Expected output schema: Go package with: (1) main.go that reads LICENSE file at a given path and emits SPDX ID or FAIL with override check, (2) overrides.go with hard-coded table of eight NOASSERTION traps with operative license sentence, (3) schema.go defining manual-override JSON schema with required fields (artifact_id, operative_sentence, override_date, justification), (4) exit codes: 0=OK, 1=FAIL, 2=OVERRIDE_NEEDED.
Validation/evidence required: Unit tests verify gate reads actual LICENSE files; override logic correctly identifies the eight trap artifacts and applies quoted operative sentence; manual-override JSON schema validation rejects incomplete records; test data includes at least ComplianceAsCode (BSD-3-Clause text with NOASSERTION tag) and PurpleLlama (Llama Community License with NOASSERTION tag).
Stop condition: Binary compiles; `license-gate /path/to/LICENSE` exits 0 or 1; `license-gate --list-overrides` dumps the eight override table; manual-override JSON is validated on read and rejected if operative_sentence is missing.
Why this model:   Implementation of the design from C.9; bounded, high-validation-requirement gate code.
```

### Serial Phase 7: Exclusion List Enforcement
**Dependency:** C.10

```
Step ID:          C.11
Phase/group:      serial
Depends on:       C.10
Backend/model:    Claude Code subagent (haiku)
Objective:        Implement exclusion list as an enforced denylist in CI, not documentation; wire it into the license gate.
Scope and files:  WRITE: cmd/license-gate/exclusions.go, data/EXCLUSION-LIST.json; READ: 00-SPINE.md S5 (hard exclusions), research/13-license-compatibility-audit.md (matrix rows for excluded artifacts)
Forbidden actions: Do not put exclusion list in README or docs only; do not make it optional; do not list rationales (list only artifact names and rejection reason code)
Inputs/artifact refs: 00-SPINE.md S5 (CodeQL, Semgrep Rules, archived opengrep-rules, CIS Benchmarks, Gemma 1–3 / Llama / StarCoder2 / Mistral-MNPL weights, DiverseVul, Metasploit modules, PoC-aggregator, AFL++, FuzzDB web-backdoors/, code: protocol Nuclei templates), research/13-license-compatibility-audit.md tables (verify each is in the matrix and has rationale)
Expected output schema: Go code that checks artifact names against denylist and exits with code 2; JSON file with format: [{"artifact": "semgrep/semgrep-rules", "reason": "INTERNAL_BUSINESS_USE_ONLY", "reference": "13-C20"}, ...]. At least 13 entries (one per S5 bullet point).
Validation/evidence required: Each exclusion entry has a matrix reference (13-Cxx or 13-Bxx); license gate rejects any artifact in the exclusion list before checking overrides; denylist is consulted on repository inventory scans and model-weight selection.
Stop condition: exclusions.go is imported by main.go; `license-gate --deny-check artifact-name` returns 0 (found and denied) or 1 (not on list); data/EXCLUSION-LIST.json has at least 13 entries with source references.
Why this model:   Bounded configuration work: organize existing spine S5 list into enforced denylist; mechanical assembly.
```

### Serial Phase 8: Validation and Checklist
**Dependency:** C.11

```
Step ID:          C.12
Phase/group:      serial
Depends on:       C.11
Backend/model:    orchestrator-inline
Objective:        Generate final compliance checklist verifying all obligations are present and no artifact is licensed under an excluded condition.
Scope and files:  WRITE: plan/COMPLIANCE-CHECKLIST.md; READ: all artifacts created in C.1–C.11, data/EXCLUSION-LIST.json, data/LICENSE-OVERRIDES.csv, spine-b-open-licences.md
Forbidden actions: none
Inputs/artifact refs: spine-b-open-licences.md compliance checklist (7 items at end of file); research/13-license-compatibility-audit.md obligations table; 00-SPINE.md S8
Expected output schema: Markdown checklist with sections: (1) Seven newly-closed items and their obligations (Gemma 4, go-apispec, llama-swap, Valkey, Docker Engine, Docker Compose, Qwen model), (2) Share-alike quarantine (ubuntu, alpine, openvas-feed), (3) Defect fixes (sqlmap GPL version, MITRE ATT&CK year), (4) Plugin boundary rules verified, (5) License gate deployed, (6) Exclusion list enforced, (7) Model revision SHAs pinned and archived.
Validation/evidence required: Each item on the checklist is checkable at CI time (file exists, gate runs, exclusion list is present, overrides are valid JSON); checkmarks indicate successful local test run.
Stop condition: COMPLIANCE-CHECKLIST.md is complete and all checkmarks are filled in based on artifacts created in previous steps.
Why this model:   Rollup and verification that all obligations are satisfied; no synthesis or judgment.
```

---

## Repository Layout

```
Anvil/
├── LICENSE                         # Apache-2.0 full text (SPINE S8)
├── NOTICE                          # Apache §4 aggregation: lists Gemma 4, go-apispec, Docker Engine/Compose, Qwen model
├── THIRD-PARTY-LICENSES.md         # MIT/BSD attributions: llama-swap, iris-sast/cwe-bench-java, Nikto database, etc.
├──
├── data/
│   ├── LICENSES/                   # Per-source license archives
│   │   ├── APACHE-2.0.txt          # Canonical Apache-2.0 text (reference)
│   │   ├── GEMMA4-LICENSE          # Gemma 4 Apache-2.0 at pinned revision SHA
│   │   ├── QWEN-CODER-30B-LICENSE  # Qwen3-Coder-30B-A3B-Instruct Apache-2.0 at SHA
│   │   ├── LLAMA-SWAP-LICENSE      # llama-swap MIT license
│   │   ├── GO-APISPEC-NOTICE       # go-apispec NOTICE file (Apache §4 duty)
│   │   ├── DOCKER-ENGINE-LICENSE   # Docker Engine Apache-2.0
│   │   ├── DOCKER-COMPOSE-LICENSE  # Docker Compose Apache-2.0
│   │   ├── VALKEY-LICENSE          # Valkey BSD-3-Clause (no-endorsement clause documented)
│   │   ├── CWE-BENCH-JAVA-LICENSE  # iris-sast/cwe-bench-java MIT
│   │   ├── CVE-TOU.txt             # MITRE CVE ToU
│   │   ├── CWE-TERMS.txt           # MITRE CWE ToU
│   │   ├── ATTACK-NOTICE-TEMPLATE.txt  # MITRE ATT&CK notice with {YEAR} placeholder (E4 fix)
│   │   ├── MODEL-REVISION-PINS.csv # SHAs and fetch dates for all model weights; Qwen parameter-count caveat noted
│   │   └── NOTICES/                # Aggregate NOTICE files by source category
│   │       └── APACHE-COMPONENTS.NOTICE
│   │
│   └── share-alike/                # Segregated copyleft sources (SPINE S8)
│       ├── ubuntu/
│       │   └── LICENSE             # CC-BY-SA-4.0 (Ubuntu OVAL/USN)
│       ├── alpine/
│       │   └── LICENSE             # CC-BY-SA-4.0 (Alpine secdb)
│       └── openvas-feed/
│           └── LICENSE             # ODbL-1.0 (Greenbone Community Feed)
│
├── plan/
│   ├── 80-compliance.md            # THIS FILE
│   ├── PLUGIN-SQLMAP-BOUNDARY.md   # Four enforceable sqlmap plugin rules (S8, R3 from 13a)
│   ├── SPEC-SPDX-GATE.md           # SPDX gate design: eight NOASSERTION overrides, override schema
│   └── COMPLIANCE-CHECKLIST.md     # Final validation checklist
│
├── cmd/license-gate/
│   ├── main.go                     # Gate entry point: reads LICENSE files, checks SPDX
│   ├── overrides.go                # Hard-coded override table for eight NOASSERTION traps
│   ├── schema.go                   # Manual-override JSON schema validation
│   └── exclusions.go               # Denylist check (S5 hard exclusions)
│
└── data/
    ├── EXCLUSION-LIST.json         # Enforced denylist: CodeQL, Semgrep Rules, CIS Benchmarks, etc. (13+ items)
    ├── LICENSE-OVERRIDES.csv       # Audit defect fixes: sqlmap GPL version (E3), MITRE ATT&CK year (E4)
    └── .gitignore updates          # Ensure data/share-alike/* is never merged into published artifacts
```

**Rationale by section:**
- **LICENSE, NOTICE, THIRD-PARTY-LICENSES.md**: Apache-2.0 core declaration and §4 duty aggregation (SPINE S8).
- **data/LICENSES/**: Archiving model SHAs and license bodies at revision time catches parameter-count divergence and license-card-drift traps (SPINE S4 caveat on Qwen, 13a coverage gap).
- **data/share-alike/**: Ubuntu/Alpine/Greenbone segregation prevents share-alike from reaching Anvil's own findings DB (SPINE S8, 13-B10/B12/B22 ODbL hazard).
- **plan/PLUGIN-SQLMAP-BOUNDARY.md**: Operationalizes SPINE S8's four plugin rules and addresses R3 architectural defects (separate repo/process/interface/knowledge).
- **plan/SPEC-SPDX-GATE.md & cmd/license-gate/***: Enforces the gate-reads-file-bodies rule (13 methodological warning); hard-coded overrides prevent silent rejection of verified-clean artifacts hidden by NOASSERTION.
- **data/EXCLUSION-LIST.json**: Makes S5 a CI enforcement, not documentation.
- **data/LICENSE-OVERRIDES.csv**: Pins the two audit self-consistencies (sqlmap -or-later, MITRE year templating) so CI uses corrected versions.

---

## CI Gate Specification

**What it reads:**
1. LICENSE or COPYING file at repository root or `data/LICENSES/` per-component archives.
2. File body, never GitHub API metadata (`spdx_id`).
3. Manual-override JSON files (`.license-override.json`) for artifacts in the hard-coded override table.

**What it rejects:**
1. Any artifact without a valid SPDX licence identifier in file body.
2. Any artifact in the EXCLUSION-LIST.json denylist (S5: CodeQL, Semgrep Rules, CIS Benchmarks, etc.).
3. Any override record missing the `operative_sentence` field (required for gate to proceed on NOASSERTION).
4. Licence mismatch: if file body says Apache-2.0 but override claims MIT, gate fails until manually verified.

**Eight NOASSERTION-trap artifacts requiring hard-coded overrides:**
1. **ComplianceAsCode/content** — API returns NOASSERTION; file body is BSD-3-Clause. Override: "SPDX license identifier: BSD-3-Clause" (operative sentence).
2. **osquery/osquery** — API NOASSERTION; file body is Apache-2.0 OR GPL-2.0. Override: "dual-licensed Apache-2.0 and GPL-2.0" (operative clause).
3. **wazuh/wazuh** — API NOASSERTION; file body is GPL-2.0 + OpenSSL exception. Override: "with OpenSSL exception" (operative clause).
4. **secureIT-project/CVEfixes** — API NOASSERTION; file body is MIT. Override: MIT text verbatim.
5. **commixproject/commix** — API NOASSERTION; file body is GPL-3.0. Override: "GNU GENERAL PUBLIC LICENSE Version 3" (operative sentence).
6. **cisagov/kev-data** — API NOASSERTION; file body is CC0-1.0. Override: "dedicated to the public domain" (operative sentence).
7. **fdtn-ai/Foundation-Sec-8B** — API returns apache-2.0; actual weights are Llama 3.1 Community License (hidden in NOTICE.md). Override: "Llama 3.1 is licensed under the Llama 3.1 Community License" (operative sentence from NOTICE.md).
8. **meta-llama/PurpleLlama** — API NOASSERTION; file body is Llama 3.2 Community License Agreement. Override: "LLAMA 3.2 COMMUNITY LICENSE AGREEMENT" (operative sentence, from research/13a E2).

**Manual-override field schema (JSON):**
```json
{
  "artifact_id": "ComplianceAsCode/content",
  "file_path": "data/LICENSES/COMPLIANCE-AS-CODE-LICENSE",
  "operative_sentence": "SPDX license identifier: BSD-3-Clause",
  "spdx_identifier": "BSD-3-Clause",
  "override_date": "2026-08-06",
  "justification": "GitHub API returns NOASSERTION; BSD-3-Clause text confirmed in LICENSE file from research/13-license-compatibility-audit.md V53",
  "reference": "research/13-license-compatibility-audit.md V53"
}
```

**Failure modes and reroute:**
1. If gate encounters an artifact without a LICENSE file and not in override table: exit 2 (OVERRIDE_NEEDED); gate must not proceed until override is added and validated.
2. If override record is malformed JSON or missing `operative_sentence`: exit 1 (FAIL); human review required.
3. If operative sentence in override does not match file body: exit 1 (FAIL); assume file has changed and re-verify against primary source.
4. If denylist check triggers: exit 1 (FAIL) immediately; do not proceed to license reading.

**Gate output:**
- Exit 0: all artifacts licensed and not on denylist.
- Exit 1: license not found, override invalid, or denylist hit.
- Exit 2: override needed (unknown artifact, gate cannot proceed).

---

## Notice Obligations

| Source | Notice Required | Type | Where It Ships | Reference |
|--------|-----------------|------|----------------|-----------|
| **Gemma 4 weights** | Yes (Apache §4(d)) | If bundled or redistributed | NOTICE, container image LABEL | spine-b A1 |
| **go-apispec** | Yes (Apache §4(d)) | NOTICE file shipped verbatim | NOTICE, data/LICENSES/GO-APISPEC-NOTICE | spine-b A2 |
| **llama-swap** | Attribution | MIT (file/doc attribution) | THIRD-PARTY-LICENSES.md | spine-b A3 |
| **Valkey** | No-endorsement clause (conduct duty) | BSD-3-Clause §3 | Contributor guidelines (marketing policy) | spine-b A4 |
| **Docker Engine** | Yes (Apache §4(d)) | If redistributed as binary | NOTICE | spine-b A5 |
| **Docker Compose** | Yes (Apache §4(d)) | If redistributed as binary | NOTICE | spine-b A6 |
| **Qwen/Qwen3-Coder-30B-A3B-Instruct** | Yes (Apache §4(d)) | If weights shipped | NOTICE, model-weight METADATA | spine-b A7 |
| **iris-sast/cwe-bench-java** | MIT attribution | Reference-only (eval use) | Experiment results docs if published | spine-b A8 |
| **MITRE CVE** | Yes | "reproduce MITRE's copyright designation" | data/LICENSES/CVE-TOU.txt | 13-B1, 13 Unsettled Q2 |
| **MITRE CWE** | Yes | "reproduce MITRE's copyright designation" | data/LICENSES/CWE-TERMS.txt | 13-B7 |
| **MITRE ATT&CK** | Yes (exact string, year dynamic) | "© {YEAR} The MITRE Corporation…" | data/NOTICES/ATTACK-NOTICE-TEMPLATE.txt with {YEAR} substitution | 13-B9, 13a E4 correction |
| **GitHub Advisory Database** | Yes (CC-BY-4.0 §3(a)) | Attribution, modification notice, URI | NOTICE, THIRD-PARTY-LICENSES.md | 13-B3 |
| **Ubuntu OVAL/USN** | Yes (CC-BY-SA-4.0) | Share-alike propagates to derivative database | **Segregated: data/share-alike/ubuntu/LICENSE** | 13-B12, S8 |
| **Alpine secdb** | Yes (CC-BY-SA-4.0) | Share-alike propagates to derivative database | **Segregated: data/share-alike/alpine/LICENSE** | 13-B13, S8 |
| **Greenbone Community Feed** | Yes (ODbL-1.0) | Share-alike on derivative databases | **Segregated: data/share-alike/openvas-feed/LICENSE** | 13-B22, 13a R6 note |

**NOTICE aggregation mechanism:**
Anvil's root NOTICE file lists:
1. Apache-2.0 §4 duty: "This product includes software developed by [contributors] under the Apache License 2.0. Copies of NOTICE files for dependencies are maintained in data/LICENSES/."
2. Per-component notices:
   - go-apispec: [verbatim from data/LICENSES/GO-APISPEC-NOTICE]
   - Docker Engine / Compose: [Apache-2.0 §4 notices if redistributed]
   - Gemma 4 / Qwen: [model-specific metadata if weights are shipped]
   - MITRE CVE/CWE/ATT&CK: [attribution strings per ToU]
   - GitHub Advisory Database: [CC-BY-4.0 §3(a) requirements]
3. **Share-alike segregation note:** "Data from Ubuntu OVAL, Alpine secdb, and Greenbone OpenVAS Community Feed are stored in data/share-alike/ with their own LICENSE files. These sources are NOT merged into Anvil's published artifacts to avoid share-alike propagation."

---

## Exit Criteria

Objectively checkable gates for release:

1. **LICENSE file present and valid:**
   - `[ -f LICENSE ] && head -1 LICENSE | grep -q "Apache License"`
   - Run: `license-gate LICENSE` → exit 0

2. **NOTICE file aggregates all Apache-2.0 obligations:**
   - NOTICE exists and contains: go-apispec, Docker Engine, Docker Compose, Gemma 4, Qwen model
   - Run: `grep -c "NOTICE duty" plan/COMPLIANCE-CHECKLIST.md` → ≥5 items

3. **Seven newly-closed items archived:**
   - `[ -f data/LICENSES/GEMMA4-LICENSE ] && [ -f data/LICENSES/QWEN-CODER-30B-LICENSE ] && [ -f data/LICENSES/LLAMA-SWAP-LICENSE ] && [ -f data/LICENSES/GO-APISPEC-NOTICE ] && [ -f data/LICENSES/DOCKER-ENGINE-LICENSE ] && [ -f data/LICENSES/DOCKER-COMPOSE-LICENSE ] && [ -f data/LICENSES/VALKEY-LICENSE ]`
   - MODEL-REVISION-PINS.csv exists with 5+ rows (Gemma 4, Qwen, llama-swap, and evaluation models)

4. **Share-alike quarantine isolated:**
   - Three directories exist: data/share-alike/ubuntu/, data/share-alike/alpine/, data/share-alike/openvas-feed/
   - Each has its own LICENSE file with verbatim CC-BY-SA-4.0 or ODbL-1.0 text
   - Run: `find data/share-alike -name LICENSE | wc -l` → 3

5. **Defect fixes applied:**
   - data/LICENSE-OVERRIDES.csv contains sqlmap entry: `sqlmap | GPL-2.0-only → GPL-2.0-or-later`
   - data/NOTICES/ATTACK-NOTICE-TEMPLATE.txt contains `{YEAR}` placeholder (not literal 2026)

6. **sqlmap plugin boundary rules documented:**
   - plan/PLUGIN-SQLMAP-BOUNDARY.md exists and contains four numbered rules
   - Each rule is independently verifiable (repo separation, process separation, interface spec, GPL-side knowledge)

7. **SPDX gate deployed and tested:**
   - `cmd/license-gate/main.go` exists and compiles
   - `cmd/license-gate/overrides.go` contains hard-coded table with all eight NOASSERTION artifacts
   - Run: `license-gate --list-overrides | wc -l` → 8
   - Test: `license-gate data/LICENSES/COMPLIANCE-AS-CODE-LICENSE` → exit 0 with override applied

8. **Exclusion list enforced:**
   - data/EXCLUSION-LIST.json exists with ≥13 entries (S5 hard exclusions)
   - Run: `jq length data/EXCLUSION-LIST.json` → ≥13
   - Each entry has `artifact`, `reason`, `reference` fields
   - Run: `license-gate --deny-check semgrep/semgrep-rules` → exit 2 (found and denied)

9. **Compliance checklist complete:**
   - plan/COMPLIANCE-CHECKLIST.md exists
   - All eight items from spine-b-open-licences.md are checked
   - Share-alike quarantine status verified
   - Defect fixes verified
   - Plugin boundary rules reviewed

---

## Open Questions

1. **Does an expanded contractual derivative-work definition (NPSL §3, sqlmap) bind a caller who never accepts the licence?** (research/13 Unsettled Q5; research/13a E1 notes the NPSL vendor carve-out; nmap is dropped on prudence, not compulsion.)

2. **Whether ODbL share-alike attaches to Anvil's findings database when VT content is ingested vs. referenced.** (research/13 Unsettled Q3; segregation into data/share-alike/ moots the question operationally.)

3. **Whether the CC-BY-SA-4.0 propagates to a merged vulnerability corpus that includes Ubuntu or Alpine records.** (research/13 Unsettled Q10; physical segregation is the engineering answer.)

4. **Whether model weights are a derivative work of their training data for GPL purposes.** (research/13 Unsettled Q1; Anvil trains classifiers, not generators, so verbatim regurgitation does not apply.)

5. **Whether Qwen license divergence by parameter count is adequately documented in MODEL-REVISION-PINS.csv.** (SPINE S4 caveat; recommend manual check at selection time for any Qwen variant not explicitly verified in spine-b-open-licences.md.)

---

## Conflicts With Spine

1. **Audit self-inconsistency: sqlmap GPL version.** research/13-license-compatibility-audit.md table C6 states "GPL v2 (June 1991)" while the same audit's recommendation page states "GPL-2.0-**or-later**" and cites it as justification for GPL-3.0 compatibility. research/13a E3 identifies this as a copy-through error. The gate (step C.10) uses the corrected -or-later version; the audit matrix row is flagged in data/LICENSE-OVERRIDES.csv but not modified. **No conflict with 00-SPINE.md S8** (which names sqlmap as a plugin and does not specify version); conflict is internal to research/13 and resolved by C.6.

2. **MITRE ATT&CK copyright year.** research/13-license-compatibility-audit.md obligations table states exact string "© 2026 The MITRE Corporation…" as literal requirement. research/13a E4 notes the source page renders dynamically. SPINE S8 does not prescribe literal year strings. **No conflict with spine**; defect is in audit execution (E4 correction), fixed by step C.7 templating year.

3. **No legal-opinion conflicts.** The audit flags multiple genuine legal-opinion boundaries (NPSL §3 derivative scope, ODbL-1.0 derivative database applicability, GPL subprocess interpretation) and marks them as unsettled. This plan segregates those operationally (nmap dropped, share-alike quarantined) rather than resolving them legally. **Consistent with 00-SPINE.md S7** (enforce in code, not documentation).

---

**Validation:** Every obligation in Notice Obligations traces to research/13 or research/13a or spine-b-open-licences.md. Seven newly-closed items and their NOTICE duties are listed. sqlmap boundary rules derive from 00-SPINE.md S8 and research/13a R3. Defect fixes cite audit corrections. SPDX gate specifications come from research/13 methodological warning and research/13a defect findings. Exclusion list is 00-SPINE.md S5 verbatim. Share-alike segregation is 00-SPINE.md S8 requirement. All eight steps are ordered and dependencies are explicit.
