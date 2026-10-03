# Third-Party Licences

Anvil is licensed under Apache-2.0 (see [`LICENSE`](LICENSE)). This file indexes every permissive
non-Apache dependency and the attribution each one requires. Apache-2.0 artifacts and their §4(d)
duties live in [`NOTICE`](NOTICE); share-alike sources are quarantined under `data/share-alike/` and
appear in neither file's body.

## How every entry here was determined

**By reading the LICENSE file body in the Go module cache at the pinned version — never from registry
metadata.** The spine's licence section requires this, and the reason is concrete: seven artifacts in
`research/13-license-compatibility-audit.md` return `NOASSERTION` over a real licence, and one
(`fdtn-ai/Foundation-Sec-8B`) is tagged `apache-2.0` on Hugging Face while its own `NOTICE.md` places the
weights under the Llama 3.1 Community License. Metadata is not evidence.

Each row below carries the SHA-256 of the exact licence file that was read, so the determination is
reproducible rather than asserted. Verify with:

```bash
go list -m -f '{{.Dir}}' modernc.org/sqlite | xargs -I{} sha256sum {}/LICENSE
```

## Go module dependencies — compiled into `anvil` and `anvil-dast`

All eleven are BSD-3-Clause or MIT. **No copyleft, no unclear licence, no `NOASSERTION` in the set.** All
are Apache-2.0 compatible in the inbound direction.

| Module | Version | SPDX | Copyright holder | LICENSE file SHA-256 |
|---|---|---|---|---|
| `modernc.org/sqlite` | v1.56.0 | BSD-3-Clause | The Sqlite Authors (2017) | `c6fe05491a60ae13bcd223088d2705e36dede24e5587226231d2459ada5c4822` |
| `modernc.org/libc` | v1.74.4 | BSD-3-Clause | The Libc Authors (2017) | `95ff867eb55a56935fa7492406cfa953fb7c13ca73f4c0a86ae05756b4605600` |
| `modernc.org/mathutil` | v1.7.1 | BSD-3-Clause | The mathutil Authors (2014) | `bfa9bf72a72ca009fd62a8f84fca3dca67e51d93af96352723646599898b6cf5` |
| `modernc.org/memory` | v1.11.0 | BSD-3-Clause | The Memory Authors (2017) | `59895e669f48f168b6b858358f6005779cdf40a265f7828813061b56af67b496` |
| `golang.org/x/sys` | v0.47.0 | BSD-3-Clause | The Go Authors (2009) | `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad` |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause | Google Inc. (2009, 2014) | `0a8d61ed3cbfd5312326e8126c31ce9c627a283adc99131b56896d29ada04b2d` |
| `github.com/remyoudompheng/bigfft` | v0.0.0-20230129092748 | BSD-3-Clause | The Go Authors (2012) | `dd26a7abddd02e2d0aba97805b31f248ef7835d9e10da289b22e3b8ab78b324d` |
| `github.com/dustin/go-humanize` | v1.0.1 | MIT | Dustin Sallings (2005–2008) | `a973b4498c13eb74baa2a8e5c351426a6826f2fcdd909916dbe53ee2e755fd71` |
| `github.com/mattn/go-isatty` | v0.0.24 | MIT | Yasuhiro Matsumoto | `08eab1118c80885fa1fa6a6dd7303f65a379fcb3733e063d20d1bbc2c76e6fa1` |
| `github.com/ncruces/go-strftime` | v1.0.0 | MIT | Nuno Cruces (2022) | `38ae43959daf953a393a585b2988672cb65a5a541aca0d0be5e72595a0a16883` |
| `github.com/klauspost/compress` | v1.20.1 | BSD-3-Clause; MIT for `zstd/internal/xxhash` | The Go Authors (2012), Klaus Post (2019); Caleb Spare (2016) for xxhash; The Snappy-Go Authors (2011) for `internal/snapref` | `0d9e582ee4bff57bf1189c9e514e6da7ce277f9cd3bc2d488b22fbb39a6d87cf` (all three bodies in `third_party/klauspost-compress/`) |

`modernc.org/sqlite` and `github.com/klauspost/compress` are the direct requirements; the other nine
arrive through sqlite, are pinned by `go.sum`, and move only when the sqlite pin moves. The compress module
is the audit payload's zstd codec, added 2026-10-03; `third_party/klauspost-compress/PIN.md` records the
three licence bodies that apply to the packages it links, and a test re-hashes them.

### BSD-3-Clause — required notice

> Redistribution and use in source and binary forms, with or without modification, are permitted
> provided that the following conditions are met: (1) redistributions of source code must retain the
> above copyright notice, this list of conditions and the following disclaimer; (2) redistributions in
> binary form must reproduce them in the documentation and/or other materials provided with the
> distribution; (3) neither the name of the copyright holder nor the names of its contributors may be
> used to endorse or promote products derived from this software without specific prior written
> permission.

Clause 3 is a **conduct duty**, not a file duty: Anvil's marketing and contributor guidelines must not
imply endorsement by any of these projects. `plan/design/spine-open-licences.md` (Valkey) records the same duty for
Valkey.

### MIT — required notice

> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
> associated documentation files to deal in the Software without restriction… The above copyright notice
> and this permission notice shall be included in all copies or substantial portions of the Software.

## `modernc.org/sqlite` — two things worth recording

**Its licence was an open item and is now closed.** `plan/design/record-and-store.md`'s Pinned Versions
table listed it as *"Requires reading the LICENSE file body at pin time — not independently re-verified
in this pass."* It has now been read: **BSD-3-Clause**, hash above.

**Its FTS5 support was spine-locked on grade-B evidence and is now directly verified.**
The spine's Go control-plane decision asserted FTS5 support as "orchestrator-verified", while the trail behind that
claim (the modernc.org/sqlite source rows in `plan/design/spine-language.md`) graded itself B, *"absence-of-evidence, not
evidence-of-absence"*. At Phase 0 bootstrap the claim was tested directly against the pinned version:

```
sqlite_version: 3.53.3
CREATE VIRTUAL TABLE ft USING fts5(body)   -> ok
SELECT count(*) FROM ft WHERE ft MATCH 'overflow'  -> 1
RESULT: FTS5 VERIFIED WORKING
```

The SQLite amalgamation itself is public domain, which is why it is absent from the table above; the Go
translation carries the BSD-3-Clause notice recorded there.

This does **not** retire the migration runner's startup FTS5 guard. That guard exists because a future dependency bump
could drop the feature silently, and a runtime check is the only thing that catches that. The pin is
verified; the guard is the control.

## Tools invoked as subprocesses — licences tracked, notices not yet triggered

Anvil shells out to these rather than linking them, so no notice duty attaches at source checkout. Duties
attach when a release artifact bakes them in, which is the container image and the systemd tarball (plan node packaging).

| Tool | SPDX | Notes |
|---|---|---|
| Trivy | Apache-2.0 | SCA + host. §4(d) duty on image build — see `NOTICE`. |
| Nuclei | MIT | Always-on DAST engine. Ships only in `anvil-dast`. |
| ZAP | Apache-2.0 | Scheduled full scans. Ships only in `anvil-dast`. |
| Syft / Grype / OSV-Scanner | Apache-2.0 | SBOM and matching. |
| opengrep (engine) | **LGPL-2.1** | The single strongest obligation in the set — see below. |
| `AikidoSec/opengrep-rules` | MIT | The rules corpus. **Not** `opengrep/opengrep-rules`, which is archived, `NOASSERTION`, and LGPL-2.1 + Commons Clause; it is on the spine's exclusion list. |
| llama.cpp / llama-server | MIT | Model serving. |
| ONNX Runtime | MIT | Encoder path. |
| honggfuzz | Apache-2.0 | The permissive AFL++ substitute. AFL++ is excluded: its LICENSE is AGPL-3.0 regardless of its README. |
| llama-swap | MIT | Attribution in docs — `plan/design/spine-open-licences.md` (llama-swap). |

**opengrep is LGPL-2.1 and it is invoked, never linked.** It is an OCaml CLI with zero bindings in any
language (the spine's Go control-plane decision), so subprocess invocation is the only option that exists — which is
also the option that keeps the LGPL boundary clean. Baking the binary into the container image is the
event that triggers offer-source obligations, and the container image must name where that offer is served rather than
leaving it implicit.

## sqlmap — a separate GPL-3.0 artifact, deliberately not a dependency

sqlmap is **not** listed above because it is not a dependency of anything in this repository. Under
the spine's licence section it ships as a separately distributed GPL-3.0 plugin under four rules: (i) separate
git repo, separate release artifact, separate package name, never vendored into this tree; (ii) separate
**process** — the core loads no plugin code into its address space; (iii) the interface is a documented
**tool-agnostic** data contract, because an interface named `SqlmapDriver` is arguably itself "designed
specifically to execute sqlmap"; (iv) all sqlmap-specific knowledge lives on the GPL side.

The sqlmap boundary document (plan node sqlmap) makes those four rules enforceable.

## nmap — an open decision, not a settled exclusion

Recorded so it is not mistaken for a resolved item. NPSL's derivative-work terms bind distribution by
parties who *accept* the licence, and the licence disclaims binding vendors whose practices fair use
already permits. Dropping nmap is prudence, not compulsion — and the proposed replacements were never
checked for coverage: nuclei's `network/` templates presuppose a known host and port and do no discovery.
See the spine's licence section.

## Maintenance

`cmd/license-gate` (plan node spdxgate) enforces this file in CI. It reads LICENSE file bodies,
never API metadata, and carries a hard-coded override table for the eight artifacts that return
`NOASSERTION` over a real licence — each override recording the quoted operative sentence that justifies
it. A dependency whose licence cannot be located **as a file body** fails the build. It does not warn.
