# `klauspost/compress` — pin and licence determination for the audit payload codec

`internal/store/payload.go` compresses `audit_record.payload` with this module's `zstd` package (plan node
contractgaps). This directory holds the licence bodies that apply to the code that build links, copied
verbatim from the Go module cache at the pinned version, and hashed so the determination is reproducible.
`internal/store/payload_test.go` re-reads all three files on every `go test ./...` and fails if any of
them drifts from the hashes below, and it fails if `go.mod` or `go.sum` moves the pin.

## The pin

Read on **2026-10-03** on the Debian development machine. The owner approved the download that day.

| Field | Value |
|---|---|
| Go module | `github.com/klauspost/compress` |
| Version | `v1.20.1` (published 2026-09-25 per `proxy.golang.org/.../@latest`) |
| Upstream commit for the tag (proxy's `Origin.Hash`) | `5d880f230c38a0fc806b9ca1613103a44feff0ac` |
| `go.sum` module hash | `h1:T7kKElXUMXrUJ2E9QhQhxFtcK5rPyLdsGZvdbLMPdiQ=` |
| Packages linked (`go list -deps ./zstd` in the module) | `zstd`, `zstd/internal/xxhash`, `huff0`, `fse`, `internal/cpuinfo`, `internal/le`, `internal/snapref`, and the module root |

Reproduce:

```bash
go list -m -f '{{.Dir}}' github.com/klauspost/compress
sha256sum "$(go list -m -f '{{.Dir}}' github.com/klauspost/compress)"/LICENSE
```

## The licence bodies, read in full

| File here | Copied from | SPDX | Applies to | SHA-256 |
|---|---|---|---|---|
| `LICENSE` | `LICENSE` at the module root | BSD-3-Clause for the module (Copyright 2012 The Go Authors, 2019 Klaus Post), followed by sections naming other licences for specific directories | `zstd`, `huff0`, `fse`, `internal/*` | `0d9e582ee4bff57bf1189c9e514e6da7ce277f9cd3bc2d488b22fbb39a6d87cf` |
| `zstd-internal-xxhash-LICENSE.txt` | `zstd/internal/xxhash/LICENSE.txt` | MIT (Copyright 2016 Caleb Spare) | `zstd/internal/xxhash` | `f566a9f97bacdaf00d9f21dd991e81dc11201c4e016c86b470799429a1c9a79c` |
| `internal-snapref-LICENSE` | `internal/snapref/LICENSE` | BSD-3-Clause (Copyright 2011 The Snappy-Go Authors) | `internal/snapref` | `f69f157b0be75da373605dbc8bbf142e8924ee82d8f44f11bcaf351335bf98cf` |

The root `LICENSE` also carries an Apache-2.0 section for `gzhttp/*` and MIT sections for
`s2/cmd/internal/readahead/*` and `s2/cmd/internal/filepathx/*`. None of those directories is linked by
`zstd`, so neither applies to Anvil's binaries today; they are recorded because they are in the file.

No copyleft, no `NOASSERTION`, and nothing beyond the BSD-3-Clause and MIT notice duties
`THIRD-PARTY-LICENSES.md` already describes. BSD clause 3 (no endorsement) is a conduct duty.
