# opengrep: what shipping the binary would oblige

opengrep, Lane B's rule engine, is LGPL-2.1 (its LICENSE body at tag v1.26.0, recorded in
`eval/tools/opengrep/LICENSES.md` §1). Anvil runs it as a separate process and links none of it, so a source
checkout of Anvil and an installation where the operator installed opengrep themselves owe nothing for it.

## Distributing the binary is distributing the Library itself

If an Anvil release artifact (the container image, a systemd tarball, any package) includes the opengrep
executable, Anvil distributes the LGPL-2.1 Library itself in object form. That is LGPL-2.1 **§4**, not §6
(§6 is about a separate "work that uses the Library", which Anvil, as a separate process, is not):

- carry the LGPL-2.1 text and opengrep's copyright notices with it (§1, by way of §4);
- accompany it with the complete corresponding machine-readable source for that exact version (opengrep
  v1.26.0, commit `1bef4ea4ff3264754132eec823b5b1d8cde3e4ee`), or, if the binary is offered for download from a
  designated place, offer equivalent access to the source from the same place (§4's last paragraph).

## The binary is a bundle, and the bundle is not only opengrep

The pinned release asset (`opengrep_manylinux_x86`, SHA-256 `40c21299…`) is a PyInstaller bundle. Unpacked on
2026-10-03 (`~/.cache/opengrep/v1.26.0/`, 65 entries), it carries, besides opengrep's own engine:

- `libreadline.so.7` (GNU Readline 7) and `libtinfo.so.6`;
- OpenSSL 1.1 (`libssl.so.1.1`, `libcrypto.so.1.1`);
- CPython's runtime and extension modules, `libffi`, `libbz2`, `liblzma`, `libsqlite3`, `libmpdec`, `libuuid`;
- Python packages including `certifi`, `chardet` and `charset_normalizer`.

The bundle contains no licence files for any of these. Their licences have **not** been read from their bodies
for this note: the same-family review of 2026-10-03 named GNU Readline 7 as GPL-3.0, certifi as MPL-2.0 and
chardet as LGPL-2.1, from memory, and those are the claims to verify first. If Readline 7 is GPL-3.0 as
expected, conveying the bundle conveys a GPL-3.0 library with GPL-3.0's source duties, which is a heavier
obligation than opengrep's own and must be settled before any artifact ships the binary.

## The choice, which is the owner's and is open as of 2026-10-03

| Option | What it costs | What it buys |
|---|---|---|
| Ship the release binary in the image | Every component above, with its own notices and source duties, verified licence by licence | Lane B works out of the box |
| Build opengrep from source for the image, without the bundled extras | A build pipeline and its own audit | Only what is built is conveyed |
| Fetch on first run from opengrep's release, verified by the SHA-256 in `eval/tools/opengrep/MANIFEST.toml` | A network fetch at install, an install step that can fail, and the fetch must happen before any scan, never at scan time | Anvil conveys nothing |
| An operator-installed prerequisite, like Trivy today | An extra install step for every operator | No duty, no fetch logic |

Until it is decided, no release artifact may include the opengrep binary. Phase 9 (plan node packaging) owns the
packaging and must cite this file.
