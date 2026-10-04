# opengrep: what shipping the binary would oblige

opengrep, Lane B's rule engine, is LGPL-2.1 (its LICENSE body at tag v1.26.0, read 2026-08-06 and recorded in
`eval/tools/opengrep/LICENSES.md` §1). Anvil runs it as a separate process and links none of it, so a source
checkout of Anvil and a running installation owe nothing under the LGPL for it.

**Distributing the binary is conveyance.** If an Anvil release artifact (the container image, a systemd
tarball, any package) includes the opengrep executable, Anvil conveys an LGPL-2.1 work in object form and must,
for that exact binary:

1. carry the LGPL-2.1 text and opengrep's copyright notices with it (§1, §6);
2. accompany it with the complete corresponding source for that version (opengrep v1.26.0,
   `1bef4ea4ff3264754132eec823b5b1d8cde3e4ee`), or a written offer, valid for at least three years, to provide
   it (§6(a)–(c)), and say where that offer is served;
3. keep the binary replaceable: Anvil already calls it by a configurable path (`recall: {opengrep: …}`), which
   is what lets a user substitute a modified build.

**The choice, which is the owner's and is open as of 2026-10-03:**

| Option | What it costs | What it buys |
|---|---|---|
| Ship the binary in the image, with the notice and a source offer | Hosting the source (or shipping it in the image), keeping the offer valid, a notice per release | Lane B works out of the box |
| Fetch on first run from opengrep's release, verified by the SHA-256 in `eval/tools/opengrep/MANIFEST.toml` | One network fetch at install, an install step that can fail, and the fetch must happen before any scan, never at scan time | Anvil never conveys the binary, so no LGPL duty attaches |
| Document it as an operator-installed prerequisite, like Trivy today | An extra install step for every operator | No duty, no fetch logic |

Until it is decided, no release artifact may include the opengrep binary. Phase 9 (plan node packaging) owns
the packaging and must cite this file.
