# Lane B exit gate: adversarial review of the licence and security conclusions

**A same-family review.** The critic was a Claude model reviewing work a Claude model wrote, on 2026-10-03,
read-only, with no network. It shares the author's blind spots, it is not legal advice, and it is not an
independent check: the owner withdrew cross-family critics so that no plan or code goes to a third-party model
provider. Where the critic relied on its own memory rather than a fetched source, that is said below.

It was asked to break ten conclusions: five on licences (what is vendored and under what licence, the gosec-derived
rules' Apache-2.0 duties, 0xdea, the LGPL analysis of opengrep, what is excluded) and five on security (whether the
scanned repository can suppress Lane B, whether gosec's package loading can be turned against the host, trust
labels, path handling, and whether a missing or failing tool can ever produce a clean scan).

## Findings, and what was done

| # | Severity | Finding | Disposition |
|---|---|---|---|
| B1 | blocking | A GitLab rule's "License: MIT (c) GitLab Inc." header is not a reliable licence reading. GitLab labels each rule's companion test file with the analyser it was ported from: 131 vendored rules (Java 42, Scala 68, C# 21) have companions labelled "LGPL-3.0 License (c) find-sec-bugs" or "(c) security-code-scan"; 52 Python rules "Apache 2.0 (c) PyCQA" (bandit); 6 JavaScript rules "MIT (c) JS Foundation". GitLab's `mappings/` agree on the origins. Two Python rules quote bandit's docstrings word for word (verified by script); several Scala messages match find-sec-bugs prose (from the critic's memory, not byte-verified). | **Fixed, by the owner's decision (2026-10-03).** A GitLab rule's licence is now the stricter of its own header and its companion's (`anvil_eval.vendor_rules`, `derive`); `selection.json`'s `exclude_by_derived_licence` leaves out LGPL-3.0-derived rules, and `MANIFEST.json` lists all 131 with their evidence. The 52 bandit-derived rules are Apache-2.0 under bandit's archived licence body; the 6 JavaScript rules are MIT with the JS Foundation's notice recorded. The pack went from 308 rule files to 177. Held by `test_an_lgpl_companion_is_left_out_when_the_selection_excludes_it`, `test_a_companion_decides_when_it_names_an_upstream` and `TestTheVendoredPackVerifies`. |
| B2 | blocking | The path exclusions match by directory name, so a repository can put code under `spec/`, `docs/` or `fixtures/` and Lane B will not report it; moving code there turns its findings into "fixed" (verified with a full scan). | **Kept, and the limit stated, by the owner's decision (2026-10-03).** Without the exclusions curl measured 525 candidates, over the budget of 500. Every scan reports how many source files the exclusions kept out; the README and the record contract state that a repository can place code under an excluded name, and the Phase 7 handoff tells the triage gate to treat a finding that is "fixed" with no code change as suspect. |
| S1 | should-fix | gosec's coverage was never checked file by file: Go files in no module, files with another platform's build tags and files under `vendor/` were silently left to opengrep. | **Fixed.** Lane B counts the non-test Go files the Go tool loads per module and compares gosec's `Stats.files`; a shortfall, and Go files in no module, are incomplete coverage; vendored Go files are a note. `TestTheReviewersEvasionsAreRecorded`. |
| S2 | should-fix | Loading packages for gosec ran the C compiler on the repository's cgo code with the operator's environment; a `#include` of a host file put its first line into the scan's problems. | **Fixed.** `CGO_ENABLED=0` (and `GOWORK=off`, with the operator's `GOOS`/`GOARCH` dropped); cgo files are then uncounted by gosec and show as incomplete coverage. The test asserts no host file content reaches the output. |
| S3 | should-fix | bandit applies its default excludes as substrings even to explicitly named files: `.github/…`, `CVSS-tool/…` were skipped. | **Fixed.** `-x` with a sentinel that matches nothing (`BanditNoExclude`); seen failing without it. |
| S4 | should-fix | A symbolic-link `.go` file in a module failed every Lane B run (gosec follows it; Lane B's snippet read refuses it). | **Fixed.** Such a match is dropped and recorded as incomplete coverage; the scan completes. Seen failing without it. |
| S5 | should-fix | `data/LICENSES/opengrep-binary-distribution.md` put the duties under LGPL-2.1 §6 rather than §4, and missed that the release binary is a PyInstaller bundle carrying GNU Readline, OpenSSL, certifi, chardet and CPython. | **Fixed.** The note now cites §4, lists the bundle's contents (verified by listing the unpacked bundle) and says which licences are still unverified (Readline's GPL-3.0 is the critic's memory). The packaging choice stays the owner's. |
| S6 | should-fix | The new corpora section split `THIRD-PARTY-LICENSES.md`'s tools table. | **Fixed.** |
| N1 | note | `anvil recall` exited 0 on a tree with nothing to scan. | **Fixed.** It records the empty plan as a problem and exits 3, as a repository scan does. |
| N2 | note | opengrep's partial parsing is not treated as incomplete. | **Kept.** The critic's five broken Java variants all still matched; on curl, about 140 of its 495 files parse in part on every scan. Recorded as a note on every scan. |
| N3 | note | Run-level `tool.extensions` strings (rule names, licence evidence) carry no trust label. | **Stated** in CONTRACT.md's 1.1.0 amendment: they are third-party text, never `anvil_generated`, and a consumer treats them as untrusted. |
| N4 | note | `anvil/reasoning` said "a parser named the enclosing function" for bandit's indentation reading and opengrep's class names. | **Fixed** in the vocabulary. |
| N5 | note | The spec harvest checked size with `Lstat` and then read without a limit. | **Fixed:** a bounded read. |

## Conclusions that survived

0xdea's rules (no per-file headers or attribution, MIT stands); the gosec-derived Go rules (byte-identical,
headers kept; 27 now, one of them derived by its companion rather than its own header; Apache-2.0 body from the release archive; §4(d) depends on gosec shipping no NOTICE, which was not
re-checked against its repository); nothing but rule YAML and licence bodies is vendored, and `c/`, `rules/lgpl*`,
`doc/` and `mappings/` are unreachable; `.bandit` discovery, files over opengrep's size limit, bandit syntax errors
and binary `.py` files are all recorded as incomplete; file names with a leading dash or a newline are safe because
targets are absolute; `anvil/reasoning` holds only vocabulary and integers; a missing tool, a wrong version, a bad
exit code, an empty or unparseable report and an empty plan all fail closed.

## What this review does not cover

It is one critic of the same model family. Two of its licence claims rest on memory (the find-sec-bugs prose
match, GNU Readline 7's licence) and were not checked against fetched sources. Every remaining Java, Scala and C#
rule still maps to a find-sec-bugs or security-code-scan rule id in GitLab's `mappings/`; GitLab labels their
companions as its own (MIT), which is the evidence the owner's criterion reads, and no text-level comparison against
the upstream analysers was made. One Java rule (`java/endpoint/rule-UnvalidatedRedirect.yml`) has a companion with
no licence header at all, so only the rule's MIT header speaks for it.
