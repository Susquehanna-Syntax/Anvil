#!/usr/bin/env python3
# ruff: noqa: E501
"""compute_golden_fingerprints.py — the INDEPENDENT oracle for anvil-fp/v1.

===========================================================================
WHY THIS FILE EXISTS
===========================================================================

plan/00-SPINE.md S6: "One fingerprint algorithm, defined once, in the record.
Two branches specified different /v1 algorithms under the same name; two
producers emitting different hashes means regression matching silently fails
forever."  *Silently* is the operative word.  research/07-database-design.md
and research/18-unified-audit-record.md really did ship two different
algorithms under the one name `anvil-fp/v1`, and nothing in the tree surfaced
it.  A conformance test whose expected values were produced by the code under
test would not have surfaced it either: it proves only that the Go equals
itself.

This script is therefore a SECOND, INDEPENDENT implementation of the same
algorithm, in a different language, written from `internal/record/
FINGERPRINT-SPEC.md` and from nothing else.  It emits the `.golden` files that
`internal/record/fingerprint_conformance_test.go` compares the Go
implementation against.  When the two agree, the algorithm has been reproduced
from its written specification by an implementer who could not see the code —
which is exactly the property a second producer will need, and the property
S6 asks for.

===========================================================================
THE INDEPENDENCE CONTRACT — DO NOT WEAKEN IT
===========================================================================

This script MUST NOT, ever:

  * read, parse, import, embed, transcribe or execute any Go source file;
  * shell out to `go` (there is no `subprocess` import here, on purpose);
  * copy a fixture's committed `expected_digest` into a `.golden` file.

It reads exactly two kinds of input:

  1. `internal/record/FINGERPRINT-SPEC.md` — the normative algorithm.  The
     193-entry reserved-word list (spec section 3.5) and the algorithm
     constants (section 8) are PARSED OUT OF THE DOCUMENT at run time rather
     than transcribed here, so this oracle is bound to the specification's
     copy of them and cannot silently drift onto the code's copy.
  2. `testdata/fingerprint_corpus/**.json` — the fixed corpus.

`expected_digest` IS read, but only to CROSS-CHECK: if this oracle's
independently computed digest disagrees with the committed fixture, `--write`
REFUSES to write and exits non-zero.  A conformance harness that re-seals its
own goldens is the exact failure this packet exists to prevent
(FINGERPRINT-SPEC.md section 0: "Do not edit a golden digest to make a test
pass").

===========================================================================
RESOLUTION OF FINGERPRINT-SPEC.md APPENDIX Z
===========================================================================

Appendix Z records six places where the prose admits more than one reading.
This oracle takes one reading of each; every reading is now PINNED BY A
FIXTURE, so a third implementation that guesses differently fails rather than
diverging silently.  See `testdata/fingerprint_corpus/derived/` and the
`resolves` key each derived fixture carries.

  Z1  section 3.2 rule 1 — "the Unicode space separators".  Read as the
      Unicode **White_Space** property: TAB, LF, VT, FF, CR, SPACE, U+0085,
      U+00A0, and categories Zs, Zl (U+2028) and Zp (U+2029).  Note this is a
      reading the specification FORCES elsewhere rather than a free choice:
      section 9 states that "a snippet containing NUL, BEL, ESC or a raw \\x1f
      survives normalization and is then rejected by section 1.2", so
      U+001C-U+001F must NOT be whitespace — which rules out the otherwise
      obvious Python shortcut `str.isspace()`, whose class does include them.
      PINNED BY: derived/ordinal-01, candidate `non-ascii-whitespace-separators`
      (U+00A0 and U+2028 inside a snippet).

  Z2  section 3.5 clauses (c) and (d) — "the next non-space input characters".
      Read as the same class as Z1, so a newline between an identifier and
      `::` still preserves the identifier.  PINNED BY: derived/ordinal-01,
      candidate `namespace-qualifier-across-a-newline`.

  Z3  section 6.3 rule P — and/or precedence.  Read as
      `len >= 2 AND (starts { and ends }  OR  starts < and ends >  OR
      starts :)`, so a one-character segment `:` is NOT a placeholder.
      PINNED BY: derived/route-01, cases `bare_colon_segment_is_not_a_placeholder`
      and `two_character_placeholders_are`.

  Z4  section 4 — ordinals were NOT EXERCISED BY THE CORPUS AT ALL: every SAST
      fixture in the main corpus supplies a pre-computed `ordinal`, so an
      implementation could get the grouping key wrong and still pass
      everything.  PINNED BY: derived/ordinal-01, a ten-candidate batch,
      deliberately shuffled out of source order, that forces every component of
      the grouping key (target_id, rule_id_versioned, CANONICALISED
      repo_relpath, normalized_match) and every tier of the ordering rule
      (line, then column, then original batch index) to be exercised
      independently.  It also pins the two documented NON-members of the key:
      `enclosing_symbol_path` (FINGERPRINT-SPEC.md section 9 / CRITIQUE-01
      finding 4 — still OPEN, pinned here as current behaviour, not endorsed)
      and line/column.

  Z5  section 3 generally — block comments, backtick raw strings, <NUM>, and
      most of the reserved-word list had no fixture.  PARTIALLY RESOLVED:
      derived/ordinal-01 candidate `block-comment-backtick-raw-string-and-number`
      exercises section 3.2 rule 4, section 3.3's backtick no-escape rule,
      section 3.4 hex `<NUM>`, and one reserved word (`const`).  The bulk of
      the 193-word list REMAINS UNEXERCISED by any fixture; the list itself is
      still locked by `fingerprint_spec_test.go`, which is a different
      guarantee (the list is the same) from this one (the list is applied
      correctly).

  Z6  fixture schema — the corpus JSON says `evidence_signal` where the spec
      says `evidence_class_detail`, and `repo_rel_path` / `manifest_rel_path`
      where the spec says `repo_relpath` / `manifest_relpath`.  RESOLVED by
      writing the mapping down: see FIXTURE_KEY_MAP below, which is this
      oracle's normative reading of the fixture interface.

Resolving any of these is an `anvil-fp/v2` event IF IT CHANGES A DIGEST, and a
v1 clarification if it does not.  None of the readings above changes any
committed digest: this script reproduces all eight committed
`expected_digest` values and every committed mutation unchanged, which is
asserted on every run.

===========================================================================
USAGE
===========================================================================

    python scripts/compute_golden_fingerprints.py            # check (default)
    python scripts/compute_golden_fingerprints.py --check
    python scripts/compute_golden_fingerprints.py --write

`--check` recomputes everything and compares against the committed `.golden`
files and the committed `expected_digest` values; it writes nothing and exits
non-zero on any disagreement.  `--write` is the authoring path, used when a
NEW fixture is added; it refuses to write if a digest would contradict a
committed fixture.

No third-party dependencies.  Standard library only, Python 3.11+.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = REPO_ROOT / "internal" / "record" / "FINGERPRINT-SPEC.md"
CORPUS_DIR = REPO_ROOT / "testdata" / "fingerprint_corpus"
DERIVED_DIR = CORPUS_DIR / "derived"

# ---------------------------------------------------------------------------
# Constants, parsed out of FINGERPRINT-SPEC.md rather than transcribed
# ---------------------------------------------------------------------------

RESERVED_WORDS_BEGIN = "<!-- ANVIL-FP-RESERVED-WORDS: BEGIN -->"
RESERVED_WORDS_END = "<!-- ANVIL-FP-RESERVED-WORDS: END -->"
CONSTANTS_BEGIN = "<!-- ANVIL-FP-CONSTANTS: BEGIN -->"
CONSTANTS_END = "<!-- ANVIL-FP-CONSTANTS: END -->"

# Section 3.5: "Matching is exact and case-sensitive. [...] Whitespace-separated,
# sorted in byte order (uppercase before lowercase), 193 entries".
RESERVED_WORD_COUNT = 193


class SpecError(Exception):
    """The specification document could not be read as specified."""


class FingerprintError(Exception):
    """An input that anvil-fp/v1 refuses to fingerprint."""


def _block(text: str, begin: str, end: str, what: str) -> str:
    i = text.find(begin)
    j = text.find(end)
    if i < 0 or j < 0 or j < i:
        raise SpecError(f"{SPEC_PATH}: {what} block markers not found")
    body = text[i + len(begin) : j]
    # Strip the fenced-code delimiters; the fence is presentation, not content.
    return "\n".join(line for line in body.splitlines() if not line.strip().startswith("```"))


def load_spec() -> tuple[frozenset[str], dict[str, str]]:
    """Return (reserved words, constants) as the DOCUMENT states them."""
    text = SPEC_PATH.read_text(encoding="utf-8")

    words = _block(text, RESERVED_WORDS_BEGIN, RESERVED_WORDS_END, "reserved-word").split()
    if len(words) != RESERVED_WORD_COUNT:
        raise SpecError(
            f"{SPEC_PATH}: reserved-word list has {len(words)} entries, "
            f"the document says {RESERVED_WORD_COUNT}"
        )
    if len(set(words)) != len(words):
        raise SpecError(f"{SPEC_PATH}: reserved-word list contains duplicates")
    if words != sorted(words):
        raise SpecError(f"{SPEC_PATH}: reserved-word list is not sorted in byte order")

    consts: dict[str, str] = {}
    for line in _block(text, CONSTANTS_BEGIN, CONSTANTS_END, "constants").splitlines():
        if not line.strip():
            continue
        name, _, value = line.partition("=")
        consts[name.strip()] = value.strip()

    return frozenset(words), consts


RESERVED_WORDS, SPEC_CONSTANTS = load_spec()


def _const(name: str, want: str) -> str:
    got = SPEC_CONSTANTS.get(name)
    if got != want:
        raise SpecError(
            f"{SPEC_PATH}: constant {name} is {got!r}; this oracle implements {want!r}. "
            "A changed constant is an anvil-fp/v2 event (FINGERPRINT-SPEC.md section 0)."
        )
    return want


# Section 8's machine-checked block, asserted against this oracle's own reading.
ALG_NAME = _const("FingerprintAlgV1", "anvil-fp/v1")
_const("FingerprintFieldSeparator", "U+001F")
_const("FingerprintDigestHexLen", "64")
STR_TOKEN = _const("NormalizedStringToken", "<STR>")
NUM_TOKEN = _const("NormalizedNumberToken", "<NUM>")
METAVAR_PREFIX = _const("NormalizedMetavarPrefix", "$")
VAR_TOKEN = _const("NormalizedRouteSegmentToken", "<VAR>")
ROUTE_HEX_MIN_LEN = int(_const("routeHexSegmentMinLen", "16"))
ROUTE_OPAQUE_MIN_LEN = int(_const("routeOpaqueSegmentMinLen", "20"))

# Section 1.1: U+001F, the ASCII Unit Separator.
SEP = "\x1f"
DIGEST_HEX_LEN = 64

# Section 2.1 / 2.3: the literal tier tokens hashed in field position 2.  The
# SAST token is "sast" for BOTH evidence classes.
TIER_TOKEN_SAST = "sast"
TIER_TOKEN_DAST = "dast"

# Section 2.2: detector_kind.
DETECTOR_KIND_SCA = "sca"
DETECTOR_KIND_HOST = "host"

# Section 2.3 fields 6 and 8: closed value sets, "any other value is rejected".
INJECTION_POINTS = frozenset({"query", "body", "header", "cookie", "path"})
EVIDENCE_CLASS_DETAILS = frozenset(
    {
        "responseStackTrace",
        "statusCodeFlip",
        "dbErrorString",
        "timingSideChannel",
        "reflectedPayload",
        "other",
    }
)

# Z6: the fixture JSON's key names, mapped onto the specification's field
# names.  Written down here because the specification never states the fixture
# schema and Appendix Z records the mapping as "inferred by eye".
FIXTURE_KEY_MAP = {
    "sast": {
        "target_id": "target_id",
        "rule_id_versioned": "rule_id_versioned",
        "repo_rel_path": "repo_relpath",
        "enclosing_symbol_path": "enclosing_symbol_path",
        "snippet": "(raw input to normalized_match)",
        "ordinal": "ordinal",
    },
    "sca": {
        "target_id": "target_id",
        "advisory_id": "advisory_id",
        "purl": "(raw input to purl_base)",
        "manifest_rel_path": "manifest_relpath (the locator)",
    },
    "host": {
        "target_id": "target_id",
        "advisory_id": "advisory_id",
        "purl": "(raw input to purl_base)",
        "package_manager": "package_manager (locator, left half)",
        "host_identifier": "host_identifier (locator, right half)",
    },
    "dast": {
        "target_id": "target_id",
        "rule_id_versioned": "rule_id_versioned",
        "http_method": "http_method",
        "route_template": "(raw input to CanonicalRouteTemplate)",
        "injection_point": "injection_point",
        "param_name": "param_name",
        "evidence_signal": "evidence_class_detail",
    },
}


# ---------------------------------------------------------------------------
# Section 1 — primitives
# ---------------------------------------------------------------------------


def digest(fields: list[str]) -> str:
    """Section 1.2 field guard + section 1.3 digest."""
    if not fields:
        raise FingerprintError("an empty field list is rejected (section 1.2)")
    for i, f in enumerate(fields):
        for ch in f:
            if ch <= "\x1f" or ch == "\x7f":
                what = "the U+001F field separator" if ch == SEP else f"control character U+{ord(ch):04X}"
                raise FingerprintError(
                    f"field {i} contains {what}; a field boundary would move and two "
                    "distinct findings could collide (section 1.2)"
                )
    return hashlib.sha256(SEP.join(fields).encode("utf-8")).hexdigest()


def validate_digest(s: str) -> None:
    """Section 1.3: exactly 64 lowercase hex characters, never truncated."""
    if len(s) != DIGEST_HEX_LEN:
        raise FingerprintError(f"digest must be exactly {DIGEST_HEX_LEN} hex characters, got {len(s)}")
    if any(c not in "0123456789abcdef" for c in s):
        raise FingerprintError("digest must be lowercase hexadecimal (uppercase is rejected, not folded)")


def require(field: str, value: str) -> str:
    if value == "":
        raise FingerprintError(f"{field} must not be empty")
    return value


# ---------------------------------------------------------------------------
# Section 3 — normalized_match
# ---------------------------------------------------------------------------
#
# Z1 lives here.  Section 3.2 rule 1 names "\t \n \v \f \r, space, U+0085,
# U+00A0, and the Unicode space separators".  Read as the Unicode White_Space
# property, i.e. the explicit list plus categories Zs, Zl and Zp.  Python's
# str.isspace() is deliberately NOT used: its class also contains U+001C-U+001F,
# and section 9 requires a raw \x1f in a snippet to SURVIVE normalization so
# that section 1.2 can reject it.


# TAB, LF, VT, FF, CR, SPACE, U+0085 (NEL) and U+00A0 (NBSP), named
# explicitly by section 3.2 rule 1.  Spelled as escapes so no invisible
# character can be lost to an editor or a copy-paste.
SPEC_NAMED_WHITESPACE = frozenset("\t\n\v\f\r \u0085\u00a0")


def is_space(ch: str) -> bool:
    if ch in SPEC_NAMED_WHITESPACE:
        return True
    # "the Unicode space separators", read as Zs plus the line and paragraph
    # separators Zl/Zp -- together exactly the Unicode White_Space property.
    return unicodedata.category(ch) in ("Zs", "Zl", "Zp")


def is_letter(ch: str) -> bool:
    # Unicode general category L (section 3.2, "identifier-start").
    return unicodedata.category(ch)[0] == "L"


def is_digit_nd(ch: str) -> bool:
    # Section 3.2: "any digit (IsDigit, i.e. Unicode category Nd - not only ASCII)".
    return unicodedata.category(ch) == "Nd"


def is_ident_start(ch: str) -> bool:
    return ch in "_$" or is_letter(ch)


def is_ident_part(ch: str) -> bool:
    return ch in "_$" or is_letter(ch) or is_digit_nd(ch)


def normalize_match(snippet: str) -> str:
    """Section 3, one left-to-right pass over Unicode code points."""
    # 3.1 preprocessing, in this order.
    src = snippet.replace("\r\n", "\n").replace("\r", "\n")
    n = len(src)

    out: list[str] = []

    def emit(s: str) -> None:
        out.extend(s)

    def emit_space() -> None:
        # 3.1: "only if the output is non-empty and does not already end in a
        # space".  Never two consecutive spaces, never a leading space.
        if out and out[-1] != " ":
            out.append(" ")

    def ends_with_selector() -> bool:
        # 3.5 clause (b), asked of the OUTPUT, ignoring trailing spaces.
        end = len(out)
        while end > 0 and out[end - 1] == " ":
            end -= 1
        if end == 0:
            return False
        if out[end - 1] == ".":
            return True
        if end >= 2 and out[end - 2] == "-" and out[end - 1] == ">":
            return True
        if end >= 2 and out[end - 2] == ":" and out[end - 1] == ":":
            return True
        return False

    def skip_spaces_from(k: int) -> int:
        # Z2: "non-space" is read as the same class as rule 1's "whitespace".
        while k < n and is_space(src[k]):
            k += 1
        return k

    def next_non_space_is_scope(k: int) -> bool:
        k = skip_spaces_from(k)
        return k + 1 < n and src[k] == ":" and src[k + 1] == ":"

    def next_non_space_is_call_open(k: int) -> bool:
        k = skip_spaces_from(k)
        return k < n and src[k] == "("

    metavars: dict[str, str] = {}
    next_metavar = 1

    i = 0
    while i < n:
        c = src[i]

        # Rule 1 — whitespace run.
        if is_space(c):
            while i < n and is_space(src[i]):
                i += 1
            emit_space()
            continue

        # Rule 2 — "//" line comment.  Tested before rule 4, so "//*" is a line
        # comment.
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            emit_space()
            continue

        # Rule 3 — "#" line comment.
        if c == "#":
            while i < n and src[i] != "\n":
                i += 1
            emit_space()
            continue

        # Rule 4 — "/* ... */" block comment; unterminated means to end of input.
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i < n:
                if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    i += 2
                    break
                i += 1
            emit_space()
            continue

        # Rule 5 — string literal (section 3.3).
        if c in "\"'`":
            quote = c
            i += 1
            while i < n:
                if src[i] == "\\" and quote != "`":
                    # Backslash escapes are honoured inside " and ', NOT inside `.
                    i += 2
                    continue
                if src[i] == quote:
                    i += 1
                    break
                i += 1
            emit(STR_TOKEN)
            continue

        # Rule 6 — number token (section 3.4).  ASCII digit only; a Unicode Nd
        # digit that is not ASCII falls through to rule 7's identifier-part.
        if "0" <= c <= "9":
            while i < n:
                r = src[i]
                if is_letter(r) or is_digit_nd(r) or r in "_.":
                    i += 1
                    continue
                if r in "+-" and i > 0 and src[i - 1] in "eE":
                    i += 1
                    continue
                break
            emit(NUM_TOKEN)
            continue

        # Rule 7 — identifier (section 3.5).
        if is_ident_start(c):
            j = i
            while j < n and is_ident_part(src[j]):
                j += 1
            word = src[i:j]
            i = j

            if word in RESERVED_WORDS:  # (a)
                emit(word)
            elif ends_with_selector():  # (b)
                emit(word)
            elif next_non_space_is_scope(i):  # (c)
                emit(word)
            elif next_non_space_is_call_open(i):  # (d)
                emit(word)
            else:  # (e)
                mv = metavars.get(word)
                if mv is None:
                    mv = METAVAR_PREFIX + str(next_metavar)
                    next_metavar += 1
                    metavars[word] = mv
                emit(mv)
            continue

        # Rule 8 — anything else, verbatim.
        out.append(c)
        i += 1

    # 3.6 final trim.  Only spaces can appear at the edges: emit_space() is the
    # sole producer of whitespace and it emits U+0020 only.
    return "".join(out).strip(" ")


# ---------------------------------------------------------------------------
# Section 7 — the remaining canonicalisations
# ---------------------------------------------------------------------------


def canonical_repo_relpath(p: str) -> str:
    """Section 7.1, in order.  No case folding, no '..' resolution."""
    p = p.replace("\\", "/")
    while "//" in p:
        p = p.replace("//", "/")
    while p.startswith("./"):
        p = p[2:]
    if p.startswith("/"):
        p = p[1:]
    if p.endswith("/"):
        p = p[:-1]
    return p


def purl_base(purl: str) -> str:
    """Section 7.2.  The enforcement point for 'the version is never hashed'."""
    p = purl.strip()
    if p == "":
        raise FingerprintError("purl_base: must not be empty")
    if len(p) < 4 or p[:4].lower() != "pkg:":
        raise FingerprintError(f"purl_base: must begin with 'pkg:', got {purl!r}")
    rest = p[4:]
    for delim in ("#", "?", "@"):  # subpath, then qualifiers, then version
        idx = rest.find(delim)
        if idx >= 0:
            rest = rest[:idx]
    if rest.endswith("/"):
        rest = rest[:-1]
    if rest == "":
        raise FingerprintError(f"purl_base: no type or name after 'pkg:': {purl!r}")
    slash = rest.find("/")
    if slash < 0:
        raise FingerprintError(f"purl_base: a type but no name: {purl!r}")
    # Only the type (up to the first '/') is lower-cased; namespace and name
    # are left alone because their case-sensitivity is type-dependent.
    rest = rest[:slash].lower() + rest[slash:]
    return "pkg:" + rest


def host_locator(package_manager: str, host_identifier: str) -> str:
    """Section 7.3."""
    if ":" in package_manager:
        raise FingerprintError("host locator: package_manager must not contain ':' (its own delimiter)")
    mgr = package_manager.strip()
    ident = host_identifier.strip()
    if mgr == "":
        raise FingerprintError("host locator: package_manager must not be empty")
    if ident == "":
        raise FingerprintError("host locator: host_identifier must not be empty")
    return mgr.lower() + ":" + ident


def canonical_http_method(method: str) -> str:
    """Section 7.4: trim, upper-case, reject empty or multi-token."""
    if method.strip() == "":
        raise FingerprintError("http_method: must not be empty")
    m = method.strip().upper()
    if any(is_space(ch) for ch in m):
        raise FingerprintError("http_method: must be a single token")
    return m


# ---------------------------------------------------------------------------
# Section 6 — route_template, a DERIVED value
# ---------------------------------------------------------------------------


def _is_all_ascii_digits(s: str) -> bool:
    return s != "" and all("0" <= c <= "9" for c in s)


def _is_ascii_hex(c: str) -> bool:
    return ("0" <= c <= "9") or ("a" <= c <= "f") or ("A" <= c <= "F")


def _is_route_placeholder(s: str) -> bool:
    # Z3: read as len >= 2 AND (A or B or C).  A one-character ":" is therefore
    # NOT a placeholder.
    if len(s) < 2:
        return False
    if s[0] == "{" and s[-1] == "}":
        return True
    if s[0] == "<" and s[-1] == ">":
        return True
    return s[0] == ":"


def _is_uuid_segment(s: str) -> bool:
    if len(s) != 36:
        return False
    for idx, ch in enumerate(s):
        if idx in (8, 13, 18, 23):
            if ch != "-":
                return False
        elif not _is_ascii_hex(ch):
            return False
    return True


def _is_long_hex_segment(s: str) -> bool:
    return len(s) >= ROUTE_HEX_MIN_LEN and all(_is_ascii_hex(c) for c in s)


def _is_long_opaque_segment(s: str) -> bool:
    if len(s) < ROUTE_OPAQUE_MIN_LEN:
        return False
    has_digit = has_letter = False
    for c in s:
        if "0" <= c <= "9":
            has_digit = True
        elif ("a" <= c <= "z") or ("A" <= c <= "Z"):
            has_letter = True
        else:
            return False
    return has_digit and has_letter


def is_volatile_route_segment(s: str) -> bool:
    """Section 6.3, rules P, N, U, H, O in that order.  Empty is never volatile."""
    if s == "":
        return False
    return (
        _is_route_placeholder(s)
        or _is_all_ascii_digits(s)
        or _is_uuid_segment(s)
        or _is_long_hex_segment(s)
        or _is_long_opaque_segment(s)
    )


def canonical_route_template(route: str) -> str:
    """Section 6.2, steps 1-8 in order."""
    cut = min((i for i in (route.find("?"), route.find("#")) if i >= 0), default=-1)
    if cut >= 0:
        route = route[:cut]
    route = route.replace("\\", "/")
    while "//" in route:
        route = route.replace("//", "/")
    if route == "":
        return ""
    if not route.startswith("/"):
        route = "/" + route
    if len(route) > 1 and route.endswith("/"):
        route = route[:-1]
    if route == "/":
        return "/"
    segs = [VAR_TOKEN if is_volatile_route_segment(s) else s for s in route[1:].split("/")]
    return "/" + "/".join(segs)


# ---------------------------------------------------------------------------
# Section 2 — the four tiers
# ---------------------------------------------------------------------------


def sast_fields(inp: dict) -> list[str]:
    """Section 2.1: seven fields."""
    target_id = require("target_id", inp["target_id"])
    rule_id = require("rule_id_versioned", inp["rule_id_versioned"])
    raw_path = require("repo_relpath", inp["repo_rel_path"])
    relpath = canonical_repo_relpath(raw_path)
    if relpath == "":
        raise FingerprintError("repo_relpath canonicalises to the empty string")
    snippet = require("normalized_match (snippet)", inp["snippet"])
    normalized = normalize_match(snippet)
    if normalized == "":
        raise FingerprintError("snippet normalises to the empty string; it carries no identity")
    ordinal = int(inp["ordinal"])
    if ordinal < 0:
        raise FingerprintError("ordinal must not be negative")
    return [
        target_id,
        TIER_TOKEN_SAST,
        rule_id,
        relpath,
        inp.get("enclosing_symbol_path", ""),  # may be empty
        normalized,
        str(ordinal),  # base 10, no padding, no sign
    ]


def sca_fields(inp: dict) -> list[str]:
    """Section 2.2 with detector_kind = 'sca'."""
    locator = canonical_repo_relpath(require("manifest_relpath", inp["manifest_rel_path"]))
    if locator == "":
        raise FingerprintError("manifest_relpath canonicalises to the empty string")
    return [
        require("target_id", inp["target_id"]),
        DETECTOR_KIND_SCA,
        require("advisory_id", inp["advisory_id"]),  # verbatim, NOT case-folded
        purl_base(require("purl", inp["purl"])),
        locator,
    ]


def host_fields(inp: dict) -> list[str]:
    """Section 2.2 with detector_kind = 'host'."""
    return [
        require("target_id", inp["target_id"]),
        DETECTOR_KIND_HOST,
        require("advisory_id", inp["advisory_id"]),
        purl_base(require("purl", inp["purl"])),
        host_locator(inp["package_manager"], inp["host_identifier"]),
    ]


def dast_fields(inp: dict) -> list[str]:
    """Section 2.3: eight fields."""
    target_id = require("target_id", inp["target_id"])
    rule_id = require("rule_id_versioned", inp["rule_id_versioned"])
    method = canonical_http_method(inp["http_method"])
    route = canonical_route_template(require("route_template", inp["route_template"]))
    if route == "":
        raise FingerprintError("route_template canonicalises to the empty string")
    injection = inp["injection_point"]
    if injection not in INJECTION_POINTS:
        raise FingerprintError(f"injection_point {injection!r} is not one of {sorted(INJECTION_POINTS)}")
    # Z6: the fixture spells this `evidence_signal`; the specification calls the
    # hashed field `evidence_class_detail`.  Same field.
    detail = inp["evidence_signal"]
    if detail not in EVIDENCE_CLASS_DETAILS:
        raise FingerprintError(
            f"evidence_class_detail {detail!r} is not one of {sorted(EVIDENCE_CLASS_DETAILS)}"
        )
    return [
        target_id,
        TIER_TOKEN_DAST,
        rule_id,
        method,
        route,
        injection,
        inp.get("param_name", ""),  # may be empty
        detail,
    ]


TIER_BUILDERS = {
    "sast": sast_fields,
    "sca": sca_fields,
    "host": host_fields,
    "dast": dast_fields,
}


def fields_for(tier: str, inp: dict) -> list[str]:
    builder = TIER_BUILDERS.get(tier)
    if builder is None:
        raise FingerprintError(f"unknown tier {tier!r}")
    unknown = set(inp) - set(FIXTURE_KEY_MAP[tier])
    if unknown:
        # Z6 again: an unmapped fixture key would otherwise default a hashed
        # field to "" and lock in a wrong digest, silently.
        raise FingerprintError(f"tier {tier}: fixture carries unmapped key(s) {sorted(unknown)}")
    return builder(inp)


# ---------------------------------------------------------------------------
# Section 4 — ordinal and its grouping key
# ---------------------------------------------------------------------------


def ordinal_group_key(inp: dict) -> str:
    """Section 4: target_id, rule_id_versioned, CanonicalRepoRelPath(repo_relpath),
    normalized_match — joined with U+001F for COMPARISON only, never hashed.

    Note what is NOT in this key and is documented as such: enclosing_symbol_path
    (section 9 / CRITIQUE-01 finding 4, still open) and line/column.
    """
    return SEP.join(
        [
            inp["target_id"],
            inp["rule_id_versioned"],
            canonical_repo_relpath(inp["repo_rel_path"]),
            normalize_match(inp["snippet"]),
        ]
    )


def assign_ordinals(candidates: list[dict]) -> list[int]:
    """Section 4.  Ordering within a group is ascending by line, then column,
    then the candidate's original index in the batch (a stable tiebreak).
    """
    groups: dict[str, list[int]] = {}
    for idx, cand in enumerate(candidates):
        groups.setdefault(ordinal_group_key(cand["input"]), []).append(idx)

    ordinals = [-1] * len(candidates)
    for members in groups.values():
        members.sort(key=lambda i: (candidates[i]["line"], candidates[i]["column"], i))
        for ordinal, idx in enumerate(members):
            ordinals[idx] = ordinal
    return ordinals


# ---------------------------------------------------------------------------
# Golden files
# ---------------------------------------------------------------------------
#
# Format: TSV, three columns, "#" comment lines ignored.
#
#     kind <TAB> label <TAB> value
#
# kind is "digest" (value is a 64-lowercase-hex digest) or "ordinal" (value is
# a base-10 non-negative integer).  Labels are "base", "mutation:<name>",
# "candidate:<name>" and "case:<name>".  Both this script and
# internal/record/fingerprint_conformance_test.go parse it; it is deliberately
# trivial so neither parser can be the interesting part.

GOLDEN_HEADER = """\
# anvil-fp/v1 conformance golden — {fixture_id}
#
# PRODUCED BY: scripts/compute_golden_fingerprints.py, an implementation of
# internal/record/FINGERPRINT-SPEC.md written WITHOUT reading
# internal/record/fingerprint.go.  These values were NOT produced by the code
# they gate, and they are NOT a copy of the fixture's `expected_digest`.
#
# DO NOT regenerate this file to make a test pass.  A changed digest means every
# stored finding under it loses its identity, silently: `first_seen_at` resets,
# every fingerprint-keyed suppression stops applying, and every handoff row is
# orphaned.  That is an anvil-fp/v2 event with a dual-write migration
# (FINGERPRINT-SPEC.md section 0), never a v1 edit and never a re-seal.
#
# Format: TSV — kind <TAB> label <TAB> value.
"""


def render_golden(fixture_id: str, rows: list[tuple[str, str, str]]) -> str:
    body = "".join(f"{kind}\t{label}\t{value}\n" for kind, label, value in rows)
    return GOLDEN_HEADER.format(fixture_id=fixture_id) + body


def parse_golden(text: str) -> list[tuple[str, str, str]]:
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise SpecError(f"malformed golden line: {line!r}")
        rows.append((parts[0], parts[1], parts[2]))
    return rows


# ---------------------------------------------------------------------------
# Corpus walking
# ---------------------------------------------------------------------------


class Mismatch(Exception):
    """This oracle disagrees with something already committed."""


def rows_for_main_fixture(fx: dict, path: Path) -> list[tuple[str, str, str]]:
    """The eight tier fixtures: base + every mutation."""
    tier = fx["tier"]
    rows: list[tuple[str, str, str]] = []

    fields = fields_for(tier, fx["input"])
    if fields != fx["hashed_fields"]:
        raise Mismatch(
            f"{path.name}: hashed_fields disagree.\n"
            f"  this oracle: {fields!r}\n"
            f"  committed:   {fx['hashed_fields']!r}"
        )
    base = digest(fields)
    validate_digest(base)
    committed = fx.get("expected_digest", "")
    if committed and base != committed:
        raise Mismatch(
            f"{path.name}: base digest disagrees with the committed expected_digest.\n"
            f"  this oracle: {base}\n"
            f"  committed:   {committed}\n"
            "STOP. Do not re-seal. Either the specification and the implementation have "
            "diverged, or this is an anvil-fp/v2 event."
        )
    rows.append(("digest", "base", base))

    for m in fx.get("mutations", []):
        d = digest(fields_for(tier, m["input"]))
        validate_digest(d)
        if d != base:
            raise Mismatch(
                f"{path.name}: mutation {m['name']!r} changed the digest.\n"
                f"  base:     {base}\n"
                f"  mutation: {d}\n"
                "Every mutation differs ONLY in fields the specification forbids hashing."
            )
        rows.append(("digest", f"mutation:{m['name']}", d))

    return rows


def rows_for_derived_fixture(fx: dict, path: Path) -> list[tuple[str, str, str]]:
    """The derived corpus: values the fixture does NOT supply and an
    implementation must compute (Appendix Z4 and friends)."""
    kind = fx["kind"]
    rows: list[tuple[str, str, str]] = []

    if kind == "sast_ordinal_batch":
        candidates = fx["candidates"]
        ordinals = assign_ordinals(candidates)
        for cand, ordinal in zip(candidates, ordinals, strict=True):
            if "ordinal" in cand["input"]:
                raise Mismatch(
                    f"{path.name}: candidate {cand['name']!r} supplies a pre-computed ordinal; "
                    "the whole point of this fixture is that the ordinal must be DERIVED."
                )
            if ordinal != cand["expected_ordinal"]:
                raise Mismatch(
                    f"{path.name}: candidate {cand['name']!r} — derived ordinal {ordinal}, "
                    f"fixture says {cand['expected_ordinal']}"
                )
            inp = dict(cand["input"], ordinal=ordinal)
            fields = fields_for("sast", inp)
            if fields != cand["hashed_fields"]:
                raise Mismatch(
                    f"{path.name}: candidate {cand['name']!r} hashed_fields disagree.\n"
                    f"  this oracle: {fields!r}\n"
                    f"  committed:   {cand['hashed_fields']!r}"
                )
            d = digest(fields)
            validate_digest(d)
            committed = cand.get("expected_digest", "")
            if committed and d != committed:
                raise Mismatch(
                    f"{path.name}: candidate {cand['name']!r} digest disagrees with the fixture.\n"
                    f"  this oracle: {d}\n  committed:   {committed}"
                )
            rows.append(("ordinal", f"candidate:{cand['name']}", str(ordinal)))
            rows.append(("digest", f"candidate:{cand['name']}", d))
        return rows

    if kind == "dast_cases":
        for case in fx["candidates"]:
            # The fixture states the DERIVED route it expects, in the clear.
            # Checking it separately from the digest turns "the digest moved"
            # into "segment X templated when it should not have".
            want_route = case["canonical_route"]
            got_route = canonical_route_template(case["input"]["route_template"])
            if got_route != want_route:
                raise Mismatch(
                    f"{path.name}: case {case['name']!r} canonical_route disagrees.\n"
                    f"  this oracle: {got_route!r}\n  committed:   {want_route!r}"
                )
            fields = fields_for("dast", case["input"])
            if fields != case["hashed_fields"]:
                raise Mismatch(
                    f"{path.name}: case {case['name']!r} hashed_fields disagree.\n"
                    f"  this oracle: {fields!r}\n"
                    f"  committed:   {case['hashed_fields']!r}"
                )
            d = digest(fields)
            validate_digest(d)
            committed = case.get("expected_digest", "")
            if committed and d != committed:
                raise Mismatch(
                    f"{path.name}: case {case['name']!r} digest disagrees with the fixture.\n"
                    f"  this oracle: {d}\n  committed:   {committed}"
                )
            rows.append(("digest", f"case:{case['name']}", d))
        return rows

    raise Mismatch(f"{path.name}: unknown derived fixture kind {kind!r}")


def fixture_files() -> list[tuple[Path, bool]]:
    """(path, is_derived) for every fixture, in a stable order."""
    main = sorted(CORPUS_DIR.glob("*.json"))
    derived = sorted(DERIVED_DIR.glob("*.json")) if DERIVED_DIR.is_dir() else []
    if not main:
        raise Mismatch(f"no fixtures in {CORPUS_DIR}; the fixed corpus is mandatory (00-SPINE.md S6)")
    return [(p, False) for p in main] + [(p, True) for p in derived]


def run(write: bool) -> int:
    failures = 0
    total_rows = 0

    for path, is_derived in fixture_files():
        fx = json.loads(path.read_text(encoding="utf-8"))
        try:
            rows = rows_for_derived_fixture(fx, path) if is_derived else rows_for_main_fixture(fx, path)
        except (Mismatch, FingerprintError) as exc:
            print(f"FAIL  {path.name}\n      {exc}", file=sys.stderr)
            failures += 1
            continue

        total_rows += len(rows)
        golden_path = path.with_suffix(".golden")
        rendered = render_golden(fx["id"], rows)

        if write:
            golden_path.write_text(rendered, encoding="utf-8", newline="\n")
            print(f"WROTE {golden_path.relative_to(REPO_ROOT)}  ({len(rows)} rows)")
            continue

        if not golden_path.exists():
            print(f"FAIL  {golden_path.relative_to(REPO_ROOT)} is missing; run with --write", file=sys.stderr)
            failures += 1
            continue
        committed = parse_golden(golden_path.read_text(encoding="utf-8"))
        if committed != rows:
            print(f"FAIL  {golden_path.relative_to(REPO_ROOT)} disagrees with this oracle", file=sys.stderr)
            for a, b in zip(committed, rows, strict=False):
                if a != b:
                    print(f"      committed {a}\n      oracle    {b}", file=sys.stderr)
            if len(committed) != len(rows):
                print(f"      row count: committed {len(committed)}, oracle {len(rows)}", file=sys.stderr)
            failures += 1
            continue
        print(f"OK    {golden_path.relative_to(REPO_ROOT)}  ({len(rows)} rows)")

    if failures:
        print(f"\n{failures} fixture(s) FAILED. Do NOT re-seal goldens to make this pass.", file=sys.stderr)
        return 1
    print(f"\n{ALG_NAME}: all fixtures reproduced from FINGERPRINT-SPEC.md ({total_rows} rows).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="recompute and compare (default); writes nothing")
    g.add_argument("--write", action="store_true", help="author mode: (re)write the .golden files")
    args = ap.parse_args()
    return run(write=args.write)


if __name__ == "__main__":
    sys.exit(main())
