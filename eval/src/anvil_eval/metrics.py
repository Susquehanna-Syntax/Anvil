"""Classic code metrics of one C or C++ function, computed from its text alone.

These are the features of the code-metrics baseline's regression (register row
code-metrics-baseline). They are deliberately the textbook ones: nothing here knows what a
vulnerability looks like, which is the point of the comparison. The lexer is approximate, in the
same way for every function, and has no dependency beyond the standard library.
"""

from __future__ import annotations

import math
import re

FEATURES = (
    "nonblank_lines",
    "tokens",
    "cyclomatic",
    "max_nesting",
    "parameters",
    "calls",
    "distinct_callees",
    "returns",
    "loops",
    "conditionals",
    "pointer_derefs",
    "array_subscripts",
    "halstead_volume",
    "comment_lines",
)

_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_LITERAL = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'')
_TOKEN = re.compile(
    r"[A-Za-z_]\w*|\d[\w.]*|->|\+\+|--|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^]=|::|"
    r"[{}()\[\];,.<>=+\-*/%&|^!~?:#]|\"\"|''"
)
_KEYWORDS = frozenset(
    "auto break case catch char class const continue default delete do double else enum extern "
    "float for goto if inline int long new register return short signed sizeof static struct "
    "switch template this throw try typedef union unsigned virtual void volatile while bool "
    "true false nullptr NULL".split()
)
_NOT_CALLS = frozenset({"if", "for", "while", "switch", "return", "sizeof", "catch", "defined"})


def _strip(func: str) -> tuple[str, int]:
    comment_lines = 0
    for m in _COMMENT.finditer(func):
        comment_lines += m.group(0).count("\n") + 1
    code = _COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), func)
    code = _LITERAL.sub(lambda m: '""' if m.group(0)[0] == '"' else "''", code)
    return code, comment_lines


def _parameters(tokens: list[str]) -> int:
    try:
        open_at = tokens.index("(")
    except ValueError:
        return 0
    depth, count, seen = 0, 0, False
    for t in tokens[open_at:]:
        if t == "(":
            depth += 1
            continue
        if t == ")":
            depth -= 1
            if depth == 0:
                break
            continue
        if depth == 1 and t == ",":
            count += 1
        elif depth >= 1:
            seen = True
    inner = tokens[open_at + 1 : open_at + 3]
    if not seen or inner == ["void", ")"]:
        return 0
    return count + 1


def compute(func: str) -> dict[str, float]:
    code, comment_lines = _strip(func)
    tokens = _TOKEN.findall(code)
    body_start = tokens.index("{") if "{" in tokens else len(tokens)
    body = tokens[body_start:]

    depth = max_depth = 0
    for t in body:
        if t == "{":
            depth += 1
            max_depth = max(max_depth, depth)
        elif t == "}":
            depth -= 1

    calls: list[str] = []
    derefs = 0
    for i, t in enumerate(body):
        nxt = body[i + 1] if i + 1 < len(body) else ""
        if nxt == "(" and re.fullmatch(r"[A-Za-z_]\w*", t) and t not in _NOT_CALLS:
            calls.append(t)
        if t == "->":
            derefs += 1
        elif t == "*":
            prev = body[i - 1] if i else ""
            if not re.fullmatch(r"[\w)\]]+", prev):  # unary: after an operator or punctuation
                derefs += 1

    operators = [t for t in tokens if not re.fullmatch(r"\w+|\"\"|''", t) or t in _KEYWORDS]
    operands = [t for t in tokens if t not in operators]
    n = len(set(operators)) + len(set(operands))
    big_n = len(operators) + len(operands)
    volume = big_n * math.log2(n) if n > 1 else 0.0

    count = body.count
    conditionals = count("if") + count("switch") + count("?")
    loops = count("for") + count("while") + count("do") - _do_while_overlap(body)
    cyclomatic = 1 + count("if") + count("for") + count("while") + count("case") + count(
        "catch"
    ) + count("&&") + count("||") + count("?")

    return {
        "nonblank_lines": float(sum(1 for line in code.splitlines() if line.strip())),
        "tokens": float(len(tokens)),
        "cyclomatic": float(cyclomatic),
        "max_nesting": float(max(max_depth - 1, 0)),
        "parameters": float(_parameters(tokens[:body_start])),
        "calls": float(len(calls)),
        "distinct_callees": float(len(set(calls))),
        "returns": float(count("return")),
        "loops": float(loops),
        "conditionals": float(conditionals),
        "pointer_derefs": float(derefs),
        "array_subscripts": float(count("[")),
        "halstead_volume": float(volume),
        "comment_lines": float(comment_lines),
    }


def _do_while_overlap(body: list[str]) -> int:
    """A ``do { } while (...)`` is one loop, not two: count the ``while`` that closes a ``do``."""
    n = 0
    for i, t in enumerate(body):
        if t == "while" and i and body[i - 1] == "}":
            depth = 0
            for j in range(i - 1, -1, -1):
                if body[j] == "}":
                    depth += 1
                elif body[j] == "{":
                    depth -= 1
                    if depth == 0:
                        n += 1 if j and body[j - 1] == "do" else 0
                        break
    return n


def vector(func: str) -> list[float]:
    m = compute(func)
    return [m[f] for f in FEATURES]
