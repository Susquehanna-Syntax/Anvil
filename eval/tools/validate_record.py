"""Validate Anvil records against the wire schema (draft 2020-12).

usage: python3 validate_record.py SCHEMA RECORD...

The Go validator checks what Go can; this is the wire gate, and it is what
caught null index maps and a null cveIds list on 2026-10-03.
"""

import json
import sys

import jsonschema


def main(argv: list[str]) -> int:
    schema_path, records = argv[1], argv[2:]
    with open(schema_path, encoding="utf-8") as f:
        validator = jsonschema.Draft202012Validator(json.load(f))
    failed = False
    for path in records:
        with open(path, encoding="utf-8") as f:
            errors = sorted(validator.iter_errors(json.load(f)), key=lambda e: list(e.path))
        for e in errors[:20]:
            print(f"{path}: {'/'.join(str(p) for p in e.path)}: {e.message}", file=sys.stderr)
        print(f"{path}: {'valid' if not errors else f'{len(errors)} error(s)'}")
        failed = failed or bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
