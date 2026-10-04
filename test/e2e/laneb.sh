#!/bin/sh
# Lane B end to end, on testdata/laneb-fixture, through the built binary and the
# real, pinned tools.
#
#   sh test/e2e/laneb.sh
#
# Needs Go, Python with jsonschema (eval/'s dependencies), and opengrep 1.26.0,
# gosec 2.29.0 and bandit 1.9.4, on PATH or named by ANVIL_OPENGREP,
# ANVIL_GOSEC and ANVIL_BANDIT. CI runs it in the "Lane B end to end (real
# tools)" job.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fixture="$root/testdata/laneb-fixture"

go build -o "$work/anvil" "$root/cmd/anvil"
anvil="$work/anvil"
export ANVIL_CONFIG="$work/anvil.yml"
{
	printf 'version: 1\nstateDir: %s/state\nrecall:\n  rules: %s/data/rules\n' "$work" "$root"
	[ -n "${ANVIL_OPENGREP:-}" ] && printf '  opengrep: %s\n' "$ANVIL_OPENGREP"
	[ -n "${ANVIL_GOSEC:-}" ] && printf '  gosec: %s\n' "$ANVIL_GOSEC"
	[ -n "${ANVIL_BANDIT:-}" ] && printf '  bandit: %s\n' "$ANVIL_BANDIT"
	printf '  goBin: %s\n' "$(dirname "$(command -v go)")"
} > "$ANVIL_CONFIG"

expect() { # expect STATUS DESCRIPTION -- COMMAND...
	want=$1; what=$2; shift 3
	set +e
	"$@" > "$work/out" 2> "$work/err"
	got=$?
	set -e
	cat "$work/out"
	if [ "$got" -ne "$want" ]; then
		echo "FAIL: $what exited $got, want $want" >&2
		cat "$work/err" >&2
		exit 1
	fi
	cat "$work/err"
	echo "ok: $what (exit $got)"
}

expect 1 "Lane B scan, first run" -- "$anvil" scan --repo "$fixture" --target laneb-fixture --out "$work/laneb1.sarif"
grep -q 'findings, 11 finding(s); scan_run 1 ok; new 11, persisting 0, regressed 0, fixed 0' "$work/out" ||
	{ echo "FAIL: first run marks" >&2; exit 1; }
expect 1 "Lane B scan, second run" -- "$anvil" scan --repo "$fixture" --target laneb-fixture --out "$work/laneb2.sarif"
grep -q 'new 0, persisting 11, regressed 0, fixed 0' "$work/out" || { echo "FAIL: second run marks" >&2; exit 1; }
expect 1 "anvil recall" -- "$anvil" recall "$fixture"
grep -q '"count": 11' "$work/out" || { echo "FAIL: anvil recall count" >&2; exit 1; }

python3 - "$work/laneb1.sarif" <<'PY'
import json, sys
log = json.load(open(sys.argv[1]))
run = log["runs"][0]
assert log["properties"]["anvil/schemaVersion"] == "1.1.0", log["properties"]["anvil/schemaVersion"]
assert len(run["results"]) == 11
for r in run["results"]:
    p = r["properties"]
    assert p["anvil/verdict"] == "unconfirmed" and p["anvil/confidence"] == 1, r["ruleId"]
    assert p["anvil/detector"]["model"] == "" and "rank" not in r, r["ruleId"]
    ext = run["tool"]["extensions"][r["rule"]["toolComponent"]["index"]]
    prov = next(d for d in ext["rules"] if d["id"] == r["ruleId"])["properties"]["anvil/ruleProvenance"]
    assert all(str(v).strip() for v in prov.values()), prov
assert [f["location"]["uri"] for f in run["properties"]["anvil/specHarvest"]["files"]] == ["api/openapi.yaml"]
print("ok: every result is unconfirmed, with complete rule provenance; the spec was harvested")
PY
python3 "$root/eval/tools/validate_record.py" "$root/schemas/anvil-record-v1.schema.json" \
	"$work/laneb1.sarif" "$work/laneb2.sarif"
echo "PASS: Lane B end to end on the fixture"
