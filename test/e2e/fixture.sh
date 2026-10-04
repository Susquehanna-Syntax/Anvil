#!/bin/sh
# Phase 4's exit gate, on the offline fixture, through the built binary.
#
#   sh test/e2e/fixture.sh
#
# Needs Go, Python with jsonschema (eval/'s dependencies), and Trivy with a
# seeded vulnerability database for the repository half. Every step asserts
# its exit status; any surprise fails the script. CI runs it in the
# "anvil end to end" job.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fixture="$root/testdata/lanea-fixture"

go build -o "$work/anvil" "$root/cmd/anvil"
anvil="$work/anvil"
export ANVIL_CONFIG="$work/anvil.yml"
# Lane B is on by default; the Lane A fixture repository holds no source in a
# language its rules cover, so it needs the rule pack and no tool.
printf 'version: 1\nstateDir: %s/state\ntrivyDB:\n  enabled: true\nrecall:\n  rules: %s/data/rules\n' "$work" "$root" > "$ANVIL_CONFIG"

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
	echo "ok: $what (exit $got)"
}

expect 0 "feeds import" -- "$anvil" feeds import "$fixture"
expect 1 "host scan, first run" -- "$anvil" scan --host --inventory "$fixture/host/inventory-1.json" --out "$work/host1.sarif"
grep -q 'new 3, persisting 0, regressed 0, fixed 0' "$work/out" || { echo "FAIL: first run marks" >&2; exit 1; }
expect 1 "host scan, second run" -- "$anvil" scan --host --inventory "$fixture/host/inventory-2.json" --out "$work/host2.sarif"
grep -q 'new 1, persisting 2, regressed 0, fixed 1' "$work/out" || { echo "FAIL: second run marks" >&2; exit 1; }
expect 3 "a host scan never collects itself" -- "$anvil" scan --host
expect 1 "repository scan with real Trivy" -- "$anvil" scan --repo "$fixture/repo" --target lanea-fixture --out "$work/repo.sarif"
expect 1 "findings in the store" -- "$anvil" findings

python3 "$root/eval/tools/validate_record.py" "$root/schemas/anvil-record-v1.schema.json" \
	"$work/host1.sarif" "$work/host2.sarif" "$work/repo.sarif"
echo "PASS: the exit gate on the fixture"
