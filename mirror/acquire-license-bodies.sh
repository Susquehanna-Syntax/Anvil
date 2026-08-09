#!/bin/sh
# Anvil A.4 — deliberate acquisition of the publisher licence texts the licence
# gate reads as evidence.
#
# NOTHING RUNS THIS FOR YOU. It is not wired into any build, test or CI job, and
# internal/ingest/license imports no HTTP client at all. An operator runs it
# once, on purpose, and then READS what it fetched.
#
# Two invariants, both taken from eval/tools/opengrep/anvil_opengrep/acquire.py:
#
#   1. ONLY WHAT THE MANIFEST PINS. Every URL comes verbatim out of
#      LICENSE-MANIFEST.toml. No "latest", no version resolution, no URL
#      derived from anything else.
#   2. CHECKSUM OR NOTHING. A pinned entry whose download does not match its
#      sha256 deletes the download and fails. It is never retried, never warned
#      about, never ignored.
#
# An UNPINNED entry (sha256 = "") cannot be verified, so this script fetches it,
# prints the digest, and stops short of blessing it. Recording that digest is a
# human act: you are certifying that the document you just read is the operative
# licence for that feed. See mirror/README.md.
#
# Usage:
#   sh mirror/acquire-license-bodies.sh              fetch and verify everything
#   sh mirror/acquire-license-bodies.sh --verify-only  check what is on disk
#   sh mirror/acquire-license-bodies.sh ghsa cwe     only these feeds

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
manifest="$here/LICENSE-MANIFEST.toml"
verify_only=0
wanted=""

for arg in "$@"; do
	case "$arg" in
	--verify-only) verify_only=1 ;;
	-h | --help)
		sed -n '2,30p' "$0"
		exit 0
		;;
	-*)
		echo "unknown option: $arg" >&2
		exit 2
		;;
	*) wanted="$wanted $arg" ;;
	esac
done

[ -f "$manifest" ] || {
	echo "FATAL: $manifest not found" >&2
	exit 1
}

# --- digest helper: whichever of the two standard tools this host has ---
sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		echo "FATAL: neither sha256sum nor shasum is on PATH; cannot verify anything" >&2
		exit 1
	fi
}

fetch() {
	# fetch <url> <dest>
	if command -v curl >/dev/null 2>&1; then
		curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
			--output "$2" -- "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget --quiet --https-only --output-document="$2" -- "$1"
	else
		echo "FATAL: neither curl nor wget is on PATH" >&2
		exit 1
	fi
}

# --- manifest reader: the same tiny grammar internal/ingest/license parses ---
# Emits: feed_id <TAB> tier <TAB> dir <TAB> sha256 <TAB> text_url
entries=$(awk '
	function unq(s) { sub(/^[^"]*"/, "", s); sub(/"[[:space:]]*(#.*)?$/, "", s); return s }
	/^[[:space:]]*#/ { next }
	/^[[:space:]]*\[\[body\]\][[:space:]]*$/ {
		if (id != "") print id "\t" tier "\t" dir "\t" sha "\t" url
		id=""; tier=""; dir=""; sha=""; url=""; next
	}
	/^[[:space:]]*feed_id[[:space:]]*=/  { id  = unq($0); next }
	/^[[:space:]]*dir[[:space:]]*=/      { dir = unq($0); next }
	/^[[:space:]]*sha256[[:space:]]*=/   { sha = unq($0); next }
	/^[[:space:]]*text_url[[:space:]]*=/ { url = unq($0); next }
	/^[[:space:]]*tier[[:space:]]*=/     { t=$0; sub(/^[^=]*=[[:space:]]*/, "", t); sub(/[[:space:]]*(#.*)?$/, "", t); tier=t; next }
	END { if (id != "") print id "\t" tier "\t" dir "\t" sha "\t" url }
' "$manifest")

[ -n "$entries" ] || {
	echo "FATAL: $manifest pins no licence bodies" >&2
	exit 1
}

rc=0
pinned_ok=0
unpinned=0
failed=0

printf '%s\n' "manifest : $manifest"
printf '%s\n' ""

# Read from a FILE, not a pipe: in a pipeline the loop body runs in a subshell
# on most POSIX shells and the counters below would be discarded, which would
# turn a failed acquisition into a zero exit status. In a licence tool that is
# not a cosmetic bug.
entryfile="${TMPDIR:-/tmp}/anvil-license-entries.$$"
printf '%s\n' "$entries" >"$entryfile"
while IFS='	' read -r feed tier dir sha url; do
	[ -n "$feed" ] || continue
	if [ -n "$wanted" ]; then
		case " $wanted " in
		*" $feed "*) ;;
		*) continue ;;
		esac
	fi

	dest_dir="$here/tier$tier/$dir"
	dest="$dest_dir/LICENSE.full.txt"

	if [ "$verify_only" -eq 1 ] || [ -f "$dest" ]; then
		if [ ! -f "$dest" ]; then
			printf '%-20s MISSING   %s\n' "$feed" "$dest"
			printf '%-20s           fetch it: drop --verify-only\n' ""
			failed=$((failed + 1))
			rc=1
			continue
		fi
	else
		mkdir -p "$dest_dir"
		tmp="$dest.partial.$$"
		if ! fetch "$url" "$tmp"; then
			rm -f "$tmp"
			printf '%-20s FETCH FAILED  %s\n' "$feed" "$url"
			failed=$((failed + 1))
			rc=1
			continue
		fi
		mv "$tmp" "$dest"
	fi

	actual=$(sha256_of "$dest")

	if [ -z "$sha" ]; then
		printf '%-20s UNPINNED  %s\n' "$feed" "$dest"
		printf '%-20s           from %s\n' "" "$url"
		printf '%-20s           sha256 = "%s"\n' "" "$actual"
		printf '%-20s           READ THIS FILE, then record that digest in LICENSE-MANIFEST.toml.\n' ""
		unpinned=$((unpinned + 1))
		rc=1
	elif [ "$actual" != "$sha" ]; then
		printf '%-20s MISMATCH  %s\n' "$feed" "$dest"
		printf '%-20s           pinned  %s\n' "" "$sha"
		printf '%-20s           actual  %s\n' "" "$actual"
		printf '%-20s           Supply-chain or upstream-terms change. NOT retried. Investigate.\n' ""
		rm -f "$dest"
		failed=$((failed + 1))
		rc=1
	else
		printf '%-20s verified  %s\n' "$feed" "$dest"
		pinned_ok=$((pinned_ok + 1))
	fi
done <"$entryfile"
rm -f "$entryfile"

printf '%s\n' ""
printf '%s\n' "verified: $pinned_ok   unpinned: $unpinned   failed: $failed"
if [ "$rc" -ne 0 ]; then
	printf '%s\n' "The licence gate refuses every feed that is not 'verified' above. That is the design."
fi
exit "$rc"
