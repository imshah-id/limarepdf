#!/usr/bin/env bash
# Compares this tree's limarepdf-cli with an earlier build over every PDF in tests/data (the
# committed ones, and the render corpus and dss/ samples when fetched), to see what a change does
# to real files (docs/developer/testing.md). Builds this tree's CLI (ci-test profile, two jobs),
# then for each file runs `verify` with both and diffs the outputs, counts the exit codes of the
# signed files, and runs `info` with both, comparing the notes on stderr and timing each pass.
# PDFs given after the base CLI (crafted attack files, say) are run through both too, in full.
#
# Usage, from anywhere: bash crates/limarepdf-core/tools/compare-cli.sh BASE-CLI [PDF...]
# For BASE-CLI, build the CLI before the change (`cargo build --profile ci-test -p
# limarepdf-cli`) and copy target/ci-test/limarepdf-cli elsewhere. The outputs and summary.txt
# go to target/tmp/compare-cli (COMPARE_CLI_OUT), emptied first.
set -uo pipefail
base=$(realpath "${1:?usage: compare-cli.sh BASE-CLI [PDF...]}")
shift
extra=()
for f in "$@"; do extra+=("$(realpath "$f")"); done
cd "$(dirname "$0")/../../.."
out=${COMPARE_CLI_OUT:-target/tmp/compare-cli}
rm -rf "$out"
mkdir -p "$out"/verify-before "$out"/verify-after "$out"/info-before "$out"/info-after
cargo build -j2 --profile ci-test -p limarepdf-cli > "$out/build.log" 2>&1 || {
    tail "$out/build.log"
    exit 1
}
cp target/ci-test/limarepdf-cli "$out/cli-after"
after=$out/cli-after
find crates/limarepdf-core/tests/data -name '*.pdf' | sort > "$out/all.txt"

# Each file's output is kept under its path with `/` as `_`.
verify() { # cli outdir
    while IFS= read -r f; do
        o="$2/$(echo "$f" | tr / _).txt"
        timeout 60 "$1" verify "$f" < /dev/null > "$o" 2>&1
        echo "exit $?" >> "$o"
    done < "$out/all.txt"
}
verify "$base" "$out/verify-before"
verify "$after" "$out/verify-after"
# The signed files: those whose output before names a signature.
grep -l -E ': [0-9]+ digital signatures?$' "$out"/verify-before/*.txt |
    while IFS= read -r p; do basename "$p"; done > "$out/signed.txt"
diff -r "$out/verify-before" "$out/verify-after" > "$out/verify-diff.txt"

info() { # cli outdir: prints the seconds taken
    local t0
    t0=$(date +%s.%N)
    while IFS= read -r f; do
        o="$2/$(echo "$f" | tr / _).txt"
        timeout 60 "$1" info "$f" < /dev/null 2>&1 > /dev/null | grep -v '^\s*$' > "$o"
    done < "$out/all.txt"
    awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }'
}
# Twice each, alternating, so the file cache is warm for both.
tb1=$(info "$base" "$out/info-before")
ta1=$(info "$after" "$out/info-after")
tb2=$(info "$base" "$out/info-before")
ta2=$(info "$after" "$out/info-after")
diff -r "$out/info-before" "$out/info-after" > "$out/info-diff.txt"

{
    echo "$(wc -l < "$out/all.txt") PDFs in tests/data; before: $base"
    echo "verify: files whose output names a signature (before): $(wc -l < "$out/signed.txt")"
    echo "verify: diff before after: $(wc -l < "$out/verify-diff.txt") lines"
    echo "verify: exit codes after, signed files:"
    while IFS= read -r o; do tail -1 "$out/verify-after/$o"; done < "$out/signed.txt" | sort | uniq -c
    echo "info: seconds, before: $tb1 $tb2, after: $ta1 $ta2"
    echo "info: notes before: $(cat "$out"/info-before/* | grep -c '^note'), after: $(cat "$out"/info-after/* | grep -c '^note')"
    echo "info: diff before after: $(wc -l < "$out/info-diff.txt") lines"
    cat "$out/verify-diff.txt" "$out/info-diff.txt"
    for f in "${extra[@]}"; do
        for cli in "$base" "$after"; do
            echo "== $f with $([ "$cli" = "$base" ] && echo before || echo after)"
            timeout 60 "$cli" verify "$f" < /dev/null 2>&1
            echo "verify exit $?"
            timeout 60 "$cli" info "$f" < /dev/null 2>&1 > /dev/null
            echo "info exit $?"
        done
    done
} > "$out/summary.txt"
cat "$out/summary.txt"
