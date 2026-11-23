#!/usr/bin/env bash
# Compares this tree's limarepdf-cli with an earlier build over every PDF in tests/data (the
# committed ones, and the render corpus and dss/ samples when fetched), plus any extra PDFs.
# See docs/developer/testing.md.
#
# Usage: bash crates/limarepdf-core/tools/compare-cli.sh BASE-CLI [PDF...]
# Build BASE-CLI before the change (cargo build --profile ci-test -p limarepdf-cli) and copy it
# out of target. Reports go to a new directory under target/tmp, or to COMPARE_CLI_OUT if set.
set -euo pipefail
base=$(realpath "${1:?usage: compare-cli.sh BASE-CLI [PDF...]}")
shift
extra=()
for f in "$@"; do extra+=("$(realpath "$f")"); done
cd "$(dirname "$0")/../../.."
if [ -n "${COMPARE_CLI_OUT:-}" ]; then
    out=$COMPARE_CLI_OUT
    mkdir -p "$(dirname "$out")"
    mkdir "$out" || { echo "compare-cli needs a new output directory: $out" >&2; exit 2; }
else
    mkdir -p target/tmp
    out=$(mktemp -d target/tmp/compare-cli.XXXXXX)
fi
mkdir "$out"/verify-before "$out"/verify-after "$out"/info-before "$out"/info-after

cargo build -j2 --profile ci-test -p limarepdf-cli --message-format=json-render-diagnostics \
    > "$out/build.jsonl" 2> "$out/build.log" || { tail "$out/build.log" >&2; exit 2; }
# Cargo reports the executable path even when the target directory or target triple is configured.
built=$(python3 - "$out/build.jsonl" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        artifact = json.loads(line)
        if (artifact["reason"] == "compiler-artifact"
                and artifact["target"]["name"] == "limarepdf-cli"
                and "bin" in artifact["target"]["kind"] and artifact["executable"]):
            print(artifact["executable"])
            break
    else:
        sys.exit("Cargo did not report a limarepdf-cli executable")
PY
)
cp "$built" "$out/cli-after"
after=$out/cli-after
if [ ! -x "$base" ] || [ ! -x "$after" ]; then
    echo "compare-cli needs executable before and after binaries" >&2
    exit 2
fi
{
    find crates/limarepdf-core/tests/data -name '*.pdf'
    if [ "$#" -gt 0 ]; then printf '%s\n' "${extra[@]}"; fi
} | sort -u > "$out/all.txt"
if [ ! -s "$out/all.txt" ]; then
    echo "compare-cli found no PDFs to compare" >&2
    exit 2
fi

# Each file's output is kept under its path with `/` as `_`.
verify() { # cli outdir
    local f o status
    while IFS= read -r f; do
        o="$2/$(printf '%s' "$f" | tr / _).txt"
        status=0
        timeout 60 "$1" verify "$f" < /dev/null > "$o" 2>&1 || status=$?
        echo "exit $status" >> "$o"
    done < "$out/all.txt"
}
verify "$base" "$out/verify-before"
verify "$after" "$out/verify-after"
# grep returns 1 if none of the files named a signature.
grep -l -E ': [0-9]+ digital signatures?$' "$out"/verify-before/*.txt > "$out/signed-paths.txt" ||
    [ "$?" -eq 1 ]
while IFS= read -r p; do basename "$p"; done < "$out/signed-paths.txt" > "$out/signed.txt"

info() { # cli outdir pass
    local f o status t0
    t0=$(date +%s.%N)
    while IFS= read -r f; do
        o="$2/$(printf '%s' "$f" | tr / _).txt"
        status=0
        timeout 60 "$1" info "$f" < /dev/null > /dev/null 2> "$out/info-stderr.txt" || status=$?
        grep -v '^[[:space:]]*$' "$out/info-stderr.txt" >> "$o" || [ "$?" -eq 1 ]
        echo "pass $3: exit $status" >> "$o"
    done < "$out/all.txt"
    info_seconds=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN { printf "%.1f", b - a }')
}
# Twice each, alternating, so the file cache is warm for both.
info "$base" "$out/info-before" 1
tb1=$info_seconds
info "$after" "$out/info-after" 1
ta1=$info_seconds
info "$base" "$out/info-before" 2
tb2=$info_seconds
info "$after" "$out/info-after" 2
ta2=$info_seconds

changed=0
for command in verify info; do
    if diff -r "$out/$command-before" "$out/$command-after" > "$out/$command-diff.txt"; then
        continue
    else
        status=$?
    fi
    if [ "$status" -ne 1 ]; then
        echo "Could not compare $command logs in $out" >&2
        exit 2
    fi
    changed=1
done

{
    echo "$(wc -l < "$out/all.txt") PDFs compared; before: $base"
    echo "verify: files whose output names a signature (before): $(wc -l < "$out/signed.txt")"
    echo "verify: diff before after: $(wc -l < "$out/verify-diff.txt") lines"
    echo "verify: exit codes after, signed files:"
    while IFS= read -r o; do tail -1 "$out/verify-after/$o"; done < "$out/signed.txt" | sort | uniq -c
    echo "info: seconds, before: $tb1 $tb2, after: $ta1 $ta2"
    note_count() { awk '/^note/ { n++ } END { print n+0 }' "$1"/*.txt; }
    echo "info: notes before: $(note_count "$out/info-before"), after: $(note_count "$out/info-after")"
    echo "info: diff before after: $(wc -l < "$out/info-diff.txt") lines"
    cat "$out/verify-diff.txt" "$out/info-diff.txt"
} > "$out/summary.txt"
cat "$out/summary.txt"
echo "Reports: $out"
exit "$changed"
