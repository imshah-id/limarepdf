#!/usr/bin/env bash
# Writes the AUR's copies of the Arch packages for a release: packaging/arch/limarepdf and limarepdf-bin with
# the version and the release files' checksums filled in, each with its .SRCINFO, in <out>/limarepdf and
# <out>/limarepdf-bin (the AUR's git clones, say). The PKGBUILDs here are left as they are.
#
#   packaging/arch/update.sh [--pkgrel N] <version> <out> [<dist>]
#
# The checksums come from the release's SHA256SUMS, once its signature checks against docs/limarepdf-signing-
# key.asc, or, given <dist>, from the files there (check-arch.sh, before a release), leaving out a package
# whose files aren't (limarepdf-bin while only the source archive is made). pkgrel is 1 unless
# given: a new PKGBUILD for a version already on the AUR takes the next one. Needs makepkg (on Arch), and for
# a release curl, gpg and gpgv. docs/developer/releasing.md has the steps.
set -euo pipefail

pkgrel=1
if [ "${1:-}" = --pkgrel ]; then
    pkgrel=$2
    shift 2
fi
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "usage: update.sh [--pkgrel N] <version> <out> [<dist>]" >&2
    exit 2
fi
version=$1 out=$2 dist=${3:-}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "update.sh: not a version: $version" >&2; exit 2; }
[[ $pkgrel =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "update.sh: not a pkgrel: $pkgrel" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if [ -n "$dist" ]; then
    (cd "$dist" && sha256sum limarepdf-"$version"-*.tar.gz) > "$tmp/SHA256SUMS"
else
    release="https://github.com/smaug42/limarepdf/releases/download/v$version"
    curl -fsSL -o "$tmp/SHA256SUMS" "$release/SHA256SUMS"
    curl -fsSL -o "$tmp/SHA256SUMS.asc" "$release/SHA256SUMS.asc"
    gpg --dearmor < "$repo/docs/limarepdf-signing-key.asc" > "$tmp/key.gpg"
    gpgv --keyring "$tmp/key.gpg" "$tmp/SHA256SUMS.asc" "$tmp/SHA256SUMS"
fi

# The package's PKGBUILD with this version, pkgrel and, for each array and file given, the file's checksum
# in place of the array's first SKIP.
fill() {
    local pkg=$1 sum
    shift
    sed -e "s/^pkgver=.*/pkgver=$version/" -e "s/^pkgrel=.*/pkgrel=$pkgrel/" "$here/$pkg/PKGBUILD" > "$tmp/PKGBUILD"
    while [ $# -gt 0 ]; do
        sum=$(awk -v f="$2" '$2 == f || $2 == "*" f {print $1}' "$tmp/SHA256SUMS")
        if [ -z "$sum" ] && [ -n "$dist" ]; then
            echo "$pkg left out: $2 isn't in $dist"
            return
        fi
        [[ $sum =~ ^[0-9a-f]{64}$ ]] || { echo "update.sh: no checksum for $2" >&2; exit 1; }
        sed -i "s/^$1=('SKIP'/$1=('$sum'/" "$tmp/PKGBUILD"
        grep -q "^$1=('$sum'" "$tmp/PKGBUILD" || { echo "update.sh: $pkg's $1 doesn't start with 'SKIP'" >&2; exit 1; }
        shift 2
    done
    mkdir -p "$out/$pkg"
    cp "$tmp/PKGBUILD" "$out/$pkg/PKGBUILD"
    (cd "$out/$pkg" && makepkg --printsrcinfo > .SRCINFO)
    echo "$out/$pkg: $pkg $version-$pkgrel"
}
fill limarepdf sha256sums "limarepdf-$version-source.tar.gz"
fill limarepdf-bin sha256sums_x86_64 "limarepdf-$version-linux-x86_64.tar.gz" \
    sha256sums_aarch64 "limarepdf-$version-linux-arm64.tar.gz"
