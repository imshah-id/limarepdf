#!/usr/bin/env bash
# Writes the winget and Scoop manifests for a release from the templates beside this script (winget/ and scoop/),
# with the version, the release files' checksums, and the MSIs' product codes, upgrade code, publisher and name
# filled in: winget's in <out>/winget-pkgs/manifests/c/ClaytonCornell/LimarePDF/<version> (a clone of the
# maintainer's fork of microsoft/winget-pkgs, say), Scoop's in <out>/scoop-limarepdf/bucket/limarepdf.json (the
# bucket's clone). The templates are left as they are.
#
#   packaging/windows/update.sh <version> <out> [<dist>]
#
# The checksums come from the release's SHA256SUMS, once its signature checks against docs/limarepdf-signing-
# key.asc, and the MSIs, downloaded to be read, must match it; given <dist>, they come from the files there (CI,
# before a release). Each MSI must be for this version, and both must have the same upgrade code, publisher and
# name. Needs msitools (msiinfo), and for a release curl, gpg and gpgv. docs/developer/releasing.md has the steps.
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "usage: update.sh <version> <out> [<dist>]" >&2
    exit 2
fi
version=$1 out=$2 dist=${3:-}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "update.sh: not a version: $version" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
fail() {
    echo "update.sh: $*" >&2
    exit 1
}

x64_msi=limarepdf-$version-x86_64.msi
arm64_msi=limarepdf-$version-arm64.msi
x64_zip=limarepdf-$version-windows-x86_64.zip
arm64_zip=limarepdf-$version-windows-arm64.zip
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if [ -n "$dist" ]; then
    (cd "$dist" && sha256sum "$x64_msi" "$arm64_msi" "$x64_zip" "$arm64_zip") > "$tmp/SHA256SUMS"
    msis=$dist
else
    release="https://github.com/smaug42/limarepdf/releases/download/v$version"
    curl -fsSL -o "$tmp/SHA256SUMS" "$release/SHA256SUMS"
    curl -fsSL -o "$tmp/SHA256SUMS.asc" "$release/SHA256SUMS.asc"
    gpg --dearmor < "$repo/docs/limarepdf-signing-key.asc" > "$tmp/key.gpg"
    gpgv --keyring "$tmp/key.gpg" "$tmp/SHA256SUMS.asc" "$tmp/SHA256SUMS"
    curl -fsSL -o "$tmp/$x64_msi" "$release/$x64_msi"
    curl -fsSL -o "$tmp/$arm64_msi" "$release/$arm64_msi"
    msis=$tmp
fi

# A release file's checksum from SHA256SUMS.
sum() {
    local s
    s=$(awk -v f="$1" '$2 == f || $2 == "*" f {print $1}' "$tmp/SHA256SUMS")
    [[ $s =~ ^[0-9a-f]{64}$ ]] || fail "no checksum for $1"
    echo "$s"
}
# A property of an MSI, from its Property table.
property() {
    msiinfo export "$msis/$1" Property | tr -d '\r' | awk -F '\t' -v p="$2" '$1 == p {print $2}'
}
x64_msi_sum=$(sum "$x64_msi")
arm64_msi_sum=$(sum "$arm64_msi")
x64_zip_sum=$(sum "$x64_zip")
arm64_zip_sum=$(sum "$arm64_zip")
[ "$(sha256sum "$msis/$x64_msi" | cut -d ' ' -f 1)" = "$x64_msi_sum" ] || fail "$x64_msi doesn't match SHA256SUMS"
[ "$(sha256sum "$msis/$arm64_msi" | cut -d ' ' -f 1)" = "$arm64_msi_sum" ] || fail "$arm64_msi doesn't match SHA256SUMS"
guid='^\{[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}\}$'
for msi in "$x64_msi" "$arm64_msi"; do
    [ "$(property "$msi" ProductVersion)" = "$version" ] || fail "$msi isn't version $version"
    [[ $(property "$msi" ProductCode) =~ $guid ]] || fail "$msi has no product code"
done
for p in UpgradeCode Manufacturer ProductName; do
    [ "$(property "$x64_msi" $p)" = "$(property "$arm64_msi" $p)" ] || fail "the MSIs' $p differs"
done
x64_product=$(property "$x64_msi" ProductCode)
arm64_product=$(property "$arm64_msi" ProductCode)
upgrade=$(property "$x64_msi" UpgradeCode)
publisher=$(property "$x64_msi" Manufacturer)
name=$(property "$x64_msi" ProductName)
[[ $upgrade =~ $guid ]] || fail "$x64_msi has no upgrade code"
[ -n "$publisher" ] && [ -n "$name" ] || fail "$x64_msi has no publisher or name"

# A template with every @NAME@ filled in. winget's checksums are written in capitals, as its tools write them.
fill() {
    local text
    text=$(< "$1")
    text=${text//@VERSION@/"$version"}
    text=${text//@PUBLISHER@/"$publisher"}
    text=${text//@NAME@/"$name"}
    text=${text//@UPGRADE_CODE@/"$upgrade"}
    text=${text//@X64_PRODUCT_CODE@/"$x64_product"}
    text=${text//@ARM64_PRODUCT_CODE@/"$arm64_product"}
    text=${text//@X64_MSI_SHA256@/"${x64_msi_sum^^}"}
    text=${text//@ARM64_MSI_SHA256@/"${arm64_msi_sum^^}"}
    text=${text//@X64_ZIP_SHA256@/"$x64_zip_sum"}
    text=${text//@ARM64_ZIP_SHA256@/"$arm64_zip_sum"}
    [[ ! $text =~ @[A-Z0-9_]+@ ]] || fail "$1: ${BASH_REMATCH[0]} isn't filled in"
    printf '%s\n' "$text" > "$2"
}
winget=$out/winget-pkgs/manifests/c/ClaytonCornell/LimarePDF/$version
scoop=$out/scoop-limarepdf/bucket
mkdir -p "$winget" "$scoop"
for f in "$here"/winget/*.yaml; do
    fill "$f" "$winget/${f##*/}"
done
fill "$here/scoop/limarepdf.json" "$scoop/limarepdf.json"
echo "$winget: ClaytonCornell.LimarePDF $version"
echo "$scoop/limarepdf.json: limarepdf $version"
