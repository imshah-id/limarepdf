#!/usr/bin/env bash
# Checks an AppImage make-appimage.sh made, on a computer of its architecture with FUSE (Ubuntu's
# fuse3), as ci.yml's build job does:
#
#   packaging/linux/check-appimage.sh <LimarePDF-<version>-<arch>.AppImage> <target triple>
#
# Its runtime needs no library (libfuse2 included) and is built for the target's architecture;
# check-package.py checks the files inside, unpacked; AppRun, run with stand-ins for the programs,
# starts the one asked for with the arguments as given; and the command-line tool runs through the
# AppImage both ways AppRun offers.
set -euo pipefail

appimage=$(realpath "$1")
target=$2
here=$(cd "$(dirname "$0")" && pwd)
id=io.github.smaug42.limarepdf
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail() {
    echo "::error::$*"
    exit 1
}

# The runtime: static, so it starts on a system without libfuse2, or any library.
headers=$(readelf -hlWd "$appimage")
if grep -E 'INTERP|NEEDED' <<< "$headers"; then
    fail "$appimage's runtime needs a library"
fi
machine=$(sed -n 's/^ *Machine: *//p' <<< "$headers")
case $target in
    x86_64-*) want=X86-64 ;;
    aarch64-*) want=AArch64 ;;
    *) fail "No AppImage is made for $target" ;;
esac
if [[ $machine != *"$want" ]]; then
    fail "$appimage's runtime is for $machine, not $target"
fi
echo "Runtime: static, for $machine"

# The files inside, as installed: every one listed, then the programs, docs and licences checked.
(cd "$work" && "$appimage" --appimage-extract > /dev/null)
root="$work/squashfs-root"
(cd "$root" && find . | sort)
for f in AppRun usr/bin/limarepdf usr/bin/limarepdf-cli "usr/share/applications/$id.desktop" \
    "usr/share/icons/hicolor/256x256/apps/$id.png" "$id.desktop" "$id.png" .DirIcon; do
    if [ ! -e "$root/$f" ]; then
        fail "$f is missing from $appimage"
    fi
done
python3 "$here/../check-package.py" --target "$target" "$root"

# AppRun with stand-ins printing their name and arguments, one a line: run as the AppImage's
# runtime runs it (ARGV0 the name the AppImage was started by), and unpacked, by a link.
fake="$work/fake"
mkdir -p "$fake/usr/bin" "$work/links"
cp "$root/AppRun" "$fake/"
for bin in limarepdf limarepdf-cli; do
    printf '#!/bin/sh\nprintf "%%s\\n" %s "$@"\n' "$bin" > "$fake/usr/bin/$bin"
    chmod +x "$fake/usr/bin/$bin"
done
ln -s "$fake/AppRun" "$work/links/limarepdf-cli"
ln -s "$fake/AppRun" "$work/links/LimarePDF"
# starts <ARGV0, or - for none> <the program, then each argument, | between> <AppRun> [arguments]
starts() {
    local argv0=$1 want=$2 apprun=$3 got
    shift 3
    if [ "$argv0" = - ]; then
        got=$(env -u ARGV0 "$apprun" "$@" | paste -sd '|')
    else
        got=$(ARGV0=$argv0 "$apprun" "$@" | paste -sd '|')
    fi
    if [ "$got" != "$want" ]; then
        fail "AppRun as $argv0 ($apprun) with $*: started $got, not $want"
    fi
}
starts /home/u/LimarePDF-1-x86_64.AppImage 'limarepdf|a b.pdf|--page|3' "$fake/AppRun" 'a b.pdf' --page 3
starts LimarePDF.AppImage limarepdf "$fake/AppRun"
starts LimarePDF.AppImage 'limarepdf-cli|info|a b.pdf' "$fake/AppRun" limarepdf-cli info 'a b.pdf'
starts LimarePDF.AppImage limarepdf-cli "$fake/AppRun" limarepdf-cli
starts LimarePDF.AppImage 'limarepdf|limarepdf-cli.pdf' "$fake/AppRun" limarepdf-cli.pdf
starts LimarePDF.AppImage 'limarepdf|x.pdf|limarepdf-cli' "$fake/AppRun" x.pdf limarepdf-cli
starts /home/u/bin/limarepdf-cli 'limarepdf-cli|info|a b.pdf' "$fake/AppRun" info 'a b.pdf'
starts limarepdf-cli 'limarepdf-cli|--version' "$fake/AppRun" --version
starts /home/u/bin/limarepdf-cli2 'limarepdf|x.pdf' "$fake/AppRun" x.pdf
starts - 'limarepdf-cli|info' "$work/links/limarepdf-cli" info
starts - 'limarepdf|x.pdf' "$work/links/LimarePDF" x.pdf
starts - 'limarepdf|x.pdf' "$fake/AppRun" x.pdf
echo "AppRun starts the program asked for, with its arguments"

# The command-line tool through the AppImage (FUSE), by its first argument and by a link's name.
direct=$("$root/usr/bin/limarepdf-cli" --version)
prints_version() {
    local got
    got=$("$@") || fail "$* failed"
    if [ "$got" != "$direct" ]; then
        fail "$* printed $got, not $direct"
    fi
}
ln -s "$appimage" "$work/limarepdf-cli"
prints_version "$appimage" limarepdf-cli --version
prints_version "$work/limarepdf-cli" --version
echo "Through the AppImage, both ways: $direct"
