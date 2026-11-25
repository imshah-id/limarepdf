#!/usr/bin/env bash
# Makes LimarePDF-<version>-<x86_64|aarch64>.AppImage from a Linux release archive: one file holding
# the desktop app and the command-line tool (packaging/linux/AppRun says which starts).
#
#   packaging/linux/make-appimage.sh <limarepdf-<version>-linux-<x86_64|arm64>.tar.gz> <output folder>
#
# Run on Linux, on a computer of the archive's architecture: appimagetool runs there. It downloads
# AppImage's static runtime, which needs no libfuse2, and appimagetool, each a set version checked
# by its SHA-256 below; releasing.md says when to move them. The programs load glibc and the
# desktop's libraries (D-Bus, EGL, Wayland, X11, xkbcommon) from the system, as the deb and rpm do:
# none is bundled, so the AppImage needs the glibc they need.
set -euo pipefail

archive=$1
out=$2
here=$(cd "$(dirname "$0")" && pwd)
name=$(basename "$archive" .tar.gz)
version=${name#limarepdf-}
version=${version%-linux-*}
case $name in
    *-linux-x86_64) arch=x86_64 ;;
    *-linux-arm64) arch=aarch64 ;;
    *) echo "Not a Linux release archive: $archive" >&2; exit 1 ;;
esac

# AppImage/type2-runtime's release 20251108 and appimagetool 1.9.1.
runtime_url=https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-$arch
tool_url=https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-$arch.AppImage
case $arch in
    x86_64)
        runtime_sha=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
        tool_sha=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
        ;;
    aarch64)
        runtime_sha=00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444
        tool_sha=f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158
        ;;
esac

work=$(mktemp -d)
# The work folder goes however the script ends, a failed step included.
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 3 -o "$work/runtime" "$runtime_url"
curl -fsSL --retry 3 -o "$work/appimagetool" "$tool_url"
printf '%s  %s\n' "$runtime_sha" "$work/runtime" "$tool_sha" "$work/appimagetool" | sha256sum --check --strict
# Unpacked here and run from here, as FUSE may be missing (a container); --appimage-extract-and-run
# would leave a copy in /tmp.
chmod +x "$work/appimagetool"
(cd "$work" && ./appimagetool --appimage-extract > /dev/null && mv squashfs-root appimagetool.AppDir)

# The AppDir: the programs in usr/bin, the desktop entry and icon where desktops look for them and,
# as an AppImage has them, at the top; the rest of the archive (README, docs, licences) in
# usr/share/doc/limarepdf, the README's links to the guide working there as in the archive.
tar -xzf "$archive" -C "$work"
from="$work/$name"
app="$work/LimarePDF.AppDir"
id=io.github.smaug42.limarepdf
mkdir -p "$app/usr/bin" "$app/usr/share/applications" "$app/usr/share/icons/hicolor/256x256/apps" \
    "$app/usr/share/doc"
mv "$from/limarepdf" "$from/limarepdf-cli" "$app/usr/bin/"
mv "$from/$id.desktop" "$app/usr/share/applications/"
mv "$from/$id.png" "$app/usr/share/icons/hicolor/256x256/apps/"
mv "$from" "$app/usr/share/doc/limarepdf"
ln -s "usr/share/applications/$id.desktop" "$app/$id.desktop"
ln -s "usr/share/icons/hicolor/256x256/apps/$id.png" "$app/$id.png"
ln -s "$id.png" "$app/.DirIcon"
cp "$here/AppRun" "$app/AppRun"
chmod 755 "$app/AppRun"

# No AppStream metadata (-n) and no update information: new versions are on the release page.
mkdir -p "$out"
ARCH=$arch "$work/appimagetool.AppDir/AppRun" -n --runtime-file "$work/runtime" \
    "$app" "$out/LimarePDF-$version-$arch.AppImage"
