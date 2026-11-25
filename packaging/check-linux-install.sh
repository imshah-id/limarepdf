#!/usr/bin/env bash
# Installs the .deb or .rpm in FOLDER as a user's package manager installs a downloaded one, the
# libraries it depends on coming from the system's own repositories (recommended ones left out),
# checks that both programs load on this system's glibc and libraries, from the package and from
# the AppImage in FOLDER, and removes the package again. Run as root in a clean container of the
# system to try, on a computer of the package's architecture; ci.yml's linux-install job runs it on
# the oldest systems docs/install.md names and a current Fedora, for x86_64 and Arm64:
#
#   podman run --rm -v "$PWD:/w:ro" -w /w docker.io/library/ubuntu:24.04 bash packaging/check-linux-install.sh dist
set -euo pipefail

dir=$1
# Run as $(one …): the error goes to stderr, or the command substitution would swallow it.
one() {
    if [ $# != 1 ] || [ ! -f "$1" ]; then
        echo "::error::Expected one package in $dir, found: $*" >&2
        exit 1
    fi
    realpath "$1"
}

# shellcheck source=/dev/null
. /etc/os-release
echo "$PRETTY_NAME ($(uname -m)), $(ldd --version | head -1)"
if command -v apt-get > /dev/null; then
    package=$(one "$dir"/limarepdf_*.deb)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -q --no-install-recommends "$package"
    dpkg-query -W -f='Installed ${Version}; depends on ${Depends}\n' limarepdf
    remove=(apt-get remove -y -qq limarepdf)
elif command -v dnf > /dev/null; then
    package=$(one "$dir"/limarepdf-*.rpm)
    dnf install -y -q --setopt=install_weak_deps=False "$package"
    rpm -q --requires limarepdf | grep GLIBC
    remove=(dnf remove -y -q limarepdf)
elif command -v zypper > /dev/null; then
    package=$(one "$dir"/limarepdf-*.rpm)
    zypper --non-interactive --quiet install --no-recommends --allow-unsigned-rpm "$package"
    rpm -q --requires limarepdf | grep GLIBC
    remove=(zypper --non-interactive --quiet remove limarepdf)
else
    echo "::error::No apt-get, dnf or zypper on $PRETTY_NAME"
    exit 1
fi

# A glibc too old for the binaries, or a library missing, shows here as "not found".
loads() {
    local bin libraries
    for bin in "$@"; do
        libraries=$(ldd "$bin" 2>&1) || true
        if grep 'not found' <<< "$libraries"; then
            echo "::error::$bin can't load on $PRETTY_NAME"
            exit 1
        fi
    done
}
loads /usr/bin/limarepdf /usr/bin/limarepdf-cli
limarepdf-cli --version

# The AppImage in FOLDER too, as a user runs a downloaded one, on the libraries a desktop has (here
# those the package brought): both programs load from it unpacked, and the command-line tool runs
# through it without FUSE, which containers don't have.
appimage=$(one "$dir"/LimarePDF-*.AppImage)
work=$(mktemp -d)
cp "$appimage" "$work/LimarePDF.AppImage"
chmod +x "$work/LimarePDF.AppImage"
(cd "$work" && ./LimarePDF.AppImage --appimage-extract > /dev/null)
loads "$work/squashfs-root/usr/bin/limarepdf" "$work/squashfs-root/usr/bin/limarepdf-cli"
APPIMAGE_EXTRACT_AND_RUN=1 "$work/LimarePDF.AppImage" limarepdf-cli --version
rm -r "$work"

"${remove[@]}"
for bin in /usr/bin/limarepdf /usr/bin/limarepdf-cli; do
    if [ -e "$bin" ]; then
        echo "::error::$bin is still there after removing the package"
        exit 1
    fi
done
echo "Installed, loaded and removed on $PRETTY_NAME"
