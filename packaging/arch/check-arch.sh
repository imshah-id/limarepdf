#!/usr/bin/env bash
# The Arch Linux packages (packaging/arch) built from a release's files before it is made, checked, installed,
# upgraded and removed. Two runs, each as root in a clean archlinux:base-devel, from the repository root:
#
#   bash packaging/arch/check-arch.sh source <dist>
#   bash packaging/arch/check-arch.sh <dist>
#
# The first builds limarepdf from <dist>'s limarepdf-<version>-source.tar.gz into <dist> (ci.yml's arch-source
# job, while the other platforms build); the second, given that package, the source archive and the linux-x86_64
# and linux-arm64 archives, does the rest (the arch job). Each signs the files with a key made for the run, which
# the AUR's copies of the PKGBUILDs (update.sh) then ask for in place of the release key, and builds as makepkg
# builds for a user: limarepdf from source (it fetches the crates), then limarepdf-bin for both architectures.
# Each package is checked: namcap's errors (its warnings are listed: the libraries limarepdf loads at run time
# look unneeded to it, and it would have $CARCH for the x86_64 in an archive's name, arm64 for aarch64),
# packaging/check-package.py, no test seam, and every file of the release archive it was made from in its place
# (limarepdf's programs are its own build). Then, on x86_64: an earlier limarepdf-bin installed, upgraded,
# replaced by limarepdf and removed, the programs at work after each step (the command line, and the app's
# window under X11 and Wayland), nothing left behind and the user's files as they were.
# The Arm64 package is built and checked but not installed: there's no Arch Linux ARM to install it on here
# (docs/developer/testing.md).
set -euo pipefail

repo=$PWD
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
work=/home/builder/check
home=/home/builder
sample=$repo/crates/limarepdf-core/tests/data/paragraphs/madeup/ch01_ragged_sans11.pdf
built=limarepdf-$version-1-x86_64.pkg.tar.zst

fail() {
    echo "check-arch.sh: $*" >&2
    exit 1
}
user() { sudo -u builder -H "$@"; }

# As the builder: the files signed, the AUR's copies written asking for the run's key, and limarepdf built
# (source), or limarepdf-bin for both architectures and an earlier build of it to upgrade from.
build() {
    cd "$work"
    gpg --batch --passphrase '' --quick-gen-key 'LimarePDF check <check@invalid>' ed25519 sign 1d 2> /dev/null
    local key f
    key=$(gpg --with-colons --list-keys check@invalid | awk -F: '$1 == "fpr" {print $10; exit}')
    for f in dist/*.tar.gz; do
        gpg --batch --armor --detach-sign -o "$f.asc" "$f"
    done
    bash "$repo/packaging/arch/update.sh" "$version" new dist
    [ "$1" = source ] || bash "$repo/packaging/arch/update.sh" --pkgrel 0.1 "$version" old dist
    for f in */*/PKGBUILD; do
        sed -i "s/^validpgpkeys=.*/validpgpkeys=('$key')/" "$f"
    done
    export SRCDEST=$work/dist PKGDEST=$work/out
    if [ "$1" = source ]; then
        (cd new/limarepdf && makepkg --syncdeps --noconfirm)
    else
        (cd new/limarepdf-bin && makepkg --syncdeps --noconfirm && CARCH=aarch64 makepkg --nodeps --cleanbuild --noconfirm)
        (cd old/limarepdf-bin && makepkg --noconfirm)
    fi
}
if [ "${1:-}" = --build ]; then
    build "$2"
    exit
fi

[ "$(id -u)" = 0 ] || fail "run it as root, in a container"
run=check
if [ "${1:-}" = source ]; then
    run=source
    shift
fi
dist=$(realpath "$1")
# The image leaves the docs out of what pacman installs; a user's system has them.
sed -i '/^NoExtract/d' /etc/pacman.conf
useradd -m builder
echo 'builder ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/builder
mkdir -p "$work/dist" "$work/out"
if [ $run = source ]; then
    pacman -Syu --noconfirm > /dev/null
    cp "$dist/limarepdf-$version-source.tar.gz" "$work/dist/"
    chown -R builder: "$work"
    user bash "$0" --build source
    cp "$work/out/$built" "$dist/"
    echo "$dist/$built: built from the source archive"
    exit
fi
pacman -Syu --noconfirm --needed namcap python rust xorg-server-xvfb xdotool weston mesa > /dev/null
cp "$dist"/limarepdf-"$version"-{source,linux-x86_64,linux-arm64}.tar.gz "$work/dist/"
cp "$dist/$built" "$work/out/"
chown -R builder: "$work"
user bash "$0" --build bin

# What a package holds against the release archive it was made from: every file in its place and nothing else,
# with the modes pacman gives a user's files. <pkgname> names its licences' folder; "built", the programs are the
# package's own build, so they are there but not compared.
holds() { # <package> <archive> <triple> <pkgname> [built]
    local f to n=0 bad dir=$work/unpacked/$4-${3%%-*}
    mkdir -p "$dir"
    bsdtar -xf "$1" -C "$dir"
    while IFS= read -r f; do
        case $f in
            limarepdf | limarepdf-cli) to=usr/bin/$f ;;
            io.github.smaug42.limarepdf.desktop) to=usr/share/applications/$f ;;
            io.github.smaug42.limarepdf.png) to=usr/share/icons/hicolor/256x256/apps/$f ;;
            LICENSE-* | *-LICENSE-*.txt | THIRD-PARTY-LICENSES.html) to=usr/share/licenses/$4/$f ;;
            *) to=usr/share/doc/limarepdf/$f ;;
        esac
        if [ "${5:-}" = built ] && [ "$to" = "usr/bin/$f" ]; then
            [ -f "$dir/$to" ] || fail "$1 has no /$to"
        elif ! cmp -s "$2/$f" "$dir/$to"; then
            fail "$1: /$to isn't the archive's $f"
        fi
        n=$((n + 1))
    done < <(cd "$2" && find . -type f -printf '%P\n')
    [ "$(find "$dir/usr" -type f | wc -l)" = "$n" ] || fail "$1 holds files its archive doesn't"
    bad=$(find "$dir/usr" \( -type d ! -perm 755 \) -o \( -type f -path "$dir/usr/bin/*" ! -perm 755 \) \
        -o \( -type f ! -path "$dir/usr/bin/*" ! -perm 644 \))
    [ -z "$bad" ] || fail "$1: wrong modes: $bad"
    if grep -q LIMAREPDF_TEST_SYNC_FAILS "$dir"/usr/bin/*; then
        fail "$1 was built with the test seam"
    fi
    user python3 "$repo/packaging/check-package.py" --target "$3" "$dir"
    echo "$1: as its archive"
}
lint() {
    local out
    out=$(namcap "$1")
    [ -z "$out" ] || echo "$out"
    if grep -q ' E: ' <<< "$out"; then
        fail "namcap: errors in $1"
    fi
}
for f in "$work"/new/*/PKGBUILD "$work"/out/*.pkg.tar.zst; do
    lint "$f"
done
mkdir -p "$work/archives"
for a in linux-x86_64 linux-arm64; do
    tar -xzf "$work/dist/limarepdf-$version-$a.tar.gz" -C "$work/archives"
done
archive=$work/archives/limarepdf-$version-linux
bin=$work/out/limarepdf-bin-$version
holds "$bin-1-x86_64.pkg.tar.zst" "$archive-x86_64" x86_64-unknown-linux-gnu limarepdf-bin
holds "$bin-1-aarch64.pkg.tar.zst" "$archive-arm64" aarch64-unknown-linux-gnu limarepdf-bin
holds "$work/out/$built" "$archive-x86_64" x86_64-unknown-linux-gnu limarepdf built

# The user's documents and settings, which installing, upgrading and removing leave as they are.
user mkdir -p "$home/Documents" "$home/.config/limarepdf"
user cp "$sample" "$home/Documents/sample.pdf"
user sh -c 'echo "made before installing" > ~/.config/limarepdf/check.txt'
mine() { (cd "$home" && find Documents .config/limarepdf -type f -exec sha256sum {} + | sort); }
pac() {
    local before
    before=$(mine)
    pacman "$@" --noconfirm > /dev/null
    [ "$(mine)" = "$before" ] || fail "pacman $* changed the user's files"
}

# The app's window, named for the document it opened, under X11 (Xvfb).
x11() {
    local xvfb app win=""
    Xvfb :99 -screen 0 1280x800x24 -nolisten tcp 2> /dev/null &
    xvfb=$!
    for _ in $(seq 50); do
        [ -S /tmp/.X11-unix/X99 ] && break
        sleep 0.1
    done
    user env DISPLAY=:99 limarepdf "$home/Documents/sample.pdf" > "$work/x11.log" 2>&1 &
    app=$!
    for _ in $(seq 60); do
        win=$(DISPLAY=:99 xdotool search --name '^sample\.pdf - LimarePDF$' 2> /dev/null | head -1) && [ -n "$win" ] && break
        sleep 0.5
    done
    sleep 2
    if [ -z "$win" ] || ! kill -0 $app 2> /dev/null; then
        cat "$work/x11.log"
        fail "$1: no window for the document under X11"
    fi
    kill $app $xvfb 2> /dev/null || true
    wait $app $xvfb || true
}
# And under Wayland (Weston, headless): the window titled, and its surface drawn.
wayland() {
    local rt=/tmp/wayland-check log=$work/wayland.log weston app surface=""
    rm -rf "$rt"
    user mkdir -m 700 "$rt"
    user env XDG_RUNTIME_DIR=$rt weston --backend=headless --socket=check --idle-time=0 > "$work/weston.log" 2>&1 &
    weston=$!
    for _ in $(seq 50); do
        [ -S "$rt/check" ] && break
        sleep 0.1
    done
    user env XDG_RUNTIME_DIR=$rt WAYLAND_DISPLAY=check WAYLAND_DEBUG=client \
        limarepdf "$home/Documents/sample.pdf" > "$log" 2>&1 &
    app=$!
    for _ in $(seq 60); do
        grep -q 'set_title("sample.pdf - LimarePDF")' "$log" && break
        sleep 0.5
    done
    sleep 2
    surface=$(grep -m1 -o 'get_xdg_surface(new id xdg_surface#[0-9]*, wl_surface#[0-9]*' "$log" | grep -o 'wl_surface#[0-9]*$') || true
    if ! grep -q 'set_title("sample.pdf - LimarePDF")' "$log" || [ -z "$surface" ] \
        || ! grep -q "$surface\.attach(wl_buffer" "$log" || ! kill -0 $app 2> /dev/null; then
        grep -v '^\[' "$log" | tail -20
        fail "$1: no window drawn for the document under Wayland"
    fi
    kill $app $weston 2> /dev/null || true
    wait $app $weston || true
}
# The installed package's files as packaged, the command line rotating a document, and the app opening it.
works() {
    pacman -Qkk "$1" > /dev/null || fail "$1: installed files differ from the package's"
    user limarepdf-cli rotate --degrees 90 -o "$home/Documents/rotated.pdf" "$home/Documents/sample.pdf" > /dev/null
    user limarepdf-cli info "$home/Documents/rotated.pdf" | grep -qx 'pages:    6' \
        || fail "$1: limarepdf-cli didn't rotate the document"
    x11 "$1"
    wayland "$1"
    echo "$1 $(pacman -Q "$1" | cut -d' ' -f2): installed and working"
}

pac -U "$bin-0.1-x86_64.pkg.tar.zst"
works limarepdf-bin
pac -U "$bin-1-x86_64.pkg.tar.zst"
[ "$(pacman -Q limarepdf-bin)" = "limarepdf-bin $version-1" ] || fail "limarepdf-bin wasn't upgraded"
works limarepdf-bin
# limarepdf in its place: pacman asks to remove limarepdf-bin, which conflicts with it, and --ask 4 says yes.
pac -U --ask 4 "$work/out/$built"
if pacman -Q limarepdf-bin > /dev/null 2>&1 || [ -e /usr/share/licenses/limarepdf-bin ]; then
    fail "limarepdf-bin is still there after limarepdf replaced it"
fi
works limarepdf
files=$(pacman -Qlq limarepdf | grep -v '/$')
pac -R limarepdf
for f in $files /usr/share/doc/limarepdf /usr/share/licenses/limarepdf; do
    if [ -e "$f" ] || [ -L "$f" ]; then
        fail "$f is left after removing limarepdf"
    fi
done
echo "Removed, with nothing left and the user's files as they were"
