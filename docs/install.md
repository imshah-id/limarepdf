[User guide](README.md) › Getting started

# Install LimarePDF

LimarePDF comes as two programs: the desktop app (`limarepdf`) and the command-line tool (`limarepdf-cli`). Every
way of installing below gives you both. Downloads are on the project's
[Releases page](https://github.com/smaug42/limarepdf/releases) on GitHub.

Pick your system:

- **Windows:** the [installer](#windows-installer).
- **macOS:** the [app](#macos-app).
- **Linux:** the [package repository](#linux-packages), which keeps LimarePDF updated with the rest of your system;
  on Arch Linux, the [AUR](#arch-linux). On systems they don't cover, the [AppImage](#appimage).
- **Without installing**, on any of them: an [archive](#archives) you unpack anywhere.

## Requirements

- **Windows:** Windows 10 or 11, 64-bit (x64), or Windows 11 on Arm.
- **macOS:** macOS 11 (Big Sur) or later, on Apple Silicon or Intel.
- **Linux:** 64-bit (x86_64 or Arm64) with glibc 2.39 or later, as in Ubuntu 24.04, Debian 13, Fedora, Red Hat
  Enterprise Linux 10 and the systems built from it (AlmaLinux, Rocky Linux), openSUSE Leap 16 and Tumbleweed,
  current Arch Linux, and later; a working Vulkan or OpenGL graphics driver; and an X11 or Wayland desktop session.
  On older systems, you can [build LimarePDF from source](#build-from-source). If you'd like packages for an older
  system, [say so](troubleshooting.md#reporting-a-problem): they could be made if enough people need them.
- **Printing:** CUPS on Linux and macOS (macOS includes it).

Support for all of them is **provisional** for now. Every change is built and its automated tests run on each of
them, but the release checks by hand haven't all passed on each yet: installing and uninstalling, opening a PDF
from the file manager, editing and saving, recovery after a crash, printing, and display scaling. They are run
before LimarePDF 1.0. So far:

| System | Checked by hand |
| --- | --- |
| Linux | Used every day; printing on paper checked; not yet the whole set of release checks |
| Linux on Arm64 | None yet |
| Windows | Installing and starting (0.5); the print dialog |
| Windows on Arm | None yet |
| macOS | None yet |

## Windows installer

Download `limarepdf-<version>-x86_64.msi`, or `limarepdf-<version>-arm64.msi` for Windows on Arm, and open it. The
installer lets you choose the folder (`Program Files\LimarePDF` by default) and, under it, whether to create a
desktop shortcut (not ticked unless you tick it). It installs LimarePDF for all users, adds it to the Start menu
and to Open with for PDF files, and puts `limarepdf-cli` on the `PATH` (open a new terminal to use it).

For an install without the screens, `msiexec /i limarepdf-<version>-x86_64.msi /qn` installs with no desktop
shortcut; add `DESKTOPSHORTCUT=1` for one. Installing a newer version keeps the shortcut choice made before, unless
you give `DESKTOPSHORTCUT` again (`DESKTOPSHORTCUT=0` removes the shortcut).

The installer is not code-signed yet, so SmartScreen warns: choose More info, then Run anyway.

To make LimarePDF the default PDF app, choose it in Settings > Apps > Default apps. Installing a newer version
replaces the old one, as the Arm64 installer replaces an x64 LimarePDF of the same version; uninstall from
Settings > Apps.

## macOS app

Download `LimarePDF-<version>.dmg`, open it and drag LimarePDF to Applications. It is one app for both Apple Silicon
and Intel Macs. LimarePDF then appears under Open With for PDF files, and a PDF opened that way, or dropped on its
Dock icon, opens in LimarePDF.

LimarePDF is not signed with an Apple Developer ID yet, so the first start says Apple cannot check it: choose Done,
then open System Settings > Privacy & Security, choose Open Anyway next to LimarePDF, and confirm.

The command-line tool is inside the app; to use it from a terminal:

```
sudo ln -s /Applications/LimarePDF.app/Contents/MacOS/limarepdf-cli /usr/local/bin/limarepdf-cli
```

## Linux packages

The easiest way is LimarePDF's package repository, which brings updates with the rest of your system. It has
packages for x86_64 and Arm64 computers, and your system picks the right one itself. It is signed with the
project's key (see [Checking a download](#checking-a-download)).

### Debian and Ubuntu

Debian 13, Ubuntu 24.04 and later.

```
sudo install -d /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/limarepdf.asc https://smaug42.github.io/limarepdf/limarepdf-signing-key.asc
sudo curl -fsSLo /etc/apt/sources.list.d/limarepdf.sources https://smaug42.github.io/limarepdf/apt/limarepdf.sources
sudo apt update
sudo apt install limarepdf
```

### Fedora

```
sudo rpm --import https://smaug42.github.io/limarepdf/limarepdf-signing-key.asc
sudo dnf config-manager addrepo --from-repofile=https://smaug42.github.io/limarepdf/rpm/limarepdf.repo
sudo dnf install limarepdf
```

The first time, dnf still asks once to import the key, for the repository's own signature: check that the
fingerprint it shows is `0CF9 7E88 BAFE E9B6 38D2 14CB EB40 041A 7A8D C801` (Fedora shows it without the spaces),
then answer `y`.

### Red Hat Enterprise Linux, AlmaLinux and Rocky Linux

Version 10 and later.

```
sudo rpm --import https://smaug42.github.io/limarepdf/limarepdf-signing-key.asc
sudo dnf config-manager --add-repo https://smaug42.github.io/limarepdf/rpm/limarepdf.repo
sudo dnf install limarepdf
```

As on Fedora, dnf still asks once to import the key the first time: check the fingerprint, then answer `y`.

### openSUSE

Leap 16 and Tumbleweed.

```
sudo rpm --import https://smaug42.github.io/limarepdf/limarepdf-signing-key.asc
sudo zypper addrepo https://smaug42.github.io/limarepdf/rpm/limarepdf.repo
sudo zypper install limarepdf
```

### Downloaded packages

Each release also has a `.deb` (Debian 13, Ubuntu 24.04 and later) and an `.rpm` (Fedora, Red Hat Enterprise
Linux 10, AlmaLinux and Rocky Linux 10, openSUSE Leap 16 and Tumbleweed) to download and install by hand. Like the
archives, they need glibc 2.39 or later; on older systems, [build from source](#build-from-source). They install
`limarepdf` and `limarepdf-cli` in `/usr/bin`, with the menu entry, the icon, the licences and a README that links
to this guide online, and pull in the libraries the app needs. Take the one for your computer (the commands below
use the x86_64 names):

| Package | x86_64 | Arm64 |
| --- | --- | --- |
| `.deb` | `limarepdf_<version>-1_amd64.deb` | `limarepdf_<version>-1_arm64.deb` |
| `.rpm` | `limarepdf-<version>-1.x86_64.rpm` | `limarepdf-<version>-1.aarch64.rpm` |

Debian and Ubuntu:

```
sudo apt install ./limarepdf_<version>-1_amd64.deb
```

Fedora, Red Hat Enterprise Linux, AlmaLinux and Rocky Linux:

```
sudo rpm --import https://smaug42.github.io/limarepdf/limarepdf-signing-key.asc
rpm --checksig limarepdf-<version>-1.x86_64.rpm
sudo dnf install ./limarepdf-<version>-1.x86_64.rpm
```

openSUSE:

```
sudo rpm --import https://smaug42.github.io/limarepdf/limarepdf-signing-key.asc
rpm --checksig limarepdf-<version>-1.x86_64.rpm
sudo zypper install ./limarepdf-<version>-1.x86_64.rpm
```

The `.rpm` is signed with the project's key, and `rpm --checksig` checks it: it should say `digests signatures OK`.
The `.deb` is checked as any download is ([below](#checking-a-download)).

## Arch Linux

**Not on the AUR yet:** its packages go there with the next release.

On Arch Linux and the systems built from it (EndeavourOS, CachyOS, Manjaro and others), LimarePDF comes from the
Arch User Repository (AUR), in two packages:

- `limarepdf-bin`, the programs as released, ready to install;
- `limarepdf`, built on your computer from the release's source, which takes a while (about 20 minutes on two
  processor cores, less with more) and a few GB of memory.

Both are for x86_64 and Arm64 (Arch Linux ARM), and install the same: `limarepdf` and `limarepdf-cli` in
`/usr/bin`, the menu entry, the icon, this guide (in `/usr/share/doc/limarepdf`) and the licences, with the libraries
the app needs. Installing one replaces the other.

They check the release's signature, so import the project's key first, once, and check its fingerprint as under
[Checking a download](#checking-a-download):

```
curl -fsSL https://smaug42.github.io/limarepdf/limarepdf-signing-key.asc | gpg --import
```

Then install with an AUR helper (`yay -S limarepdf-bin`, `paru -S limarepdf-bin`), or by hand:

```
git clone https://aur.archlinux.org/limarepdf-bin.git
cd limarepdf-bin
makepkg -si
```

The AUR helper's upgrade brings new versions; by hand, run `git pull` in that folder, then `makepkg -si` again. To
remove LimarePDF, `sudo pacman -R limarepdf-bin` (or `limarepdf`); your documents and settings stay. On Arm64 the
packages haven't been installed and run yet, and `limarepdf` hasn't been built there.

## AppImage

For Linux systems the packages don't cover, the AppImage is LimarePDF in a single file that runs without
installing: `LimarePDF-<version>-x86_64.AppImage`, or `LimarePDF-<version>-aarch64.AppImage` for Arm64. Like the
packages, it needs glibc 2.39 or later ([Requirements](#requirements)). Make it executable and run it:

```
chmod +x LimarePDF-<version>-x86_64.AppImage
./LimarePDF-<version>-x86_64.AppImage
```

The command-line tool is in the same file: give `limarepdf-cli` as the first argument
(`./LimarePDF-<version>-x86_64.AppImage limarepdf-cli --help`), or start the AppImage through a link named
`limarepdf-cli`.

The AppImage runs through FUSE, which most desktops have. If it says "Cannot mount AppImage", install your
system's `fuse3` package. Or put `--appimage-extract-and-run` before the other arguments: it runs without FUSE, but
leaves an unpacked copy (about 100 MB) in `/tmp`.

To keep it, with both programs on your `PATH` and a menu entry, run in the folder you downloaded it to:

```
install -Dm755 LimarePDF-<version>-x86_64.AppImage ~/.local/bin/limarepdf
ln -sf limarepdf ~/.local/bin/limarepdf-cli
~/.local/bin/limarepdf --appimage-extract 'usr/share/*' > /dev/null
install -Dm644 squashfs-root/usr/share/applications/io.github.smaug42.limarepdf.desktop ~/.local/share/applications/io.github.smaug42.limarepdf.desktop
install -Dm644 squashfs-root/usr/share/icons/hicolor/256x256/apps/io.github.smaug42.limarepdf.png ~/.local/share/icons/hicolor/256x256/apps/io.github.smaug42.limarepdf.png
rm -r squashfs-root
```

The menu entry runs `limarepdf`, so `~/.local/bin` must be on your `PATH` (it is on most systems). The AppImage
doesn't update itself: for a new version, download it from the Releases page and run the first command again.

## Archives

To use LimarePDF without installing it, download the archive for your system: Linux (`.tar.gz`) or Windows
(`.zip`), each for x86_64 or Arm64, or macOS for Intel or for Apple Silicon (`.tar.gz`). Unpack it anywhere and run
`limarepdf` from there. Each archive holds the desktop app, the command-line tool, these docs, the changelog, and
the licences, including those of the bundled text recognition model and fonts.

The programs are not code-signed yet, so the system warns the first time you run them. On Windows, choose More
info, then Run anyway. On macOS, run `xattr -d com.apple.quarantine limarepdf-cli limarepdf` in the unpacked
folder, or try to run it once, then choose Open Anyway under System Settings > Privacy & Security.

### Menu entry and icon on Linux

The packages set this up; for the archive, do it yourself. Without a menu entry, Wayland desktops (GNOME, KDE
Plasma and others) show the window with a generic icon, since they take a window's icon from its entry. The Linux
archive includes `io.github.smaug42.limarepdf.desktop` and `io.github.smaug42.limarepdf.png`; to install them for
your user, run in the unpacked folder:

```
install -Dm644 io.github.smaug42.limarepdf.desktop ~/.local/share/applications/io.github.smaug42.limarepdf.desktop
install -Dm644 io.github.smaug42.limarepdf.png ~/.local/share/icons/hicolor/256x256/apps/io.github.smaug42.limarepdf.png
```

The entry runs `limarepdf`, so put `limarepdf` on your `PATH` (for example in `~/.local/bin`), or change the `Exec=` line
to its full path. LimarePDF then appears in your applications menu and in the list of apps that can open PDF files.
When building from source, the files are `crates/limarepdf-gui/assets/io.github.smaug42.limarepdf.desktop` and
`docs/images/icon.png`.

## Start LimarePDF

Start it from your applications menu, or with `limarepdf` in a terminal. If the system warns about it, see above
for your system, or [Troubleshooting](troubleshooting.md#the-system-warns-about-the-app-the-first-time). Then go
on to [First steps](first-steps.md).

## Checking a download

To be sure a download really comes from this project and wasn't changed on the way, check it. Every release file
has a GPG signature beside it (`.asc`), and `SHA256SUMS`, which lists every file's checksum, is signed too. The
signing key is [`limarepdf-signing-key.asc`](limarepdf-signing-key.asc), also on keys.openpgp.org, with the
fingerprint `0CF9 7E88 BAFE E9B6 38D2  14CB EB40 041A 7A8D C801`. To check a file:

```
gpg --import limarepdf-signing-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

Each file also has a build attestation recording that it was built by this project's GitHub Actions from a given
commit. With the GitHub CLI: `gh attestation verify <file> --repo smaug42/limarepdf`.

Between releases, each run of the project's continuous integration on GitHub Actions builds the same archives; they
are under the run's artifacts (this needs a GitHub sign-in).

## Build from source

You need the latest stable Rust (`rustup update stable`); older versions aren't supported. Build in a clone of the
repository, or in a release's source, `limarepdf-<version>-source.tar.gz` (signed like the other files):

```
cargo build --release --locked
# the binaries: target/release/limarepdf and target/release/limarepdf-cli
cargo test --workspace
```

`--locked` builds with exactly the library versions in `Cargo.lock`, the ones the releases are built and checked
with.

More for developers is in the [developer docs](developer/README.md).

---

[← User guide](README.md) · [First steps →](first-steps.md)
