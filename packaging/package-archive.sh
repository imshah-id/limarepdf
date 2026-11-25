#!/usr/bin/env bash
# Makes the folder a release archive holds (limarepdf-<version>-<platform>): the programs built in target/release,
# the README, changelog, security notes and guide, and the licences and notices, the crates' for this computer's
# target (packaging/package-notices.sh, so it needs cargo-about). ci.yml's build job archives it for each platform;
# the Arch package built from source (packaging/arch/limarepdf) installs from it.
#
#   packaging/package-archive.sh <folder>
#
# Run from the repository root after the release build. The folder must not exist yet.
# packaging/check-package.py checks what it holds.
set -euo pipefail

dir=$1
if [ -e "$dir" ]; then
    echo "package-archive.sh: $dir already exists" >&2
    exit 1
fi
ext=""
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) ext=.exe ;; esac
mkdir -p "$dir"
cp "target/release/limarepdf-cli$ext" "target/release/limarepdf$ext" "$dir/"
cp README.md CHANGELOG.md SECURITY.md LICENSE-MIT LICENSE-APACHE "$dir/"
# The README links to docs/, so the docs travel with each version.
cp -r docs "$dir/docs"
# Attribution and licence for the OCR model built into the binaries.
cp crates/limarepdf-core/models/README.md "$dir/OCR-MODEL.md"
# Licences for the Inter and Phosphor (icons) fonts built into limarepdf.
cp crates/limarepdf-gui/assets/fonts/OFL.txt "$dir/FONT-LICENSE-Inter.txt"
cp crates/limarepdf-gui/assets/fonts/LICENSE-Phosphor.txt "$dir/FONT-LICENSE-Phosphor.txt"
# Licences for the fonts built into limarepdf-core: Liberation (text typed on the page, and embedded in PDFs) and
# the handwriting fonts (typed signatures).
for f in OFL-Liberation OFL-Caveat OFL-CedarvilleCursive LICENSE-HomemadeApple OFL-Zeyada; do
    cp "crates/limarepdf-core/assets/fonts/$f.txt" "$dir/FONT-LICENSE-${f#*-}.txt"
done
# Notices and licences for the spelling dictionaries built into limarepdf-core (SCOWL's English, Grammalecte's
# French) and the MPL-2.0, the French one's and the spellbook crate's.
cp crates/limarepdf-core/assets/dictionaries/README_en_CA.txt "$dir/DICTIONARY-LICENSE-English.txt"
cp crates/limarepdf-core/assets/dictionaries/README_dict_fr.txt "$dir/DICTIONARY-LICENSE-French.txt"
cp crates/limarepdf-core/assets/dictionaries/LICENSE-MPL-2.0.txt "$dir/LICENSE-MPL-2.0.txt"
# The licences and notices of the crates built in, this platform's (cargo-about).
bash packaging/package-notices.sh
cp target/package-notices/THIRD-PARTY-LICENSES.html "$dir/"
# On Linux, the licence of the font that draws the window title bars under Wayland, and the desktop entry and
# icon; docs/install.md says where they go.
if [ "$(uname -s)" = Linux ]; then
    cp packaging/linux/FONT-LICENSE-Cantarell.txt "$dir/"
    cp crates/limarepdf-gui/assets/io.github.smaug42.limarepdf.desktop "$dir/"
    cp docs/images/icon.png "$dir/io.github.smaug42.limarepdf.png"
fi
