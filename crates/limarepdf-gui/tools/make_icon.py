# Makes the app icon (docs/images/icon.png and crates/limarepdf-gui/assets/icon.ico) from
# Phosphor's file-pdf glyph, the icon on the start page card, in blue: the light theme's accent
# when the icon was made. The theme's accent is teal now (theme.rs); the icon kept its blue.
# Needs Pillow. Run from the repository root:
#   python3 crates/limarepdf-gui/tools/make_icon.py
from PIL import Image, ImageDraw, ImageFont

ACCENT = (37, 99, 235, 255)  # theme.rs's earlier light accent
FONT = "crates/limarepdf-gui/assets/fonts/Phosphor.ttf"
GLYPH = ""  # icon::FILE_PDF (src/icon.rs)
MASTER = 2048
FILL = 0.92  # share of the canvas the glyph's longer side takes
ICO_SIZES = [256, 64, 48, 40, 32, 24, 20, 16]


def fitted_font(path):
    font = ImageFont.truetype(path, MASTER)
    left, top, right, bottom = font.getbbox(GLYPH)
    scale = FILL * MASTER / max(right - left, bottom - top)
    return ImageFont.truetype(path, round(MASTER * scale))


def main():
    font = fitted_font(FONT)
    left, top, right, bottom = font.getbbox(GLYPH)
    at = ((MASTER - (right - left)) / 2 - left, (MASTER - (bottom - top)) / 2 - top)
    master = Image.new("RGBA", (MASTER, MASTER), (0, 0, 0, 0))
    ImageDraw.Draw(master).text(at, GLYPH, font=font, fill=ACCENT)
    icon = master.resize((256, 256), Image.LANCZOS)
    icon.save("docs/images/icon.png", optimize=True)
    icon.save("crates/limarepdf-gui/assets/icon.ico", sizes=[(s, s) for s in ICO_SIZES])


if __name__ == "__main__":
    main()
