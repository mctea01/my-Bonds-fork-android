"""Renders the desktop app icons from the launcher icon geometry (res/drawable/ic_launcher_*.xml).

Run from the repository root: python3 app/icons/generate_icons.py (needs Pillow).
Writes app/icons/app-icon.png (Linux installer), app/icons/app-icon.ico (Windows installer) and
app/src/desktopMain/resources/app-icon.png (window and taskbar icon).
"""
from pathlib import Path

from PIL import Image, ImageDraw

INDIGO = (0x4B, 0x4E, 0xD6, 255)
WHITE = (255, 255, 255, 255)
BACK_CARD = (255, 255, 255, 140)
SIZE = 1024
SCALE = 4  # supersampling for smooth edges

# The launcher viewport is 108 units; the visible square of the adaptive icon is 18..90.
VIEW_MIN, VIEW_SPAN = 18, 72


def render(size: int) -> Image.Image:
    big = size * SCALE
    unit = big / VIEW_SPAN

    def p(x: float, y: float) -> tuple:
        return ((x - VIEW_MIN) * unit, (y - VIEW_MIN) * unit)

    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, big - 1, big - 1], radius=int(big * 0.22), fill=INDIGO)
    layer = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    ld.rounded_rectangle([*p(36, 34), *p(76, 56)], radius=5 * unit, fill=BACK_CARD)
    img = Image.alpha_composite(img, layer)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([*p(30, 46), *p(78, 76)], radius=5 * unit, fill=WHITE)
    width = int(6 * unit)
    points = [p(43, 61), p(51, 69), p(66, 54)]
    d.line(points, fill=INDIGO, width=width, joint="curve")
    r = width / 2
    for x, y in (points[0], points[-1]):
        d.ellipse([x - r, y - r, x + r, y + r], fill=INDIGO)
    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    out = Path(__file__).resolve().parent
    icon = render(SIZE)
    png = icon.resize((512, 512), Image.LANCZOS)
    png.save(out / "app-icon.png")
    resources = out.parent / "src" / "desktopMain" / "resources"
    resources.mkdir(parents=True, exist_ok=True)
    png.resize((256, 256), Image.LANCZOS).save(resources / "app-icon.png")
    icon.save(out / "app-icon.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


if __name__ == "__main__":
    main()
