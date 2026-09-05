#!/usr/bin/env python3
"""Renders the app icons from the web's ship mark.

Source: web/assets/pommern_ship_white.png (the white ship) on the web's
navy logo square (--logo-square in web/assets/style.css). Writes the macOS
asset catalog PNGs (the rounded square sits on a transparent 1024 canvas at
the size Apple's grid gives it), the Windows tile PNGs (full bleed), and
the .ico used for the tray, the executable, and the window.

Needs Pillow: python3 -m venv .venv && .venv/bin/pip install pillow.
"""
from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
SHIP = ROOT / "web/assets/pommern_ship_white.png"
NAVY = (0x0A, 0x1C, 0x2A, 255)
MAC = ROOT / "client/macos/Votport/Assets.xcassets/AppIcon.appiconset"
WIN = ROOT / "client/windows/Votport/Assets"


def tile(size, radius_fraction, ship_fraction=0.72):
    """A navy rounded square of `size` with the ship centred on it."""
    scale = 4
    big = size * scale
    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    ImageDraw.Draw(img).rounded_rectangle(
        (0, 0, big - 1, big - 1), radius=int(big * radius_fraction), fill=NAVY)
    ship = Image.open(SHIP).convert("RGBA")
    width = int(big * ship_fraction)
    ship = ship.resize((width, int(width * ship.height / ship.width)), Image.LANCZOS)
    img.alpha_composite(ship, ((big - ship.width) // 2, (big - ship.height) // 2))
    return img.resize((size, size), Image.LANCZOS)


def mac_icon(size):
    """Apple's grid: the shape covers 824 of a 1024 canvas, corners at 22.37%."""
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    inner = round(size * 824 / 1024)
    canvas.alpha_composite(tile(inner, 0.2237), ((size - inner) // 2, (size - inner) // 2))
    return canvas


def main():
    MAC.mkdir(parents=True, exist_ok=True)
    images = []
    for points in (16, 32, 128, 256, 512):
        for scale in (1, 2):
            px = points * scale
            name = f"icon_{points}x{points}@{scale}x.png"
            mac_icon(px).save(MAC / name)
            images.append({"size": f"{points}x{points}", "idiom": "mac", "scale": f"{scale}x", "filename": name})
    (MAC / "Contents.json").write_text(
        '{\n  "images": [\n' + ",\n".join(
            f'    {{"size": "{i["size"]}", "idiom": "mac", "scale": "{i["scale"]}", "filename": "{i["filename"]}"}}'
            for i in images) + '\n  ],\n  "info": {"version": 1, "author": "xcode"}\n}\n')
    # Windows tiles are full bleed; the shell rounds nothing, so a soft
    # corner keeps the square from looking cut out of the taskbar.
    for name, size in (("Square44x44Logo.png", 44), ("Square150x150Logo.png", 150), ("StoreLogo.png", 50)):
        tile(size, 0.12).save(WIN / name)
    tile(256, 0.12).save(WIN / "tray.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (256, 256)])
    tile(512, 0.2237).save(ROOT / "client/design/icon/votport-512.png")


if __name__ == "__main__":
    main()
