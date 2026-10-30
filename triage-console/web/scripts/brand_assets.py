"""Generate the start-up screen artwork as SVG files in web/public/brand/.

    python web/scripts/brand_assets.py

The loading screen shows a train running laps on a loop of track around the
logo, seen from above. The track itself is drawn in the page (web/src/splash.ts)
so its rails, sleepers and clips follow the loop exactly; these files are the
pieces it uses:

* train-top-lead.svg - leading car from above, nose to the right
* train-top-car.svg  - middle car from above
* train-top-tail.svg - trailing car from above, nose to the left

The SQL loading indicator (web/src/train-loader.ts) shows a train crossing
left to right, seen from the side:

* train-side-lead.svg - leading car, nose to the right, logo on the cab
* train-side-car.svg  - middle car
* train-side-tail.svg - trailing car, nose to the left (logo still reads correctly)

Drawn from reference photos of an SMRT train (silver body, dark window band,
red roof-line stripe, green waist stripe) and SMRT track (concrete sleepers,
yellow clips, rusty rails). Every run gives the same files.
"""
from __future__ import annotations

import re
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "public" / "brand"
LOGO_PATH = re.search(r'd="([^"]+)"', (OUT / "smrt-logo.svg").read_text(encoding="utf-8")).group(1)

RED = "#d71920"
EDGE_DARK = "#22262b"           # the window band, glimpsed along both sides
ROOF_EDGE, ROOF_MID = "#c3c7ca", "#f3f4f4"
UNIT, UNIT_EDGE, FAN = "#b9bdc1", "#9a9fa4", "#6c7278"
GLASS = "#1d2125"

CW, CH = 144, 44                 # one car from above: length x width (drawn at half size in the page)


def defs() -> str:
    return f"""<defs>
  <linearGradient id="roof" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="{ROOF_EDGE}"/><stop offset="0.5" stop-color="{ROOF_MID}"/><stop offset="1" stop-color="{ROOF_EDGE}"/>
  </linearGradient>
  <linearGradient id="screen" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" stop-color="#2c333a"/><stop offset="1" stop-color="{GLASS}"/>
  </linearGradient>
</defs>"""


def ac_unit(x: float) -> str:
    """Roof air-conditioning unit: grille lines and two fans."""
    grille = "".join(f'<line x1="{x + 3 + i * 3}" y1="14" x2="{x + 3 + i * 3}" y2="30" stroke="{UNIT_EDGE}" stroke-width="0.7"/>' for i in range(3))
    fans = "".join(f'<circle cx="{x + cx}" cy="22" r="5" fill="#a9aeb3" stroke="{FAN}" stroke-width="1.2"/>'
                   f'<circle cx="{x + cx}" cy="22" r="1.4" fill="{FAN}"/>' for cx in (17, 27))
    return f'<rect x="{x}" y="12" width="34" height="20" rx="3" fill="{UNIT}" stroke="{UNIT_EDGE}" stroke-width="0.8"/>{grille}{fans}'


def car_from_above(kind: str) -> str:
    """kind: 'lead' (nose right), 'tail' (nose left) or 'car'."""
    if kind == "car":
        body = f'<rect x="2" y="4" width="{CW - 4}" height="36" rx="5" fill="url(#roof)" stroke="#9fa4a8" stroke-width="0.8"/>'
        edges = (f'<rect x="4" y="4" width="{CW - 8}" height="3.4" fill="{EDGE_DARK}"/>'
                 f'<rect x="4" y="36.6" width="{CW - 8}" height="3.4" fill="{EDGE_DARK}"/>'
                 f'<line x1="4" y1="9" x2="{CW - 4}" y2="9" stroke="{RED}" stroke-width="3.2"/>'
                 f'<line x1="4" y1="35" x2="{CW - 4}" y2="35" stroke="{RED}" stroke-width="3.2"/>')
        gangways = f'<rect x="0" y="14" width="3" height="16" fill="#2a2d31"/><rect x="{CW - 3}" y="14" width="3" height="16" fill="#2a2d31"/>'
        parts = [body, edges, ac_unit(18), ac_unit(CW - 18 - 34), gangways]
        return svg(parts)
    # Cab car, drawn nose-right; the tail car is its mirror image (nothing on it reads as text).
    body = (f'<path d="M 4 4 H 112 C 132 4 142 12 142 22 C 142 32 132 40 112 40 H 4 Q 2 40 2 38 V 6 Q 2 4 4 4 Z" '
            f'fill="url(#roof)" stroke="#9fa4a8" stroke-width="0.8"/>')
    edges = (f'<path d="M 4 4 H 112 C 118 4 123 5 127 7.4 L 125 7.4 H 4 Z" fill="{EDGE_DARK}"/>'
             f'<path d="M 4 40 H 112 C 118 40 123 39 127 36.6 L 125 36.6 H 4 Z" fill="{EDGE_DARK}"/>'
             f'<path d="M 4 9 H 110 C 120 9 128 11 133 15" fill="none" stroke="{RED}" stroke-width="3.2" stroke-linecap="round"/>'
             f'<path d="M 4 35 H 110 C 120 35 128 33 133 29" fill="none" stroke="{RED}" stroke-width="3.2" stroke-linecap="round"/>')
    windscreen = (f'<path d="M 118 9 C 131 9 139 15 139.5 22 C 139 29 131 35 118 35 C 122 30 123 26 123 22 C 123 18 122 14 118 9 Z" '
                  f'fill="url(#screen)"/>'
                  '<path d="M 124 12 C 131 13 136 17 137 21" fill="none" stroke="#ffffff" stroke-opacity="0.3" stroke-width="1.2"/>')
    lights = '<circle cx="140" cy="15" r="1.3" fill="#fff6c8"/><circle cx="140" cy="29" r="1.3" fill="#fff6c8"/>'
    gangway = '<rect x="0" y="14" width="3" height="16" fill="#2a2d31"/>'
    parts = [body, edges, ac_unit(14), ac_unit(62), windscreen, lights, gangway]
    if kind == "tail":
        return svg([f'<g transform="translate({CW} 0) scale(-1 1)">' + "".join(parts) + "</g>"])
    return svg(parts)


def svg(parts: list[str], width: int = CW, height: int = CH) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}">'
            + defs() + "".join(parts) + "</svg>\n")


# --- side view (SQL loading indicator) ---------------------------------------------------

SW, SH = 320, 96                 # one car from the side: length x height
SILVER_TOP, SILVER_MID, SILVER_LOW = "#f4f4f3", "#e3e4e4", "#c4c7c9"
BAND, SIDE_GLASS, DOOR, DOOR_EDGE = "#22262b", "#3b4249", "#2c3137", "#8d949b"
GREEN, UNDER, BOGIE, WHEEL = "#16a04a", "#3a3e43", "#2a2d31", "#1c1e21"
LOGO_SCALE = 0.024
CAB_LENGTH = 315


def side_defs() -> str:
    return f"""<defs>
  <linearGradient id="body" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="{SILVER_TOP}"/><stop offset="0.55" stop-color="{SILVER_MID}"/><stop offset="1" stop-color="{SILVER_LOW}"/>
  </linearGradient>
  <linearGradient id="glass" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#2d343b"/><stop offset="0.5" stop-color="{BAND}"/><stop offset="1" stop-color="#16191c"/>
  </linearGradient>
  <linearGradient id="shine" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0" stop-color="#ffffff" stop-opacity="0"/><stop offset="0.5" stop-color="#ffffff" stop-opacity="0.16"/><stop offset="1" stop-color="#ffffff" stop-opacity="0"/>
  </linearGradient>
</defs>"""


def side_svg(parts: list[str]) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {SW} {SH}" width="{SW}" height="{SH}">'
            + side_defs() + "".join(parts) + "</svg>\n")


def bogie(x: float) -> str:
    wheels = "".join(f'<circle cx="{x + dx}" cy="88" r="6.5" fill="{WHEEL}"/><circle cx="{x + dx}" cy="88" r="2.2" fill="#6d7277"/>'
                     for dx in (-15, 15))
    return f'<rect x="{x - 26}" y="78" width="52" height="9" rx="2.5" fill="{BOGIE}"/>{wheels}'


def door(x: float) -> str:
    """A pair of sliding doors, dark, with tall windows."""
    leaves = "".join(
        f'<rect x="{x + dx}" y="20" width="12" height="52" rx="1.5" fill="{DOOR}" stroke="{DOOR_EDGE}" stroke-width="0.6"/>'
        f'<rect x="{x + dx + 2.2}" y="25" width="7.6" height="22" rx="1.2" fill="{SIDE_GLASS}"/>'
        for dx in (0, 12.4))
    return leaves + f'<rect x="{x - 0.8}" y="19" width="26.2" height="54" rx="2" fill="none" stroke="#b7bcc1" stroke-width="0.8"/>'


def reflections(x0: float, x1: float) -> str:
    out, x = [], x0 + 10
    while x < x1 - 20:
        out.append(f'<polygon points="{x},22 {x + 10},22 {x - 6},50 {x - 16},50" fill="url(#shine)"/>')
        x += 46
    return "".join(out)


def underframe(x0: float, x1: float) -> str:
    boxes = "".join(f'<rect x="{a}" y="76" width="{b - a}" height="7" rx="1" fill="#2e3236"/>'
                    for a, b in ((x0 + 70, x0 + 120), (x0 + 140, x0 + 200), (x1 - 120, x1 - 80)) if b < x1)
    return f'<rect x="{x0 + 4}" y="73" width="{x1 - x0 - 8}" height="6" fill="{UNDER}"/>{boxes}'


def logo_at(x: float) -> str:
    return (f'<g transform="translate({x:.1f} 57) scale({LOGO_SCALE}) translate(-160 -218)">'
            f'<path fill="{RED}" fill-rule="evenodd" d="{LOGO_PATH}"/></g>')


def cab_side(nose_right: bool) -> str:
    """Cab car from the side. The tail car is the mirror image, except the logo, which must not read backwards."""
    body = "M 3 10 H 258 C 288 10 307 24 313 44 L 315 66 Q 315 74 306 74 H 3 Q 0 74 0 70 V 13 Q 0 10 3 10 Z"
    windscreen = "M 256 21 H 262 C 284 21 299 31 306 46 L 307 53 H 256 Z"
    parts = [
        underframe(0, 310), bogie(52), bogie(262),
        f'<path d="{body}" fill="url(#body)" stroke="#a9adb1" stroke-width="0.8"/>',
        '<path d="M 4 11.5 H 258 C 280 11.5 296 19 304 28" fill="none" stroke="#ffffff" stroke-opacity="0.7" stroke-width="1"/>',
        '<rect x="5" y="21" width="254" height="30" rx="3" fill="url(#glass)"/>',
        f'<path d="{windscreen}" fill="url(#glass)"/>',
        '<path d="M 262 24 C 280 24 293 32 299 43" fill="none" stroke="#ffffff" stroke-opacity="0.25" stroke-width="2"/>',
        reflections(5, 256),
        f'<path d="M 0 15.5 H 256 C 279 15.5 295 24 303 36" fill="none" stroke="{RED}" stroke-width="3" stroke-linecap="round"/>',
        f'<path d="M 4 53 H 268 C 284 53 296 51 306 46" fill="none" stroke="{GREEN}" stroke-width="2.6" stroke-linecap="round"/>',
        door(44), door(120), door(196),
        '<rect x="0" y="16" width="3" height="56" fill="#2a2d31"/>',                                  # gangway
        '<rect x="300" y="60" width="9" height="3" rx="1.5" fill="#fff6c8" stroke="#a9adb1" stroke-width="0.5"/>',   # headlight
    ]
    if nose_right:
        return side_svg(parts + [logo_at(268)])
    mirrored = f'<g transform="translate({CAB_LENGTH} 0) scale(-1 1)">' + "".join(parts) + "</g>"
    return side_svg([mirrored, logo_at(CAB_LENGTH - 268 - 680 * LOGO_SCALE)])


def middle_side() -> str:
    return side_svg([
        underframe(0, SW), bogie(54), bogie(266),
        f'<rect x="2" y="10" width="{SW - 4}" height="64" rx="4" fill="url(#body)" stroke="#a9adb1" stroke-width="0.8"/>',
        f'<line x1="5" y1="11.5" x2="{SW - 5}" y2="11.5" stroke="#ffffff" stroke-opacity="0.7" stroke-width="1"/>',
        f'<rect x="6" y="21" width="{SW - 12}" height="30" rx="3" fill="url(#glass)"/>',
        reflections(6, SW - 6),
        f'<line x1="0" y1="15.5" x2="{SW}" y2="15.5" stroke="{RED}" stroke-width="3"/>',
        f'<line x1="2" y1="53" x2="{SW - 2}" y2="53" stroke="{GREEN}" stroke-width="2.6"/>',
        door(30), door(108), door(186), door(264),
        '<rect x="0" y="16" width="3" height="56" fill="#2a2d31"/>',
        f'<rect x="{SW - 3}" y="16" width="3" height="56" fill="#2a2d31"/>',
    ])


if __name__ == "__main__":
    for old in ("train-lead.svg", "train-tail.svg", "train-car.svg", "track.svg", "viaduct.svg", "ballast.svg"):   # earlier versions
        (OUT / old).unlink(missing_ok=True)
    for name, content in (("train-top-lead.svg", car_from_above("lead")), ("train-top-car.svg", car_from_above("car")),
                          ("train-top-tail.svg", car_from_above("tail")),
                          ("train-side-lead.svg", cab_side(True)), ("train-side-car.svg", middle_side()),
                          ("train-side-tail.svg", cab_side(False))):
        (OUT / name).write_text(content, encoding="utf-8")
        print(f"{name}: {len(content):,} bytes")
