#!/usr/bin/env python3
"""
Generate Windows build files and a minimal app.rc, filtering out corrupt icons/PNGs.
If SKIP_RESOURCES=1 is set in the environment, the RC step is omitted entirely.

Assumptions:
- Assets live under: work/recovered_project/assets/carved/
- Output RC path:    work/recovered_project_win/res/app.rc
- Called as part of your Windows build orchestration.

This script is conservative: it only includes images that pass lightweight validation.
"""

import os
import sys
import re
from pathlib import Path

ROOT = Path(os.getenv("ROOT_DIR", ".")).resolve()
WORK = ROOT / "work"
ASSETS = WORK / "recovered_project" / "assets" / "carved"
OUTDIR = WORK / "recovered_project_win" / "res"
OUTRC = OUTDIR / "app.rc"

VALID_ICO_EXT = {".ico", ".cur"}     # include cursors if present
VALID_PNG_EXT = {".png"}

def is_valid_png(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            sig = f.read(8)
        return sig == b"\x89PNG\r\n\x1a\n" and p.stat().st_size > 32
    except Exception:
        return False

def is_valid_ico(p: Path) -> bool:
    """
    Minimal ICO/CUR sanity:
    - 6-byte header: reserved(0), type(1=ICO or 2=CUR), count>0
    - not empty/trivial size
    """
    try:
        with p.open("rb") as f:
            hdr = f.read(6)
            if len(hdr) < 6:
                return False
            reserved = int.from_bytes(hdr[0:2], "little")
            typ = int.from_bytes(hdr[2:4], "little")
            count = int.from_bytes(hdr[4:6], "little")
            if reserved != 0:
                return False
            if typ not in (1, 2):     # 1=ICO, 2=CUR
                return False
            if count <= 0:
                return False
        return p.stat().st_size > 32
    except Exception:
        return False

def find_assets():
    if not ASSETS.exists():
        return [], []
    icons, pngs = [], []
    for p in sorted(ASSETS.glob("*")):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        if ext in VALID_ICO_EXT:
            if is_valid_ico(p):
                icons.append(p)
            else:
                print(f"[rc] skipping bad ico: {p}", file=sys.stderr)
        elif ext in VALID_PNG_EXT:
            if is_valid_png(p):
                pngs.append(p)
            else:
                print(f"[rc] skipping bad png: {p}", file=sys.stderr)
    return icons, pngs

def write_app_rc(icons, pngs):
    OUTDIR.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append('// Auto-generated resource script')
    lines.append('#include <windows.h>')
    lines.append('')

    # One main icon if present (use the first valid .ico)
    if icons:
        main_ico = icons[0]
        lines.append('IDI_APP_ICON ICON "%s"' % str(main_ico).replace("\\", "\\\\"))
    else:
        print("[rc] no valid .ico found; resource will not include an app icon", file=sys.stderr)

    # Optional PNG include (if you use them with custom loaders; windres doesn't embed PNG as icon)
    # You can create user-defined resources like:
    #   APPPNG1 RCDATA "path/to/img.png"
    for i, p in enumerate(pngs):
        lines.append('APPPNG%d RCDATA "%s"' % (i+1, str(p).replace("\\", "\\\\")))

    OUTRC.write_text("\n".join(lines), encoding="utf-8")
    print(f"[rc] wrote {OUTRC} (icons={len(icons)}, pngs={len(pngs)})")

def main():
    if os.getenv("SKIP_RESOURCES", "") in ("1", "true", "TRUE", "yes", "YES"):
        print("[rc] SKIP_RESOURCES=1 → not generating app.rc")
        return 0

    icons, pngs = find_assets()
    write_app_rc(icons, pngs)
    return 0

if __name__ == "__main__":
    sys.exit(main())

