#!/usr/bin/env python3
"""
Generate Windows build files and a minimal app.rc, filtering out corrupt icons/PNGs.
If the input project path isn't provided or doesn't exist, auto-discover it under
./work (host) or /work (container).

Usage:
  python3 generate_windows_build.py [/path/to/recovered_project]

Env:
  SKIP_RESOURCES=1   -> skip writing app.rc (to unblock builds)
"""

import os
import sys
from pathlib import Path
from typing import List, Optional, Tuple

# ---------- simple validators ----------
def is_valid_png(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            sig = f.read(8)
        return sig == b"\x89PNG\r\n\x1a\n" and p.stat().st_size > 32
    except Exception:
        return False

def is_valid_ico(p: Path) -> bool:
    # ICO/CUR 6-byte header: 0, type in {1,2}, count > 0
    try:
        with p.open("rb") as f:
            hdr = f.read(6)
            if len(hdr) < 6:
                return False
            reserved = int.from_bytes(hdr[0:2], "little")
            typ      = int.from_bytes(hdr[2:4], "little")
            count    = int.from_bytes(hdr[4:6], "little")
            if reserved != 0 or typ not in (1, 2) or count <= 0:
                return False
        return p.stat().st_size > 32
    except Exception:
        return False

# ---------- discovery ----------
def _candidates_under(root: Path) -> List[Path]:
    if not root.exists():
        return []
    pats = [
        "recovered_project",
        "recovered*project*",
        "recovered*/",
        "*recovered*",
    ]
    cands: List[Path] = []
    for pat in pats:
        cands.extend([p for p in root.glob(pat) if p.is_dir()])
    # uniq by resolved path
    uniq = []
    seen = set()
    for p in cands:
        try:
            r = p.resolve()
        except Exception:
            continue
        if r in seen:
            continue
        seen.add(r)
        uniq.append(p)
    # sort newest first
    uniq.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return uniq

def autodiscover_project(proj_arg: Optional[str]) -> Optional[Path]:
    # 1) if arg provided and exists → use it
    if proj_arg:
        p = Path(proj_arg).resolve()
        if p.exists() and p.is_dir():
            print(f"[rc] using provided project: {p}")
            return p
        else:
            print(f"[rc] provided project not found: {p}")

    # 2) try host root ./work
    host_root = Path("./work").resolve()
    cands = _candidates_under(host_root)
    if cands:
        print(f"[rc] autodiscovered project (host): {cands[0]}")
        return cands[0].resolve()

    # 3) try container root /work
    cont_root = Path("/work")
    cands = _candidates_under(cont_root)
    if cands:
        print(f"[rc] autodiscovered project (container): {cands[0]}")
        return cands[0].resolve()

    return None

# ---------- assets + rc writing ----------
def find_assets(assets_dir: Path) -> Tuple[List[Path], List[Path]]:
    icons, pngs = [], []
    if not assets_dir.exists():
        return icons, pngs
    for p in sorted(assets_dir.iterdir()):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        if ext in {".ico", ".cur"}:
            if is_valid_ico(p): icons.append(p)
            else: print(f"[rc] skipping bad ico: {p}", file=sys.stderr)
        elif ext == ".png":
            if is_valid_png(p): pngs.append(p)
            else: print(f"[rc] skipping bad png: {p}", file=sys.stderr)
    return icons, pngs

def write_app_rc(out_rc: Path, icons: List[Path], pngs: List[Path]) -> None:
    out_rc.parent.mkdir(parents=True, exist_ok=True)
    lines = ['// Auto-generated resource script', '#include <windows.h>', '']
    if icons:
        main_ico = icons[0]
        lines.append(f'IDI_APP_ICON ICON "{str(main_ico).replace("\\\\","/")}"')
    else:
        print("[rc] no valid .ico found; resource will not include an app icon", file=sys.stderr)
    for i, p in enumerate(pngs):
        lines.append(f'APPPNG{i+1} RCDATA "{str(p).replace("\\\\","/")}"')
    out_rc.write_text("\n".join(lines), encoding="utf-8")
    print(f"[rc] wrote {out_rc} (icons={len(icons)}, pngs={len(pngs)})")

def main() -> int:
    if len(sys.argv) >= 2:
        proj = autodiscover_project(sys.argv[1])
    else:
        proj = autodiscover_project(None)

    if proj is None:
        print("[rc] recovered project not found under ./work or /work", file=sys.stderr)
        print("    Try: python3 generate_windows_build.py ./work/recovered_project", file=sys.stderr)
        return 2

    # Derive out dir: <proj>  ->  <proj>_win/res/app.rc
    out_root = proj.parent / (proj.name + "_win")
    out_res  = out_root / "res"
    out_rc   = out_res / "app.rc"

    # Assets in <proj>/assets/carved
    assets_dir = proj / "assets" / "carved"

    if os.getenv("SKIP_RESOURCES","") in ("1","true","TRUE","yes","YES"):
        print("[rc] SKIP_RESOURCES=1 → not generating app.rc")
        return 0

    icons, pngs = find_assets(assets_dir)
    write_app_rc(out_rc, icons, pngs)
    return 0

if __name__ == "__main__":
    sys.exit(main())

