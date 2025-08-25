#!/usr/bin/env python3
# tools/pre_unpack.py — detect & extract SFX/packed EXEs and choose primary payload

from __future__ import annotations
import os, sys, json, shutil, subprocess, zipfile
from pathlib import Path
from typing import List, Optional, Tuple

def is_pe(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            mz = f.read(2)
            if mz != b"MZ": return False
            f.seek(0x3c)
            off = int.from_bytes(f.read(4), "little")
            f.seek(off)
            return f.read(4) == b"PE\x00\x00"
    except Exception:
        return False

def pe_overlay_offset(p: Path) -> int:
    try:
        import pefile
        pe = pefile.PE(str(p), fast_load=True)
        pe.parse_data_directories()
        last_end = 0
        for s in pe.sections:
            last_end = max(last_end, s.PointerToRawData + s.SizeOfRawData)
        fsize = p.stat().st_size
        return max(0, fsize - last_end)
    except Exception:
        return 0

def detect_signatures(p: Path) -> dict:
    sig = {
        "zip_sfx": False, "seven_sfx": False, "rar_sfx": False, "cab_sfx": False,
        "upx": False, "nsis": False, "inno": False, "overlay_bytes": 0
    }
    try:
        data = p.read_bytes()
        sig["overlay_bytes"] = pe_overlay_offset(p)
        # simple string heuristics
        if b"UPX!" in data or b"UPX0" in data[:4096] or b"UPX1" in data[:4096]:
            sig["upx"] = True
        if b"Nullsoft.NSIS" in data or b"NSIS" in data:
            sig["nsis"] = True
        if b"Inno Setup" in data:
            sig["inno"] = True
        # SFX archive hints
        # ZIP SFX: stdlib zipfile can open SFX as long as EOCD is present
        try:
            with zipfile.ZipFile(p) as zf:
                zf.infolist()
                sig["zip_sfx"] = True
        except Exception:
            pass
        # 7z/RAR/CAB — rely on external tools if present
        if shutil.which("7z"):
            try:
                # Check if 7z can list the file AND it's not just a regular PE
                result = subprocess.run(["7z","l",str(p)], capture_output=True, text=True, check=True)
                # Only consider it 7z SFX if it contains actual archive entries, not just PE sections
                if "Type = 7z" in result.stdout or ("Type = " in result.stdout and "Type = PE" not in result.stdout):
                    sig["seven_sfx"] = True
            except Exception:
                pass
        if b"Rar!\x1a\x07" in data[:16]:
            sig["rar_sfx"] = True
        if b"MSCF" in data:
            sig["cab_sfx"] = True
    except Exception:
        pass
    return sig

def extract_zip_sfx(p: Path, outdir: Path) -> List[Path]:
    out = outdir / "zip"
    out.mkdir(parents=True, exist_ok=True)
    paths: List[Path] = []
    with zipfile.ZipFile(p) as zf:
        zf.extractall(out)
        for n in zf.namelist():
            q = (out / n).resolve()
            if q.exists(): paths.append(q)
    return paths

def extract_with_7z(p: Path, outdir: Path) -> List[Path]:
    if not shutil.which("7z"): return []
    out = outdir / "7z"
    out.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["7z","x","-y",f"-o{out}",str(p)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return []
    return list(out.rglob("*"))

def extract_cab(p: Path, outdir: Path) -> List[Path]:
    if not shutil.which("cabextract"): return []
    out = outdir / "cab"
    out.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["cabextract","-d",str(out), str(p)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return []
    return list(out.rglob("*"))

def unpack_upx(p: Path, outdir: Path) -> Optional[Path]:
    if not shutil.which("upx"): return None
    out = outdir / "unpacked_upx.exe"
    try:
        subprocess.run(["upx","-d","-o",str(out), str(p)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return out if out.exists() else None
    except Exception:
        return None

def choose_primary(paths: List[Path]) -> Optional[Path]:
    # prefer biggest PE file among extracted; fallback to original if none
    pes = [q for q in paths if q.is_file() and is_pe(q)]
    if pes:
        pes.sort(key=lambda x: x.stat().st_size, reverse=True)
        return pes[0]
    return None

def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Detect & extract SFX/packed EXE; choose primary payload")
    ap.add_argument("--bin", required=True, help="Input EXE")
    ap.add_argument("--out", default="work/extracted", help="Output dir for extraction")
    ap.add_argument("--work", default="work", help="Work dir (for primary_bin.txt)")
    args = ap.parse_args()

    exe = Path(args.bin).resolve()
    out = Path(args.out).resolve()
    work = Path(args.work).resolve()
    out.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)

    if not exe.exists():
        print(f"[pre] not found: {exe}")
        return 2

    info = {"input": str(exe), "signatures": {}, "extracted": []}
    sig = detect_signatures(exe)
    info["signatures"] = sig

    extracted: List[Path] = []
    # Try extraction in priority order
    if sig.get("zip_sfx"):
        print("[pre] ZIP SFX detected → extracting via zipfile")
        extracted += extract_zip_sfx(exe, out)
    elif sig.get("seven_sfx"):
        print("[pre] 7z SFX likely → extracting via 7z")
        extracted += extract_with_7z(exe, out)
    elif sig.get("rar_sfx"):
        print("[pre] RAR SFX likely → extracting via 7z")
        extracted += extract_with_7z(exe, out)
    elif sig.get("cab_sfx"):
        print("[pre] CAB SFX likely → extracting via cabextract")
        extracted += extract_cab(exe, out)

    # UPX unpack (even if also SFX)
    upx_out = None
    if sig.get("upx"):
        print("[pre] UPX packing detected → attempting upx -d")
        upx_out = unpack_upx(exe, out)
        if upx_out: extracted.append(upx_out)

    # record extracted list
    info["extracted"] = [str(p) for p in extracted]

    # choose primary payload
    primary = choose_primary(extracted) or (exe if is_pe(exe) else None)
    if primary:
        (work / "primary_bin.txt").write_text(str(primary), encoding="utf-8")
        # convenience symlink
        try:
            link = work / "primary.exe"
            if link.exists() or link.is_symlink(): link.unlink()
            link.symlink_to(primary)
        except Exception:
            pass
        info["primary"] = str(primary)
        print(f"[pre] primary payload: {primary}")
    else:
        info["primary"] = None
        print("[pre] no PE payload found")

    # write summary
    summary = out / "summary.json"
    summary.write_text(json.dumps(info, indent=2), encoding="utf-8")
    print(f"[pre] wrote summary: {summary}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

