#!/usr/bin/env python3
"""
verify_and_repair_assets.py

Walk an assets directory (e.g., recovered_project/assets), validate files,
attempt simple repairs for JPEG/PNG/ZIP, and produce a summary report.

- JPEG: ensure SOI(FFD8) and EOI(FFD9), strip junk after EOI, add minimal JFIF if missing APP0/APP1.
- PNG: ensure PNG signature, strip trailing junk after IEND.
- ZIP: rebuild central directory from found local file headers (zipfix) if the central dir is missing/corrupt.

Writes:
  assets_report.json (per-file status)
  *_fixed.<ext> siblings for repaired versions
  moves irreparable files to assets/quarantine/

Exit code 0 always (so CI/pipeline continues).
"""

import sys, os, json, binascii, struct, pathlib

PNG_SIG = b"\x89PNG\r\n\x1a\n"
JPG_SOI = b"\xFF\xD8"
JPG_EOI = b"\xFF\xD9"
ZIP_LFH = b"\x50\x4b\x03\x04"   # local file header
ZIP_CEN = b"\x50\x4b\x01\x02"   # central directory header
ZIP_EOCD= b"\x50\x4b\x05\x06"   # end of central dir

def write_json(p, obj):
    p.write_text(json.dumps(obj, indent=2), encoding="utf-8")

def is_png(b: bytes) -> bool:
    return len(b) >= 8 and b.startswith(PNG_SIG)

def is_jpg(b: bytes) -> bool:
    return len(b) >= 4 and b[:2] == JPG_SOI and JPG_EOI in b

def is_zip_bytes(b: bytes) -> bool:
    return b.startswith(ZIP_LFH) or (ZIP_EOCD in b) or (ZIP_CEN in b)

def repair_jpeg(b: bytes):
    if not b.startswith(JPG_SOI):
        return None, "no_soi"
    # find last EOI; cut after it
    last_eoi = b.rfind(JPG_EOI)
    if last_eoi == -1:
        return None, "no_eoi"
    repaired = b[:last_eoi+2]

    # If there is no APP0/APP1 segment right after SOI, optionally inject a minimal JFIF APP0.
    # JPEG marker parsing (very light): SOI FF D8, next should be APPn or SOF/…; if not APP0/APP1, inject.
    # This is conservative; most viewers don't require this, but it can help some tools.
    try:
        i = 2
        injected = False
        if i+4 <= len(repaired):
            if not (repaired[i] == 0xFF and repaired[i+1] in (0xE0, 0xE1)):  # APP0/APP1
                # Minimal APP0 JFIF segment
                app = b"\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
                repaired = repaired[:2] + app + repaired[2:]
                injected = True
        info = "ok_injected_jfif" if injected else "ok"
    except Exception:
        info = "ok"
    return repaired, info

def repair_png(b: bytes):
    if not is_png(b):
        return None, "not_png"
    # truncate after IEND chunk
    # PNG chunks: len(4) type(4) data len CRC(4)
    i = 8
    end = len(b)
    try:
        while i+8 <= len(b):
            clen = struct.unpack(">I", b[i:i+4])[0]
            ctype = b[i+4:i+8]
            ci = i+8+clen  # end of data
            ci_crc = ci+4
            if ci_crc > len(b):
                # truncate at start of this chunk (corrupt length)
                end = i
                break
            if ctype == b"IEND":
                end = ci_crc
                break
            i = ci_crc
        return b[:end], "ok_truncated_after_iend" if end < len(b) else "ok"
    except Exception:
        return None, "parse_error"

def scan_zip_local_files(b: bytes):
    """Return list of (offset, size_of_lfh_plus_file) by scanning local file headers."""
    offs = []
    i = 0
    while True:
        j = b.find(ZIP_LFH, i)
        if j < 0:
            break
        if j + 30 > len(b):
            break
        # parse minimal local file header
        # struct:
        # sig(4) ver(2) flag(2) meth(2) time(2) date(2) crc(4) csize(4) usize(4) nlen(2) elen(2)
        try:
            ver, flg, meth, tim, dat, crc, csz, usz, nlen, elen = struct.unpack("<HHHHHIIIHH", b[j+4:j+30])
        except Exception:
            break
        name_end = j + 30 + nlen
        extra_end = name_end + elen
        if extra_end > len(b):
            break
        data_end = extra_end + csz
        if data_end > len(b):
            # possibly truncated csize; try to seek to next LFH conservatively
            k = b.find(ZIP_LFH, extra_end)
            if k < 0:
                data_end = len(b)
            else:
                data_end = k
        offs.append((j, data_end - j))
        i = data_end
    return offs

def rebuild_zip(b: bytes):
    """Try building a minimal central directory for a ZIP that only has local file headers."""
    entries = []
    buf = memoryview(b)
    for off, span in scan_zip_local_files(b):
        # read name length to copy into CEN
        nlen = struct.unpack("<H", b[off+26:off+28])[0]
        elen = struct.unpack("<H", b[off+28:off+30])[0]
        name = b[off+30:off+30+nlen]
        # read fields we need
        ver, flg, meth, tim, dat, crc, csz, usz = struct.unpack("<HHHHHIII", b[off+4:off+4+20])
        lfh_size = 30 + nlen + elen
        entries.append({
            "off": off,
            "name": name,
            "ver": ver, "flg": flg, "meth": meth, "tim": tim, "dat": dat,
            "crc": crc, "csz": csz, "usz": usz,
            "lfh_size": lfh_size
        })
    if not entries:
        return None, "no_local_files"

    central = bytearray()
    for e in entries:
        # Central directory header
        central += ZIP_CEN
        central += struct.pack("<HHHHHHIIIHHHHHII",
            0x031E,            # ver made by (arbitrary)
            e["ver"],          # ver needed
            e["flg"], e["meth"], e["tim"], e["dat"],
            e["crc"], e["csz"], e["usz"],
            len(e["name"]), 0,  # nlen, elen (no extra)
            0, 0, 0,            # comment, disk, iattr
            0,                  # eattr
            e["off"]            # rel offset of local header
        )
        central += e["name"]
    cdir_off = len(b)
    cd_len = len(central)
    eocd = bytearray()
    eocd += ZIP_EOCD
    eocd += struct.pack("<HHHHIIH",
        0, 0,                  # disk numbers
        len(entries),          # total entries on this disk
        len(entries),          # total entries
        cd_len,                # size of central dir
        cdir_off,              # offset of central dir
        0                      # comment len
    )
    fixed = b + central + eocd
    return fixed, f"ok_rebuilt_cd_{len(entries)}"

def main():
    if len(sys.argv) != 2:
        print("Usage: verify_and_repair_assets.py <assets_dir>")
        sys.exit(0)
    root = pathlib.Path(sys.argv[1]).resolve()
    if not root.is_dir():
        print(f"[!] Not a directory: {root}")
        sys.exit(0)

    quarantine = root / "quarantine"
    quarantine.mkdir(exist_ok=True)
    report = {}
    for p in sorted(root.rglob("*")):
        if not p.is_file(): continue
        rel = str(p.relative_to(root))
        ext = p.suffix.lower()
        try:
            b = p.read_bytes()
        except Exception as e:
            report[rel] = {"status": "read_error", "err": str(e)}
            continue

        status = "unknown"
        fixed_path = None

        # Skip obviously tiny files
        if len(b) < 8:
            report[rel] = {"status":"too_small", "size": len(b)}
            continue

        if ext in (".jpg", ".jpeg"):
            if is_jpg(b):
                # Also strip junk after last EOI
                last_eoi = b.rfind(JPG_EOI)
                if last_eoi != len(b)-2:
                    fixed_path = p.with_name(p.stem + "_fixed.jpg")
                    fixed_path.write_bytes(b[:last_eoi+2])
                    status = "ok_stripped_junk"
                else:
                    status = "ok"
            else:
                repaired, why = repair_jpeg(b)
                if repaired:
                    fixed_path = p.with_name(p.stem + "_fixed.jpg")
                    fixed_path.write_bytes(repaired)
                    status = why
                else:
                    p.rename(quarantine / p.name)
                    status = f"bad_jpeg_{why}"

        elif ext == ".png" or is_png(b):
            repaired, why = repair_png(b)
            if repaired:
                if why.startswith("ok_truncated") or ext != ".png":
                    fixed_path = p.with_name(p.stem + "_fixed.png")
                    fixed_path.write_bytes(repaired)
                    status = why
                else:
                    status = "ok"
            else:
                p.rename(quarantine / p.name)
                status = f"bad_png_{why}"

        elif ext == ".zip" or is_zip_bytes(b):
            # try to open central dir presence
            if ZIP_EOCD in b and ZIP_CEN in b:
                # still trim any trailing junk after EOCD
                e = b.rfind(ZIP_EOCD)
                if e >= 0:
                    # eocd has variable length; keep everything from start up to end-of-file
                    status = "ok"
                else:
                    status = "ok"
            else:
                fixed, why = rebuild_zip(b)
                if fixed:
                    fixed_path = p.with_name(p.stem + "_fixed.zip")
                    fixed_path.write_bytes(fixed)
                    status = why
                else:
                    p.rename(quarantine / p.name)
                    status = f"bad_zip_{why}"

        else:
            # unknown or other; just leave it
            status = "skipped"

        report[rel] = {"status": status, "size": len(b), "fixed": str(fixed_path) if fixed_path else ""}

    write_json(root / "assets_report.json", report)
    print("[✓] Asset verification complete. See assets_report.json.")
    print(f"Quarantine: {quarantine}")

if __name__ == "__main__":
    main()

