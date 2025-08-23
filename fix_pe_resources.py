#!/usr/bin/env python3
"""
fix_pe_resources.py <pe_resources_dir>

- Builds .ico from RT_GROUP_ICON + RT_ICON blobs.
- Wraps .dib (DIB-only) into valid .bmp (adds BITMAPFILEHEADER).
- Writes assets_report.json with per-file status.
- Keeps originals; writes *_fixed.* next to them.
- Creates assets/pe_resources/quarantine/ only if something is unsalvageable.
"""

import sys, os, json, struct, pathlib

def read(path):
    with open(path, "rb") as f: return f.read()

def write(path, data):
    with open(path, "wb") as f: f.write(data)

def parse_group_icon(data):
    """
    RT_GROUP_ICON structure (IconDir-like):
      WORD idReserved; WORD idType; WORD idCount;
      GRPICONDIRENTRY[idCount]:
        BYTE bWidth, bHeight, bColorCount, bReserved;
        WORD wPlanes, wBitCount;
        DWORD dwBytesInRes;
        WORD nID;   <-- resource ID for RT_ICON blob
    """
    if len(data) < 6: return None
    idReserved, idType, idCount = struct.unpack("<HHH", data[:6])
    if idReserved != 0 or idType != 1 or idCount <= 0: return None
    entries = []
    off = 6
    for _ in range(idCount):
        if off + 14 > len(data): return None
        bWidth, bHeight, bColorCount, bReserved, wPlanes, wBitCount, dwBytesInRes, nID = \
            struct.unpack("<BBBBHHIH", data[off:off+14])
        entries.append({
            "bWidth": bWidth, "bHeight": bHeight, "bColorCount": bColorCount, "bReserved": bReserved,
            "wPlanes": wPlanes, "wBitCount": wBitCount,
            "dwBytesInRes": dwBytesInRes, "nID": nID
        })
        off += 14
    return {"count": idCount, "entries": entries}

def build_ico(group, id_to_icon_blob):
    """
    Build standard ICO:
      ICONDIR {2 bytes reserved=0, 2 type=1, 2 count}
      ICONDIRENTRY[count] (last field is offset)
      image data blobs concatenated (each is RT_ICON DIB or PNG)
    """
    count = group["count"]
    entries = group["entries"]
    # header
    out = bytearray(struct.pack("<HHH", 0, 1, count))
    # placeholder entries (16 bytes each)
    out += b"\x00" * (16 * count)
    # write images and fill entries
    images = []
    offset = 6 + 16 * count
    icondir = bytearray()
    idx = 0
    for e in entries:
        blob = id_to_icon_blob.get(e["nID"])
        if not blob:
            return None
        size = len(blob)
        images.append(blob)
        # ICONDIRENTRY: BYTE w,h,color,res, WORD planes, WORD bitcount, DWORD bytesInRes, DWORD offset
        entry = struct.pack("<BBBBHHII",
                            e["bWidth"] if e["bWidth"] else 0,   # 0 means 256
                            e["bHeight"] if e["bHeight"] else 0,
                            e["bColorCount"], 0,
                            e["wPlanes"], e["wBitCount"],
                            size, offset)
        # write into the correct position later
        icondir += entry
        offset += size
        idx += 1
    # assemble: header + entries + images
    out = bytearray(struct.pack("<HHH", 0,1,count)) + icondir
    for img in images:
        out += img
    return bytes(out)

def is_dib(b):
    # Check BITMAPINFOHEADER (size >= 40)
    if len(b) < 40: return False
    biSize = struct.unpack("<I", b[:4])[0]
    return biSize in (40, 52, 56, 108, 124)  # common header sizes

def dib_to_bmp(dib):
    """
    Wrap a DIB (header + palette + pixels) in a BITMAPFILEHEADER.
    We approximate bfOffBits as 14 + biSize + palette bytes (for <=8bpp).
    """
    if not is_dib(dib):
        return None
    biSize, biWidth, biHeight, biPlanes, biBitCount, biCompression, biSizeImage, biXPels, biYPels, biClrUsed, biClrImportant = \
        struct.unpack("<IiiHHIIIIII", dib[:40])
    palette_colors = 0
    if biBitCount <= 8:
        palette_colors = biClrUsed if biClrUsed != 0 else (1 << biBitCount)
    palette_bytes = palette_colors * 4
    # BITFIELDS masks (compression=3) may add 12 bytes right after header
    masks_bytes = 12 if biCompression == 3 and biSize >= 40 else 0
    off_bits = 14 + biSize + masks_bytes + palette_bytes
    if off_bits > len(dib):
        off_bits = 14 + biSize  # fallback
    bfSize = 14 + len(dib)
    bf = struct.pack("<2sIHHI", b"BM", bfSize, 0, 0, off_bits)
    return bf + dib

def main():
    if len(sys.argv) != 2:
        print("Usage: fix_pe_resources.py <pe_resources_dir>")
        return 0
    root = pathlib.Path(sys.argv[1]).resolve()
    if not root.exists():
        print("[fix_pe] No such directory:", root)
        return 0

    report = {}
    quarantine = root / "quarantine"
    quarantine.mkdir(exist_ok=True)

    # Gather RT_ICON blobs and GROUPs
    icons = {}
    groups = {}
    dibs = []

    for p in sorted(root.glob("icon_*.bin")):
        try:
            rid = int(p.stem.split("_")[1], 16)
            icons[rid] = read(str(p))
        except Exception:
            pass
    for p in sorted(root.glob("groupicon_*.bin")):
        try:
            rid = int(p.stem.split("_")[1], 16)
            groups[rid] = read(str(p))
        except Exception:
            pass
    for p in sorted(root.glob("bitmap_*.dib")):
        dibs.append(p)

    # Assemble ICOs
    for gid, data in groups.items():
        g = parse_group_icon(data)
        if not g:
            report[f"groupicon_{gid:04x}.bin"] = {"status":"bad_groupicon"}
            continue
        ico = build_ico(g, icons)
        if ico:
            outp = root / f"groupicon_{gid:04x}.ico"
            write(str(outp), ico)
            report[outp.name] = {"status":"ico_built", "sources": [f"icon_{e['nID']:04x}.bin" for e in g["entries"]]}
        else:
            report[f"groupicon_{gid:04x}.bin"] = {"status":"missing_member_icons"}

    # Wrap DIBs to BMP
    for p in dibs:
        b = read(str(p))
        bmp = dib_to_bmp(b)
        if bmp:
            outp = p.with_suffix(".bmp")
            write(str(outp), bmp)
            report[p.name] = {"status":"bmp_wrapped", "output": outp.name}
        else:
            # leave original; mark bad if too small
            status = "dib_invalid" if len(b) < 40 else "dib_unhandled"
            report[p.name] = {"status": status}
            # keep it, do not quarantine unless truly junk

    # Basic per-file presence summary
    for p in root.iterdir():
        if p.is_file() and p.name not in report:
            report[p.name] = {"status":"kept"}

    with open(root / "assets_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("[fix_pe] Done. Built ICOs and wrapped BMPs where possible.")
    return 0

if __name__ == "__main__":
    sys.exit(main())

