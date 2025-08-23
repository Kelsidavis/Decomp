#!/usr/bin/env python3
"""
embed_assets.py <assets_dir> <project_dir>

- Prefers *_fixed.* over originals
- Skips quarantine/
- If a wrapped/built asset exists, skips the raw parts:
    * prefer *.ico over groupicon_*.bin + icon_*.bin
    * prefer *.bmp over bitmap_*.dib
- Emits include/resources.h and src/resources_embedded.c
- Logs total embedded size
"""
import sys, os, pathlib, re

def norm(rel: str) -> str:
    p = rel.replace("\\", "/")
    return p[2:] if p.startswith("./") else p

def to_ident(rel: str) -> str:
    s = re.sub(r'[^A-Za-z0-9_]', '_', rel)
    if not re.match(r'[A-Za-z_]', s):
        s = "_" + s
    return "res_" + s

def chunk_bytes(b: bytes, width=12):
    lines = []
    for i in range(0, len(b), width):
        part = b[i:i+width]
        lines.append(", ".join(f"0x{v:02x}" for v in part))
    return lines

def pick_assets(assets_root: pathlib.Path):
    # Pass 1: index all files, skip quarantine
    all_files = [p for p in assets_root.rglob("*") if p.is_file() and "quarantine" not in p.parts]

    # Pass 2: prefer *_fixed.* over originals (by base stem+ext)
    chosen = {}
    for p in sorted(all_files):
        rel = str(p.relative_to(assets_root)).replace("\\", "/")
        stem, ext = os.path.splitext(os.path.basename(rel))
        parent = os.path.dirname(rel)
        if stem.endswith("_fixed"):
            basekey = (os.path.join(parent, stem[:-6] + ext)).lower()
            chosen[basekey] = p
        else:
            basekey = rel.lower()
            chosen.setdefault(basekey, p)

    # Pass 3: replace raw members with assembled/wrapped outputs
    # a) If any *.ico exists, drop groupicon_*.bin and icon_*.bin
    have_ico = any(str(k).lower().endswith(".ico") for k in chosen)
    # b) If any *.bmp exists, drop bitmap_*.dib
    have_bmp = any(str(k).lower().endswith(".bmp") for k in chosen)

    filtered = {}
    for key, p in chosen.items():
        name = os.path.basename(key).lower()
        if have_ico and (name.startswith("groupicon_") and name.endswith(".bin")):
            continue
        if have_ico and (name.startswith("icon_") and name.endswith(".bin")):
            continue
        if have_bmp and (name.startswith("bitmap_") and name.endswith(".dib")):
            continue
        filtered[key] = p

    # Return in a stable order
    return [filtered[k] for k in sorted(filtered.keys())]

HEADER_TEXT = r'''#ifndef RESOURCES_H
#define RESOURCES_H
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *name;
    const unsigned char *data;
    size_t size;
} Asset;

size_t asset_count(void);
const Asset *asset_by_index(size_t i);
const Asset *asset_get(const char *name);

#ifdef __cplusplus
}
#endif
#endif /* RESOURCES_H */
'''

C_PREAMBLE = r'''#include "resources.h"
#include <string.h>

#ifndef RES_ALIGN
#define RES_ALIGN 16
#endif

#if defined(__GNUC__)
#  define ALIGNED __attribute__((aligned(RES_ALIGN)))
#else
#  define ALIGNED
#endif
'''

ASSET_STRUCT_HEAD = "static const Asset ASSETS[] = {\n"
ASSET_STRUCT_TAIL = "};\n\n"

API_IMPL = r'''
size_t asset_count(void) { return sizeof(ASSETS)/sizeof(ASSETS[0]); }

const Asset *asset_by_index(size_t i) {
    return (i < asset_count()) ? &ASSETS[i] : NULL;
}

const Asset *asset_get(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < asset_count(); ++i) {
        if (strcmp(ASSETS[i].name, name) == 0) return &ASSETS[i];
    }
    return NULL;
}
'''

def main():
    if len(sys.argv) != 3:
        print("Usage: embed_assets.py <assets_dir> <project_dir>")
        return 0
    assets_dir = pathlib.Path(sys.argv[1]).resolve()
    proj = pathlib.Path(sys.argv[2]).resolve()
    inc = proj / "include"
    src = proj / "src"
    inc.mkdir(parents=True, exist_ok=True)
    src.mkdir(parents=True, exist_ok=True)

    if not assets_dir.is_dir():
        raise SystemExit(f"Assets directory not found: {assets_dir}")

    files = pick_assets(assets_dir)
    if not files:
        print("[embed] No embeddable assets.")
        return 0

    # header
    (inc / "resources.h").write_text(HEADER_TEXT, encoding="utf-8")

    # source
    out_lines = [C_PREAMBLE]
    asset_entries = []
    total_bytes = 0

    for p in files:
        rel = norm(str(p.relative_to(assets_dir)))
        ident = to_ident(rel)
        data = p.read_bytes()
        total_bytes += len(data)
        out_lines.append(f"static const unsigned char {ident}[] ALIGNED = {{")
        out_lines += ["  " + line + "," for line in chunk_bytes(data)]
        out_lines.append("};\n")
        asset_entries.append((rel, ident, len(data)))

    out_lines.append(ASSET_STRUCT_HEAD)
    for rel, ident, sz in asset_entries:
        out_lines.append(f'  {{"{rel}", {ident}, {sz}}},')
    out_lines.append(ASSET_STRUCT_TAIL)
    out_lines.append(API_IMPL)

    (src / "resources_embedded.c").write_text("\n".join(out_lines), encoding="utf-8")
    print(f"[✓] Wrote: {inc/'resources.h'}")
    print(f"[✓] Wrote: {src/'resources_embedded.c'}")
    print(f"[✓] Embedded {len(asset_entries)} assets, total {total_bytes} bytes.")

if __name__ == "__main__":
    main()

