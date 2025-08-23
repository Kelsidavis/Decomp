#@category Export/PE
# -*- coding: utf-8 -*-
# dump_imports.py  → writes /work/imports.json as:
# { "modules": { "KERNEL32.DLL": ["CreateFileW", ...], ... } }

import os, sys, json

OUT = "/work/imports.json"

program = getCurrentProgram()
mods = {}

# ---- Method 1: walk ExternalManager locations (Ghidra 11.x safe) ----
try:
    extMgr = program.getExternalManager()
    it = extMgr.getExternalLocations()  # ExternalLocationIterator
    while it.hasNext():
        loc = it.next()
        lib = loc.getLibraryName() or "UNKNOWN"
        name = loc.getLabel()
        if not name:
            try:
                ordv = loc.getOrdinal()
                if ordv is not None and ordv >= 0:
                    name = "ORDINAL_%d" % ordv
            except Exception:
                pass
        if name:
            mods.setdefault(lib, set()).add(name)
except Exception as e:
    print("[dump_imports] ExternalManager scan failed:", e)

# ---- Method 2: parse PE import table (robust) ----
try:
    from ghidra.app.util.bin.format.pe import PortableExecutable
    pe = PortableExecutable.createPortableExecutable(program.getMemory(), program.getLanguage())
    it = pe.getImageNTHeader().getOptionalHeader().getDataDirectories().getImportTable()
    if it:
        for imp in it.getImports():
            dll = imp.getName()
            s = mods.setdefault(dll, set())
            for e in imp.getImports():
                nm = e.getName()
                if not nm:
                    nm = "ORDINAL_%d" % e.getOrdinal()
                s.add(nm)
except Exception as e:
    print("[dump_imports] PE import scan failed:", e)

# ---- write JSON (convert sets) ----
mods = {k: sorted(v) for k, v in mods.items() if v}

# Make sure /work exists (container writes there)
try:
    d = os.path.dirname(OUT)
    if d and not os.path.exists(d):
        os.makedirs(d)
except Exception:
    pass

with open(OUT, "w") as f:
    json.dump({"modules": mods}, f, indent=2)

print("Wrote imports to", OUT)

