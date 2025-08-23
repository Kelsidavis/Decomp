#@category Export/PE
# dump_pe_resources.py <outdir>
# Dumps RT_ICON, RT_GROUP_ICON, RT_BITMAP to files and writes manifest.json with counts.

import os, sys, json

outdir = getScriptArgs()[0] if getScriptArgs() else None
if not outdir:
    print("[dump_pe_resources] ERROR: outdir required")
    sys.exit(1)
if not os.path.exists(outdir):
    os.makedirs(outdir)

program = getCurrentProgram()
from ghidra.app.util.bin.format.pe import PortableExecutable
try:
    pe = PortableExecutable.createPortableExecutable(program.getMemory(), program.getLanguage())
    rsrc = pe.getResourceDirectory()
except Exception as e:
    print("[dump_pe_resources] ERROR creating PE:", e)
    rsrc = None

counts = {"RT_ICON":0, "RT_GROUP_ICON":0, "RT_BITMAP":0, "OTHER":0}
items = []

def write_blob(name, data):
    p = os.path.join(outdir, name)
    with open(p, "wb") as f: f.write(data)
    return p

if rsrc:
    for e in rsrc.getEntries():
        t = e.getType().name() if e.getType() else "UNKNOWN"
        for id2 in e.getDirectory().getEntries():
            for lang in id2.getDirectory().getEntries():
                data = lang.getData()
                if data is None: continue
                blob = data.getBytes()
                if t == "RT_ICON":
                    fn = write_blob("icon_%04x.bin" % id2.getNameID(), blob)
                    counts["RT_ICON"] += 1; items.append({"type":"RT_ICON","id":id2.getNameID(),"file":fn})
                elif t == "RT_GROUP_ICON":
                    fn = write_blob("groupicon_%04x.bin" % id2.getNameID(), blob)
                    counts["RT_GROUP_ICON"] += 1; items.append({"type":"RT_GROUP_ICON","id":id2.getNameID(),"file":fn})
                elif t == "RT_BITMAP":
                    # RT_BITMAP payload is a DIB (no BMP file header)
                    fn = write_blob("bitmap_%04x.dib" % id2.getNameID(), blob)
                    counts["RT_BITMAP"] += 1; items.append({"type":"RT_BITMAP","id":id2.getNameID(),"file":fn})
                else:
                    counts["OTHER"] += 1

with open(os.path.join(outdir, "manifest.json"), "w") as f:
    json.dump({"counts":counts, "items":items}, f, indent=2)

print("[dump_pe_resources] counts:", counts)

