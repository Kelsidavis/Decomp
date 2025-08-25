#@category Decomp/Export
#@menupath
# Usage (headless):
#   analyzeHeadless <projDir> <projName> -import <binary> \
#     -scriptPath <path_to_this_dir> \
#     -postScript simple_export.py <out.json>
#
# Emits a JSON with:
#   {
#     "binary": "<currentProgram name>",
#     "functions": [
#       {
#         "name": "sub_401000",
#         "address": "0x401000",
#         "size": 1234,
#         "pseudocode": "...\n",
#         "module": null
#       }, ...
#     ]
#   }

import json
import sys
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileOptions
from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType

# -------- args --------
if len(sys.argv) < 2:
    print("[export] ERROR: need output JSON path", file=sys.stderr)
    sys.exit(2)
out_path = sys.argv[1]

prog = currentProgram
fm = prog.getFunctionManager()
listing = prog.getListing()

# -------- decompiler --------
opts = DecompileOptions()
iface = DecompInterface()
iface.setOptions(opts)
iface.openProgram(prog)

monitor = ConsoleTaskMonitor()

def decompile(fn, timeout_ms=5000):
    try:
        res = iface.decompileFunction(fn, timeout_ms, monitor)
        if res and res.decompileCompleted():
            return res.getDecompiledFunction().getC()
        elif res:
            return "// decompile incomplete: " + res.getErrorMessage()
    except Exception as e:
        return "// decompile error: %s" % e
    return ""

def est_size(fn):
    try:
        body = fn.getBody()
        if body is None:
            return 0
        return int(body.getNumAddresses())
    except:
        return 0

# -------- walk functions --------
out = {
    "binary": prog.getExecutablePath(),
    "functions": []
}

it = fm.getFunctions(True)
count = 0
while it.hasNext() and not monitor.isCancelled():
    fn = it.next()
    count += 1
    name = fn.getName()
    addr = fn.getEntryPoint()
    size = est_size(fn)
    code = decompile(fn, 8000)  # allow a bit more time per fn

    rec = {
        "name": name,
        "address": "0x%s" % addr.toString(),
        "size": size if size > 0 else max(1, len(code)),
        "pseudocode": code,
        "module": None
    }
    out["functions"].append(rec)

# -------- write --------
with open(out_path, "w") as fh:
    json.dump(out, fh)

print("[export] wrote %s (functions=%d)" % (out_path, len(out["functions"])))

