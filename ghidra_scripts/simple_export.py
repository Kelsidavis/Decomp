# -*- coding: utf-8 -*-
#@category Export
# simple_export.py - dump basic facts for function_hunt (Jython 2.x / Ghidra headless)
# Usage (headless -postScript):
#   -postScript simple_export.py /work/snapshots/<base>_out.json
#
# Output JSON schema:
# {
#   "binary": "<path>",
#   "arch": "<lang-id>",
#   "imageBase": "0x...",
#   "generated_at": <unix>,
#   "functions": [
#     { "name": "...", "addr": "0x...", "size": 123, "decomp": "...", "asm": "..." }
#   ]
# }

import sys, os, json, time, traceback
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# ---- helpers (Python 2 compatible) ----
def eprint(msg):
    try:
        sys.stderr.write(str(msg) + "\n")
    except:
        try:
            print >> sys.stderr, msg
        except:
            pass

def jhex(addr):
    try:
        return "0x%s" % addr.toString()
    except:
        return "0x0"

def ensure_parent(path):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d)
        except:
            pass

def get_args_or_die():
    args = getScriptArgs()
    if args is None or len(args) < 1 or not args[0]:
        eprint("[export] ERROR: need output JSON path")
        raise RuntimeError("missing OUT_JSON arg")
    return args

def decompile_func(ifc, fn, timeout_ms, monitor):
    res = ifc.decompileFunction(fn, timeout_ms, monitor)
    if res is None or not res.getDecompiledFunction():
        return None
    return res.getDecompiledFunction().getC()

def asm_snippet(fn, max_ins):
    try:
        listing = currentProgram.getListing()
        it = listing.getInstructions(fn.getBody(), True)
        lines, count = [], 0
        while it.hasNext() and count < max_ins:
            ins = it.next()
            mn = ins.getMnemonicString()
            ops = []
            oi = 0
            while oi < ins.getNumOperands():
                try:
                    ops.append(ins.getDefaultOperandRepresentation(oi))
                except:
                    ops.append("?")
                oi += 1
            lines.append("%s: %s %s" % (ins.getAddress().toString(), mn, ", ".join(ops) if ops else ""))
            count += 1
        return "\n".join(lines)
    except:
        return ""

def body_size_approx(fn):
    try:
        return int(fn.getBody().getNumAddresses())
    except:
        try:
            mn = fn.getBody().getMinAddress()
            mx = fn.getBody().getMaxAddress()
            if mn and mx:
                return int(mx.subtract(mn)) + 1
        except:
            pass
    return 0

def main():
    t0 = time.time()
    args = get_args_or_die()
    out_path = args[0]

    prog = currentProgram
    lang = prog.getLanguageID().getIdAsString()
    image_base = prog.getImageBase()

    ifc = DecompInterface()
    ifc.openProgram(prog)
    monitor = ConsoleTaskMonitor()

    MAX_DECOMP_LINES = 80
    MAX_DECOMP_CHARS = 12000
    MAX_ASM_INSNS = 100

    fm = prog.getFunctionManager()
    funcs = fm.getFunctions(True)

    out = {
        "binary": prog.getExecutablePath() or (prog.getDomainFile().getPathname() if prog.getDomainFile() else ""),
        "arch": lang,
        "imageBase": jhex(image_base),
        "generated_at": int(time.time()),
        "functions": []
    }

    count = 0
    while funcs.hasNext():
        fn = funcs.next()
        try:
            name = fn.getName()
            addr = fn.getEntryPoint()
            size = body_size_approx(fn)

            dec = ""
            try:
                dectxt = decompile_func(ifc, fn, 30 * 1000, monitor)
                if dectxt:
                    lines = dectxt.splitlines()
                    if len(lines) > MAX_DECOMP_LINES:
                        lines = lines[:MAX_DECOMP_LINES] + ["/* ...snip... */"]
                    dec = "\n".join(lines)
                    if len(dec) > MAX_DECOMP_CHARS:
                        dec = dec[:MAX_DECOMP_CHARS] + "\n/* ...snip... */"
            except:
                pass

            asm = asm_snippet(fn, MAX_ASM_INSNS)

            out["functions"].append({
                "name": name,
                "addr": jhex(addr),
                "size": int(size),
                "decomp": dec,
                "asm": asm
            })
            count += 1
            if count % 500 == 0:
                print("[export] progress %d functions..." % count)
        except:
            eprint("[export] WARN: failed on function %s" % (fn.getName(),))
            eprint(traceback.format_exc())

    ensure_parent(out_path)
    try:
        with open(out_path, "w") as fh:
            json.dump(out, fh)
        print("[export] wrote %s (%d functions) in %.1fs" % (out_path, len(out["functions"]), time.time()-t0))
    except:
        eprint("[export] ERROR: failed to write %s" % out_path)
        eprint(traceback.format_exc())
        raise

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except:
        eprint(traceback.format_exc())
        raise

