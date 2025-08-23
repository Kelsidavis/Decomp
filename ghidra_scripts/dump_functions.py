#@category Decomp/Export
# Dump decompiled C and metadata for all functions to a JSON lines file.
# Usage (headless):
#   analyzeHeadless <projdir> <projname> -import <binary> \
#     -scriptPath ghidra_scripts -postScript dump_functions.py out.json

import json, sys, time
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType

outfile = "decomp.json"
args = getScriptArgs()
if args and len(args) >= 1:
    outfile = args[0]

program = getCurrentProgram()
listing = program.getListing()
fm = currentProgram.getFunctionManager()

decomp = DecompInterface()
decomp.toggleCCode(True)
decomp.toggleSyntaxTree(False)
decomp.setSimplificationStyle("decompile")
decomp.openProgram(program)

monitor = ConsoleTaskMonitor()

def str_addr(addr):
    return "0x%x" % addr.getOffset()

def xref_names(func):
    names = []
    for ref in getReferencesTo(func.getEntryPoint()):
        if ref.getReferenceType() in [RefType.UNCONDITIONAL_CALL, RefType.CONDITIONAL_CALL, RefType.DATA]:
            from_sym = getSymbolAt(ref.getFromAddress())
            if from_sym:
                names.append(from_sym.getName())
    return list(sorted(set(names)))

with open(outfile, "w") as f:
    funcs = fm.getFunctions(True)
    for func in funcs:
        try:
            res = decomp.decompileFunction(func, 60, monitor)
            ccode = res.getDecompiledFunction().getC() if res and res.getDecompiledFunction() else ""
        except:
            ccode = ""

        dis = []
        it = listing.getInstructions(func.getBody(), True)
        # keep it bounded
        while it.hasNext() and len(dis) < 20000:
            ins = it.next()
            dis.append("%s: %s" % (str_addr(ins.getAddress()), ins))

        sy = getSymbolAt(func.getEntryPoint())
        name = sy.getName() if sy else func.getName()

        try:
            stack_sz = func.getStackFrame().getLocalSize()
        except:
            stack_sz = None

        item = {
            "function_name": name,
            "entry": str_addr(func.getEntryPoint()),
            "sig": str(func.getSignature()),
            "calling_convention": func.getCallingConventionName(),
            "size_bytes": func.getBody().getNumAddresses(),
            "stack_frame": stack_sz,
            "decompiled_c": ccode,
            "disasm_sample": dis[:1000],
            "callers": xref_names(func),
            "timestamp": int(time.time())
        }
        f.write(json.dumps(item) + "\n")

print("Wrote JSON lines to", outfile)

