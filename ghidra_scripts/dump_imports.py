#@category FunctionHunt/Export
# Headless-friendly: dump imported symbols for the currentProgram.
# Works on Ghidra 11.4.x. Prefers program externals; falls back to PE factory if needed.
#
# Usage (example):
# analyzeHeadless <projDir> <projName> -process <binary> -postScript dump_imports.py

import json
from java.lang import System

# Ghidra APIs
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import ConsoleTaskMonitor

# Optional PE fallback (for raw container parse)
try:
    from ghidra.app.util.bin.format.pe import PortableExecutableFactory
    from ghidra.app.util.bin.format.pe.PortableExecutable import SectionLayout
    from ghidra.app.util.bin import BinaryReader
    from ghidra.app.util.bin import ByteProvider
    from ghidra.app.util.bin.format.pe import PortableExecutable
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.util import Msg
except Exception:
    PortableExecutableFactory = None

def _hex(addr):
    try:
        return "0x%X" % addr.getOffset()
    except Exception:
        return None

def _dump_from_externals(program):
    """Use the program's SymbolTable/ExternalManager (most reliable)."""
    out = []
    symtab = program.getSymbolTable()
    externals = symtab.getExternalSymbols()
    for sym in externals:
        try:
            name = sym.getName()
            ns = sym.getParentNamespace()
            lib = ns.getName() if ns else None
            addr = sym.getAddress()
            out.append({
                "lib": lib,
                "name": name,
                "addr": _hex(addr),
            })
        except Exception as e:
            # keep going
            pass
    return out

def _dump_from_pe_factory(program):
    """Fallback: parse raw PE container with the factory API available in 11.4.x."""
    if PortableExecutableFactory is None:
        return []
    try:
        # Acquire FileBytes of the current program
        file_bytes = program.getMemory().getAllFileBytes()
        if not file_bytes:
            return []
        fb = file_bytes[0]
        # Create ByteProvider over the entire file
        bp = fb.getOriginalProvider()
        pe = PortableExecutableFactory.createPortableExecutable(
            bp, SectionLayout.MEMORY, ConsoleTaskMonitor()
        )
        imports = []
        imp = pe.getImportTable()
        if imp is None:
            return []
        dlls = imp.getImports()  # list of ImportInfo (per DLL)
        for dll in dlls:
            dll_name = dll.getName()
            entries = dll.getImportEntries()  # list of ImportEntry
            for ent in entries:
                nm = ent.getName()
                ordval = ent.getOrdinal()
                imports.append({
                    "lib": dll_name,
                    "name": nm if nm else None,
                    "ordinal": int(ordval) if ordval is not None else None
                })
        return imports
    except Exception as e:
        return []

def run():
    prog = currentProgram
    if prog is None:
        printerr("[dump_imports] No currentProgram loaded")
        return

    # 1) Try externals (preferred)
    imports = _dump_from_externals(prog)

    # 2) If empty, try PE factory fallback
    if not imports:
        imports = _dump_from_pe_factory(prog)

    # 3) Emit JSON on stdout (headless-safe)
    result = {
        "program": prog.getName(),
        "imports": imports,
    }
    print(json.dumps(result, indent=2, sort_keys=True))

if __name__ == "__main__":
    run()

